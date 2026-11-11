"""Review 2 Amendment 2: independent real-data benchmark on the PASS sample (cross-account signals).

Data: public sample of Wang et al., "The Next Domino To Fall" (ACM CODASPY 2018), stored
privately in data/private/pass/. Nothing tuned on these data: thresholds and models come from
the Review 2 synthetic validation. Only aggregate statistics are written; a guard refuses to
write any result that contains a password from the dataset.
"""
import argparse
import hashlib
import json
import platform
import random
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import numpy as np
from scipy.special import expit
from sklearn.linear_model import LogisticRegression

from scripts.review2_experiments import (attack_ranks, git_state, nonnegative_logistic, profile_bootstrap,
                                         sha256_file, source_digest, wilson)
from scripts.review_experiments import metrics, synthetic_rows, threshold_at_fpr
from vault.audit import _are_derivatives, extract_base_password
from vault.research import features, fixed_score, guesses, guesses_s6, zxcvbn_meter_score

AMENDMENT = ROOT / 'docs/REVIEW2_PROTOCOL_AMENDMENT2.md'
DATA = ROOT / 'data/private/pass/sample_dataset.txt'
BUDGETS = (100, 1000, 10000)


def load_users(path):
    users = []
    for line in Path(path).read_text(encoding='utf-8', errors='replace').splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        parts = line.split('\t')
        pws = [p for p in parts[1:] if p != '']
        if len(pws) >= 2:
            users.append(pws)
    return users


def synthetic_models():
    """Rebuilds B7 and B9 exactly as in Review 2 and checks their frozen thresholds."""
    rows = synthetic_rows(1002, 42)
    x = np.asarray([features(r) for r in rows])
    tr = np.array([i for i, r in enumerate(rows) if r['split'] == 'train'])
    va = np.array([i for i, r in enumerate(rows) if r['split'] == 'validation'])
    ranks, _ = attack_ranks(rows, 1000)
    y = np.array([int(ranks[(i, 'S5')] is not None) for i in range(len(rows))])
    b7 = LogisticRegression(random_state=42, max_iter=1000).fit(x[tr], y[tr])
    w9, c9 = nonnegative_logistic(x[tr], y[tr])
    frozen = json.loads((ROOT / 'results/review2/e2.json').read_text())['thresholds']
    assert abs(threshold_at_fpr(y[va], b7.predict_proba(x[va])[:, 1]) - frozen['B7_logistic']) < 1e-12
    assert abs(threshold_at_fpr(y[va], expit(x[va] @ w9 + c9)) - frozen['B9_nonneg_logistic']) < 1e-12
    return b7, (w9, c9), frozen


def history_rank(target, history, attacker, budget):
    best = None
    for previous in history:
        stream = (guesses({}, previous, 'S3', budget) if attacker == 'S3' else guesses_s6({}, previous, budget))
        for k, guess in enumerate(stream, 1):
            if guess == target:
                best = k if best is None else min(best, k)
                break
    return best


def evaluate(cases, b7, b9, frozen, meter_thr, reps, label):
    x = np.asarray([features(dict(password=t, profile={}, other_passwords=h, breach_count=0, age_days=0))
                    for t, h, _ in cases])
    groups = np.array([g for _, _, g in cases])
    to_unit = lambda s: 1.0 / (1.0 - s)
    scores = {
        'CAV_current': np.array([fixed_score(v) for v in x]),
        'B7_logistic_transfer': b7.predict_proba(x)[:, 1],
        'B9_nonneg_logistic_transfer': expit(x @ b9[0] + b9[1]),
        'B8a_zxcvbn_meter': np.array([to_unit(zxcvbn_meter_score(t)) for t, _, _ in cases]),
        'B8b_zxcvbn_history_inputs': np.array([to_unit(zxcvbn_meter_score(t, h)) for t, h, _ in cases]),
        'B5_reuse_or_derivative': np.maximum(x[:, 3], x[:, 4]),
        'R1_gate_rule_no_profile': np.maximum.reduce([x[:, 2], x[:, 3], x[:, 4]]),
    }
    thresholds = {'CAV_current': frozen['CAV_current'], 'B7_logistic_transfer': frozen['B7_logistic'],
                  'B9_nonneg_logistic_transfer': frozen['B9_nonneg_logistic'],
                  'B8a_zxcvbn_meter': meter_thr['B8a_zxcvbn_meter'],
                  'B8b_zxcvbn_history_inputs': meter_thr['B8b_zxcvbn_user_inputs'],
                  'B5_reuse_or_derivative': 1.0, 'R1_gate_rule_no_profile': 1.0}
    ranks = {a: [history_rank(t, h, a, max(BUDGETS)) for t, h, _ in cases] for a in ('S3', 'S6')}
    out = dict(cases=len(cases), users=len(set(groups)), signal_prevalence=dict(
        exact_reuse=float(x[:, 3].mean()), derivative=float(x[:, 4].mean()),
        weak_syntax=float(x[:, 2].mean()), reuse_or_derivative=float(np.maximum(x[:, 3], x[:, 4]).mean())),
        outcomes={})
    for attacker in ('S3', 'S6'):
        for budget in BUDGETS:
            y = np.array([int(r is not None and r <= budget) for r in ranks[attacker]])
            entry = dict(recovered=int(y.sum()), rate=float(y.mean()), rate_ci95=wilson(int(y.sum()), len(y)), methods={})
            preds = {k: s >= thresholds[k] for k, s in scores.items()}
            boot = profile_bootstrap(y, preds, groups, reps=reps) if 0 < y.sum() < len(y) else {}
            for name, s in scores.items():
                m = metrics(y, s, thresholds[name])
                entry['methods'][name] = dict(
                    precision=m['precision'], recall=m['recall'], fpr=m['fpr'],
                    pr_auc=None if name.startswith(('B5', 'R1')) else m['pr_auc'],
                    flagged=int(preds[name].sum()), bootstrap_ci95=boot.get(name, {}))
            out['outcomes'][f'{attacker}@{budget}'] = entry
    # Paired user-level comparison of the cross-account rule against the published contextual meter.
    y = np.array([int(r is not None and r <= 1000) for r in ranks['S6']])
    out['paired_B5_minus_B8b_S6_1000'] = paired_difference(
        y, scores['B5_reuse_or_derivative'] >= 1.0, scores['B8b_zxcvbn_history_inputs'] >= thresholds['B8b_zxcvbn_history_inputs'],
        groups, reps)
    # Exploratory, not pre-specified: targets that are not an exact copy of any history password.
    keep = np.array([t not in h for t, h, _ in cases])
    sub = dict(cases=int(keep.sum()), note='exploratory post-hoc subset: target differs from every history password')
    for attacker in ('S3', 'S6'):
        ys = np.array([int(r is not None and r <= 1000) for r in ranks[attacker]])[keep]
        sub[f'{attacker}@1000'] = dict(recovered=int(ys.sum()), rate=float(ys.mean()), rate_ci95=wilson(int(ys.sum()), len(ys)),
            methods={name: dict(recall=metrics(ys, s[keep], thresholds[name])['recall'],
                                fpr=metrics(ys, s[keep], thresholds[name])['fpr'],
                                precision=metrics(ys, s[keep], thresholds[name])['precision'],
                                flagged=int((s[keep] >= thresholds[name]).sum()))
                     for name, s in scores.items()})
    ys = np.array([int(r is not None and r <= 1000) for r in ranks['S6']])[keep]
    sub['paired_B5_minus_B8b_S6_1000'] = paired_difference(
        ys, (scores['B5_reuse_or_derivative'] >= 1.0)[keep],
        (scores['B8b_zxcvbn_history_inputs'] >= thresholds['B8b_zxcvbn_history_inputs'])[keep], groups[keep], reps)
    out['non_reuse_targets'] = sub
    return out


def paired_difference(y, pred_a, pred_b, groups, reps, seed=42):
    """User-level bootstrap 95% intervals for recall and FPR differences (a minus b)."""
    rng = np.random.default_rng(seed)
    unique = np.unique(groups)
    index = {g: np.flatnonzero(groups == g) for g in unique}
    def rates(idx):
        yy, a, b = y[idx], pred_a[idx], pred_b[idx]
        pos, neg = yy == 1, yy == 0
        return ((a[pos].mean() - b[pos].mean()) if pos.any() else np.nan,
                (a[neg].mean() - b[neg].mean()) if neg.any() else np.nan)
    point = rates(np.arange(len(y)))
    draws = np.array([rates(np.concatenate([index[g] for g in rng.choice(unique, len(unique), replace=True)]))
                      for _ in range(reps)])
    return dict(recall_difference=float(point[0]), recall_difference_ci95=np.nanpercentile(draws[:, 0], [2.5, 97.5]).tolist(),
                fpr_difference=float(point[1]), fpr_difference_ci95=np.nanpercentile(draws[:, 1], [2.5, 97.5]).tolist())


def run(out_path, reps):
    started = time.time()
    users = load_users(DATA)
    rng = random.Random(2018)
    primary, secondary = [], []
    for u, pws in enumerate(users):
        k = rng.randrange(len(pws))
        primary.append((pws[k], pws[:k] + pws[k + 1:], u))
        for j in range(len(pws)):
            secondary.append((pws[j], pws[:j] + pws[j + 1:], u))
    b7, b9, frozen = synthetic_models()
    meter_thr = json.loads((ROOT / 'results/review2/amendment1/baselines.json').read_text())['thresholds']

    # Prevalence of exact reuse and of CAV-derivative relations within users, and specificity across users.
    within_distinct = within_related = users_with_exact = 0
    for pws in users:
        users_with_exact += len(set(pws)) < len(pws)
        uniq = sorted(set(pws))
        for a in range(len(uniq)):
            for b in range(a + 1, len(uniq)):
                within_distinct += 1
                within_related += _are_derivatives(uniq[a], uniq[b], extract_base_password(uniq[a]),
                                                   extract_base_password(uniq[b]))
    prng = random.Random(7)
    cross_related = cross_equal = 0
    pairs = 20000
    for _ in range(pairs):
        u1, u2 = prng.sample(range(len(users)), 2)
        a, b = prng.choice(users[u1]), prng.choice(users[u2])
        cross_equal += a == b
        cross_related += a != b and _are_derivatives(a, b, extract_base_password(a), extract_base_password(b))
    lengths = [len(p) for pws in users for p in pws]
    report = dict(
        provenance='PASS public sample (Wang et al., ACM CODASPY 2018); real pseudonymous breached passwords; '
                   'only aggregates reported; no HIBP lookups; thresholds and models frozen from Review 2',
        dataset=dict(users=len(users), passwords=len(lengths), sha256=sha256_file(DATA),
                     passwords_per_user={str(n): sum(len(p) == n for p in users) for n in range(2, 6)},
                     length_median=float(np.median(lengths)), length_p10_p90=[float(np.percentile(lengths, 10)),
                                                                             float(np.percentile(lengths, 90))]),
        relations=dict(users_with_exact_reuse=users_with_exact, users_with_exact_reuse_rate=users_with_exact / len(users),
                       within_user_distinct_pairs=within_distinct, within_user_pairs_derivative=within_related,
                       within_user_derivative_rate=within_related / within_distinct,
                       within_user_derivative_rate_ci95=wilson(within_related, within_distinct),
                       cross_user_random_pairs=pairs, cross_user_identical=cross_equal,
                       cross_user_derivative=cross_related, cross_user_derivative_rate=cross_related / pairs,
                       cross_user_derivative_rate_ci95=wilson(cross_related, pairs)),
        primary_one_target_per_user=evaluate(primary, b7, b9, frozen, meter_thr, reps, 'primary'),
        secondary_every_password_as_target=evaluate(secondary, b7, b9, frozen, meter_thr, reps, 'secondary'),
        amendment='docs/REVIEW2_PROTOCOL_AMENDMENT2.md', amendment_sha256=sha256_file(AMENDMENT),
        source_tree_sha256=source_digest(), git=git_state(), python=sys.version.split()[0],
        platform=platform.platform(), runtime_seconds=round(time.time() - started, 1))
    text = json.dumps(report, indent=2)
    # Privacy guard: every key and text value is checked (computed numbers and hex digests are not
    # text that could carry a password; digit-only passwords can coincide with their digits).
    strings = []  # (path, text)

    def collect(node, path='$'):
        if isinstance(node, dict):
            for key, value in node.items():
                strings.append((path + '.<key>', str(key)))
                collect(value, f'{path}.{key}')
        elif isinstance(node, list):
            for k, value in enumerate(node):
                collect(value, f'{path}[{k}]')
        elif isinstance(node, str) and not re.fullmatch(r'[0-9a-f]{40,64}', node):
            strings.append((path, node))
    collect(report)
    own_metadata = ('$.git', '$.platform', '$.python', '$.amendment', '$.provenance')  # written by this script
    strings = [(where, s) for where, s in strings if not where.startswith(own_metadata)]
    hits = [(where, len(p)) for pws in users for p in pws if len(p) >= 4
            for where, s in strings if p in s]
    if hits:  # report locations and lengths only, never the password itself
        raise SystemExit(f'Refusing to write: dataset passwords would appear at {sorted(set(hits))[:10]}')
    Path(out_path).write_text(text)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'results/review2/pass_benchmark.json')
    parser.add_argument('--bootstrap', type=int, default=1000)
    args = parser.parse_args()
    r = run(args.out, args.bootstrap)
    print(json.dumps(dict(dataset=r['dataset'] | {'sha256': r['dataset']['sha256'][:12]}, relations=r['relations'],
                          runtime=r['runtime_seconds']), indent=2))
