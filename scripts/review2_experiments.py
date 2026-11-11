"""Review 2 E1-E3 analyses under the frozen protocol in docs/REVIEW2_PROTOCOL.md.

Reuses the Review 1 generator, attacker and metrics unchanged. Synthetic engineering
fixture only: results are not independent validation. No network access, no real vault.
"""
import argparse
import csv
import hashlib
import importlib.metadata
import json
import math
import platform
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import numpy as np
from scipy.optimize import minimize
from scipy.special import expit
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score

from modules.semantic import calculate_thematic_coverage
from scripts.review_experiments import metrics, synthetic_rows, threshold_at_fpr, validate_rows
from vault.audit import AuditConfig, calculate_risk_score
from vault.research import FEATURES, LEGACY, features, fixed_score, guesses

PRIMARY_BUDGET = 1000
SCENARIOS = ('S1', 'S2', 'S3', 'S4', 'S5')
PROTOCOL = ROOT / 'docs/REVIEW2_PROTOCOL.md'


# ── statistics helpers ─────────────────────────────────────────────────────────
def wilson(successes, total, z=1.959963984540054):
    if total == 0:
        return [None, None]
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return [max(0.0, centre - half), min(1.0, centre + half)]


def profile_bootstrap(y, preds, groups, reps=1000, seed=42):
    """95% intervals for recall/FPR/precision of each prediction vector, resampling profiles."""
    rng = np.random.default_rng(seed)
    unique = np.unique(groups)
    index = {g: np.flatnonzero(groups == g) for g in unique}
    draws = defaultdict(lambda: defaultdict(list))
    for _ in range(reps):
        idx = np.concatenate([index[g] for g in rng.choice(unique, len(unique), replace=True)])
        yy = y[idx]
        for name, pred in preds.items():
            pp = pred[idx]
            tp = int(np.sum(pp & (yy == 1))); fp = int(np.sum(pp & (yy == 0)))
            pos = int(np.sum(yy == 1)); neg = int(np.sum(yy == 0))
            if pos:
                draws[name]['recall'].append(tp / pos)
            if neg:
                draws[name]['fpr'].append(fp / neg)
            if tp + fp:
                draws[name]['precision'].append(tp / (tp + fp))
        if 'CAV_current' in preds and np.any(yy == 1):
            base = np.sum(preds['CAV_current'][idx] & (yy == 1)) / np.sum(yy == 1)
            for name, pred in preds.items():
                draws[name]['recall_minus_cav'].append(np.sum(pred[idx] & (yy == 1)) / np.sum(yy == 1) - base)
    return {name: {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] for k, v in d.items()}
            for name, d in draws.items()}


def recall_at_test_fpr(y, scores, max_fpr):
    """Exploratory: best recall over thresholds chosen ON TEST with test FPR <= max_fpr."""
    best = (0.0, None, 0.0)
    for t in sorted(set(scores.tolist()) | {float(np.nextafter(scores.max(), np.inf))}, reverse=True):
        m = metrics(y, scores, t)
        if m['fpr'] is not None and m['fpr'] <= max_fpr and m['recall'] > best[0]:
            best = (m['recall'], t, m['fpr'])
    return dict(recall=best[0], threshold=best[1], test_fpr=best[2])


def nonnegative_logistic(x, y, C=1.0):
    """Logistic regression (sklearn's L2 objective) with coefficients constrained >= 0."""
    n, d = x.shape

    def loss(w):
        z = x @ w[:d] + w[d]
        ll = np.sum(np.logaddexp(0, z) - y * z)
        residual = expit(z) - y
        return 0.5 * np.dot(w[:d], w[:d]) + C * ll, np.append(w[:d] + C * (x.T @ residual), C * np.sum(residual))
    res = minimize(loss, np.zeros(d + 1), jac=True, method='L-BFGS-B',
                   bounds=[(0, None)] * d + [(None, None)], options=dict(maxiter=5000))
    if not res.success:
        raise RuntimeError(f'Non-negative logistic fit failed: {res.message}')
    return res.x[:d], res.x[d]


def renormalized_fixed_score(vector, drop):
    weights = dict(LEGACY.weights)
    removed = weights.pop(drop)
    weights = {k: v / (1 - removed) for k, v in weights.items()}
    weights[drop] = 0.0
    cfg = AuditConfig(weights=weights, enable_age_score=True, max_correlated_contribution=1.0)
    return calculate_risk_score(*vector, config=cfg)


# ── attack outcomes ────────────────────────────────────────────────────────────
def attack_ranks(rows, budget, subset=None):
    """rank[(row_index, scenario)] of the target in the scenario's distinct-guess stream, plus
    stream statistics. Streams depend only on (profile, previous password) and are cached."""
    cache, ranks, stats = {}, {}, defaultdict(lambda: dict(seconds=0.0, streams=0, distinct=[]))
    for i, r in enumerate(rows):
        if subset is not None and i not in subset:
            continue
        for scenario in SCENARIOS:
            key = ('general',) if scenario == 'S1' else (scenario, r['profile_id'], r['previous_password'])
            if key not in cache:
                start = time.perf_counter()
                lookup = {g: k for k, g in enumerate(guesses(r['profile'], r['previous_password'], scenario, budget), 1)}
                stats[scenario]['seconds'] += time.perf_counter() - start
                stats[scenario]['streams'] += 1
                stats[scenario]['distinct'].append(len(lookup))
                cache[key] = lookup  # the S1 stream is profile-independent and kept for all rows
            ranks[(i, scenario)] = cache[key].get(r['password'])
        # Free per-profile streams once all of that profile's rows are processed.
        if i + 1 == len(rows) or rows[i + 1]['profile_id'] != r['profile_id']:
            for scenario in SCENARIOS[1:]:
                cache.pop((scenario, r['profile_id'], r['previous_password']), None)
    return ranks, {s: dict(seconds=round(v['seconds'], 3), streams=v['streams'],
                           distinct_min=min(v['distinct']), distinct_median=float(np.median(v['distinct'])),
                           distinct_max=max(v['distinct']), budget=budget,
                           exhausted_streams=sum(d < budget for d in v['distinct'])) for s, v in stats.items()}


# ── stress-test transformations (author-written, never used for tuning) ────────
def stress_rows(rows):
    out = []
    seen = set()
    for r in rows:
        if r['split'] != 'test' or r['profile_id'] in seen:
            continue
        seen.add(r['profile_id'])
        p = r['profile']
        name, city, year = p['first_name'], p['city'], str(p['birth_year'])
        mid = len(name) // 2
        families = {
            'reversed_name': name[::-1] + year,
            'vowel_dropped': ''.join(c for c in name if c.lower() not in 'aeiou') + '!' + year[-2:],
            'symbol_split': '.'.join(name) + '!',
            'diacritics': name.translate(str.maketrans('aeiouAEIOU', 'áéíóúÁÉÍÓÚ')) + year,
            'adjacent_swap': name[:mid - 1] + name[mid] + name[mid - 1] + name[mid + 1:] + '!',
            'two_char_parts': name[:2] + city[:2] + year[-2:],
            'digit_inserted': name[:mid] + '7' + name[mid:] + '#',
            'initials_year': name[0] + p['surname'][0] + city[0] + year,
        }
        for family, password in families.items():
            out.append(dict(profile_id=r['profile_id'], family=family, password=password, profile=p))
    return out


# ── provenance ─────────────────────────────────────────────────────────────────
def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_digest():
    files = sorted([*ROOT.glob('vault/*.py'), *ROOT.glob('modules/*.py'), *ROOT.glob('scripts/review*.py'),
                    ROOT / 'requirements-lock.txt'])
    h = hashlib.sha256()
    for f in files:
        h.update(str(f.relative_to(ROOT)).encode() + b'\0' + f.read_bytes() + b'\0')
    return h.hexdigest()


def git_state():
    def run(*args):
        return subprocess.run(['git', *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    return dict(base_commit=run('rev-parse', 'HEAD'), branch=run('rev-parse', '--abbrev-ref', 'HEAD'),
                dirty_files=len([l for l in run('status', '--porcelain').splitlines() if l.strip()]))


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


# ── main analysis ──────────────────────────────────────────────────────────────
def run(out, profiles=1002, seed=42, e3_budgets=(100, 1000, 10000, 100000), reps=1000, input_path=None):
    started = time.time()
    out.mkdir(parents=True, exist_ok=True)
    # An independently authored benchmark (JSONL, docs/INDEPENDENT_BENCHMARK_KIT.md) replaces the fixture.
    rows = ([json.loads(line) for line in Path(input_path).read_text().splitlines() if line.strip()]
            if input_path else synthetic_rows(profiles, seed))
    validate_rows(rows)
    x = np.asarray([features(r) for r in rows])
    part = {s: np.array([i for i, r in enumerate(rows) if r['split'] == s]) for s in ('train', 'validation', 'test')}
    tr, va, te = part['train'], part['validation'], part['test']
    groups_te = np.array([rows[i]['profile_id'] for i in te])
    personal = np.array([r['label_personal'] for r in rows])
    categories = np.array([r['category'] for r in rows])
    report = dict(protocol_sha256=sha256_file(PROTOCOL))

    # ── E1 ──
    e1_threshold = threshold_at_fpr(personal[va], x[va, 1])
    e1 = dict(validation_threshold=e1_threshold, thresholds={})
    for label, thr in (('validation_selected', e1_threshold), ('production_0.30', 0.30)):
        overall = metrics(personal[te], x[te, 1], thr)
        overall['recall_ci95'] = wilson(overall['tp'], overall['tp'] + overall['fn'])
        overall['fpr_ci95'] = wilson(overall['fp'], overall['fp'] + overall['tn'])
        per_cat = {}
        for c in sorted(set(categories)):
            idx = te[categories[te] == c]
            flagged = int(np.sum(x[idx, 1] >= thr))
            positive = bool(personal[idx].all())
            per_cat[c] = dict(n=len(idx), label=int(positive), flagged=flagged,
                              rate=flagged / len(idx), rate_ci95=wilson(flagged, len(idx)),
                              rate_is='recall' if positive else 'false_positive_rate')
        e1['thresholds'][label] = dict(threshold=thr, overall=overall, categories=per_cat)
    hard = te[categories[te] == 'hard_negative']
    flagged_hard = [i for i in hard if x[i, 1] >= e1_threshold]
    why = Counter(tuple(calculate_thematic_coverage(rows[i]['password'], rows[i]['profile'])['matched_fields'])
                  for i in flagged_hard)
    e1['hard_negative_analysis'] = dict(flagged=len(flagged_hard), of=len(hard),
                                        matched_fields={'+'.join(k): v for k, v in why.items()},
                                        coverage_values=sorted({round(float(x[i, 1]), 3) for i in flagged_hard}))
    stress = stress_rows(rows)
    fam = defaultdict(list)
    for s in stress:
        res = calculate_thematic_coverage(s['password'], s['profile'])
        fam[s['family']].append((res['score'], set(res['matched_fields'])))

    def stress_summary(values, thr):
        hits = [fields for score, fields in values if score >= thr]
        year_only = sum(fields <= {'birth year'} for fields in hits)
        surname = sum('surname' in fields for fields in hits)
        return dict(n=len(values), detected=len(hits), recall=len(hits) / len(values),
                    recall_ci95=wilson(len(hits), len(values)), detected_by_birth_year_only=year_only,
                    detected_with_name_or_city_field=sum(bool(fields & {'name', 'hometown'}) for fields in hits),
                    detected_with_surname_field=surname)
    e1['stress_families'] = {f: {lab: stress_summary(v, thr)
                                 for lab, thr in (('validation_selected', e1_threshold), ('production_0.30', 0.30))}
                             for f, v in fam.items()}
    e1['stress_note'] = ('Fixture surnames are the reversed first name, so reversed_name matches the surname field; '
                         'detections driven only by the birth year do not show that the transformed name was recognised.')
    (out / 'e1.json').write_text(json.dumps(e1, indent=2))

    # ── attack outcomes ──
    ranks_all, stream_all = attack_ranks(rows, PRIMARY_BUDGET)
    test_set = set(te.tolist())
    max_budget = max(e3_budgets)
    ranks_te, stream_te = attack_ranks(rows, max_budget, subset=test_set)
    for i in te:  # stream order is budget independent: ranks within 1,000 must agree
        for s in SCENARIOS:
            a, b = ranks_all[(i, s)], ranks_te[(i, s)]
            assert a == (b if b is not None and b <= PRIMARY_BUDGET else None), (i, s, a, b)
    r1_path = ROOT / 'results/review1/attack_outcomes.json'
    if r1_path.exists() and profiles == 1002 and seed == 42 and not input_path:
        r1 = {(o['id'], o['scenario']): o['rank'] for o in json.loads(r1_path.read_text())}
        mismatch = sum(r1[(rows[i]['id'], s)] != ranks_all[(i, s)] for i in range(len(rows)) for s in SCENARIOS)
        report['review1_rank_mismatches'] = mismatch
        assert mismatch == 0, 'Review 1 attack outcomes not reproduced'

    def outcome(scenario, budget, idx):
        src = ranks_all if budget <= PRIMARY_BUDGET else ranks_te
        return np.array([int(src[(i, scenario)] is not None and src[(i, scenario)] <= budget) for i in idx])

    y_all = outcome('S5', PRIMARY_BUDGET, range(len(rows)))
    y_te = y_all[te]

    # ── E2 methods ──
    scored = {
        'B1_syntax': x[:, 2], 'B2_breach_fixture': x[:, 0], 'B3_syntax_breach': np.maximum(x[:, 0], x[:, 2]),
        'B4_personal': x[:, 1], 'B5_history': np.maximum(x[:, 3], x[:, 4]),
        'B6_submitted_weights': np.array([fixed_score(v, True) for v in x]),
        'CAV_current': np.array([fixed_score(v) for v in x]),
    }
    b7 = LogisticRegression(random_state=42, max_iter=1000).fit(x[tr], y_all[tr])
    scored['B7_logistic'] = b7.predict_proba(x)[:, 1]
    w9, c9 = nonnegative_logistic(x[tr], y_all[tr])
    scored['B9_nonneg_logistic'] = expit(x @ w9 + c9)
    rules = {
        'R1_gate_rule': ((x[:, 0] > 0) | (x[:, 1] > 0) | (x[:, 2] > 0) | (x[:, 3] > 0) | (x[:, 4] > 0)).astype(float),
        'R2_context_rule': ((x[:, 1] >= 0.30) | (x[:, 3] > 0) | (x[:, 4] > 0)).astype(float),
    }
    thresholds = {k: threshold_at_fpr(y_all[va], v[va]) for k, v in scored.items()}
    thresholds.update({k: 1.0 for k in rules})
    methods = {**scored, **rules}
    e2 = {}
    preds = {}
    for name, score in methods.items():
        m = metrics(y_te, score[te], thresholds[name])
        m['validation_fpr'] = metrics(y_all[va], score[va], thresholds[name])['fpr']
        m['score_semantics'] = ('probability model' if name in ('B7_logistic', 'B9_nonneg_logistic')
                                else 'fixed rule' if name in rules else 'heuristic or binary score')
        if m['score_semantics'] != 'probability model':
            m['brier_exploratory_only'] = m.pop('brier')
        e2[name] = m
        preds[name] = score[te] >= thresholds[name]
    boot = profile_bootstrap(y_te, preds, groups_te, reps=reps)
    for name in e2:
        e2[name]['bootstrap_ci95'] = boot[name]
    b7_fpr = e2['B7_logistic']['fpr']
    matched = {name: dict(at_b7_test_fpr=recall_at_test_fpr(y_te, s[te], b7_fpr),
                          at_test_fpr_0_05=recall_at_test_fpr(y_te, s[te], 0.05))
               for name, s in scored.items()}
    sensitivity = []
    for t in [round(v, 2) for v in np.arange(0.05, 0.61, 0.05)]:
        mv = metrics(y_all[va], scored['CAV_current'][va], t)
        mt = metrics(y_te, scored['CAV_current'][te], t)
        sensitivity.append(dict(threshold=t, validation_fpr=mv['fpr'], test_recall=mt['recall'],
                                test_fpr=mt['fpr'], test_precision=mt['precision']))
    syn_va = metrics(y_all[va], x[va, 2], 1.0)
    b3_va = metrics(y_all[va], scored['B3_syntax_breach'][va], 1.0)
    b2_va = metrics(y_all[va], x[va, 0], 1.0)
    discrete = dict(
        B1_syntax_validation_fpr_at_flag=syn_va['fpr'], B3_validation_fpr_at_flag=b3_va['fpr'],
        B2_validation_fpr_at_flag=b2_va['fpr'], B2_validation_recall_at_flag=b2_va['recall'],
        distinct_scores={k: len(set(np.round(v, 9))) for k, v in scored.items()})
    ablation = {}
    for j, f in enumerate(FEATURES):
        masked = x.copy(); masked[:, j] = 0
        fixed = np.array([fixed_score(v, True) for v in masked])
        renorm = np.array([renormalized_fixed_score(v, f) for v in masked])
        keep = [k for k in range(len(FEATURES)) if k != j]
        refit = LogisticRegression(random_state=42, max_iter=1000).fit(x[tr][:, keep], y_all[tr]).predict_proba(x[:, keep])[:, 1]
        ablation[f] = {}
        for label, s in (('fixed_no_renorm', fixed), ('fixed_renormalized', renorm), ('refit_logistic', refit)):
            thr = threshold_at_fpr(y_all[va], s[va])
            m = metrics(y_te, s[te], thr)
            ablation[f][label] = dict(recall=m['recall'], fpr=m['fpr'], pr_auc=m['pr_auc'], threshold=thr)
    calibration = {}
    for name in ('B7_logistic', 'B9_nonneg_logistic'):
        s = scored[name][te]; bands = []
        for low in np.arange(0, 1, .2):
            mask = (s >= low) & ((s < low + .2) if low < .8 else (s <= 1))
            bands.append(dict(lower=round(float(low), 1), n=int(mask.sum()),
                              mean_score=float(s[mask].mean()) if mask.any() else None,
                              observed=float(y_te[mask].mean()) if mask.any() else None))
        calibration[name] = bands
    coefficients = dict(B7=dict(intercept=float(b7.intercept_[0]), **dict(zip(FEATURES, b7.coef_[0].tolist()))),
                        B9=dict(intercept=float(c9), **dict(zip(FEATURES, w9.tolist()))))
    (out / 'e2.json').write_text(json.dumps(dict(primary=e2, thresholds=thresholds, matched_fpr_exploratory=matched,
                                                 cav_threshold_sensitivity=sensitivity, discrete_score_effects=discrete,
                                                 ablation=ablation, calibration_probability_models=calibration,
                                                 coefficients_research_only=coefficients,
                                                 positives=int(y_te.sum()), n=len(te)), indent=2))

    # ── E3 ──
    e3 = dict(streams_all_profiles_budget_1000=stream_all, streams_test_budget_max=stream_te, scenarios={})
    show = ('B1_syntax', 'B2_breach_fixture', 'B5_history', 'CAV_current', 'B7_logistic', 'B9_nonneg_logistic',
            'R1_gate_rule', 'R2_context_rule')
    for s in SCENARIOS:
        for budget in e3_budgets:
            ys = outcome(s, budget, te)
            entry = dict(recovered=int(ys.sum()), total=len(te), rate=float(ys.mean()),
                         rate_ci95=wilson(int(ys.sum()), len(te)), methods={})
            for name in show:
                m = metrics(ys, methods[name][te], thresholds[name])
                entry['methods'][name] = dict(recall=m['recall'], fpr=m['fpr'], pr_auc=m['pr_auc'],
                                              recall_ci95=wilson(m['tp'], m['tp'] + m['fn']))
            e3['scenarios'][f'{s}@{budget}'] = entry
    specific = {}
    for s in SCENARIOS:
        yv, yt = outcome(s, PRIMARY_BUDGET, va), outcome(s, PRIMARY_BUDGET, te)
        specific[s] = {}
        for name in ('CAV_current', 'B7_logistic', 'B9_nonneg_logistic'):
            try:
                thr = threshold_at_fpr(yv, methods[name][va])
            except ValueError:
                specific[s][name] = None
                continue
            m = metrics(yt, methods[name][te], thr)
            specific[s][name] = dict(threshold=thr, recall=m['recall'], fpr=m['fpr'])
    e3['scenario_specific_thresholds_exploratory'] = specific
    errors = {}
    y5 = outcome('S5', PRIMARY_BUDGET, te)
    single = {s: outcome(s, PRIMARY_BUDGET, te) for s in ('S1', 'S2', 'S3')}
    for c in sorted(set(categories[te])):
        mask = categories[te] == c
        rec = mask & (y5 == 1)
        errors[c] = dict(n=int(mask.sum()), recovered_s5=int(rec.sum()),
                         recovered_by={s: int((mask & (v == 1)).sum()) for s, v in single.items()},
                         detected_among_recovered={n: int((preds[n] & rec).sum())
                                                   for n in ('CAV_current', 'B7_logistic', 'B9_nonneg_logistic',
                                                             'R1_gate_rule', 'R2_context_rule')})
    e3['error_analysis_s5_1000_by_category'] = errors
    (out / 'e3.json').write_text(json.dumps(e3, indent=2))

    # ── tables for the paper ──
    tables = out / 'tables'
    write_csv(tables / 'e1_overall.csv', [dict(threshold=k, **{m: v['overall'][m] for m in
              ('tp', 'fp', 'tn', 'fn', 'precision', 'recall', 'f1', 'fpr', 'balanced_accuracy', 'pr_auc', 'roc_auc')})
              for k, v in e1['thresholds'].items()])
    write_csv(tables / 'e1_categories.csv', [dict(category=c, threshold=k, **v) for k, t in e1['thresholds'].items()
                                             for c, v in t['categories'].items()])
    write_csv(tables / 'e1_stress.csv', [dict(family=f, threshold=k, **v) for f, d in e1['stress_families'].items()
                                         for k, v in d.items()])
    write_csv(tables / 'e2_primary.csv', [dict(method=n, precision=m['precision'], recall=m['recall'], fpr=m['fpr'],
              pr_auc=m['pr_auc'], threshold=thresholds[n], recall_ci_low=m['bootstrap_ci95'].get('recall', [None])[0],
              recall_ci_high=m['bootstrap_ci95'].get('recall', [None, None])[1]) for n, m in e2.items()])
    write_csv(tables / 'e2_ablation.csv', [dict(removed=f, variant=k, **v) for f, d in ablation.items() for k, v in d.items()])
    write_csv(tables / 'e2_sensitivity.csv', sensitivity)
    write_csv(tables / 'e3_scenarios.csv', [dict(outcome=k, recovered=v['recovered'], total=v['total'], rate=v['rate'],
              **{f'{n}_recall': v['methods'][n]['recall'] for n in show}) for k, v in e3['scenarios'].items()])

    deps = {p: importlib.metadata.version(p) for p in ('numpy', 'scipy', 'scikit-learn', 'zxcvbn-python', 'rapidfuzz')}
    manifest = dict(protocol='docs/REVIEW2_PROTOCOL.md', protocol_sha256=report['protocol_sha256'],
                    dataset_sha256=hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest(),
                    samples=len(rows), profiles=len({r['profile_id'] for r in rows}), seed=seed, primary_budget=PRIMARY_BUDGET,
                    e3_budgets=list(e3_budgets), bootstrap_replicates=reps,
                    review1_rank_mismatches=report.get('review1_rank_mismatches'),
                    source_tree_sha256=source_digest(), git=git_state(), python=sys.version.split()[0],
                    platform=platform.platform(), machine=platform.machine(), dependencies=deps,
                    runtime_seconds=round(time.time() - started, 1),
                    command=' '.join(['.venv/bin/python', 'scripts/review2_experiments.py', *sys.argv[1:]]),
                    dataset_type=('supplied_benchmark_provenance_as_declared' if input_path
                                  else 'synthetic_smoke_not_independent'),
                    input=str(input_path) if input_path else None)
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=Path('results/review2'))
    parser.add_argument('--profiles', type=int, default=1002)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--budgets', nargs='+', type=int, default=[100, 1000, 10000, 100000])
    parser.add_argument('--bootstrap', type=int, default=1000)
    parser.add_argument('--input', type=Path, help='Independently authored JSONL benchmark (see docs/INDEPENDENT_BENCHMARK_KIT.md)')
    args = parser.parse_args()
    print(json.dumps(run(args.out, args.profiles, args.seed, tuple(args.budgets), args.bootstrap, args.input), indent=2))


if __name__ == '__main__':
    main()
