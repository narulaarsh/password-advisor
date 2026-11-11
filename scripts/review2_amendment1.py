"""Review 2 Amendment 1 (docs/REVIEW2_PROTOCOL_AMENDMENT1.md): published-meter baselines,
a stronger rule-based attacker (S6) and a multilingual/transliteration E1 analysis.

Secondary and exploratory. The primary Review 2 result is recomputed only to obtain its
frozen thresholds, which are checked against results/review2/e2.json.
"""
import argparse
import hashlib
import json
import platform
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import numpy as np
from scipy.special import expit
from sklearn.linear_model import LogisticRegression

from modules.semantic import calculate_thematic_coverage
from scripts.review2_experiments import (SCENARIOS, attack_ranks, git_state, nonnegative_logistic,
                                         profile_bootstrap, sha256_file, source_digest, wilson)
from scripts.review_experiments import metrics, synthetic_rows, threshold_at_fpr, validate_rows
from vault.research import features, fixed_score, guesses_s6, zxcvbn_meter_score

AMENDMENT = ROOT / 'docs/REVIEW2_PROTOCOL_AMENDMENT1.md'
BUDGETS = (100, 1000, 10000, 100000)

# (family, profile name, password stem). Passwords carry no digits, so the birth year
# cannot contribute to coverage; profile birth year is 1990 throughout.
MULTILINGUAL = [
    ('a_diacritic_profile_ascii_password', 'José', 'Jose'), ('a_diacritic_profile_ascii_password', 'Zoë', 'Zoe'),
    ('a_diacritic_profile_ascii_password', 'François', 'Francois'),
    ('a_diacritic_profile_ascii_password', 'Ángela', 'Angela'),
    ('a_diacritic_profile_ascii_password', 'Müller', 'Muller'), ('a_diacritic_profile_ascii_password', 'Müller', 'Mueller'),
    ('a_diacritic_profile_ascii_password', 'Søren', 'Soren'), ('a_diacritic_profile_ascii_password', 'Łukasz', 'Lukasz'),
    ('a_diacritic_profile_ascii_password', 'Çelik', 'Celik'),
    ('b_alternative_romanization', 'Mohammed', 'Muhammad'), ('b_alternative_romanization', 'Aleksandr', 'Alexander'),
    ('b_alternative_romanization', 'Yusuf', 'Yousef'), ('b_alternative_romanization', 'Sergei', 'Sergey'),
    ('b_alternative_romanization', 'Lakshmi', 'Laxmi'), ('b_alternative_romanization', 'Chaudhary', 'Choudhury'),
    ('b_alternative_romanization', 'Zhang', 'Chang'),
    ('c_non_latin_profile_latin_password', 'प्रिया', 'Priya'), ('c_non_latin_profile_latin_password', 'राहुल', 'Rahul'),
    ('c_non_latin_profile_latin_password', 'Анна', 'Anna'), ('c_non_latin_profile_latin_password', 'Дмитрий', 'Dmitry'),
    ('c_non_latin_profile_latin_password', 'Ελένη', 'Eleni'), ('c_non_latin_profile_latin_password', 'محمد', 'Mohammed'),
    ('d_same_script', 'प्रिया', 'प्रिया'), ('d_same_script', 'राहुल', 'राहुल'), ('d_same_script', 'Анна', 'Анна'),
    ('d_same_script', 'Дмитрий', 'Дмитрий'), ('d_same_script', 'Ελένη', 'Ελένη'), ('d_same_script', 'محمد', 'محمد'),
    ('e_punctuation_removed', "O'Brien", 'OBrien'), ('e_punctuation_removed', "D'Souza", 'DSouza'),
    ('e_punctuation_removed', 'Jean-Luc', 'JeanLuc'), ('e_punctuation_removed', 'Anne-Marie', 'AnneMarie'),
    ('control_same_ascii_name', 'Priya', 'Priya'), ('control_same_ascii_name', 'Anna', 'Anna'),
    ('control_same_ascii_name', 'Jose', 'Jose'), ('control_same_ascii_name', 'Rahul', 'Rahul'),
]


def multilingual_analysis(e1_threshold):
    rows = []
    for family, name, stem in MULTILINGUAL:
        profile = dict(first_name=name, surname='', city='', birth_year=1990)
        password = stem + '##'
        res = calculate_thematic_coverage(password, profile)
        rows.append(dict(family=family, profile_name=name, password=password, coverage=res['score'],
                         matched_fields=res['matched_fields'], flagged_0_30=res['score'] >= 0.30,
                         flagged_validation=res['score'] >= e1_threshold))
    summary = defaultdict(lambda: dict(n=0, flagged_0_30=0, flagged_validation=0))
    for r in rows:
        s = summary[r['family']]
        s['n'] += 1
        s['flagged_0_30'] += r['flagged_0_30']
        s['flagged_validation'] += r['flagged_validation']
    return dict(rows=rows, summary=dict(summary))


def s6_ranks(rows, test):
    cache, ranks, distinct, seconds = {}, {}, [], 0.0
    for i in test:
        r = rows[i]
        key = (r['profile_id'], r['previous_password'])
        if key not in cache:
            cache.clear()
            start = time.perf_counter()
            cache[key] = {g: k for k, g in enumerate(guesses_s6(r['profile'], r['previous_password'], max(BUDGETS)), 1)}
            seconds += time.perf_counter() - start
            distinct.append(len(cache[key]))
        ranks[i] = cache[key].get(r['password'])
    return ranks, dict(streams=len(distinct), seconds=round(seconds, 2), distinct_min=min(distinct),
                       distinct_median=float(np.median(distinct)), distinct_max=max(distinct),
                       exhausted_streams=sum(d < max(BUDGETS) for d in distinct))


def run(out):
    started = time.time()
    out.mkdir(parents=True, exist_ok=True)
    rows = synthetic_rows(1002, 42)
    validate_rows(rows)
    x = np.asarray([features(r) for r in rows])
    part = {s: np.array([i for i, r in enumerate(rows) if r['split'] == s]) for s in ('train', 'validation', 'test')}
    tr, va, te = part['train'], part['validation'], part['test']
    ranks, _ = attack_ranks(rows, 1000)
    y_all = np.array([int(ranks[(i, 'S5')] is not None) for i in range(len(rows))])
    y_te = y_all[te]

    # Primary methods, recomputed exactly as in review2_experiments, thresholds checked.
    scored = {'B1_syntax': x[:, 2], 'B2_breach_fixture': x[:, 0], 'B5_history': np.maximum(x[:, 3], x[:, 4]),
              'CAV_current': np.array([fixed_score(v) for v in x])}
    scored['B7_logistic'] = LogisticRegression(random_state=42, max_iter=1000).fit(x[tr], y_all[tr]).predict_proba(x)[:, 1]
    w9, c9 = nonnegative_logistic(x[tr], y_all[tr])
    scored['B9_nonneg_logistic'] = expit(x @ w9 + c9)
    rules = {'R1_gate_rule': ((x[:, 0] > 0) | (x[:, 1] > 0) | (x[:, 2] > 0) | (x[:, 3] > 0) | (x[:, 4] > 0)).astype(float),
             'R2_context_rule': ((x[:, 1] >= 0.30) | (x[:, 3] > 0) | (x[:, 4] > 0)).astype(float)}
    frozen = json.loads((ROOT / 'results/review2/e2.json').read_text())['thresholds']
    thresholds = {k: threshold_at_fpr(y_all[va], v[va]) for k, v in scored.items()}
    for k, v in thresholds.items():
        assert abs(v - frozen[k]) < 1e-12, (k, v, frozen[k])
    thresholds.update({k: 1.0 for k in rules})

    # A1: published-meter baselines.
    start = time.perf_counter()
    # 1 / (1 + log10 guesses): a monotone map of the meter into (0, 1]; ranks and thresholds are unchanged.
    to_unit = lambda s: 1.0 / (1.0 - s)
    meters = {
        'B8a_zxcvbn_meter': np.array([to_unit(zxcvbn_meter_score(r['password'])) for r in rows]),
        'B8b_zxcvbn_user_inputs': np.array([to_unit(zxcvbn_meter_score(r['password'], [
            r['profile']['first_name'], r['profile']['surname'], r['profile']['city'],
            str(r['profile']['birth_year']), str(r['profile']['birth_year'])[-2:], r['previous_password']])) for r in rows]),
    }
    meter_seconds = time.perf_counter() - start
    for k, v in meters.items():
        thresholds[k] = threshold_at_fpr(y_all[va], v[va])
    baselines, preds = {}, {}
    for name, score in {**meters, 'CAV_current': scored['CAV_current'], 'B7_logistic': scored['B7_logistic']}.items():
        m = metrics(y_te, score[te], thresholds[name])
        m['validation_fpr'] = metrics(y_all[va], score[va], thresholds[name])['fpr']
        if name.startswith('B8'):
            m['brier_not_applicable'] = m.pop('brier')
        baselines[name] = m
        preds[name] = score[te] >= thresholds[name]
    boot = profile_bootstrap(y_te, preds, np.array([rows[i]['profile_id'] for i in te]), reps=1000)
    for name in baselines:
        baselines[name]['bootstrap_ci95'] = boot[name]
    per_scenario = {}
    for s in SCENARIOS:
        ys = np.array([int(ranks[(i, s)] is not None) for i in te])
        per_scenario[s] = {k: metrics(ys, v[te], thresholds[k])['recall'] for k, v in meters.items()}
    (out / 'baselines.json').write_text(json.dumps(dict(primary_outcome='S5@1000', thresholds={k: thresholds[k] for k in meters},
                                                        methods=baselines, recall_by_scenario_at_1000=per_scenario,
                                                        zxcvbn_seconds_all_rows=round(meter_seconds, 2)), indent=2))

    # A2: S6 attacker on the test partition.
    s6, stream = s6_ranks(rows, te)
    all_scores = {**scored, **rules, **meters}
    s6_report = dict(stream=stream, budgets={})
    for budget in BUDGETS:
        ys = np.array([int(s6[i] is not None and s6[i] <= budget) for i in te])
        entry = dict(recovered=int(ys.sum()), total=len(te), rate=float(ys.mean()),
                     rate_ci95=wilson(int(ys.sum()), len(te)), recall_at_frozen_thresholds={})
        for name, score in all_scores.items():
            m = metrics(ys, score[te], thresholds[name])
            entry['recall_at_frozen_thresholds'][name] = dict(recall=m['recall'], fpr=m['fpr'])
        cats = defaultdict(lambda: [0, 0])
        for k, i in enumerate(te):
            cats[rows[i]['category']][0] += int(ys[k])
            cats[rows[i]['category']][1] += 1
        entry['recovered_by_category'] = {c: v[0] for c, v in sorted(cats.items())}
        s6_report['budgets'][str(budget)] = entry
    (out / 's6.json').write_text(json.dumps(s6_report, indent=2))

    # A3: multilingual analysis at the validation-selected E1 threshold and at 0.30.
    e1_threshold = json.loads((ROOT / 'results/review2/e1.json').read_text())['validation_threshold']
    (out / 'multilingual.json').write_text(json.dumps(multilingual_analysis(e1_threshold), indent=2, ensure_ascii=False))

    manifest = dict(amendment='docs/REVIEW2_PROTOCOL_AMENDMENT1.md', amendment_sha256=sha256_file(AMENDMENT),
                    primary_thresholds_match_review2=True, source_tree_sha256=source_digest(), git=git_state(),
                    python=sys.version.split()[0], platform=platform.platform(),
                    runtime_seconds=round(time.time() - started, 1), command='.venv/bin/python scripts/review2_amendment1.py')
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'results/review2/amendment1')
    print(json.dumps(run(parser.parse_args().out), indent=2))
