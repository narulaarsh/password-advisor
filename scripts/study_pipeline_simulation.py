"""E4 analysis-pipeline validation with SIMULATED participants (not evidence about people).

Plants known arm effects in synthetic participants, writes them through the real study
logger with source='synthetic', and runs the real analysis (scripts/export_study_logs.py)
to check that it recovers the planted G3-G2 contrast and that its 95% interval covers
the planted value at roughly the nominal rate. No human data are involved.
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.export_study_logs import export_study_summary
from vault.study import CONDITIONS, log_study_event

PLANTED = {'G1': 0.60, 'G2': 0.60, 'G3': 0.40, 'G4': 0.35}  # vulnerable-credential rates
ICC = 0.4
TASKS = 3


def simulate(path, per_arm, rng):
    for condition in CONDITIONS:
        p = PLANTED[condition]
        a, b = p * (1 - ICC) / ICC, (1 - p) * (1 - ICC) / ICC
        for k in range(per_arm):
            pid = f'SIM-{condition}-{k:03d}'
            rate = rng.beta(a, b)
            for task in range(TASKS):
                vulnerable = bool(rng.random() < rate)
                warned = condition != 'G1' or vulnerable
                log_study_event(pid, condition, f'T{task + 1}', '', warned, warned and vulnerable,
                                condition == 'G4' and warned and not vulnerable,
                                float(rng.lognormal(9.5, 0.4)), str(path), vulnerable=vulnerable,
                                source='synthetic', task_position=task + 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--per-arm', type=int, default=80)
    parser.add_argument('--replicates', type=int, default=200)
    parser.add_argument('--seed', type=int, default=20261111)
    parser.add_argument('--out', type=Path, default=ROOT / 'results/review2/simulated_study.json')
    args = parser.parse_args()
    rng = np.random.default_rng(args.seed)
    planted = PLANTED['G3'] - PLANTED['G2']
    estimates, covered = [], 0
    example = None
    with tempfile.TemporaryDirectory() as tmp:
        for rep in range(args.replicates):
            events = Path(tmp) / f'events_{rep}.csv'
            simulate(events, args.per_arm, rng)
            report = export_study_summary(str(events), str(Path(tmp) / 'summary.json'), source='synthetic')
            contrast = report['contrasts']['G3_minus_G2']
            estimates.append(contrast['difference'])
            covered += contrast['ci95'][0] <= planted <= contrast['ci95'][1]
            if example is None:
                example = report
    result = dict(
        provenance='SIMULATED participants with planted effects; validates the analysis pipeline only; not human data',
        planted_rates=PLANTED, icc=ICC, tasks_per_participant=TASKS, participants_per_arm=args.per_arm,
        replicates=args.replicates, seed=args.seed, planted_g3_minus_g2=planted,
        mean_estimate=float(np.mean(estimates)), bias=float(np.mean(estimates) - planted),
        ci95_coverage=covered / args.replicates,
        example_replicate=dict(groups={c: dict(participants=example['groups'][c]['participants'],
                                               rate=example['groups'][c]['participant_mean_vulnerable_rate'],
                                               ci95=example['groups'][c]['cluster_bootstrap_ci95'])
                                       for c in CONDITIONS},
                               contrasts=example['contrasts']))
    args.out.write_text(json.dumps(result, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k != 'example_replicate'}, indent=2))


if __name__ == '__main__':
    main()
