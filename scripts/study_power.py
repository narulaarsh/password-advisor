"""E4 sample-size planning by simulation (Review 2). Planning assumptions, not data.

Model: each participant completes 3 fictional tasks. A participant's probability of a
vulnerable final credential is Beta-distributed around the arm rate with intraclass
correlation `icc`; task outcomes are Binomial(3, p_i). The primary contrast (G3 vs G2)
is tested with Welch's t-test on participant-level rates at a Bonferroni-corrected
alpha of 0.05/3 (three planned contrasts). Power is the share of simulated studies
that reject. Replace the assumed control rates and effects with pilot or literature
values before preregistration.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
from scipy import stats

TASKS_PER_PARTICIPANT = 3
ALPHA = 0.05 / 3


def participant_rates(rng, n, p, icc, sims):
    if icc <= 0:
        probs = np.full((sims, n), p)
    else:
        a = p * (1 - icc) / icc
        b = (1 - p) * (1 - icc) / icc
        probs = rng.beta(a, b, size=(sims, n))
    return rng.binomial(TASKS_PER_PARTICIPANT, probs) / TASKS_PER_PARTICIPANT


def power(n, control, effect, icc, sims, seed):
    rng = np.random.default_rng(seed)
    g2 = participant_rates(rng, n, control, icc, sims)
    g3 = participant_rates(rng, n, control - effect, icc, sims)
    _, pvalues = stats.ttest_ind(g3, g2, axis=1, equal_var=False)
    pvalues = np.nan_to_num(pvalues, nan=1.0)
    return float(np.mean((pvalues < ALPHA) & (g3.mean(axis=1) < g2.mean(axis=1))))


def required_n(control, effect, icc, sims, seed, target=0.80, max_n=600, step=10):
    for n in range(step, max_n + 1, step):
        if power(n, control, effect, icc, sims, seed) >= target:
            return n
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sims', type=int, default=2000)
    parser.add_argument('--seed', type=int, default=20261111)
    parser.add_argument('--out', type=Path, default=Path('results/review2/power.json'))
    args = parser.parse_args()
    scenarios = []
    for control in (0.50, 0.60):
        for effect in (0.10, 0.15, 0.20):
            for icc in (0.2, 0.4):
                n = required_n(control, effect, icc, args.sims, args.seed)
                scenarios.append(dict(control_rate=control, absolute_reduction=effect, icc=icc,
                                      participants_per_arm=n, total_participants=4 * n if n else None,
                                      achieved_power=power(n, control, effect, icc, args.sims, args.seed) if n else None))
                print(scenarios[-1], flush=True)
    report = dict(
        provenance='simulation under planning assumptions; no participant data',
        model='Beta-binomial participant rates, 3 tasks each, Welch t-test on participant rates',
        primary_contrast='G3 vs G2 (pre-save vs post-save), one-sided direction, two-sided test',
        alpha=ALPHA, target_power=0.80, simulations_per_point=args.sims, seed=args.seed,
        search='participants per arm in steps of 10 up to 600', scenarios=scenarios,
        python=sys.version.split()[0], numpy=np.__version__)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
