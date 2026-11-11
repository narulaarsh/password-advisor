# Review 2 frozen analysis protocol

Frozen on 11 November 2026, before any Review 2 experiment was run. `scripts/review2_experiments.py` records this file's SHA-256 in `results/review2/manifest.json`. Any later change to this file changes that digest. Results produced under a different digest are not results of this protocol.

## Data

The data is the same synthetic fixture as Review 1: `synthetic_rows(profiles=1002, seed=42)` from `scripts/review_experiments.py`, with 11,022 examples, 11 categories, and profile-disjoint train, validation and test partitions of 334 profiles each. It is an author-written engineering fixture, not independent data. No result from it is described as external validation.

## Primary decision criterion (E2), fixed in advance

- **Outcome.** S5 (all-information attacker) recovers the password within 1,000 distinct guesses. This is the same outcome as Review 1. Larger budgets never replace it.
- **Metric.** Held-out recall at a threshold selected on the validation partition, as the threshold with the highest validation recall subject to a validation FPR of at most 5%. The threshold is frozen before the test partition is scored.
- **Methods.** B1 zxcvbn flag, B2 breach fixture, B3 = max(B1, B2), B4 personal coverage, B5 reuse or derivative, B6 submitted weights, CAV current score, B7 logistic regression, and two methods added in Review 2:
  - B9 non-negative logistic regression (coefficients constrained to be at least 0).
  - Two fixed non-additive rules that need no threshold: R1, the deployed save-time gate rule (any of breach, coverage > 0, weak syntax, reuse, derivative); and R2, a context rule (coverage at least 0.30, or reuse, or derivative).
- **Uncertainty.** A profile-level bootstrap with 1,000 replicates and seed 42 gives 95% intervals for recall, FPR and precision, and for paired recall differences against CAV.

## Secondary and exploratory analyses (labelled as such)

1. **E1** at the validation-selected threshold and at the production threshold of 0.30, with Wilson 95% intervals per category, an analysis of flagged hard negatives, and an author-written stress set of eight transformation families that were never used to tune the detector.
2. **Matched-FPR comparison.** Recall at a test FPR of at most B7's achieved test FPR, and at most 5%. This tunes thresholds on test data, so it is optimistic and exploratory.
3. **Threshold sensitivity** of the CAV score from 0.05 to 0.60, and an explanation of discrete-score effects such as B3 having no positives.
4. **Ablations** under fixed submitted weights, with and without renormalizing the remaining weights, and with refitted logistic models.
5. **Calibration bands** for probability models (B7, B9). Brier scores for heuristic scores are reported as exploratory only.
6. **E3** at budgets of 100, 1,000, 10,000 and 100,000 on the test partition, with successes and Wilson intervals, actual distinct guesses, exhaustion and run time. It reports recall at the frozen S5 thresholds, scenario-specific validation thresholds (exploratory), and an error analysis by attacker knowledge and category.

## Interpretation rules

- A password not recovered was not guessed by this deterministic attacker within the stated budget. That does not mean it is safe.
- E1 measures construction-defined personal relationships, and E2 and E3 measure attack outcomes. E1 F1 is never described as attack detection.
- Any advantage of B7 or B9 is a result on this author-written distribution. Neither model is deployed by the application.
- B8, a faithful published contextual model, is not available. No superiority claim over published work is made.
