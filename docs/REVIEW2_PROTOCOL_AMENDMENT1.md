# Review 2 protocol, Amendment 1

Frozen on 11 November 2026, after the Review 2 results were committed (commit `786bd94`) and before any analysis below was run. The original protocol (`REVIEW2_PROTOCOL.md`) and its primary criterion are unchanged: S5 within 1,000 guesses, with validation-selected thresholds at FPR ≤ 5%. Everything in this amendment is secondary. It is reported separately and does not replace a primary result. `scripts/review2_amendment1.py` records this file's SHA-256.

## A1. Published-meter baselines (closest available B8)

No published targeted-guessing model (MDIGuess, Ou et al.) can be reproduced faithfully without its code, models and training data. As the closest available published methods, we add two zxcvbn variants (Wheeler, USENIX Security 2016), computed with the same pinned zxcvbn-python version:

- **B8a, structural meter.** The score is `-guesses_log10` with no user inputs, so a higher score means riskier.
- **B8b, contextual meter.** The same, with zxcvbn's documented `user_inputs` set to the declared first name, surname, city, birth year (four-digit and two-digit) and the previous password.

Thresholds follow the primary rule: highest validation recall at validation FPR ≤ 5%, then frozen. We report test recall, FPR and PR-AUC on the primary outcome with 1,000 profile-bootstrap replicates (seed 42), plus recall on each E3 scenario at 1,000 guesses. B8b is a published meter with user context, not a targeted-guessing model, and is not described as MDIGuess or as any other attack.

## A2. Stronger rule-based attacker (S6), exploratory

S6 is a deterministic rule-based attacker. It never sees the target and its guesses are distinct and ordered. It mangles declared tokens (first name, surname, city, four-digit and two-digit birth year) and the previous password using:

- case variants
- leetspeak subsets
- reversal
- 3–5 character prefixes
- two-token joins with separators
- year and digit suffixes and common symbol suffixes
- history increments

It is stronger than S5 but was written by the same authors who wrote the fixture, so it is not independent. It is run on the test partition at budgets of 100, 1,000, 10,000 and 100,000 guesses. We report recovery with Wilson intervals, actual distinct guesses, and the recall of the frozen S5-threshold methods (B1, B2, B5, CAV, B7, B9, B8a, B8b, R1, R2) on S6 outcomes.

## A3. Multilingual and transliteration analysis (E1), exploratory

This is an author-written set of fictional profiles. The families are:

- (a) a profile name with diacritics, with an ASCII-folded password
- (b) an ASCII profile name, with a password using a common alternative romanization
- (c) a profile name in a non-Latin script (Devanagari, Cyrillic, Greek, Arabic), with a password in its common Latin form
- (d) a non-Latin profile name, with a password in the same script
- (e) a name with an apostrophe or hyphen, with that punctuation removed in the password

We report the coverage score at the production threshold of 0.30 and the validation-selected threshold of 0.25, with the matched fields. The detector is not changed in response.

## Interpretation

Nothing in this amendment changes the deployed weights or detector. Amendment results are exploratory and do not support a claim of superiority over published work.
