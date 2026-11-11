# Review 2 protocol, Amendment 2: independent real-data benchmark (PASS sample)

Frozen on 11 November 2026, after commit `4492cf3` and before any analysis of the data below. `scripts/review2_pass_benchmark.py` records this file's SHA-256. Nothing here changes the primary criterion of `REVIEW2_PROTOCOL.md`.

## Data

- **Source.** The public sample of the PASS dataset (Wang, Jan, Hu, Bossart and Wang, "The Next Domino To Fall: Empirical Analysis of User Passwords across Online Services", ACM CODASPY 2018), downloaded from the authors' page (`people.cs.vt.edu/gangwang/sample_dataset.txt`, 22,976 bytes).
- **Contents.** 1,000 pseudonymous users, each with 2–5 passwords taken from breaches of different online services. There are no names, emails, birth dates or service order.
- **Handling.** Real leaked passwords are handled as sensitive data. The file stays in `data/private/` (ignored by git, mode 0600). No password, hash or user identifier is written to any result file, printed or put in the paper; only aggregate counts are reported.
- **No breach lookups.** No HIBP lookup is made for these passwords. Breach evidence is set to absent (b = 0), so the analysis isolates the cross-account signals.
- **Not tested.** The sample has no profile data, so the personal-context signal cannot be tested on it.

## Task

1. For each user, one password is chosen as the target, using a seeded random choice (seed 2018). The user's other passwords form the known history.
2. **Outcome.** The target is recovered when an attacker given the history guesses it within B guesses, B ∈ {100, 1,000, 10,000}. The attacker tries each history password as the "previous password" and succeeds if any attempt does.
3. **Attackers.** S3 (history mutations) and the history tiers of S6, both run with an empty profile. They are the attackers from Review 2 and are not tuned on these data.
4. **Primary outcome.** S6 at 1,000 guesses.

## Methods (no thresholds or rules are tuned on PASS)

Features are computed with the deployed code: reuse and derivative relations against the history, and zxcvbn. Breach, coverage and age are 0.

| Method | Definition | Operating point |
|---|---|---|
| CAV | Fixed score | Frozen threshold 0.60 from Review 2 validation |
| B7, B9 | Logistic models trained only on the synthetic training partition, applied unchanged | Frozen thresholds from Review 2 |
| B5 | Reuse or derivative | Fixed rule |
| R1 | Gate rule (weak syntax, reuse or derivative) | Fixed rule |
| B8a | zxcvbn meter | Frozen threshold from Amendment 1 |
| B8b | zxcvbn with the history passwords as user inputs | Frozen threshold from Amendment 1 |

**Reported.** Recovery rates with Wilson intervals; recall, FPR and precision with 1,000 user-level bootstrap replicates; PR-AUC for scored methods; and the prevalence of exact reuse and of CAV-derivative relations.

**Specificity check.** The derivative rule is also applied to 20,000 seeded random pairs of passwords from different users, to estimate how often it links unrelated real passwords.

**Secondary analysis.** Every password of every user is treated as a target in turn, again with user-level bootstrap.

## Interpretation

- **Scope.** This is independent real data for the cross-account component only. The attacker is still author-written, so non-recovery does not establish safety.
- **Transfer.** Applying B7 and B9 unchanged tests whether models fitted on the synthetic fixture transfer to real data. Whatever the result, it is reported.
