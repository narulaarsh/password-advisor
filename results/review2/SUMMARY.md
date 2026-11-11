# Review 2 executed results

Run on 11 November 2026 on an Apple M5 (16 GB RAM, macOS 27.3, Python 3.14.7). Analyses follow the frozen protocol in `docs/REVIEW2_PROTOCOL.md`; its SHA-256 is in `manifest.json`. Data are a synthetic, author-written fixture, so none of these results is independent validation. No human participants were recruited.

## Verification

- **Tests.** 152 tests passed, with one zxcvbn-python deprecation warning (`test_results.txt`). This is 102 earlier tests plus 50 added during Review 2.
- **Reproduction check.** The runner reproduced all 55,110 Review 1 attack outcomes exactly (0 mismatches).

## E1: personal-context detection (held out, n = 3,674)

| Threshold | Precision | Recall (95% CI) | FPR (95% CI) | Unseen transformations | Hard negatives flagged |
|---|---:|---:|---:|---:|---:|
| 0.25 (validation-selected) | 0.989 | 0.877 (0.864–0.889) | 0.026 (0.018–0.038) | 5/334 | 25/334 |
| 0.30 (production) | 0.989 | 0.875 (0.862–0.887) | 0.026 (0.018–0.038) | 0/334 | 25/334 |

- **Hard negatives.** 24 of the 25 flagged hard negatives matched the name prefix plus a two-digit birth year that coincides with the index digits. This is a fixture artefact.
- **Stress families.** These eight author-written families were never used for tuning. Their apparent detection mostly comes from unrelated fields:
  - Reversed names match only because fixture surnames are reversed first names.
  - "Initials plus year" (334/334) and most "two-character parts" (312/334) were detected through the birth year alone.
  - Vowel-dropped names: 202/334 at 0.25 and 169/334 at 0.30.

## E2: primary criterion (S5 within 1,000 guesses; 2,183 of 3,674 held-out passwords recovered)

| Method | Recall (95% CI) | FPR | PR-AUC |
|---|---:|---:|---:|
| CAV (current) | 0.153 (0.152–0.154) | 0.000 | 0.781 |
| B2 breach fixture | 0.153 | 0.000 | 0.656 |
| B5 reuse or derivative | 0.306 | 0.000 | 0.718 |
| B7 logistic | 0.503 (0.497–0.508) | 0.048 | 0.956 |
| B9 non-negative logistic | 0.459 (0.455–0.463) | 0.000 | 0.956 |
| R1 gate rule (fixed) | 1.000 | 0.556 | – |
| R2 context rule (fixed) | 0.847 | 0.345 | – |

- **Why CAV misses.** Without breach evidence its score is at most 0.50, while the validation-selected threshold is 0.60. Lowering the threshold to 0.20 gives recall 0.847, but the FPR rises to 0.328.
- **B3 has no positives.** The syntax flag alone has a validation FPR of 0.223, so the only binary threshold that meets FPR ≤ 5% flags nothing.
- **Renormalization.** Renormalizing the fixed weights after removing a signal leaves every ablation unchanged. Without the cap, renormalization is a monotone rescaling, so ranks and operating points stay the same.
- **B9 coefficients.** B9 sets the syntax and age coefficients to 0.

## E3: attacker budgets (test partition)

Recovery does not grow beyond 1,000 guesses. S1–S4 streams are exhausted at 80,032, 80,069, 10,006 and 90,075 distinct guesses, and only S5 reaches 100,000. At 1,000 guesses the recovery rates are S1 9.1%, S2 32.1%, S3 18.2%, S4 50.3% and S5 59.4%. At its frozen S5 threshold, CAV detects none of the S2–S4 recoveries. Of the 1,181 recoveries made with personal information (S2), CAV and B9 detect none and B7 detects 95, all in the leetspeak category. R1 and R2 detect all of them, at the false-positive rates shown above.

## Derivative clustering (178 entries, 88 planted families)

| Mode | Pair precision | Pair recall | Adjusted Rand | Gradual-chain pair recall |
|---|---:|---:|---:|---:|
| chain | 0.993 | 1.000 | 0.997 | 1.000 |
| pairwise | 0.992 | 0.875 | 0.929 | 0.500 |

- **False merge.** The one false merge is Mountain93!/Fountain48! (base similarity 87.5).
- **Gradual chains.** None of the six gradual chains has directly related ends.
- **S3 attacker.** It guessed only the year-variant families (18/18 pairs) and none of the others.

## E4: planning only

- **Data.** No participant data exist.
- **Sample size.** The simulation (5,000 runs per point; Welch test on participant rates; alpha 0.05/3; 80% power) needs 60–80 participants per arm for a 0.20 absolute reduction, 110–140 for 0.15 and 240–320 for 0.10, depending on the assumed intraclass correlation (0.2 or 0.4) and control rate (0.5 or 0.6).

## E5 and E6

- **Network capture.** 20 fictional passwords produced only `GET api.pwnedpasswords.com:443/range/<5 hex>` requests. All requests carried Add-Padding, and no body, suffix, full digest or password was sent. Padded responses were 78.6–102.0 KB (decompressed).
- **Argon2id.** Calibration chooses 256 MiB and p = 4, with t set from timing. Five recorded runs chose t = 10 at 312–320 ms; the previous default (64 MiB, t = 3) takes 21.7 ms on this host (`argon2_calibration.json`).
- **Derivative search.** The indexed search gives identical results to the quadratic search and takes 928 ms instead of 4,361 ms at 5,000 entries (38 ms instead of 177 ms at 1,000).
- **Full audit.** Median 353 ms at 1,000 entries and 2.56 s at 5,000. Peak RSS is at most 113 MiB, including a 63–65 MiB interpreter baseline.
- **Save gate.** It stays under 7 ms locally, takes about 1.0 s at 1 s breach-check latency, and takes about 20 s when the breach service hangs (two 10 s attempts).

## Amendment 1 (secondary, `docs/REVIEW2_PROTOCOL_AMENDMENT1.md`)

| Method (primary outcome S5@1000) | Recall (95% CI) | FPR | PR-AUC |
|---|---:|---:|---:|
| B8a zxcvbn meter | 0.153 (0.152–0.154) | 0.000 | 0.587 |
| B8b zxcvbn with user inputs | 0.306 (0.303–0.309) | 0.000 | 0.818 |
| CAV (current) | 0.153 | 0.000 | 0.781 |

- **S6 recovery.** 27.3% (100 guesses), 28.0% (1,000), 67.3% (10,000) and 72.5% (100,000). Streams ended after 30,341–87,115 distinct guesses.
- **Recall and FPR at 100,000 guesses.** CAV 0.125 at 0.000, B8b 0.251 at 0.000, B9 0.376 at 0.000, R2 0.875 at 0.033, R1 1.000 at 0.345.
- **Multilingual names flagged at 0.30.**

  | Group | Flagged |
  |---|---:|
  | Accented / accent-free | 2/9 |
  | Alternative romanization | 1/7 |
  | Non-Latin profile / Latin password | 0/6 |
  | Same non-Latin script | 6/6 |
  | Apostrophe removed | 0/2 |
  | Hyphen removed | 2/2 |
  | ASCII control | 4/4 |

- **Packet capture.** See `packet_capture.json`.
- **OS clipboard check.** See `os_clipboard_check.json`.

## E4 pipeline validation (simulated, not human data)

`simulated_study.json` comes from 1,000 simulated studies (80 per arm; planted rates 0.60/0.60/0.40/0.35; within-participant correlation 0.4) run through the real logger and the real analysis. The G3−G2 estimate averaged −0.197 against −0.200 planted, and 95% interval coverage was 94.2%. This validates the analysis only.
