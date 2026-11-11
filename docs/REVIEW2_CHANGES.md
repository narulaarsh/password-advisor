# Changes made against faculty Review 2

Source: `Review 2.docx` ("Strict Evaluation and Revision Roadmap", 11 November 2026). All sections, tables and the header and footer were read; the file has no comments, footnotes or endnotes. Each item below is marked:

- **Done**: implemented and evidenced in this repository.
- **Partly done**: the part possible without new data or people is complete.
- **Needs authors or faculty**: cannot be done by changing the software.

The manuscript follows the review's **Path B** (an evaluation and negative-results paper), because Path A needs an independent benchmark and a completed human study.

## Code and security changes

| # | Change | Files | Review item |
|---|---|---|---|
| 1 | **Authenticated backup manifest.** Version 2 backups carry an HMAC-SHA256 over the format, version, record count, header, profile and every record, keyed by HKDF(DEK, `cav-backup-manifest-v1`). Restore verifies it before replacing anything. Deleting a record and lowering the count, swapping IDs, removing the profile, editing the header or stripping the manifest are all rejected. Legacy version 1 backups still restore, after an explicit UI warning; `require_manifest=True` refuses them. | `vault/backup.py`, `vault/crypto.py`, `pages/4_Import_Export.py`, `tests/test_review2_security.py` | E5: backup-manifest integrity |
| 2 | **Rollback and deletion assessed explicitly.** Tests show that whole-file rollback and live-row deletion are not detected. The paper says so and no longer implies that per-record integrity prevents them. | `tests/test_review2_security.py` | E5: rollback/deletion |
| 3 | **Per-device Argon2id calibration.** New vaults choose parameters that reach the authors' 300–600 ms target, with a floor of 64 MiB and t = 3. On the development host five recorded runs chose 256 MiB, t = 10, p = 4 at 312–320 ms. The iteration count is stepped up until the measured time reaches the target. Existing vaults keep their stored parameters. | `vault/crypto.py`, `vault/ui_common.py`, `tests/test_review2_argon2.py` | E5: Argon2id tuning; Table II note |
| 4 | **Lossless indexed derivative search.** rapidfuzz `cdist` generates candidates in row chunks, and every candidate is re-checked with the original pair rule. Equivalence tests compare it with the old quadratic code on random, structured, short and non-ASCII vaults in both modes. | `vault/audit.py`, `tests/test_review2_derivatives.py` | E6: "indexing or candidate pruning…quantify precision/recall change" (change: none) |
| 5 | **Study readiness.** The study now has a concealed permuted-block allocation schedule (blocks of 4, slot IDs), counterbalanced task order within each arm, the System Usability Scale after the three tasks, and SUS summaries in the analysis. Human mode requires an ethics reference and the allocation file. | `vault/study.py`, `pages/7_Controlled_Study.py`, `scripts/make_allocation_schedule.py`, `scripts/export_study_logs.py`, `tests/test_review2_study.py` | E4: randomization, counterbalancing, usability measure |
| 6 | **Sample-size simulation** for the four-arm clustered design. | `scripts/study_power.py`, `results/review2/power.json` | E4: power analysis |

## Experiments (results in `results/review2/`)

| Review request | What was done |
|---|---|
| Frozen primary criterion before rerunning | `docs/REVIEW2_PROTOCOL.md` was written before the run. Its SHA-256 is recorded in `manifest.json`. The primary outcome stays S5 at 1,000 guesses. |
| Both E1 thresholds, per-transformation CIs | E1 is reported at 0.25 and 0.30 with Wilson intervals per category, an analysis of flagged hard negatives, and eight stress families with field attribution. |
| Separate relationship labels from attack labels | This was already separate; the paper now states it in the results and in the discussion. |
| Matched-FPR comparison; B3 explanation | Recall at B7's test FPR and at a test FPR of 5% is labelled exploratory. The discrete-score effects are explained (the syntax flag alone has a validation FPR of 0.223). |
| Non-additive rules; constrained interpretable model | R1 (the deployed gate rule), R2 (a context rule) and B9 (non-negative logistic) were added. |
| Ablation with renormalization handling, threshold sensitivity | Ablations are run without and with renormalization and with refitting; the CAV threshold is swept from 0.05 to 0.60. |
| Brier only with clear semantics | Heuristic Brier scores are stored as `brier_exploratory_only`, and calibration bands are given only for probability models. |
| Budgets 100 / 1,000 / 10,000 / 100,000; resources | Every budget was run, with recoveries, Wilson CIs, stream exhaustion and run time. |
| Scenario-specific thresholds; error analysis by attacker knowledge | Both are reported and labelled exploratory. |
| Wider derivative evaluation | A 178-entry fixture with six mutation types, near-miss words and gradual chains, reported per mode. |
| Network traffic in a controlled environment | An application-layer capture of live HIBP requests. It is not a packet capture. |
| E6: more trials, p95/p99, CPU, native memory, network faults | 20 trials (5 at 5,000 entries), CPU time, peak RSS from a fresh subprocess, and seven emulated network conditions. |
| Reproducibility | The manifest records the commands, base commit, source-tree digest and dependency versions. Paper tables are written as CSV in `results/review2/tables/`. |

## Manuscript (Version 3.0, `docs/paper/`)

The paper was reframed as Path B. It adds:

- the affiliation, taken from the authors' own draft
- a capability comparison table and a threat-model table
- a statement of the model-deployment status
- dual-threshold E1, all new E2 and E3 analyses, the clustering, E5 and E6 tables, the power-analysis table
- a reproducibility section

Behavioural efficacy is not claimed, and the study is presented as an instrument.

## Needs the authors or faculty (cannot be done in code)

| Item | Why |
|---|---|
| Independent, externally adjudicated E1/E2 benchmark | It must be authored and labelled by people independent of the generator. The data contract and validator are ready (`REVIEW1_PROTOCOL.md`). |
| Faithful reproduction of MDIGuess, Ou et al. or another B8 | This needs their code, models and authorized training data. |
| Running the human study (G1–G4) | It needs ethics approval, recruitment and the planning inputs from `power.json`. |
| Second machine for E6 | Run `scripts/review2_performance.py` on another computer. |
| Packet capture, OS clipboard history | These need administrator access and changes to the user's real clipboard, which were deliberately not done. |
| Journal choice and formatting | The paper keeps the IEEE conference template; switch templates when a venue is chosen. |

## Follow-up: closing the partly and not-addressed items (11 November 2026)

| Item | What was done | Evidence |
|---|---|---|
| B8 published baseline | No targeted-guessing model can be reproduced faithfully (no code, models or data). Under a dated Amendment 1 (`REVIEW2_PROTOCOL_AMENDMENT1.md`), the closest published methods were added: zxcvbn's estimate (B8a) and zxcvbn with its user-input dictionary set to the declared context (B8b). B8b reached recall 0.306 against CAV's 0.153 at the same operating rule. | `results/review2/amendment1/baselines.json` |
| Stronger attacker | S6, a rule-based attacker, was added and run at 100 to 100,000 guesses: 28.0% recovery at 1,000 and 72.5% at 100,000. The context rule's FPR falls from 0.345 to 0.033 against it. It is author-written and disclosed as not independent. | `results/review2/amendment1/s6.json` |
| E1 multilingual and transliterated attributes | An analysis of accented, romanized, non-Latin, same-script and punctuated names, without changing the detector. It shows the expected gaps: no Unicode folding or transliteration. | `results/review2/amendment1/multilingual.json` |
| E5 packet capture | A tcpdump capture (access_bpf group, no root). The observer sees the server name and constant 1,844-byte requests; no path, prefix or password appears in plaintext. The raw capture is deleted and local addresses are not stored. | `scripts/review2_packet_capture.py`, `results/review2/packet_capture.json` |
| E5 OS clipboard | A real macOS pasteboard check, run with the user's consent and their text restored. It showed copies were not marked concealed, so `vault/clipboard.py` now adds `org.nspasteboard.ConcealedType`, passing the secret on stdin. A re-check confirmed the marker. | `scripts/review2_os_clipboard_check.py`, `results/review2/os_clipboard_check.json`, `tests/test_clipboard.py` |
| E6 second machine | A one-command kit (`scripts/run_second_machine.sh`) and a comparison script (`scripts/compare_hosts.py`). **Still needs another computer.** | |
| P0 independent benchmark | Authoring and annotation kit, a Cohen's kappa and adjudication tool, and an `--input` path in the Review 2 runner, tested end to end. **Still needs independent authors and annotators.** | `docs/INDEPENDENT_BENCHMARK_KIT.md`, `scripts/benchmark_agreement.py` |
| P0 human study (E4) | Ethics submission drafts: protocol, data management, recruitment, information sheet, consent and debrief. **Still needs ethics approval and participants.** | `docs/ethics/` |
| Journal formatting | An Elsevier (JISA) version is built from the same source alongside the IEEE version, with author declarations left for the authors to complete. | `docs/paper/jisa/` |

Also added: a labelled simulation that validates the E4 analysis pipeline (`scripts/study_pipeline_simulation.py`, coverage 94.2%), and an AI-use acknowledgment in the IEEE paper, which becomes the JISA AI declaration.

Tests: 152 pass.
