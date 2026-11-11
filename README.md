# Context Aware Password Advisor

A local encrypted password vault with personal-context assessment, credential relationship checks and save-time warnings. This is a research prototype. The current risk score is a heuristic priority, not a probability of compromise.

## Run locally

Python 3.14 on macOS was used for the recorded verification. Other Python/platform combinations need their own validation.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python -m streamlit run app.py
```

Existing vault data is opened only when you use the app. No real vault or credentials are needed for tests or research experiments. Credential suggestions are generated locally; no Groq key is needed. HIBP queries send a five-character SHA-1 prefix with padding requested. Failed checks remain unknown.

## Faculty review deliverables

Review 2 (current):

- [Review 2 change list and item-by-item status](docs/REVIEW2_CHANGES.md)
- [Frozen Review 2 analysis protocol](docs/REVIEW2_PROTOCOL.md) (its SHA-256 is recorded in `results/review2/manifest.json`)
- [Executed Review 2 results](results/review2/SUMMARY.md) and paper tables in `results/review2/tables/`
- Paper source and PDF: `docs/paper/`

Review 1:

- [Detailed change list and review mapping](docs/REVIEW1_CHANGES.md)
- [Research revision and limitations](docs/RESEARCH_REVISION.md)
- [Experimental protocol and reproduction commands](docs/REVIEW1_PROTOCOL.md)
- [Security test matrix](docs/SECURITY_MATRIX.md)
- [Executed results](results/review1/SUMMARY.md)

## Verify

```sh
.venv/bin/python -m pytest -q
.venv/bin/python scripts/review2_experiments.py --out results/review2        # E1-E3 (about 30 s)
.venv/bin/python scripts/review2_clusters.py                                 # derivative clustering
.venv/bin/python scripts/review2_performance.py                              # E6 (about 6 min)
.venv/bin/python scripts/study_power.py --sims 5000                          # E4 sample-size planning
.venv/bin/python scripts/review2_network_capture.py                          # E5, makes live HIBP requests
```

`results/review1/` was produced by the Review 1 scripts at commit `3054432`. Re-running `scripts/review_performance.py` on newer code gives different timings, because Review 2 changed the derivative search; the E1-E3 outcomes are unchanged (the Review 2 runner checks this).

The experiment generator creates **synthetic engineering fixtures**, not independent validation data. It does not read the real vault. `requirements-lock.txt` records the tested environment. New evaluation outputs are separate from the existing historical result files, whose provenance has not been established.

The Controlled Study page defaults to demo mode. Human collection additionally requires `STUDY_MODE=1`, `STUDY_ETHICS_REFERENCE` and a concealed allocation schedule in `STUDY_ALLOCATION_FILE`, created with `scripts/make_allocation_schedule.py`. Participants then use their schedule slot IDs (S001, S002, ...) in enrollment order. These settings record configuration and cannot verify actual institutional approval. Use fictional credentials only. Do not present demo or simulated decisions as human results.

New vaults calibrate Argon2id on the creating device so that unlocking takes about 300–600 ms. The parameters are stored in the vault header, so existing vaults keep their original settings. Backups made from an unlocked vault carry an authenticated manifest, and restoring a legacy backup without one requires an extra confirmation.
