# Hosting the G1–G4 study for participants

This guide puts the **study only** online, so your faculty's students can take part from a link. It does not deploy the password vault: a shared server would give every participant the same vault, and some people would type real passwords into it.

## Why not Vercel

Streamlit apps need a long-running Python server. Vercel runs short serverless functions, so it cannot host this app. These steps use **Streamlit Community Cloud** (free) for the app and a free **PostgreSQL** database for the records, because the app's disk on Community Cloud is wiped whenever the app restarts.

## What is and is not recorded

- **Recorded,** after the participant ticks consent: condition, task, warning shown, override, whether the alternative was accepted, total time, whether the S5 attacker would recover the final made-up password, ten SUS answers, the participant's first name, surname, city and birth year (`study_participants`), and every entered password with the issues detected, reasons shown, any suggested password and the action taken (`study_responses`), and the end-of-study report each participant is shown: per account, the final password, every issue found with its reason and any suggested alternative (`study_report`). Records are stored against an automatic code such as S014.
- **Not recorded:** emails, IP addresses, keystrokes, or anything outside the study page. The hosting provider may keep standard server logs, and the participant information says so.
- **"Recording in the background"** is limited to the items listed above, and every one of them is disclosed before consent. Do not add hidden tracking.

## Before launch (needs your faculty)

1. **Ethics.** Running the study with students needs your institution's approval or a written exemption before any results are reported; the drafts are in `docs/ethics/`. Students must be free to decline, which matters because the faculty member is their teacher.
2. **Sample size.** Decide the target effect and N (`results/review2/power.json`). For example, 80 per arm (320 in total) suits an absolute reduction of 0.20.

## Steps

1. **Make the concealed schedule** on your Mac. Keep the seed secret and do not commit the file:

   ```bash
   .venv/bin/python scripts/make_allocation_schedule.py --seed "<secret seed>" --slots 320 --out data/private/allocation.csv
   ```

2. **Create a free PostgreSQL database** (for example Supabase or Neon) and copy its connection string (`postgresql://…`).

3. **Push the code to GitHub.** The repository already has the remote `Garry-21/password-advisor`. Keep it private: Community Cloud can deploy from a private repository once you grant it access. `data/private/` is ignored by git, so the schedule and the PASS data are never pushed.

4. **Create the app on Streamlit Community Cloud** (`share.streamlit.io`):
   1. Choose New app, then select the repository and the `review1-revision` branch.
   2. Set the main file to `study_site/streamlit_app.py`. Dependencies come from `study_site/requirements.txt`.
   3. In Advanced settings, choose Python 3.12 or newer.
   4. Paste the secrets below. Root-level secrets become environment variables:

   ```toml
   STUDY_MODE = "1"
   STUDY_ETHICS_REFERENCE = "<approval or exemption reference>"
   STUDY_AUTO_SLOT = "1"
   STUDY_DATABASE_URL = "postgresql://<user>:<password>@<host>:5432/<db>"
   STUDY_ALLOCATION_SEED = "<long random secret; keep private>"
   STUDY_ALLOCATION_SLOTS = "320"
   # Alternatively: STUDY_ALLOCATION_CSV = """<contents of data/private/allocation.csv>"""
   ```

5. **Dry run.** First run the app without `STUDY_MODE` (demo mode) and complete it once. Then switch to the secrets above and complete one real session yourself. Finally, empty the six tables (`study_events`, `study_questionnaire`, `study_slots`, `study_participants`, `study_responses`, `study_report`) so that the participants start from S001.

6. **Share the link** with the participants. Each person ticks consent, presses **Start the study** and receives the next code in the schedule. When all codes are used, the app reports that the study is full.

7. **Export and analyse** on your Mac:

   ```bash
   STUDY_DATABASE_URL="postgresql://…" .venv/bin/python scripts/export_study_db.py --out data/private
   ```

   ```bash
   .venv/bin/python scripts/export_study_logs.py --input data/private/study_events.csv --questionnaire data/private/study_questionnaire.csv --source human --output results/study1/summary.json
   ```

8. **After the study.** Delete the app. Keep or delete the database according to the approved retention period.

## Limits to state in the paper

Report the dates, the setting (students of one course, recruited by their instructor), the number who started and finished, and any exclusions. Report the observed results whatever they are. Simulated or demo records are never pooled with human ones; the analysis keeps sources apart.
