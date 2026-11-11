"""Copies hosted study records from STUDY_DATABASE_URL into private CSV files for analysis.

Then run: .venv/bin/python scripts/export_study_logs.py --input data/private/study_events.csv \
    --questionnaire data/private/study_questionnaire.csv --source human --output results/<study>/summary.json
"""
import argparse
import csv
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vault.study import (EVENT_FIELDS, PARTICIPANT_FIELDS, QUESTIONNAIRE_FIELDS, REPORT_FIELDS, RESPONSE_FIELDS,
                         _connect, database_url)


def export(out_dir):
    if not database_url():
        raise SystemExit('Set STUDY_DATABASE_URL to the study database first')
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    conn, _ = _connect(database_url())
    counts = {}
    try:
        for table, fields, name in (('study_events', EVENT_FIELDS, 'study_events.csv'),
                                    ('study_questionnaire', QUESTIONNAIRE_FIELDS, 'study_questionnaire.csv'),
                                    ('study_participants', PARTICIPANT_FIELDS, 'study_participants.csv'),
                                    ('study_responses', RESPONSE_FIELDS, 'study_responses.csv'),
                                    ('study_report', REPORT_FIELDS, 'study_report.csv')):
            cur = conn.cursor()
            try:
                cur.execute(f'SELECT {", ".join(fields)} FROM {table}')
                rows = cur.fetchall()
            except Exception:
                conn.rollback() if hasattr(conn, 'rollback') else None
                rows = []
            path = out_dir / name
            with path.open('w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(fields)
                writer.writerows(rows)
            os.chmod(path, 0o600)
            counts[name] = len(rows)
    finally:
        conn.close()
    return counts


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', default='data/private')
    print(export(parser.parse_args().out))
