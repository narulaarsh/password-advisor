"""Hosted study site: database logging, automatic slot claims and the online consent flow.

SQLite stands in for PostgreSQL; the same SQL runs against both via vault.study._connect.
"""
import sqlite3
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from scripts.export_study_db import export
from vault.study import (claim_next_slot, load_allocation_schedule_text, log_questionnaire, log_study_event,
                         make_allocation_schedule)

PAGE = str(Path(__file__).parents[1] / 'pages/7_Controlled_Study.py')


def fill_profile(app, first='Fictional', year=1999):
    app.text_input(key='profile_first').set_value(first)
    app.number_input(key='profile_year').set_value(year)
    next(b for b in app.button if b.label == 'Continue').click().run()
    return app


def schedule_csv(slots=8):
    rows = make_allocation_schedule('fixture-seed', slots)
    return 'slot_id,block,condition,task_order\n' + '\n'.join(
        f"{r['slot_id']},{r['block']},{r['condition']},{r['task_order']}" for r in rows)


def test_logs_go_to_the_database_without_passwords(tmp_path, monkeypatch):
    db = tmp_path / 'study.db'
    monkeypatch.setenv('STUDY_DATABASE_URL', f'sqlite:///{db}')
    log_study_event('S001', 'G3', 'T1', 'DoNotStoreThis#1', True, False, False, 50.0, vulnerable=True, source='human')
    log_questionnaire('S001', 'G3', [4, 2] * 5, source='human')
    conn = sqlite3.connect(db)
    events = conn.execute('SELECT participant_id, condition, vulnerable, source FROM study_events').fetchall()
    assert events == [('S001', 'G3', '1', 'human')]
    assert conn.execute('SELECT sus_score FROM study_questionnaire').fetchone() == ('75.0',)
    dump = '\n'.join(conn.iterdump())
    assert 'DoNotStoreThis' not in dump
    assert not (Path('data/private/study_events.csv').exists() and 'DoNotStoreThis' in Path('data/private/study_events.csv').read_text())


@pytest.mark.parametrize('backend', ['database', 'file'])
def test_slots_are_claimed_once_in_order(tmp_path, monkeypatch, backend):
    if backend == 'database':
        monkeypatch.setenv('STUDY_DATABASE_URL', f'sqlite:///{tmp_path / "s.db"}')
    else:
        monkeypatch.delenv('STUDY_DATABASE_URL', raising=False)
    schedule = load_allocation_schedule_text(schedule_csv(3))
    claims = tmp_path / 'claims.csv'
    assert [claim_next_slot(schedule, claims) for _ in range(4)] == ['S001', 'S002', 'S003', None]


def test_export_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv('STUDY_DATABASE_URL', f'sqlite:///{tmp_path / "s.db"}')
    for task in ('T1', 'T2', 'T3'):
        log_study_event('S002', 'G2', task, '', True, True, False, 10.0, vulnerable=False, source='human')
    counts = export(tmp_path / 'out')
    assert counts['study_events.csv'] == 3 and counts['study_questionnaire.csv'] == 0
    assert (tmp_path / 'out/study_events.csv').read_text().startswith('participant_id,condition')


def test_online_flow_assigns_a_code_and_logs_human_records(tmp_path, monkeypatch):
    import vault.study
    db = tmp_path / 'live.db'
    for key, value in {'STUDY_MODE': '1', 'STUDY_ETHICS_REFERENCE': 'fixture-ref', 'STUDY_AUTO_SLOT': '1',
                       'STUDY_ALLOCATION_CSV': schedule_csv(4), 'STUDY_DATABASE_URL': f'sqlite:///{db}'}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('STUDY_ALLOCATION_FILE', raising=False)
    app = AppTest.from_file(PAGE).run()
    assert not app.exception
    app.checkbox(key='study_consent').check().run()
    next(b for b in app.button if b.label == 'Start the study').click().run()
    assert any('participant code is S001' in i.value for i in app.info)
    fill_profile(app)
    app.text_input(key='study_password').set_value('Correct-Horse-Battery-Staple-77!')
    next(b for b in app.button if b.label == 'Save password').click().run()
    if any(b.label in ('Save anyway', 'Keep saved credential') for b in app.button):
        next(b for b in app.button if b.label in ('Save anyway', 'Keep saved credential')).click().run()
    assert not app.exception
    rows = sqlite3.connect(db).execute('SELECT participant_id, source FROM study_events').fetchall()
    expected_condition = vault.study.load_allocation_schedule_text(schedule_csv(4))['S001'][0]
    assert rows == [('S001', 'human')]
    assert sqlite3.connect(db).execute('SELECT condition FROM study_events').fetchone()[0] == expected_condition


def test_schedule_from_secret_seed_matches_generator(monkeypatch):
    from vault.study import schedule_from_environment
    for key in ('STUDY_ALLOCATION_FILE', 'STUDY_ALLOCATION_CSV'):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv('STUDY_ALLOCATION_SEED', 'fixture-seed')
    monkeypatch.setenv('STUDY_ALLOCATION_SLOTS', '8')
    schedule = schedule_from_environment()
    expected = {r['slot_id']: (r['condition'], [int(x) for x in r['task_order'].split('-')])
                for r in make_allocation_schedule('fixture-seed', 8)}
    assert schedule == expected and list(schedule) == [f'S{k:03d}' for k in range(1, 9)]
