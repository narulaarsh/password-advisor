"""Review 2 E4: concealed block randomization, counterbalanced tasks and the SUS questionnaire."""
import csv
from collections import Counter
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from scripts.export_study_logs import export_study_summary
from vault.study import (CONDITIONS, SUS_ITEMS, TASK_ORDERS, assignment, load_allocation_schedule,
                         log_questionnaire, log_study_event, make_allocation_schedule, sus_score,
                         write_allocation_schedule)

PAGE = str(Path(__file__).parents[1] / 'pages/7_Controlled_Study.py')


def fill_profile(app, first='Fictional', year=1999):
    app.text_input(key='profile_first').set_value(first)
    app.number_input(key='profile_year').set_value(year)
    next(b for b in app.button if b.label == 'Continue').click().run()
    return app


def test_every_block_contains_each_condition_once():
    rows = make_allocation_schedule('fixture-seed', 200)
    assert len(rows) == 200 and len({r['slot_id'] for r in rows}) == 200
    for block in {r['block'] for r in rows}:
        assert sorted(r['condition'] for r in rows if r['block'] == block) == CONDITIONS


def test_task_orders_are_balanced_within_each_arm():
    rows = make_allocation_schedule('fixture-seed', 4 * 6 * 3)  # three full order cycles per arm
    for condition in CONDITIONS:
        counts = Counter(r['task_order'] for r in rows if r['condition'] == condition)
        assert len(counts) == len(TASK_ORDERS) and set(counts.values()) == {3}


def test_schedule_is_reproducible_and_seed_dependent():
    assert make_allocation_schedule('a', 40) == make_allocation_schedule('a', 40)
    assert make_allocation_schedule('a', 40) != make_allocation_schedule('b', 40)


def test_human_assignment_requires_a_scheduled_slot(tmp_path):
    path = tmp_path / 'allocation.csv'
    rows = make_allocation_schedule('fixture-seed', 8)
    write_allocation_schedule(rows, path)
    assert oct(path.stat().st_mode)[-3:] == '600'
    condition, order = assignment('S003', human=True, schedule_path=str(path))
    assert condition == rows[2]['condition'] and '-'.join(map(str, order)) == rows[2]['task_order']
    with pytest.raises(ValueError, match='not a slot'):
        assignment('P99', human=True, schedule_path=str(path))
    with pytest.raises(ValueError, match='STUDY_ALLOCATION_FILE'):
        assignment('S001', human=True, schedule_path=None)


def test_tampered_schedule_is_rejected(tmp_path):
    path = tmp_path / 'allocation.csv'
    write_allocation_schedule(make_allocation_schedule('fixture-seed', 4), path)
    text = path.read_text().replace('-', '-', 1)
    lines = text.splitlines()
    lines[1] = lines[1].rsplit(',', 1)[0] + ',0-0-1'
    path.write_text('\n'.join(lines) + '\n')
    with pytest.raises(ValueError):
        load_allocation_schedule(str(path))


def test_sus_scoring_matches_the_standard_formula():
    assert sus_score([3] * 10) == 50.0
    assert sus_score([5, 1] * 5) == 100.0
    assert sus_score([1, 5] * 5) == 0.0
    with pytest.raises(ValueError):
        sus_score([3] * 9)


def test_questionnaire_and_events_store_no_passwords(tmp_path):
    events, survey = tmp_path / 'e.csv', tmp_path / 'q.csv'
    log_study_event('S001', 'G3', 'T2', 'DoNotLogThisSecret', True, False, False, 50.0, str(events),
                    vulnerable=True, source='demo', task_label='an email service', task_position=1,
                    task_order='1-0-2')
    log_questionnaire('S001', 'G3', [4, 2, 4, 2, 4, 2, 4, 2, 4, 2], str(survey), source='demo')
    for path in (events, survey):
        assert 'DoNotLogThisSecret' not in path.read_text()
        assert oct(path.stat().st_mode)[-3:] == '600'
    assert list(csv.DictReader(survey.open()))[0]['sus_score'] == '75.0'


def test_analysis_reports_sus_by_condition(tmp_path):
    events, survey, out = tmp_path / 'e.csv', tmp_path / 'q.csv', tmp_path / 's.json'
    for pid, condition, vulnerable, answers in [('S001', 'G2', True, [3] * 10), ('S002', 'G3', False, [5, 1] * 5)]:
        for task in ('T1', 'T2', 'T3'):
            log_study_event(pid, condition, task, '', True, False, False, 10.0, str(events),
                            vulnerable=vulnerable, source='human')
        log_questionnaire(pid, condition, answers, str(survey), source='human')
    report = export_study_summary(str(events), str(out), 'human', str(survey))
    assert report['usability_sus']['G2']['mean_sus'] == 50.0
    assert report['usability_sus']['G3']['mean_sus'] == 100.0
    assert report['contrasts']['G3_minus_G2']['difference'] == -1


def run_page(monkeypatch, pid='FictionalP1'):
    import vault.study
    monkeypatch.delenv('STUDY_MODE', raising=False)
    events, surveys = [], []
    monkeypatch.setattr(vault.study, 'log_study_event', lambda *a, **k: events.append((a, k)))
    monkeypatch.setattr(vault.study, 'log_questionnaire', lambda *a, **k: surveys.append((a, k)))
    app = AppTest.from_file(PAGE).run()
    app.text_input(key='study_participant').set_value(pid).run()
    app.checkbox(key='study_consent').check().run()
    fill_profile(app)
    return app, events, surveys


def test_full_demo_flow_uses_counterbalanced_order_then_sus(monkeypatch):
    import vault.study
    app, events, surveys = run_page(monkeypatch)
    expected_condition, expected_order = vault.study.assignment('FictionalP1')
    for _ in range(3):
        app.text_input(key='study_password').set_value('Correct-Horse-Battery-Staple-77!')
        next(b for b in app.button if b.label == 'Save password').click().run()
        if any(b.label in ('Save anyway', 'Keep saved credential') for b in app.button):
            next(b for b in app.button if b.label in ('Save anyway', 'Keep saved credential')).click().run()
        assert not app.exception
    assert [e[1]['task_position'] for e in events] == [1, 2, 3]
    assert [e[0][2] for e in events] == [f'T{i + 1}' for i in expected_order]
    assert all(e[0][1] == expected_condition for e in events)
    for k in range(len(SUS_ITEMS)):
        app.radio(key=f'study_sus_{k}').set_value(4 if k % 2 == 0 else 2)
    next(b for b in app.button if b.label == 'Submit questionnaire').click().run()
    assert not app.exception and len(surveys) == 1
    assert surveys[0][0][2] == [4, 2] * 5 and surveys[0][1]['source'] == 'demo'
    assert any('questionnaire are complete' in s.value for s in app.success)


def test_human_mode_refuses_without_allocation_file(monkeypatch):
    monkeypatch.setenv('STUDY_MODE', '1')
    monkeypatch.setenv('STUDY_ETHICS_REFERENCE', 'fixture-ref')
    monkeypatch.delenv('STUDY_ALLOCATION_FILE', raising=False)
    app = AppTest.from_file(PAGE).run()
    assert any('allocation schedule' in e.value for e in app.error)
