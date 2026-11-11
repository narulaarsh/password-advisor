"""Study page with the participant's own profile: detection, session-only details, results."""
import sqlite3
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

PAGE = str(Path(__file__).parents[1] / 'pages/7_Controlled_Study.py')


def start(monkeypatch, condition, tmp_path, first='Zebedee', year=2003, city='Quillport'):
    import vault.study
    monkeypatch.delenv('STUDY_MODE', raising=False)
    monkeypatch.setenv('STUDY_DATABASE_URL', f'sqlite:///{tmp_path / "s.db"}')
    monkeypatch.setattr(vault.study, 'assign_condition', lambda _: condition)
    app = AppTest.from_file(PAGE).run()
    app.text_input(key='study_participant').set_value('P1').run()
    app.checkbox(key='study_consent').check().run()
    app.text_input(key='profile_first').set_value(first)
    app.text_input(key='profile_city').set_value(city)
    app.number_input(key='profile_year').set_value(year)
    next(b for b in app.button if b.label == 'Continue').click().run()
    assert not app.exception
    return app


def save(app, password):
    app.text_input(key='study_password').set_value(password)
    next(b for b in app.button if b.label == 'Save password').click().run()
    assert not app.exception
    return app


def reasons(app):
    return ' '.join(m.value for m in app.markdown)


def test_profile_requires_first_name_and_year(monkeypatch, tmp_path):
    import vault.study
    monkeypatch.delenv('STUDY_MODE', raising=False)
    monkeypatch.setattr(vault.study, 'assign_condition', lambda _: 'G3')
    app = AppTest.from_file(PAGE).run()
    app.text_input(key='study_participant').set_value('P1').run()
    app.checkbox(key='study_consent').check().run()
    next(b for b in app.button if b.label == 'Continue').click().run()
    assert any('first name and birth year' in e.value for e in app.error)


@pytest.mark.parametrize('condition,expect_personal', [('G3', True), ('G1', False)])
def test_own_name_is_detected_except_in_structural_only_group(monkeypatch, tmp_path, condition, expect_personal):
    app = save(start(monkeypatch, condition, tmp_path), 'Zebedee2003rocks')
    assert ('personal details' in reasons(app)) == expect_personal


def test_reuse_of_an_earlier_session_password_is_flagged(monkeypatch, tmp_path):
    app = save(start(monkeypatch, 'G3', tmp_path), 'Velvet-Harbor-Lantern-91')
    assert any('Saved your password' in s.value for s in app.success)
    app = save(app, 'Velvet-Harbor-Lantern-91')
    assert 'same as a password you made for an earlier account' in reasons(app)


def test_consented_details_and_every_password_are_stored_and_results_are_shown(monkeypatch, tmp_path):
    app = start(monkeypatch, 'G3', tmp_path)
    info = ' '.join(m.value for m in app.markdown)
    assert 'every password' in info and 'first name, surname, city and birth year' in info
    for pw in ('Velvet-Harbor-Lantern-91', 'Zebedee2003!', 'Amber-Fjord-Wren-7731'):
        save(app, pw)
        if any(b.label == 'Save anyway' for b in app.button):
            next(b for b in app.button if b.label == 'Save anyway').click().run()
    for k in range(10):
        app.radio(key=f'study_sus_{k}').set_value(3)
    next(b for b in app.button if b.label == 'Submit questionnaire').click().run()
    assert not app.exception
    assert any(s.value.startswith('All tasks and the questionnaire are complete') for s in app.success)
    assert 'could be cracked quickly' in reasons(app)  # the name-plus-birth-year password
    db = sqlite3.connect(tmp_path / 's.db')
    assert db.execute('SELECT first_name, city, birth_year FROM study_participants').fetchall() == [('Zebedee', 'Quillport', '2003')]
    rows = db.execute('SELECT entered_password, issues_detected, issues_shown, action, final_password, protocol_id '
                      'FROM study_responses ORDER BY task_position, attempt').fetchall()
    assert [r[0] for r in rows] == ['Velvet-Harbor-Lantern-91', 'Zebedee2003!', 'Amber-Fjord-Wren-7731']
    assert 'personal_info' in rows[1][1] and 'personal_info' in rows[1][2] and rows[1][3] == 'kept_after_warning'
    assert rows[0][3] == 'saved_without_warning' and rows[0][4] == 'Velvet-Harbor-Lantern-91'
    assert all(r[5] == 'review2-v3-stored-responses' for r in rows)
    assert len(db.execute('SELECT * FROM study_events').fetchall()) == 3


def test_g1_records_all_detected_issues_but_shows_only_structure(monkeypatch, tmp_path):
    app = save(start(monkeypatch, 'G1', tmp_path), 'zebedee1')
    next(b for b in app.button if b.label == 'Save anyway').click().run()
    row = sqlite3.connect(tmp_path / 's.db').execute('SELECT issues_detected, issues_shown FROM study_responses').fetchone()
    assert 'personal_info' in row[0] and 'weak_structure' in row[0] and row[1] == 'weak_structure'


def test_suggestion_and_edited_attempts_are_stored(monkeypatch, tmp_path):
    app = save(start(monkeypatch, 'G4', tmp_path), 'zebedee1')
    next(b for b in app.button if b.label == 'Edit password').click().run()
    save(app, 'zebedee2')
    next(b for b in app.button if b.label == 'Use suggested alternative').click().run()
    assert not app.exception
    rows = sqlite3.connect(tmp_path / 's.db').execute(
        'SELECT attempt, entered_password, suggested_password, action, final_password FROM study_responses ORDER BY attempt').fetchall()
    assert [r[3] for r in rows] == ['edited_after_warning', 'used_suggestion']
    assert rows[0][1] == 'zebedee1' and rows[1][1] == 'zebedee2'
    assert rows[1][2] and rows[1][4] == rows[1][2]  # final password is the stored suggestion
