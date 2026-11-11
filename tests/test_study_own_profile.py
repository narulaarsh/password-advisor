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


def test_details_and_passwords_never_reach_the_database_and_results_are_shown(monkeypatch, tmp_path):
    app = start(monkeypatch, 'G3', tmp_path)
    for pw in ('Quiet-Maple-Comet-2210', 'Zebedee2003!', 'Amber-Fjord-Wren-7731'):
        save(app, pw)
        if any(b.label == 'Save anyway' for b in app.button):
            next(b for b in app.button if b.label == 'Save anyway').click().run()
    for k in range(10):
        app.radio(key=f'study_sus_{k}').set_value(3)
    next(b for b in app.button if b.label == 'Submit questionnaire').click().run()
    assert not app.exception
    assert any(s.value.startswith('All tasks and the questionnaire are complete') for s in app.success)
    assert 'could be cracked quickly' in reasons(app)  # the name-plus-birth-year password
    dump = '\n'.join(sqlite3.connect(tmp_path / 's.db').iterdump())
    for secret in ('Zebedee', 'Quillport', 'Quiet-Maple', 'Amber-Fjord'):  # a bare year could match timestamps
        assert secret not in dump, secret
    rows = sqlite3.connect(tmp_path / 's.db').execute('SELECT protocol_id, vulnerable FROM study_events').fetchall()
    assert len(rows) == 3 and all(r[0] == 'review2-v2-own-profile' for r in rows)
