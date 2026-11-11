from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest


def fill_profile(app, first='Fictional', year=1999):
    app.text_input(key='profile_first').set_value(first)
    app.number_input(key='profile_year').set_value(year)
    next(b for b in app.button if b.label == 'Continue').click().run()
    return app

@pytest.mark.parametrize('condition',['G1','G2','G3','G4'])
def test_controlled_study_intervention_timing(condition,monkeypatch):
    import vault.study
    monkeypatch.delenv('STUDY_MODE',raising=False)
    monkeypatch.setattr(vault.study,'assign_condition',lambda _:condition)
    recorded=[]
    monkeypatch.setattr(vault.study,'log_study_event',lambda *args,**kwargs:recorded.append((args,kwargs)))
    app=AppTest.from_file(str(Path(__file__).parents[1]/'pages/7_Controlled_Study.py')).run()
    app.text_input(key='study_participant').set_value('FictionalP1').run()
    app.checkbox(key='study_consent').check().run()
    fill_profile(app)
    app.text_input(key='study_password').set_value('password123!')
    next(b for b in app.button if b.label=='Save password').click().run()
    assert not app.exception
    assert len(app.warning)==1 and not recorded
    assert ('study_saved' in app.session_state)==(condition=='G2')
    assert any(b.label=='Use suggested alternative' for b in app.button)==(condition=='G4')
    label='Keep saved credential' if condition=='G2' else 'Save anyway'
    next(b for b in app.button if b.label==label).click().run()
    assert not app.exception and len(recorded)==1
    assert recorded[0][1]['source']=='demo'
    assert recorded[0][1]['vulnerable'] is True
    assert recorded[0][0][7]>0

def test_vault_warns_before_persisting(monkeypatch,tmp_path):
    from vault.store import VaultStore
    from vault.crypto import create_vault_header
    import vault.ui_common
    store=VaultStore(str(tmp_path/'fixture.db'))
    header,dek,_=create_vault_header('FictionalMasterPassword123!')
    store.save_header(header)
    monkeypatch.setattr(vault.ui_common,'require_unlocked_vault',lambda:(store,dek))
    app=AppTest.from_file(str(Path(__file__).parents[1]/'pages/1_Vault.py')).run()
    next(b for b in app.button if b.label=='Add Entry').click().run()
    next(t for t in app.text_input if t.label=='Site / Service Name').set_value('Fictional site')
    app.text_input(key='cand_pw_input').set_value('password')
    next(b for b in app.button if b.label=='Save Credential').click().run()
    assert not app.exception and store.count_entries()==0
    next(b for b in app.button if 'Save Anyway' in b.label).click().run()
    assert not app.exception and store.count_entries()==1
