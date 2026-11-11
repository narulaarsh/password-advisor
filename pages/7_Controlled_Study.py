"""Password feedback study (G1-G4); never accesses the real vault.

Each participant enters their own first name, surname, city and birth year. These are
held in session memory only, used to check passwords during the session, and never
stored or logged. Each new password is also checked against the participant's earlier
passwords from this session (no real passwords are ever requested). Task order is
counterbalanced; human mode uses a concealed permuted-block allocation schedule. A
System Usability Scale questionnaire and a personal results summary follow the tasks.
"""
import os
import time
import streamlit as st
from vault.study import (assignment, claim_next_slot, log_study_event, log_questionnaire,
                         schedule_from_environment, SUS_ITEMS, TASKS)
from vault.generator import generate_passphrase
from modules.syntactic import check_hibp_status, BreachStatus
from vault.research import attack_rank, features

PROTOCOL = 'review2-v2-own-profile'
TASK_SCENARIOS = {
    'a shop': 'You are signing up for a new **online shopping** account.',
    'an email service': 'You are creating a new **email** account.',
    'a social account': 'You are joining a new **social media** site.',
}
INFORMATION = ('You will create passwords for three new accounts and then answer ten quick questions '
               '(about 10–15 minutes). First you enter your first name, surname, home city and birth year, '
               'so the tool can check whether a password could be guessed from them. These details stay in this '
               'browser session only: they are never saved or sent anywhere. Please make up new passwords and '
               'never type one you use for a real account. To check public breach lists, the tool sends only a '
               'short 5-character fragment of a scrambled version of each password. We record which version of the '
               'tool you saw, whether a warning appeared, your choices, how long you took, whether a simple guessing '
               'program would crack your final password, and your questionnaire answers. We do not record your '
               'name, your details, any password you type, or your IP address (the hosting provider may keep '
               'standard server logs). Taking part is voluntary and you can stop at any time.')
DEBRIEF = ('Thank you! You saw one of four versions of this tool. They differ in whether the password feedback '
           'appeared before or after saving, and whether a safer alternative was offered. We are testing whether '
           'feedback shown before saving helps people choose passwords that are harder to guess. Nothing you typed '
           'was stored. For your real accounts, use a password manager and a different password for every account.')
CONSENT = 'I agree to take part, and I will only make up new passwords (never real ones).'


def findings(password, condition, profile, earlier):
    """Reasons shown to the participant. G1 sees structural feedback only."""
    try:
        status, hits = check_hibp_status(password)
    except Exception:
        status, hits = BreachStatus.UNKNOWN, -1
    row = dict(password=password, profile=profile, other_passwords=earlier,
               breach_count=hits if status == BreachStatus.BREACHED else 0)
    f = features(row)
    reasons = []
    if f[2]:
        reasons.append('It is easy for computers to guess (its structure is weak).')
    if condition != 'G1':
        if f[0]:
            reasons.append(f'It appears in public lists of leaked passwords ({hits:,} times).')
        if f[1] > 0:
            reasons.append('It contains your personal details (name, city or birth year), which people who know you can guess.')
        if f[3]:
            reasons.append('It is the same as a password you made for an earlier account.')
        elif f[4]:
            reasons.append('It is only a small change from a password you made for an earlier account.')
    return reasons


def outcome(password, profile, earlier):
    """Independent outcome: would the offline guessing program crack it within 1,000 guesses?"""
    histories = earlier or ['']
    return any(attack_rank(password, profile, previous, 'S5', 1000) is not None for previous in histories)


def profile_step():
    st.subheader('Step 1 · About you')
    st.write('These details let the tool check whether a password could be guessed from things about you. '
             'They stay in this session only and are **never saved**.')
    with st.form('study_profile_form'):
        first = st.text_input('First name', key='profile_first')
        surname = st.text_input('Surname (optional)', key='profile_surname')
        city = st.text_input('Home city (optional)', key='profile_city')
        year = st.number_input('Birth year', min_value=1930, max_value=2015, value=None, step=1,
                               placeholder='e.g. 2004', key='profile_year')
        go = st.form_submit_button('Continue')
    if go:
        if len(first.strip()) < 2 or year is None:
            st.error('Please enter at least your first name and birth year.')
        else:
            st.session_state.study_profile = dict(first_name=first.strip(), surname=surname.strip(),
                                                  city=city.strip(), birth_year=int(year))
            st.rerun()
    st.stop()


def render():
    st.title('Password feedback study')
    st.caption('Create passwords for three new accounts, then answer ten quick questions.')
    human = os.environ.get('STUDY_MODE') == '1'
    has_schedule = bool(os.environ.get('STUDY_ALLOCATION_FILE') or os.environ.get('STUDY_ALLOCATION_CSV')
                        or (os.environ.get('STUDY_ALLOCATION_SEED') and os.environ.get('STUDY_ALLOCATION_SLOTS')))
    if human and (not os.environ.get('STUDY_ETHICS_REFERENCE') or not has_schedule):
        st.error('Human collection requires the institutional ethics reference and a concealed allocation schedule (STUDY_ALLOCATION_FILE, STUDY_ALLOCATION_CSV or STUDY_ALLOCATION_SEED/SLOTS). Demo is available with STUDY_MODE unset.')
        st.stop()
    with st.expander('What happens in this study (please read)', expanded='study_profile' not in st.session_state):
        st.write(INFORMATION)
        if human:
            st.caption(f"Ethics reference: {os.environ.get('STUDY_ETHICS_REFERENCE')}")

    # Participant code and consent.
    if human and os.environ.get('STUDY_AUTO_SLOT') == '1':
        consent = st.checkbox(CONSENT, key='study_consent')
        if not consent:
            st.stop()
        if 'study_slot' not in st.session_state:
            if not st.button('Start the study', type='primary'):
                st.stop()
            slot = claim_next_slot(schedule_from_environment())
            if slot is None:
                st.error('This study is full. Thank you for your interest.')
                st.stop()
            st.session_state.study_slot = slot
            st.rerun()
        pid = st.session_state.study_slot
        st.info(f'Your participant code is {pid}. Note it down if you may later want your data withdrawn.')
    else:
        pid = st.text_input('Participant code', key='study_participant')
        consent = st.checkbox(CONSENT, key='study_consent')
        if not pid.strip() or not consent:
            st.stop()
    try:
        condition, order = assignment(pid, human=human, schedule_path=os.environ.get('STUDY_ALLOCATION_FILE'))
    except ValueError as exc:
        st.error(str(exc))
        st.stop()
    source = 'human' if human else 'demo'

    if 'study_profile' not in st.session_state:
        profile_step()
    profile = st.session_state.study_profile
    results = st.session_state.setdefault('study_results', [])
    earlier = [r['password'] for r in results]
    trial = st.session_state.get('study_trial', 0)

    # Questionnaire, then personal results and debrief.
    if trial >= len(TASKS):
        if st.session_state.get('study_sus_done'):
            st.success('All tasks and the questionnaire are complete. Thank you!')
            st.subheader('Your results')
            for r in results:
                verdict = ('**could be cracked quickly** by a guessing program that knows your details and earlier passwords'
                           if r['vulnerable'] else 'was **not cracked** by our simple guessing program (that does not prove it is safe)')
                st.write(f"- {r['label'].capitalize()}: your final password {verdict}.")
            st.write(DEBRIEF)
            return
        st.progress(1.0, text='Last step: 10 quick questions')
        st.subheader('Step 3 · How easy was the tool to use?')
        st.caption('Rate each statement from 1 (strongly disagree) to 5 (strongly agree).')
        with st.form('study_sus'):
            answers = [st.radio(f'{k + 1}. {item}', [1, 2, 3, 4, 5], index=None, horizontal=True, key=f'study_sus_{k}')
                       for k, item in enumerate(SUS_ITEMS)]
            done = st.form_submit_button('Submit questionnaire', type='primary')
        if done:
            if any(a is None for a in answers):
                st.error('Please answer all ten statements.')
            else:
                log_questionnaire(pid, condition, answers, source=source, protocol_id=PROTOCOL)
                st.session_state.study_sus_done = True
                st.rerun()
        return

    task_index = order[trial]
    label = TASKS[task_index]
    order_text = '-'.join(map(str, order))
    if st.session_state.get('study_saved_note'):
        st.success(st.session_state.pop('study_saved_note'))
    st.progress(trial / len(TASKS), text=f'Step 2 · Account {trial + 1} of {len(TASKS)}')
    st.subheader(f'Account {trial + 1} of {len(TASKS)}')
    st.write(TASK_SCENARIOS[label] + ' Create a password you would realistically use for it. '
             'Make it up now: never use a password from a real account.')
    st.session_state.setdefault('study_started', time.monotonic())
    pending = st.session_state.get('study_pending')
    if pending and (pending['pid'] != pid or pending['trial'] != trial):
        st.error('Finish the current account before changing the participant code.')
        st.stop()

    def finish(password, warning, override=False, adopt=False):
        vulnerable = outcome(password, profile, earlier)
        log_study_event(pid, condition, f'T{task_index + 1}', password, warning, override, adopt,
                        (time.monotonic() - st.session_state.study_started) * 1000,
                        vulnerable=vulnerable, source=source, task_label=label,
                        task_position=trial + 1, task_order=order_text, protocol_id=PROTOCOL)
        results.append(dict(label=label, password=password, vulnerable=vulnerable))
        for key in ('study_pending', 'study_started', 'study_password', 'study_saved', 'study_warned'):
            st.session_state.pop(key, None)
        st.session_state.study_trial = trial + 1
        nxt = ('Now the next account.' if trial + 1 < len(TASKS) else 'Now the last step.')
        st.session_state.study_saved_note = f'Saved your password for {label}. {nxt}'
        st.rerun()

    if not pending:
        with st.form('study_candidate'):
            password = st.text_input('New password', type='password', key='study_password')
            submit = st.form_submit_button('Save password', type='primary')
        if submit and password:
            reasons = findings(password, condition, profile, earlier)
            if not reasons:
                finish(password, st.session_state.get('study_warned', False))
            st.session_state.study_warned = True
            st.session_state.study_pending = dict(password=password, reasons=reasons, pid=pid, trial=trial,
                                                  alternative=generate_passphrase(num_words=4).password if condition == 'G4' else None)
            if condition == 'G2':
                st.session_state.study_saved = password
            st.rerun()
    else:
        st.warning('Your password has been saved, but please review this:' if condition == 'G2'
                   else 'Before saving, please review this:')
        for reason in pending['reasons']:
            st.write(f'- {reason}')
        if pending['alternative']:
            st.write('A safer password you could use instead:')
            st.code(pending['alternative'])
            if st.button('Use suggested alternative'):
                finish(pending['alternative'], True, adopt=True)
        if st.button('Edit password'):
            st.session_state.pop('study_pending', None)
            st.rerun()
        if st.button('Keep saved credential' if condition == 'G2' else 'Save anyway'):
            finish(pending['password'], True, override=True)


render()
