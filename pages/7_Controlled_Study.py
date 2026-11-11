"""Password feedback study (G1-G4); never accesses the real vault.

Each participant enters their own first name, surname, city and birth year. With the
participant's consent (stated in the information text), these details, every password
entered, any suggested password, and the detected and shown reasons are stored in the
research database (study_participants, study_responses). Each new password is also checked against the participant's earlier
passwords from this session (no real passwords are ever requested). Task order is
counterbalanced; human mode uses a concealed permuted-block allocation schedule. A
System Usability Scale questionnaire and a personal results summary follow the tasks.
"""
import os
import time
import streamlit as st
from vault.study import (assignment, claim_next_slot, log_participant, log_questionnaire, log_response,
                         log_study_event, schedule_from_environment, SUS_ITEMS, TASKS)
from vault.generator import generate_passphrase
from modules.semantic import calculate_thematic_coverage
from modules.syntactic import check_hibp_status, evaluate_syntactic_strength, BreachStatus
from vault.research import attack_rank, features

PROTOCOL = 'review2-v3-stored-responses'
TASK_SCENARIOS = {
    'a shop': 'You are signing up for a new **online shopping** account.',
    'an email service': 'You are creating a new **email** account.',
    'a social account': 'You are joining a new **social media** site.',
}
INFORMATION = ('You will create passwords for three new accounts and then answer ten quick questions '
               '(about 10–15 minutes). First you enter your first name, surname, home city and birth year, '
               'so the tool can check whether a password could be guessed from them.\n\n'
               '**What is stored for the research:** your first name, surname, city and birth year; every password '
               'you type in this study (stored as you typed it, readable by the researchers); any password the tool '
               'suggests; the reasons the tool gave; the version of the tool you saw; your choices; how long you took; '
               'whether a simple guessing program would crack your final password; and your questionnaire answers. '
               'The data are kept in a private research database, used only for this study, and reported only in '
               'summaries. We do not record your IP address (the hosting provider may keep standard server logs).\n\n'
               '**Because your passwords are stored, make up completely new ones. Never type a password you use, '
               'or have used, for any real account.** To check public breach lists, the tool sends only a short '
               '5-character fragment of a scrambled version of each password. Taking part is voluntary and you can '
               'stop at any time.')
DEBRIEF = ('Thank you! You saw one of four versions of this tool. They differ in whether the password feedback '
           'appeared before or after saving, and whether a safer alternative was offered. We are testing whether '
           'feedback shown before saving helps people choose passwords that are harder to guess. Your details and '
           'the passwords you made up are stored as described at the start; to have your data removed, contact the '
           'researchers with your participant code. For your real accounts, use a password manager and a different '
           'password for every account.')
CONSENT = ('I have read what is stored, I agree to take part, and I will only make up new passwords '
           '(never real ones).')
ISSUE_CODES = ('breach', 'personal_info', 'weak_structure', 'reuse', 'similar_to_earlier')


def assess(password, condition, profile, earlier):
    """Every issue detected, and the reasons shown (G1 is shown structural feedback only)."""
    try:
        status, hits = check_hibp_status(password)
    except Exception:
        status, hits = BreachStatus.UNKNOWN, -1
    row = dict(password=password, profile=profile, other_passwords=earlier,
               breach_count=hits if status == BreachStatus.BREACHED else 0)
    f = features(row)
    messages = {
        'weak_structure': 'It is easy for computers to guess (its structure is weak).',
        'breach': f'It appears in public lists of leaked passwords ({max(hits, 0):,} times).',
        'personal_info': 'It contains your personal details (name, city or birth year), which people who know you can guess.',
        'reuse': 'It is the same as a password you made for an earlier account.',
        'similar_to_earlier': 'It is only a small change from a password you made for an earlier account.',
    }
    detected = [code for code, on in (('breach', f[0] > 0), ('personal_info', f[1] > 0), ('weak_structure', f[2] > 0),
                                      ('reuse', f[3] > 0), ('similar_to_earlier', f[4] > 0 and not f[3] > 0)) if on]
    shown = [c for c in ('weak_structure', 'breach', 'personal_info', 'reuse', 'similar_to_earlier')
             if c in detected and (condition != 'G1' or c == 'weak_structure')]
    return dict(detected=detected, shown=shown, reasons=[messages[c] for c in shown],
                matched_fields=calculate_thematic_coverage(password, profile)['matched_fields'],
                zxcvbn_score=evaluate_syntactic_strength(password)['score'],
                breach_count=hits if status != BreachStatus.UNKNOWN else 'unknown')


def outcome(password, profile, earlier):
    """Independent outcome: would the offline guessing program crack it within 1,000 guesses?"""
    histories = earlier or ['']
    return any(attack_rank(password, profile, previous, 'S5', 1000) is not None for previous in histories)


def profile_step():
    st.subheader('Step 1 · About you')
    st.write('These details let the tool check whether a password could be guessed from things about you. '
             'They are **stored with your responses** for the research, as described above.')
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
            profile = dict(first_name=first.strip(), surname=surname.strip(), city=city.strip(), birth_year=int(year))
            st.session_state.study_profile = profile
            st.session_state.study_profile_pending_log = True
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
    if st.session_state.pop('study_profile_pending_log', False):
        log_participant(pid, condition, profile, source=source, protocol_id=PROTOCOL)
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

    def record(entered, check, action, final='', vulnerable=None, suggestion=None):
        st.session_state.study_attempt = st.session_state.get('study_attempt', 0) + 1
        log_response(pid, condition, f'T{task_index + 1}', label, trial + 1, st.session_state.study_attempt, entered,
                     check['detected'], check['shown'], check['reasons'], check['matched_fields'],
                     check['zxcvbn_score'], check['breach_count'], suggestion, action, final, vulnerable,
                     source=source, protocol_id=PROTOCOL)

    def finish(password, warning, override=False, adopt=False, entered=None, check=None, suggestion=None):
        vulnerable = outcome(password, profile, earlier)
        action = ('used_suggestion' if adopt else 'kept_after_warning' if override else 'saved_without_warning')
        record(entered if entered is not None else password, check, action, password, vulnerable, suggestion)
        log_study_event(pid, condition, f'T{task_index + 1}', password, warning, override, adopt,
                        (time.monotonic() - st.session_state.study_started) * 1000,
                        vulnerable=vulnerable, source=source, task_label=label,
                        task_position=trial + 1, task_order=order_text, protocol_id=PROTOCOL)
        results.append(dict(label=label, password=password, vulnerable=vulnerable))
        for key in ('study_pending', 'study_started', 'study_password', 'study_saved', 'study_warned', 'study_attempt'):
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
            check = assess(password, condition, profile, earlier)
            if not check['reasons']:
                finish(password, st.session_state.get('study_warned', False), check=check)
            st.session_state.study_warned = True
            st.session_state.study_pending = dict(password=password, reasons=check['reasons'], check=check, pid=pid,
                                                  trial=trial,
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
                finish(pending['alternative'], True, adopt=True, entered=pending['password'], check=pending['check'],
                       suggestion=pending['alternative'])
        if st.button('Edit password'):
            record(pending['password'], pending['check'], 'edited_after_warning', suggestion=pending['alternative'])
            st.session_state.pop('study_pending', None)
            st.rerun()
        if st.button('Keep saved credential' if condition == 'G2' else 'Save anyway'):
            finish(pending['password'], True, override=True, check=pending['check'], suggestion=pending['alternative'])


render()
