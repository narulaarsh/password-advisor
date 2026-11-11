"""Fictional-task study logging. Passwords and password hashes are never persisted."""
import csv
import hashlib
import itertools
import os
import random
import time
from pathlib import Path

CONDITIONS = ['G1', 'G2', 'G3', 'G4']
DEFAULT_STUDY_LOG = 'data/private/study_events.csv'
DEFAULT_QUESTIONNAIRE_LOG = 'data/private/study_questionnaire.csv'
PROTOCOL_ID = 'review2-v1'
TASKS = ('a shop', 'an email service', 'a social account')
TASK_ORDERS = [list(order) for order in itertools.permutations(range(len(TASKS)))]
SCHEDULE_FIELDS = ['slot_id', 'block', 'condition', 'task_order']

# System Usability Scale (Brooke, 1996), ten items rated 1 (strongly disagree) to 5 (strongly agree).
SUS_ITEMS = (
    'I think that I would like to use this system frequently.',
    'I found the system unnecessarily complex.',
    'I thought the system was easy to use.',
    'I think that I would need the support of a technical person to be able to use this system.',
    'I found the various functions in this system were well integrated.',
    'I thought there was too much inconsistency in this system.',
    'I would imagine that most people would learn to use this system very quickly.',
    'I found the system very cumbersome to use.',
    'I felt very confident using the system.',
    'I needed to learn a lot of things before I could get going with this system.',
)


def is_study_mode():
    return os.environ.get('STUDY_MODE') == '1'


def assign_condition(participant_id):
    """Reproducible demo allocation; conceal the study seed during recruitment.

    This is hash allocation, not a claim of balanced randomized assignment. Human
    collection uses `make_allocation_schedule` instead (see `assignment`).
    """
    if not participant_id.strip():
        raise ValueError('Participant ID required')
    seed = os.environ.get('STUDY_SEED', 'demo-allocation-not-for-recruitment')
    h = hashlib.sha256(f'{seed}:{participant_id.strip().upper()}'.encode()).digest()
    return CONDITIONS[int.from_bytes(h[:8], 'big') % 4]


def demo_task_order(participant_id):
    seed = os.environ.get('STUDY_SEED', 'demo-allocation-not-for-recruitment')
    h = hashlib.sha256(f'{seed}:order:{participant_id.strip().upper()}'.encode()).digest()
    return TASK_ORDERS[int.from_bytes(h[:8], 'big') % len(TASK_ORDERS)]


def make_allocation_schedule(seed, slots):
    """Permuted-block randomization (block size 4, one slot per condition per block).

    Within each condition the six task orders are used in a shuffled cycle, so task
    order is counterbalanced inside every arm. Slots are assigned in enrollment order
    by the study coordinator; the schedule must be kept concealed from participants.
    """
    if slots < 1:
        raise ValueError('At least one slot is required')
    rng = random.Random(f'cav-allocation:{seed}')
    order_cycles = {c: [] for c in CONDITIONS}
    rows = []
    block = 0
    while len(rows) < slots:
        block += 1
        conditions = CONDITIONS[:]
        rng.shuffle(conditions)
        for condition in conditions:
            if len(rows) >= slots:
                break
            if not order_cycles[condition]:
                order_cycles[condition] = [o[:] for o in TASK_ORDERS]
                rng.shuffle(order_cycles[condition])
            order = order_cycles[condition].pop()
            rows.append(dict(slot_id=f'S{len(rows) + 1:03d}', block=block, condition=condition,
                             task_order='-'.join(map(str, order))))
    return rows


def write_allocation_schedule(rows, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=SCHEDULE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    os.chmod(path, 0o600)


def load_allocation_schedule(path):
    with open(path, newline='') as f:
        rows = list(csv.DictReader(f))
    schedule = {}
    for row in rows:
        order = [int(x) for x in row['task_order'].split('-')]
        if row['condition'] not in CONDITIONS or sorted(order) != list(range(len(TASKS))):
            raise ValueError('Invalid allocation schedule row')
        if row['slot_id'] in schedule:
            raise ValueError('Duplicate slot in allocation schedule')
        schedule[row['slot_id']] = (row['condition'], order)
    return schedule


def assignment(participant_id, human=False, schedule_path=None):
    """Returns (condition, task_order).

    Human mode requires a concealed allocation schedule and a participant ID that is
    one of its slots. Demo mode uses reproducible hashing and is never human evidence.
    """
    if not participant_id.strip():
        raise ValueError('Participant ID required')
    if human:
        if not schedule_path:
            raise ValueError('Human collection requires STUDY_ALLOCATION_FILE')
        schedule = load_allocation_schedule(schedule_path)
        if participant_id.strip() not in schedule:
            raise ValueError('Participant ID is not a slot in the allocation schedule')
        return schedule[participant_id.strip()]
    return assign_condition(participant_id), demo_task_order(participant_id)


EVENT_FIELDS = ['participant_id', 'condition', 'task_id', 'task_label', 'task_position', 'task_order',
                'warning_shown', 'overridden', 'accepted_alternative', 'time_ms', 'vulnerable', 'source',
                'protocol_id', 'recorded_at']


def _append(path, fields, row):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size:
        with path.open(newline='') as f:
            if next(csv.reader(f)) != fields:
                raise ValueError('Incompatible legacy study log; choose a new output path')
    with path.open('a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if f.tell() == 0:
            writer.writeheader()
        writer.writerow(row)
    os.chmod(path, 0o600)


def log_study_event(participant_id, condition, task_id, final_password, warning_shown,
                    overridden, accepted_alternative, time_ms, log_path=DEFAULT_STUDY_LOG,
                    *, vulnerable=None, source='demo', protocol_id=PROTOCOL_ID,
                    task_label='', task_position='', task_order=''):
    """Store outcomes only. `final_password` is accepted for API compatibility and discarded.

    Primary outcome is nullable until independently evaluated. Do not infer it from warnings.
    """
    if condition not in CONDITIONS or not participant_id.strip() or not task_id.strip():
        raise ValueError('Valid participant, task and condition required')
    if time_ms < 0 or source not in ('demo', 'synthetic', 'human'):
        raise ValueError('Invalid event metadata')
    _append(log_path, EVENT_FIELDS, dict(
        participant_id=participant_id, condition=condition, task_id=task_id, task_label=task_label,
        task_position=task_position, task_order=task_order, warning_shown=int(warning_shown),
        overridden=int(overridden), accepted_alternative=int(accepted_alternative),
        time_ms=round(time_ms, 1), vulnerable='' if vulnerable is None else int(vulnerable),
        source=source, protocol_id=protocol_id, recorded_at=int(time.time())))


def sus_score(responses):
    """Standard SUS scoring: odd items r-1, even items 5-r, sum times 2.5 (range 0-100)."""
    if len(responses) != len(SUS_ITEMS) or any(r not in (1, 2, 3, 4, 5) for r in responses):
        raise ValueError('SUS needs ten responses from 1 to 5')
    total = sum((r - 1) if k % 2 == 0 else (5 - r) for k, r in enumerate(responses))
    return total * 2.5


QUESTIONNAIRE_FIELDS = ['participant_id', 'condition'] + [f'sus_{k + 1}' for k in range(len(SUS_ITEMS))] + \
    ['sus_score', 'source', 'protocol_id', 'recorded_at']


def log_questionnaire(participant_id, condition, responses, log_path=DEFAULT_QUESTIONNAIRE_LOG,
                      *, source='demo', protocol_id=PROTOCOL_ID):
    if condition not in CONDITIONS or not participant_id.strip():
        raise ValueError('Valid participant and condition required')
    if source not in ('demo', 'synthetic', 'human'):
        raise ValueError('Invalid source')
    row = dict(participant_id=participant_id, condition=condition, sus_score=sus_score(responses),
               source=source, protocol_id=protocol_id, recorded_at=int(time.time()))
    row.update({f'sus_{k + 1}': r for k, r in enumerate(responses)})
    _append(log_path, QUESTIONNAIRE_FIELDS, row)
    return row['sus_score']
