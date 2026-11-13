"""Descriptive analysis of the first hosted deployment of the G1-G4 study (real participants).

Reads the six tables exported from the study database (Supabase "Download CSV" gives
study_<table>_rows.csv; rename to study_<table>.csv) from a private folder and writes
aggregate results only: no names, details or passwords leave the private folder.

Usage:
  python scripts/analyze_pilot_deployment.py --data data/private/pilot_2026-11 \
      --team S006,S007,S008,S011 --out results/pilot

--team lists slot IDs of people involved in running the study; results are reported with
and without them. The sample is far too small for inferential tests, so none are run.
"""
import argparse
import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vault.research import attack_rank, guesses_s6  # noqa: E402

CONDITIONS = ('G1', 'G2', 'G3', 'G4')


def read(folder, table):
    path = Path(folder) / f'study_{table}.csv'
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def dedupe(rows, key):
    """Keep the first record per key; a repeated click logged some decisions twice."""
    seen, kept, dropped = set(), [], 0
    for r in sorted(rows, key=lambda r: int(r['recorded_at'])):
        k = key(r)
        if k in seen:
            dropped += 1
            continue
        seen.add(k)
        kept.append(r)
    return kept, dropped


def half_up(value, places=1):
    """Round half up (66.25 -> 66.3), as in the rest of the paper."""
    return float(Decimal(str(value)).quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP))


def s6_rank(password, profile, previous):
    for rank, guess in enumerate(guesses_s6(profile, previous, 1000), 1):
        if guess == password:
            return rank
    return None


def summarize(events, questionnaire, responses, participants, team, include_team):
    keep = (lambda pid: True) if include_team else (lambda pid: pid not in team)
    events = [e for e in events if keep(e['participant_id'])]
    questionnaire = [q for q in questionnaire if keep(q['participant_id'])]
    responses = [r for r in responses if keep(r['participant_id'])]
    tasks_by_pid = Counter(e['participant_id'] for e in events)
    complete = {pid for pid, n in tasks_by_pid.items() if n == 3}
    condition_of = {e['participant_id']: e['condition'] for e in events}
    sus = {q['participant_id']: float(q['sus_score']) for q in questionnaire}

    by_condition = {}
    for c in CONDITIONS:
        sub = [e for e in events if e['condition'] == c and e['participant_id'] in complete]
        warned = [e for e in sub if e['warning_shown'] == '1']
        scores = [sus[p] for p in sorted({e['participant_id'] for e in sub}) if p in sus]
        by_condition[c] = dict(
            participants=len({e['participant_id'] for e in sub}), tasks=len(sub),
            tasks_with_warning=len(warned),
            kept_after_warning=sum(e['overridden'] == '1' for e in warned),
            changed_after_warning=sum(e['overridden'] == '0' for e in warned),
            accepted_alternative=sum(e['accepted_alternative'] == '1' for e in sub),
            median_task_seconds=half_up(statistics.median(float(e['time_ms']) for e in sub) / 1000) if sub else None,
            sus_n=len(scores), sus_mean=half_up(statistics.mean(scores)) if scores else None)

    # Stored passwords exist only for protocol v3 (stored responses).
    finals = [r for r in responses if r['final_password'] and r['participant_id'] in complete]
    finals, _ = dedupe(finals, lambda r: (r['participant_id'], r['task_id']))
    issue_counts = Counter(code for r in finals for code in filter(None, r['issues_detected'].split(';')))
    profiles = {p['participant_id']: dict(first_name=p['first_name'], surname=p['surname'], city=p['city'],
                                         birth_year=p['birth_year']) for p in participants}
    s5 = s6 = 0
    per_pid = defaultdict(list)
    for r in sorted(finals, key=lambda r: (r['participant_id'], int(r['task_position']))):
        per_pid[r['participant_id']].append(r['final_password'])
    for pid, passwords in per_pid.items():
        for k, password in enumerate(passwords):
            histories = passwords[:k] or ['']
            s5 += any(attack_rank(password, profiles[pid], h, 'S5', 1000) is not None for h in histories)
            s6 += any(s6_rank(password, profiles[pid], h) is not None for h in histories)

    first_attempts = [r for r in responses if r['attempt'] == '1' and r['participant_id'] in complete]
    warned_first = [r for r in first_attempts if r['issues_shown']]
    edited = [r for r in warned_first if r['action'] == 'edited_after_warning']
    finals_by_task = {(r['participant_id'], r['task_id']): r for r in finals}
    fixed = [r for r in edited if not finals_by_task.get((r['participant_id'], r['task_id']), {}).get('issues_detected')]
    hidden = [r for r in first_attempts if r['condition'] == 'G1' and set(filter(None, r['issues_detected'].split(';')))
              - set(filter(None, r['issues_shown'].split(';')))]

    return dict(
        participants_with_any_task=len(tasks_by_pid), participants_completing_tasks=len(complete),
        participants_completing_questionnaire=len(set(sus) & complete),
        complete_by_protocol=dict(Counter(next(e['protocol_id'] for e in events if e['participant_id'] == p)
                                          for p in complete)),
        by_condition=by_condition,
        all_conditions=dict(
            tasks=sum(v['tasks'] for v in by_condition.values()),
            tasks_with_warning=sum(v['tasks_with_warning'] for v in by_condition.values()),
            kept_after_warning=sum(v['kept_after_warning'] for v in by_condition.values()),
            changed_after_warning=sum(v['changed_after_warning'] for v in by_condition.values()),
            sus_mean=half_up(statistics.mean(sus[p] for p in complete if p in sus)) if set(sus) & complete else None),
        stored_passwords=dict(
            participants=len(per_pid), final_passwords=len(finals),
            with_any_detected_issue=sum(bool(r['issues_detected']) for r in finals),
            issue_counts=dict(issue_counts),
            breach_listed=sum(r['breach_count'] not in ('', '0', 'unknown') for r in finals),
            recovered_by_s5_within_1000=s5, recovered_by_s6_within_1000=s6,
            first_attempts_warned=len(warned_first), edited_after_warning=len(edited),
            edits_ending_with_no_detected_issue=len(fixed),
            g1_first_attempts_with_hidden_contextual_issue=len(hidden)))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--data', default='data/private/pilot_2026-11')
    ap.add_argument('--team', default='', help='comma-separated slot IDs of people involved in running the study')
    ap.add_argument('--out', default='results/pilot')
    args = ap.parse_args()
    team = {t.strip() for t in args.team.split(',') if t.strip()}

    slots = read(args.data, 'slots')
    events = [e for e in read(args.data, 'events') if e['source'] == 'human']
    questionnaire = [q for q in read(args.data, 'questionnaire') if q['source'] == 'human']
    responses = [r for r in read(args.data, 'responses') if r['source'] == 'human']
    participants = read(args.data, 'participants')
    events, dup_events = dedupe(events, lambda e: (e['participant_id'], e['task_id']))
    questionnaire, dup_sus = dedupe(questionnaire, lambda q: q['participant_id'])
    responses, dup_responses = dedupe(responses, lambda r: (r['participant_id'], r['task_id'], r['entered_password'],
                                                            r['action'], r['final_password']))

    result = dict(
        slots_claimed=len(slots),
        duplicates_removed=dict(events=dup_events, questionnaire=dup_sus, responses=dup_responses),
        team_slots=len(team),
        all_records=summarize(events, questionnaire, responses, participants, team, include_team=True),
        excluding_team=summarize(events, questionnaire, responses, participants, team, include_team=False))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'pilot_deployment.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
