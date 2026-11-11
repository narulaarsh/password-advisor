"""Independent-benchmark kit: agreement statistics, adjudicated merge and the --input path."""
import csv
import json

import pytest

from scripts.benchmark_agreement import cohen_kappa, merge, read_labels
from scripts.review2_experiments import run


def write_labels(path, labels):
    with path.open('w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['id', 'label_personal', 'category'])
        for i, (label, cat) in labels.items():
            w.writerow([i, label, cat])


def test_kappa_matches_hand_calculation(tmp_path):
    a = {str(i): (v, '') for i, v in enumerate([1, 1, 1, 0, 0, 0, 1, 0])}
    b = {str(i): (v, '') for i, v in enumerate([1, 1, 0, 0, 0, 1, 1, 0])}
    kappa, observed = cohen_kappa(a, b)
    assert observed == 0.75 and kappa == pytest.approx(0.5)


def test_disagreements_require_adjudication(tmp_path):
    items = tmp_path / 'items.jsonl'
    items.write_text(json.dumps(dict(id='x1')) + '\n')
    a, b = {'x1': (1, 'direct')}, {'x1': (0, 'direct')}
    with pytest.raises(ValueError, match='adjudication'):
        merge(items, a, b)


def independent_style_rows():
    """A tiny benchmark in the documented contract, written for this test only."""
    rows = []
    for k in range(18):
        split = ('train', 'validation', 'test')[k % 3]
        name = ['Avery', 'Briar', 'Casey', 'Devon', 'Emery', 'Finley'][k % 6] + 'x' * (k // 6)
        profile = dict(first_name=name, surname=f'Sur{k}name', city=f'Town{k}ville', birth_year=1980 + k)
        old = f'{name}Lake{k}2019!'
        for j, (category, pw, label) in enumerate([
                ('direct', f'{name}{1980 + k}!', 1), ('history', old.replace('2019', '2020'), 1),
                ('random', f'Rq{k}x!Zp{k * 7}LmQ', 0), ('weak', f'sunshine{k}{split[0]}!', 0)]):
            rows.append(dict(id=f'{k}-{j}', profile_id=f'P{k}', family_id=f'F{k}', template_id=f'{split}-{category}',
                             split=split, profile=profile, password=pw, previous_password=old,
                             other_passwords=[old], label_personal=label, breach_count=int(category == 'weak'),
                             age_days=30, criticality=1 + k % 3, category=category,
                             provenance='unit-test fixture for the kit, not real data'))
    return rows


def test_input_benchmark_runs_end_to_end(tmp_path):
    path = tmp_path / 'bench.jsonl'
    path.write_text('\n'.join(json.dumps(r) for r in independent_style_rows()) + '\n')
    manifest = run(tmp_path / 'out', e3_budgets=(100, 1000), reps=20, input_path=path)
    assert manifest['dataset_type'] == 'supplied_benchmark_provenance_as_declared'
    assert manifest['samples'] == 72 and manifest['profiles'] == 18
    assert (tmp_path / 'out/e2.json').exists() and (tmp_path / 'out/e1.json').exists()


def test_merge_produces_validated_benchmark(tmp_path):
    rows = independent_style_rows()
    items = tmp_path / 'items.jsonl'
    items.write_text('\n'.join(json.dumps(r) for r in rows) + '\n')
    a = {r['id']: (r['label_personal'], r['category']) for r in rows}
    b = dict(a)
    b['0-0'] = (0, 'direct')
    adj = tmp_path / 'adj.csv'
    write_labels(adj, {'0-0': (1, 'direct')})
    final, disagreements = merge(items, a, b, adj)
    assert disagreements == ['0-0'] and len(final) == len(rows)
    assert next(r for r in final if r['id'] == '0-0')['label_personal'] == 1
    labels = tmp_path / 'a.csv'
    write_labels(labels, a)
    assert read_labels(labels) == a
