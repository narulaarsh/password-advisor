"""Independent-benchmark kit: inter-annotator agreement and adjudicated merge.

Two annotators who did not build CAV label the same authored items independently
(CSV columns: id, label_personal, category). This script reports Cohen's kappa and
lists disagreements. Given an adjudication CSV (id, label_personal, category) for the
disagreements, it writes the final JSONL that scripts/review2_experiments.py --input
accepts. See docs/INDEPENDENT_BENCHMARK_KIT.md.
"""
import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.review_experiments import validate_rows


def read_labels(path):
    with open(path, newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    labels = {}
    for r in rows:
        if r['id'] in labels:
            raise ValueError(f'Duplicate id {r["id"]} in {path}')
        if r['label_personal'] not in ('0', '1'):
            raise ValueError(f'label_personal must be 0 or 1 (id {r["id"]})')
        labels[r['id']] = (int(r['label_personal']), r.get('category', '').strip())
    return labels


def cohen_kappa(a, b):
    ids = sorted(a)
    if set(a) != set(b):
        raise ValueError('Annotators labelled different item sets')
    n = len(ids)
    observed = sum(a[i][0] == b[i][0] for i in ids) / n
    pa, pb = sum(a[i][0] for i in ids) / n, sum(b[i][0] for i in ids) / n
    expected = pa * pb + (1 - pa) * (1 - pb)
    return 1.0 if expected == 1 else (observed - expected) / (1 - expected), observed


def merge(items_path, a, b, adjudication=None):
    """Final label = agreed label, or the adjudicated label for every disagreement."""
    items = [json.loads(line) for line in Path(items_path).read_text(encoding='utf-8').splitlines() if line.strip()]
    disagreements = sorted(i for i in a if a[i][0] != b[i][0])
    if disagreements and not adjudication:
        raise ValueError(f'{len(disagreements)} disagreements need an adjudication file')
    adjudicated = read_labels(adjudication) if adjudication else {}
    missing = [i for i in disagreements if i not in adjudicated]
    if missing:
        raise ValueError(f'Adjudication missing for {len(missing)} items, e.g. {missing[:3]}')
    final = []
    for item in items:
        if item['id'] not in a:
            raise ValueError(f'Item {item["id"]} was not labelled')
        label, category = adjudicated.get(item['id'], a[item['id']])
        final.append(dict(item, label_personal=label, category=category or item.get('category', 'unspecified')))
    validate_rows(final)
    return final, disagreements


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--items', required=True, help='Authored items JSONL without labels or with provisional labels')
    parser.add_argument('--annotator-a', required=True)
    parser.add_argument('--annotator-b', required=True)
    parser.add_argument('--adjudication')
    parser.add_argument('--out', type=Path, help='Final benchmark JSONL')
    args = parser.parse_args()
    a, b = read_labels(args.annotator_a), read_labels(args.annotator_b)
    kappa, agreement = cohen_kappa(a, b)
    print(json.dumps(dict(items=len(a), raw_agreement=round(agreement, 4), cohen_kappa=round(kappa, 4),
                          disagreements=sum(a[i][0] != b[i][0] for i in a)), indent=2))
    if args.out:
        final, disagreements = merge(args.items, a, b, args.adjudication)
        args.out.write_text('\n'.join(json.dumps(r, ensure_ascii=False) for r in final) + '\n', encoding='utf-8')
        print(f'Wrote {len(final)} adjudicated items to {args.out} ({len(disagreements)} adjudicated)')


if __name__ == '__main__':
    main()
