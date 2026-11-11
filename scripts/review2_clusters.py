"""Review 2 derivative-clustering evaluation on a wider planted fixture (synthetic only).

Families cover six mutation types, near-miss word pairs that should stay separate,
gradual-edit chains whose ends fail the direct pair rule, and random singletons.
Results describe this author-written fixture, not population accuracy.
"""
import json
import random
import string
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sklearn.metrics import adjusted_rand_score

from vault.audit import _are_derivatives, detect_derivative_families, extract_base_password
from vault.models import Entry
from vault.research import attack_rank

NEAR_MISS_WORDS = [('mountain', 'fountain'), ('winter', 'winner'), ('silver', 'sliver'), ('castle', 'cattle'),
                   ('pirate', 'private'), ('garden', 'warden'), ('rocket', 'pocket'), ('shadow', 'meadow')]
LEET = str.maketrans({'a': '@', 'e': '3', 'o': '0', 's': '$'})


def base_word(rng, k=10):
    # alternating consonant/vowel so leet substitutions always apply
    cons, vows = 'bcdfghjklmnprstvwz', 'aeo'
    return ''.join(rng.choice(cons if i % 2 == 0 else vows) for i in range(k))


def substitute(word, position, rng):
    choices = [c for c in string.ascii_lowercase if c != word[position]]
    return word[:position] + rng.choice(choices) + word[position + 1:]


def build_fixture(seed=2026, per_type=6):
    rng = random.Random(seed)
    items = []  # (password, family_id, kind)
    fid = 0
    mutations = {
        'year': lambda b: [b.capitalize() + y + '!' for y in ('2023', '2024', '2025')],
        'suffix_digits': lambda b: [b + '1', b + '12', b + '123'],
        'case': lambda b: [b, b.capitalize() + '!', b.upper() + '#'],
        'leetspeak': lambda b: [b + '!', b.translate(LEET) + '!', b.capitalize().translate(LEET) + '9'],
        'symbols': lambda b: [b + '!', '#' + b, b + '$$'],
        'internal_edit': lambda b: [b + '7', substitute(b, 4, rng) + '7', substitute(b, 6, rng) + '7'],
    }
    for kind, make in mutations.items():
        for _ in range(per_type):
            for pw in make(base_word(rng)):
                items.append((pw, fid, kind))
            fid += 1
    for a, b in NEAR_MISS_WORDS:  # unrelated words: each is its own family
        for word in (a, b):
            items.append((word.capitalize() + str(rng.randrange(10, 99)) + '!', fid, 'near_miss'))
            fid += 1
    for _ in range(per_type):  # gradual edits: v0~v1~v2~v3 but v0 and v3 fail the pair rule
        word = base_word(rng)
        chain = [word]
        for position in (2, 5, 8):
            chain.append(substitute(chain[-1], position, rng))
        for pw in chain:
            items.append((pw + '!', fid, 'gradual_chain'))
        fid += 1
    for _ in range(30):
        items.append((''.join(rng.choices(string.ascii_letters + string.digits, k=20)), fid, 'random'))
        fid += 1
    return items


def evaluate(items):
    entries = [Entry(f'{k:04d}', f'site{k}', '', 'fictional', pw) for k, (pw, _, _) in enumerate(items)]
    truth = [f for _, f, _ in items]
    kinds = [k for _, _, k in items]
    pws = [pw for pw, _, _ in items]
    bases = [extract_base_password(p) for p in pws]
    report = {}
    for mode in ('chain', 'pairwise'):
        assigned, _ = detect_derivative_families(entries, mode)
        pred = [assigned.get(e.id, -k - 1) for k, e in enumerate(entries)]
        by_kind = defaultdict(lambda: dict(true_pairs=0, recovered_pairs=0))
        false_pairs = defaultdict(int)
        tp = fp = fn = 0
        for i, j in combinations(range(len(items)), 2):
            same_truth, same_pred = truth[i] == truth[j], pred[i] == pred[j]
            tp += same_truth and same_pred
            fp += (not same_truth) and same_pred
            fn += same_truth and not same_pred
            if same_truth:
                by_kind[kinds[i]]['true_pairs'] += 1
                by_kind[kinds[i]]['recovered_pairs'] += same_pred
            elif same_pred:
                false_pairs['+'.join(sorted({kinds[i], kinds[j]}))] += 1
        precisions, recalls = [], []
        for i in range(len(items)):
            actual = {j for j in range(len(items)) if truth[j] == truth[i]}
            predicted = {j for j in range(len(items)) if pred[j] == pred[i]}
            precisions.append(len(actual & predicted) / len(predicted))
            recalls.append(len(actual & predicted) / len(actual))
        report[mode] = dict(
            pair_precision=tp / (tp + fp) if tp + fp else None, pair_recall=tp / (tp + fn) if tp + fn else None,
            true_pairs=tp + fn, recovered_pairs=tp, false_pairs=fp,
            adjusted_rand=float(adjusted_rand_score(truth, pred)),
            bcubed_precision=sum(precisions) / len(items), bcubed_recall=sum(recalls) / len(items),
            by_mutation={k: dict(v, recall=v['recovered_pairs'] / v['true_pairs']) for k, v in by_kind.items()},
            false_pairs_by_kind=dict(false_pairs))
    chains = defaultdict(list)
    for k, (pw, f, kind) in enumerate(items):
        if kind == 'gradual_chain':
            chains[f].append(k)
    ends_direct = sum(_are_derivatives(pws[c[0]], pws[c[-1]], bases[c[0]], bases[c[-1]]) for c in chains.values())
    near_direct = sum(_are_derivatives(pws[a], pws[b], bases[a], bases[b])
                      for a, b in combinations([k for k, kind in enumerate(kinds) if kind == 'near_miss'], 2))
    attack = defaultdict(lambda: dict(pairs=0, guessed=0))
    for i, j in combinations(range(len(items)), 2):
        if truth[i] == truth[j]:
            attack[kinds[i]]['pairs'] += 1
            attack[kinds[i]]['guessed'] += attack_rank(pws[j], {}, pws[i], 'S3', 1000) is not None
    return dict(provenance='synthetic planted families (Review 2); not population accuracy',
                entries=len(items), families=len(set(truth)), modes=report,
                gradual_chains=dict(chains=len(chains), chain_ends_directly_related=ends_direct),
                near_miss_pairs_directly_related=near_direct,
                s3_attacker_within_family_pairs=dict(attack))


def main(out=Path('results/review2/clusters.json')):
    result = evaluate(build_fixture())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
