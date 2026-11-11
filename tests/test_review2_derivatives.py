"""Review 2: the indexed derivative search must reproduce the original quadratic rule exactly."""
import random
import string

import pytest

from vault.audit import (UnionFind, _are_derivatives, derivative_adjacency,
                         detect_derivative_families, extract_base_password)
from vault.models import Entry


def reference_families(entries, cluster_mode="chain"):
    """The pre-Review-2 implementation: every pair compared directly."""
    entries = sorted(entries, key=lambda e: e.id)
    n = len(entries)
    bases = [extract_base_password(e.password) for e in entries]

    def related(i, j):
        return _are_derivatives(entries[i].password, entries[j].password, bases[i], bases[j])

    if cluster_mode == "pairwise":
        groups = []
        for i in range(n):
            for group in groups:
                if all(related(i, j) for j in group):
                    group.append(i)
                    break
            else:
                groups.append([i])
        mapping, members = {}, {}
        for group in groups:
            if len(group) > 1:
                fid = len(members) + 1
                members[fid] = [entries[i].site_name for i in group]
                mapping.update({entries[i].id: fid for i in group})
        return mapping, members
    uf = UnionFind(n)
    for i in range(n):
        for j in range(i + 1, n):
            if related(i, j):
                uf.union(i, j)
    clusters = {}
    for idx in range(n):
        clusters.setdefault(uf.find(idx), []).append(idx)
    mapping, members, fid = {}, {}, 1
    for idxs in clusters.values():
        if len(idxs) >= 2:
            members[fid] = [entries[i].site_name for i in idxs]
            mapping.update({entries[i].id: fid for i in idxs})
            fid += 1
    return mapping, members


def make_vault(seed, size):
    rng = random.Random(seed)
    words = ["summer", "orbit", "maple", "falcon", "denver", "carter", "river", "piano"]
    passwords = []
    for _ in range(size):
        kind = rng.randrange(6)
        word = rng.choice(words)
        if kind == 0:
            pw = word.capitalize() + str(rng.randrange(1990, 2030)) + rng.choice("!#$")
        elif kind == 1:
            pw = word.replace("a", "@").replace("o", "0") + str(rng.randrange(100))
        elif kind == 2:
            pw = "".join(rng.choices(string.ascii_letters + string.digits, k=rng.randrange(4, 18)))
        elif kind == 3:
            base = word + rng.choice(words)
            i = rng.randrange(len(base))
            pw = base[:i] + rng.choice("xyz") + base[i + 1:] + "1!"
        elif kind == 4:
            pw = rng.choice(["ab", "abc", "a1", "!!", "", "ünïcødé", "Ünïcødé9"])
        else:
            pw = word[: rng.randrange(1, len(word) + 1)] + str(rng.randrange(10))
        passwords.append(pw)
    return [Entry(f"e{k:04d}", f"site{k}", "", "user", pw) for k, pw in enumerate(passwords)]


@pytest.mark.parametrize("mode", ["chain", "pairwise"])
@pytest.mark.parametrize("seed,size", [(1, 0), (2, 1), (3, 2), (4, 60), (5, 300), (6, 700)])
def test_indexed_search_matches_reference(mode, seed, size):
    entries = make_vault(seed, size)
    assert detect_derivative_families(entries, mode) == reference_families(entries, mode)


def test_adjacency_equals_pair_rule_exactly():
    entries = make_vault(11, 400)
    pws = [e.password for e in entries]
    bases = [extract_base_password(p) for p in pws]
    adjacency = derivative_adjacency(pws, bases, chunk=37)
    for i in range(len(pws)):
        for j in range(len(pws)):
            if i != j:
                assert (j in adjacency[i]) == _are_derivatives(pws[i], pws[j], bases[i], bases[j])


def test_chunk_size_does_not_change_result():
    entries = make_vault(12, 250)
    pws = [e.password for e in entries]
    bases = [extract_base_password(p) for p in pws]
    assert derivative_adjacency(pws, bases, chunk=1) == derivative_adjacency(pws, bases, chunk=1000)
