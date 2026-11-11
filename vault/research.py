"""Offline research primitives. Attack candidates never receive the target password."""
import itertools
import re
from vault.audit import _are_derivatives, extract_base_password, calculate_risk_score, AuditConfig
from modules.semantic import calculate_thematic_coverage
from modules.syntactic import evaluate_syntactic_strength

FEATURES = ('breach', 'semantic', 'syntax', 'reuse', 'derivative', 'age')
LEGACY = AuditConfig(weights=dict(zip(FEATURES, (.4, .25, .15, .1, .05, .05))),
                     enable_age_score=True, max_correlated_contribution=1.0)
COMMON = ('password', 'welcome', 'dragon', 'monkey', 'admin', 'qwerty', 'summer', 'football')

def guesses(profile, previous, scenario, budget=1000):
    """Deterministic toy attacker v1; not a reproduction of published neural attacks.

    Budget counts distinct guesses; the stream order is independent of the budget.
    """
    if scenario not in ('S1', 'S2', 'S3', 'S4', 'S5') or budget < 1:
        raise ValueError('Invalid attack scenario or budget')
    tokens = [str(profile.get(k, '')) for k in ('first_name','surname','city','birth_year')]
    tokens = [t for t in tokens if t]
    def general():
        for suffix in ('', '123!', '123', '1', '2026!', '!'):
            for word in COMMON:
                yield word + suffix
        for n in range(10000):
            for word in COMMON:
                yield word + str(n) + '!'
    def personal():
        for a, b in itertools.permutations(tokens, 2):
            for separator in ('', '_', '-'):
                yield a + separator + b + '!'
                yield a + separator + b
        for n in range(10000):
            for token in tokens:
                yield token + str(n) + '!'
                yield token.lower() + str(n)
    def history():
        if not previous:
            return
        yield previous
        yield previous.lower()
        for m in re.finditer(r'\d{4}', previous):
            for delta in (1, -1, 2, -2):
                yield previous[:m.start()] + str(int(m.group()) + delta) + previous[m.end():]
        for suffix in ('!', '1', '123', '2026!', '#'):
            yield previous + suffix
        for n in range(10000):
            yield previous.rstrip('!#0123456789') + str(n) + '!'
    sources = {'S1':[general], 'S2':[personal], 'S3':[history],
               'S4':[personal,history], 'S5':[general,personal,history]}[scenario]
    streams = [iter(f()) for f in sources]
    seen = set()
    while streams and len(seen) < budget:
        for stream in list(streams):
            try:
                item = next(stream)
            except StopIteration:
                streams.remove(stream)
                continue
            if item not in seen:
                seen.add(item)
                yield item
                if len(seen) >= budget:
                    return

def attack_rank(password, profile, previous, scenario, budget):
    for rank, candidate in enumerate(guesses(profile, previous, scenario, budget), 1):
        if candidate == password:
            return rank
    return None

def features(row):
    password, profile = row['password'], row['profile']
    others = row.get('other_passwords', [])
    base = extract_base_password(password)
    return [float(row['breach_count'] > 0),
            calculate_thematic_coverage(password, profile)['score'],
            float(evaluate_syntactic_strength(password)['score'] < 3),
            float(password in others),
            float(any(_are_derivatives(password, other, base, extract_base_password(other)) for other in others)),
            min(1., row.get('age_days', 0) / 365.) if row.get('age_days', 0) > 90 else 0.]

def fixed_score(vector, legacy=False):
    return calculate_risk_score(*vector, config=LEGACY if legacy else AuditConfig())


# ── Review 2 Amendment 1: stronger rule-based attacker (S6) ────────────────────
LEET_SUBSETS = ({}, {'a': '@'}, {'e': '3'}, {'a': '@', 'e': '3'},
                {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'})
S6_SUFFIXES = ('', '!', '1', '123', '!1', '#', '@')


def _leet(word, mapping):
    return ''.join(mapping.get(c, mapping.get(c.lower(), c)) for c in word)


def _cases(word):
    return (word.lower(), word[:1].upper() + word[1:].lower(), word.upper())


def guesses_s6(profile, previous, budget=1000):
    """Deterministic rule-based attacker S6 (Review 2 Amendment 1). Never sees the target.

    Stronger than S1-S5 but written by the same authors as the synthetic fixture, so
    it is not an independent attacker. Tiers are tried in order; guesses are distinct.
    """
    if budget < 1:
        raise ValueError('Invalid budget')
    words = [str(profile.get(k, '')) for k in ('first_name', 'surname', 'city')]
    words = [w for w in words if w]
    year = str(profile.get('birth_year', '') or '')
    years = [y for y in (year, year[-2:]) if y]
    forms = []
    for w in words:
        for base in (w, w[:5], w[:4], w[:3], w[::-1]):
            if len(base) >= 3 and base not in forms:
                forms.append(base)
    variants = []
    for base in forms:
        for cased in _cases(base):
            for mapping in LEET_SUBSETS:
                v = _leet(cased, mapping)
                if v not in variants:
                    variants.append(v)
    join_parts = []
    for base in forms[:]:
        for cased in _cases(base)[:2]:
            for mapping in LEET_SUBSETS[:4]:
                v = _leet(cased, mapping)
                if v not in join_parts:
                    join_parts.append(v)
    join_parts += years

    def tiers():
        for word in COMMON:  # general knowledge, as S1's first tier
            for suffix in ('', '123!', '123', '1', '!'):
                yield word + suffix
        if previous:  # history
            yield previous
            for cased in (previous.lower(), previous.upper(), previous[:1].upper() + previous[1:]):
                yield cased
            for m in re.finditer(r'\d{4}', previous):
                for delta in (1, -1, 2, -2, 3, -3):
                    yield previous[:m.start()] + str(int(m.group()) + delta) + previous[m.end():]
            stem = previous.rstrip('!#@$0123456789')
            for suffix in S6_SUFFIXES + tuple(years) + tuple(y + '!' for y in years):
                yield previous + suffix
                yield stem + suffix
        for v in variants:  # single token with short suffixes and the birth year
            for suffix in S6_SUFFIXES + tuple(years) + tuple(y + '!' for y in years):
                yield v + suffix
        for a, b in itertools.permutations(join_parts, 2):  # two-token joins
            if a in years and b in years:
                continue
            for sep in ('', '-', '_', '.'):
                for suffix in ('', '!'):
                    yield a + sep + b + suffix
        for v in variants:  # numeric suffixes
            for n in itertools.chain(range(100), range(1950, 2031)):
                yield v + str(n)
                yield v + str(n) + '!'
        if previous:
            for n in range(10000):
                yield stem + str(n) + '!'

    seen = set()
    for item in tiers():
        if item not in seen:
            seen.add(item)
            yield item
            if len(seen) >= budget:
                return


def zxcvbn_meter_score(password, user_inputs=None):
    """Published meter baseline (Wheeler 2016): higher = riskier (negative log10 guesses)."""
    import zxcvbn
    return -float(zxcvbn.zxcvbn(password, user_inputs=list(user_inputs or []))['guesses_log10'])
