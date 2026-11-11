"""Review 2 Amendment 1: S6 attacker and zxcvbn meter baselines."""
import inspect

from vault.research import guesses_s6, zxcvbn_meter_score

PROFILE = dict(first_name='Fictional', surname='Person', city='Nowhere', birth_year=1990)


def test_s6_never_receives_the_target():
    assert 'password' not in inspect.signature(guesses_s6).parameters


def test_s6_guesses_are_distinct_and_budget_prefix_consistent():
    small = list(guesses_s6(PROFILE, 'Orbit2024!', 500))
    large = list(guesses_s6(PROFILE, 'Orbit2024!', 5000))
    assert len(small) == len(set(small)) == 500
    assert large[:500] == small


def test_s6_covers_documented_mutations():
    stream = set(guesses_s6(PROFILE, 'Orbit2024!', 100000))
    for expected in ('Orbit2025!', 'Fictional1990', 'F1c710n@l!', 'Fict-1990!', '1990_Fictional', 'Nowhere90!'):
        assert expected in stream, expected


def test_meter_score_uses_user_inputs():
    plain = zxcvbn_meter_score('Fictional1990!')
    contextual = zxcvbn_meter_score('Fictional1990!', ['Fictional', '1990'])
    assert contextual > plain  # fewer estimated guesses once the name is known
