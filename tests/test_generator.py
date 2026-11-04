"""Password and passphrase generation: shape, settings, and honest entropy."""

import hashlib
import itertools
import math
import pathlib
import re
import string

import pytest

from hecate.generator import passphrase as passphrase_mod
from hecate.generator import password as password_mod
from hecate.generator import (
    Generated,
    PassphrasePolicy,
    PasswordPolicy,
    generate_passphrase,
    generate_password,
    passphrase_entropy,
    password_entropy,
)

SAMPLES = 200


# --- passwords ------------------------------------------------------------


def test_default_password_shape():
    result = generate_password(PasswordPolicy())
    assert len(result.value) == 20
    assert result.kind == "password"
    alphabet = set(string.ascii_letters + string.digits + password_mod.DEFAULT_SYMBOLS)
    assert set(result.value) <= alphabet


def test_every_enabled_kind_appears_in_every_password():
    pools = [
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
        password_mod.DEFAULT_SYMBOLS,
    ]
    for _ in range(SAMPLES):
        value = generate_password(PasswordPolicy(length=8)).value
        for pool in pools:
            assert any(char in pool for char in value), value


def test_disabled_kinds_never_appear():
    policy = PasswordPolicy(uppercase=False, digits=False, symbols="")
    for _ in range(SAMPLES):
        assert re.fullmatch(r"[a-z]{20}", generate_password(policy).value)


def test_only_the_chosen_symbols_are_used():
    policy = PasswordPolicy(symbols="@!")
    for _ in range(SAMPLES):
        specials = {c for c in generate_password(policy).value if not c.isalnum()}
        assert specials and specials <= {"@", "!"}


@pytest.mark.parametrize("length", [password_mod.MIN_LENGTH, 33, password_mod.MAX_LENGTH])
def test_length_is_respected(length):
    assert len(generate_password(PasswordPolicy(length=length)).value) == length


@pytest.mark.parametrize("length", [password_mod.MIN_LENGTH - 1, password_mod.MAX_LENGTH + 1])
def test_length_out_of_range_is_refused(length):
    with pytest.raises(ValueError, match="between"):
        generate_password(PasswordPolicy(length=length))


def test_nothing_to_choose_from_is_refused():
    policy = PasswordPolicy(uppercase=False, lowercase=False, digits=False, symbols="")
    with pytest.raises(ValueError, match="no characters"):
        generate_password(policy)


def test_parse_symbols_drops_repeats_so_none_is_favoured():
    assert password_mod.parse_symbols("!!@!#@") == "!@#"
    assert password_mod.parse_symbols("") == ""


@pytest.mark.parametrize("bad", ["a", "7", " ", "\t", "é", "!@ #"])
def test_parse_symbols_refuses_letters_digits_space_and_non_ascii(bad):
    with pytest.raises(ValueError):
        password_mod.parse_symbols(bad)


def test_count_matches_brute_force():
    """Check the inclusion-exclusion count against direct enumeration."""
    pools = ["ab", "XYZ", "1"]
    alphabet = "".join(pools)
    for length in range(1, 6):
        brute = sum(
            1
            for chars in itertools.product(alphabet, repeat=length)
            if all(any(c in pool for c in chars) for pool in pools)
        )
        assert password_mod.count_passwords([len(p) for p in pools], length) == brute


def test_single_kind_entropy_is_length_times_log2_alphabet():
    policy = PasswordPolicy(length=10, uppercase=False, lowercase=False, symbols="")
    assert password_entropy(policy) == pytest.approx(10 * math.log2(10))


def test_requiring_every_kind_costs_a_little_entropy():
    full = len(string.ascii_letters + string.digits + password_mod.DEFAULT_SYMBOLS)
    bits = password_entropy(PasswordPolicy())
    assert 20 * math.log2(full) - 1 < bits < 20 * math.log2(full)


# --- passphrases ----------------------------------------------------------


def test_wordlist_is_the_eff_large_list_without_hyphenated_words():
    words = passphrase_mod.wordlist()
    assert len(words) == 7772  # 7,776 in the EFF list, minus 4 with hyphens
    assert len(set(words)) == len(words)
    assert all(re.fullmatch(r"[a-z]+", word) for word in words)
    assert "t-shirt" not in words
    digest = hashlib.sha256("\n".join(words).encode()).hexdigest()
    assert digest == "76e3348ad957cad7d9c5c68873e89410ed998c19f4956367ab52d9aec4eee884"


def test_default_passphrase_shape():
    result = generate_passphrase(PassphrasePolicy())
    parts = result.value.split("-")
    assert len(parts) == 6
    assert all(part in passphrase_mod.wordlist() for part in parts)
    assert result.kind == "passphrase"


@pytest.mark.parametrize("separator", [" ", "_", "", ".:", "+++++"])
def test_custom_separator(separator):
    policy = PassphrasePolicy(words=4, separator=separator)
    value = generate_passphrase(policy).value
    if separator:
        assert value.count(separator) >= 3
    else:
        assert re.fullmatch(r"[a-z]+", value)


def test_capitalize():
    value = generate_passphrase(PassphrasePolicy(capitalize=True)).value
    assert all(word[0].isupper() and word[1:].islower() for word in value.split("-"))


def test_number_adds_exactly_one_digit_to_one_word():
    for _ in range(SAMPLES):
        parts = generate_passphrase(PassphrasePolicy(number=True)).value.split("-")
        digits = [p for p in parts if p[-1].isdigit()]
        assert len(digits) == 1
        assert digits[0][:-1] in passphrase_mod.wordlist()


@pytest.mark.parametrize("words", [passphrase_mod.MIN_WORDS - 1, passphrase_mod.MAX_WORDS + 1])
def test_word_count_out_of_range_is_refused(words):
    with pytest.raises(ValueError, match="between"):
        generate_passphrase(PassphrasePolicy(words=words))


@pytest.mark.parametrize("bad", ["a", "1", "------", "\t", "é"])
def test_bad_separator_is_refused(bad):
    with pytest.raises(ValueError):
        passphrase_mod.parse_separator(bad)


def test_passphrase_entropy():
    per_word = math.log2(7772)
    assert passphrase_entropy(PassphrasePolicy()) == pytest.approx(6 * per_word)
    assert passphrase_entropy(PassphrasePolicy(capitalize=True)) == pytest.approx(6 * per_word)
    assert passphrase_entropy(PassphrasePolicy(number=True)) == pytest.approx(
        6 * per_word + math.log2(60)
    )


# --- hygiene --------------------------------------------------------------


def test_generated_repr_hides_the_secret():
    result = Generated("hunter2-secret", 42.0, "password")
    assert "hunter2-secret" not in repr(result)


def test_random_module_is_never_imported():
    """Mersenne Twister is predictable; every draw must come from secrets."""
    src = pathlib.Path(passphrase_mod.__file__).resolve().parents[1]
    pattern = re.compile(r"^\s*(import random\b|from random\b)", re.MULTILINE)
    offenders = [p.name for p in src.rglob("*.py") if pattern.search(p.read_text())]
    assert offenders == []
