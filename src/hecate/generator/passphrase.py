"""Passphrases made of random words.

Words come from the EFF large wordlist (https://www.eff.org/dice), shipped
unmodified beside this module. The four hyphenated words in it are skipped when
it is loaded, so a ``-`` separator never makes a passphrase ambiguous, which
leaves 7,772 words: about 12.9 bits per word.

Words are drawn uniformly, with replacement, with the OS CSPRNG -- the same
thing as rolling five dice per word, minus the dice.
"""

from __future__ import annotations

import dataclasses
import functools
import math
from importlib import resources

from ..crypto import rng
from .result import Generated

WORDLIST_FILE = "eff_large_wordlist.txt"

MIN_WORDS = 4
MAX_WORDS = 20
DEFAULT_WORDS = 6
DEFAULT_SEPARATOR = "-"
MAX_SEPARATOR_LENGTH = 5


@functools.cache
def wordlist() -> tuple[str, ...]:
    """The usable words, in list order. Raises if the file is not as shipped."""
    text = resources.files(__package__).joinpath(WORDLIST_FILE).read_text("ascii")
    words = []
    for line in text.splitlines():
        _dice, word = line.split("\t")
        if word.isalpha():
            words.append(word)
    if len(set(words)) != len(words):
        raise ValueError(f"{WORDLIST_FILE} contains repeated words")
    return tuple(words)


def parse_separator(raw: str) -> str:
    """Validate what goes between words.

    Letters and digits are refused: they would blur where one word ends and the
    next begins, and a digit would also be confused with the optional number.
    """
    if len(raw) > MAX_SEPARATOR_LENGTH:
        raise ValueError(
            f"separator can be at most {MAX_SEPARATOR_LENGTH} characters, got {len(raw)}"
        )
    for char in raw:
        if not 32 <= ord(char) <= 126:
            raise ValueError(
                f"separator must be spaces or printable ASCII punctuation; {char!r} is not"
            )
        if char.isalnum():
            raise ValueError(
                f"separator cannot contain letters or digits, got {char!r}"
            )
    return raw


@dataclasses.dataclass(frozen=True)
class PassphrasePolicy:
    words: int = DEFAULT_WORDS
    separator: str = DEFAULT_SEPARATOR
    capitalize: bool = False
    number: bool = False

    def check(self) -> None:
        if not MIN_WORDS <= self.words <= MAX_WORDS:
            raise ValueError(
                f"passphrase must have between {MIN_WORDS} and {MAX_WORDS} words, "
                f"got {self.words}"
            )
        parse_separator(self.separator)


def passphrase_entropy(policy: PassphrasePolicy, words: tuple[str, ...] | None = None) -> float:
    """Bits of entropy for these settings.

    Capitalising adds nothing -- it is applied to every word, so it is not a
    choice. The optional number adds log2(10 x word count): which digit, and
    which word it is attached to.
    """
    policy.check()
    bits = policy.words * math.log2(len(words or wordlist()))
    if policy.number:
        bits += math.log2(10 * policy.words)
    return bits


def generate_passphrase(
    policy: PassphrasePolicy, words: tuple[str, ...] | None = None
) -> Generated:
    policy.check()
    pool = words or wordlist()
    chosen = [rng.choice(pool) for _ in range(policy.words)]
    if policy.capitalize:
        chosen = [word.capitalize() for word in chosen]
    if policy.number:
        chosen[rng.below(policy.words)] += str(rng.below(10))
    return Generated(
        policy.separator.join(chosen), passphrase_entropy(policy, pool), "passphrase"
    )
