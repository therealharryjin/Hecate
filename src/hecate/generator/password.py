"""Passwords made of random characters.

Every character is drawn uniformly from the enabled kinds of character with the
OS CSPRNG. Each enabled kind is guaranteed to appear at least once, because many
sites insist on it. That guarantee comes from rejection sampling: draw a whole
password, and if a kind is missing, throw it away and draw again. Every
acceptable password stays equally likely. Patching a missing character into a
random position instead would be faster, but it would skew the distribution.

The entropy reported is exact for that distribution: log2 of the number of
passwords that could have come out, counted by inclusion-exclusion over the
kinds that must appear.
"""

from __future__ import annotations

import dataclasses
import math
import string
from itertools import combinations

from ..crypto import rng
from .result import Generated

UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits
#: Accepted by most sites, and none of them is whitespace, a quote or a
#: backslash, so the password copies and pastes as one clean token.
DEFAULT_SYMBOLS = "!#$%&*+-.:=?@^_~"

MIN_LENGTH = 8
MAX_LENGTH = 128
DEFAULT_LENGTH = 20


def parse_symbols(raw: str) -> str:
    """Validate a set of special characters. Returns it with repeats removed.

    Repeats are dropped, not kept: a character listed twice would be drawn
    twice as often as the others. Whitespace is refused so a password always
    copies and pastes as one unbroken token, and letters and digits are refused
    because they have settings of their own. An empty string means "none".
    """
    unique: list[str] = []
    for char in raw:
        if not 33 <= ord(char) <= 126:
            raise ValueError(
                f"special characters must be printable ASCII with no spaces; {char!r} is not"
            )
        if char.isalnum():
            raise ValueError(f"{char!r} is a letter or digit, not a special character")
        if char not in unique:
            unique.append(char)
    return "".join(unique)


@dataclasses.dataclass(frozen=True)
class PasswordPolicy:
    length: int = DEFAULT_LENGTH
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: str = DEFAULT_SYMBOLS

    def pools(self) -> list[str]:
        """The enabled kinds of character, checked. They never overlap."""
        if not MIN_LENGTH <= self.length <= MAX_LENGTH:
            raise ValueError(
                f"password length must be between {MIN_LENGTH} and {MAX_LENGTH}, "
                f"got {self.length}"
            )
        pools = [
            pool
            for enabled, pool in (
                (self.uppercase, UPPERCASE),
                (self.lowercase, LOWERCASE),
                (self.digits, DIGITS),
                (True, parse_symbols(self.symbols)),
            )
            if enabled and pool
        ]
        if not pools:
            raise ValueError(
                "no characters to choose from: turn on at least one of uppercase, "
                "lowercase, digits or symbols"
            )
        return pools


def count_passwords(pool_sizes: list[int], length: int) -> int:
    """How many strings of ``length`` use every pool at least once.

    Inclusion-exclusion: all strings over the full alphabet, minus those that
    miss some pool, plus those that miss two, and so on. The pools must not
    overlap, which :meth:`PasswordPolicy.pools` guarantees.
    """
    total = sum(pool_sizes)
    count = 0
    for missing in range(len(pool_sizes) + 1):
        for left_out in combinations(pool_sizes, missing):
            count += (-1) ** missing * (total - sum(left_out)) ** length
    return count


def password_entropy(policy: PasswordPolicy) -> float:
    sizes = [len(pool) for pool in policy.pools()]
    return math.log2(count_passwords(sizes, policy.length))


def generate_password(policy: PasswordPolicy) -> Generated:
    pools = policy.pools()
    alphabet = "".join(pools)
    while True:
        candidate = "".join(rng.choice(alphabet) for _ in range(policy.length))
        if all(any(char in pool for char in candidate) for pool in pools):
            return Generated(candidate, password_entropy(policy), "password")
