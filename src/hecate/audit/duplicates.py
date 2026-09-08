"""Password-reuse detection over an unlocked vault.

Entry passwords are not hashed. A password manager has to hand them back, so
they are encrypted under the DEK and arrive here as plaintext -- finding
duplicates is a plain comparison, not a cryptographic problem.

The comparison still runs through a keyed hash under a per-call pepper. That is
hygiene, not a security boundary: the plaintext is already in this process, so
none of it defends against an attacker who can read our memory. What it buys is
that raw secrets never become dict keys, never land in a traceback repr, and
never leak a prefix length through an early-exiting ``==``.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable

from ..crypto import rng
from ..vault.model import Entry

_PEPPER_SIZE = 32
_DIGEST_SIZE = 16


def _fingerprint(password: str, pepper: bytes) -> bytes:
    return hashlib.blake2b(
        password.encode("utf-8"), key=pepper, digest_size=_DIGEST_SIZE
    ).digest()


def entries_sharing_password(
    entries: Iterable[Entry],
    password: str,
    *,
    exclude: Entry | None = None,
) -> list[Entry]:
    """Return the entries already using ``password``, in vault order.

    Matching is exact. ``Password1`` and ``password1`` are different secrets,
    and folding case here would both report false duplicates and teach the user
    that near-misses are the same password.

    An empty password is never a duplicate -- entries with no password set are
    not all secretly sharing one. ``exclude`` skips a single entry by identity,
    so ``edit`` does not report an entry as a duplicate of itself.

    Password history is deliberately not searched. "Two live logins share a
    secret" and "I rotated back to an old password" are different questions.
    """
    if not password:
        return []
    pepper = rng.random_bytes(_PEPPER_SIZE)
    target = _fingerprint(password, pepper)
    return [
        entry
        for entry in entries
        if entry is not exclude
        and entry.password
        and hmac.compare_digest(_fingerprint(entry.password, pepper), target)
    ]


__all__ = ["entries_sharing_password"]
