"""CSPRNG helpers and recovery-key encoding.

Everything random in Hecate originates here, and everything here comes from
``secrets`` (the OS CSPRNG). ``random`` is never imported anywhere in this
package -- it is a Mersenne Twister and is trivially predictable from a
handful of outputs.
"""

from __future__ import annotations

import base64
import secrets

KEY_SIZE = 32
SALT_SIZE = 16

#: 160 bits. Long enough that guessing is hopeless, short enough to write down.
RECOVERY_SECRET_SIZE = 20
_GROUP = 4


def random_bytes(count: int) -> bytes:
    return secrets.token_bytes(count)


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE)


def generate_data_key() -> bytes:
    """Generate the vault's data-encryption key (DEK)."""
    return secrets.token_bytes(KEY_SIZE)


def generate_recovery_secret() -> bytes:
    return secrets.token_bytes(RECOVERY_SECRET_SIZE)


def format_recovery_key(secret: bytes) -> str:
    """Render the recovery secret as grouped base32, e.g. ``ABCD-EFGH-...``.

    Base32 avoids the 0/O and 1/l confusions of base64 when a human is
    copying the key onto paper.
    """
    text = base64.b32encode(secret).decode("ascii").rstrip("=")
    return "-".join(text[i : i + _GROUP] for i in range(0, len(text), _GROUP))


def parse_recovery_key(text: str) -> bytes:
    """Parse a user-typed recovery key. Tolerates case, spaces and dashes."""
    cleaned = "".join(text.split()).replace("-", "").upper()
    padding = "=" * (-len(cleaned) % 8)
    try:
        secret = base64.b32decode(cleaned + padding, casefold=True)
    except Exception as exc:  # noqa: BLE001 - surfaced as a clean ValueError
        raise ValueError("recovery key is not valid base32") from exc
    if len(secret) != RECOVERY_SECRET_SIZE:
        raise ValueError(
            f"recovery key must decode to {RECOVERY_SECRET_SIZE} bytes, "
            f"got {len(secret)}"
        )
    return secret
