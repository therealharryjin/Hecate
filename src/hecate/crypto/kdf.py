"""Key derivation for Hecate.

Every primitive here comes from an audited library. Nothing in this module
implements a cryptographic primitive by hand:

  * Argon2id -> ``argon2-cffi`` (``argon2.low_level.hash_secret_raw``)
  * HKDF     -> ``cryptography`` (``...kdf.hkdf.HKDF``)

Two different KDFs are used on purpose, for two different kinds of input:

  * The **master password** is low-entropy and attacker-guessable, so it goes
    through Argon2id, which is deliberately slow and memory-hard.
  * The **recovery key** is 160 bits of CSPRNG output. It is already uniformly
    random, so stretching it would buy nothing; HKDF is the correct tool for
    deriving a key from an existing high-entropy secret.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from argon2.low_level import Type as _Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_SIZE = 32  # AES-256
SALT_SIZE = 16

_RECOVERY_HKDF_INFO = b"hecate/recovery-key/v1"


@dataclasses.dataclass(frozen=True)
class Argon2Params:
    """Argon2id cost parameters, persisted in the vault header."""

    time_cost: int
    memory_cost: int  # KiB
    parallelism: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "algorithm": "argon2id",
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Argon2Params":
        algorithm = data.get("algorithm")
        if algorithm != "argon2id":
            raise ValueError(f"unsupported KDF algorithm: {algorithm!r}")
        return cls(
            time_cost=int(data["time_cost"]),
            memory_cost=int(data["memory_cost"]),
            parallelism=int(data["parallelism"]),
        )


#: Production defaults: ~256 MiB of memory makes GPU/ASIC cracking expensive.
DEFAULT_ARGON2 = Argon2Params(time_cost=3, memory_cost=256 * 1024, parallelism=4)

#: Deliberately weak parameters so the test suite stays fast.
#: NEVER use these for a real vault.
FAST_ARGON2_FOR_TESTS = Argon2Params(time_cost=1, memory_cost=8 * 1024, parallelism=1)


def derive_master_key(password: bytes, salt: bytes, params: Argon2Params) -> bytes:
    """Stretch the master password into a 256-bit key using Argon2id."""
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes; encode it before calling")
    if len(salt) < SALT_SIZE:
        raise ValueError(f"salt must be at least {SALT_SIZE} bytes")
    return hash_secret_raw(
        secret=bytes(password),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_SIZE,
        type=_Argon2Type.ID,
    )


def derive_recovery_key(recovery_secret: bytes, salt: bytes) -> bytes:
    """Derive a 256-bit key from the high-entropy recovery secret via HKDF."""
    if len(salt) < SALT_SIZE:
        raise ValueError(f"salt must be at least {SALT_SIZE} bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=_RECOVERY_HKDF_INFO,
    ).derive(recovery_secret)
