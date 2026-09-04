"""AES-256-GCM authenticated encryption.

Thin, deliberately boring wrapper over ``cryptography``'s ``AESGCM``. There is
no unauthenticated code path: every ciphertext Hecate writes carries a GCM
authentication tag, and every decrypt verifies it.
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96 bits, the size GCM is designed around
KEY_SIZE = 32


class DecryptionError(Exception):
    """Raised when a ciphertext fails to authenticate.

    This is intentionally a single error type. The caller cannot distinguish
    "wrong key" from "tampered ciphertext", because leaking that distinction
    would tell an attacker whether a guessed password was correct.
    """


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt ``plaintext``, binding ``aad`` into the authentication tag.

    Returns ``(nonce, ciphertext)``. The nonce is freshly generated from the
    OS CSPRNG on every call -- GCM nonce reuse under the same key is
    catastrophic, so a nonce is never accepted from the caller.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    nonce = secrets.token_bytes(NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt and verify. Raises :class:`DecryptionError` on any failure."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("vault authentication failed") from exc
