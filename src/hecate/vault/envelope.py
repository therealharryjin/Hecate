"""The on-disk vault envelope: key hierarchy and wrapping.

Layout
------
A random 256-bit **data-encryption key (DEK)** encrypts the entry payload. The
DEK itself is wrapped twice, under two independent paths:

    master password --Argon2id--> K_master --AES-GCM--> keyring{dek, totp_secret}
    recovery key    --HKDF-----> K_recovery --AES-GCM--> {dek}

Either path recovers the same DEK. That is what makes the recovery key work
without a server, and it is also why the recovery key must be treated as
equivalent in power to the master password.

Header binding
--------------
The plaintext header (format version, KDF cost parameters, salts) is fed into
every AES-GCM call as additional authenticated data. An attacker who edits the
stored Argon2 parameters -- say, dropping ``memory_cost`` to make cracking
cheap -- invalidates every tag in the file, so the downgrade is detected
instead of silently honoured.

On the TOTP secret
------------------
``totp_secret`` lives inside the keyring, which is unwrapped by the master
password alone. Verifying the code therefore happens *after* the password has
already done its work. This is an authorization gate, not a second
cryptographic factor: an attacker holding this file who cracks the master
password also recovers the TOTP secret. See the threat model in README.md.
"""

from __future__ import annotations

import base64
import dataclasses
import json
from typing import Any

from ..crypto import aead, kdf, rng

FORMAT = "hecate-vault"
VERSION = 1


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


@dataclasses.dataclass
class _Blob:
    nonce: bytes
    ciphertext: bytes

    def as_dict(self) -> dict[str, str]:
        return {"nonce": _b64e(self.nonce), "ciphertext": _b64e(self.ciphertext)}

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "_Blob":
        return cls(nonce=_b64d(data["nonce"]), ciphertext=_b64d(data["ciphertext"]))


@dataclasses.dataclass
class Keyring:
    """What the master password unwraps."""

    dek: bytes
    totp_secret: str | None


@dataclasses.dataclass
class Envelope:
    params: kdf.Argon2Params
    master_salt: bytes
    recovery_salt: bytes
    keyring: _Blob
    recovery: _Blob
    payload: _Blob

    # -- header / AAD ----------------------------------------------------

    def header(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "version": VERSION,
            "kdf": self.params.as_dict(),
            "master_salt": _b64e(self.master_salt),
            "recovery_salt": _b64e(self.recovery_salt),
        }

    def aad(self) -> bytes:
        """Canonical header bytes, bound into every ciphertext's GCM tag."""
        return json.dumps(
            self.header(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    # -- serialization ---------------------------------------------------

    def to_json(self) -> bytes:
        document = self.header()
        document["keyring"] = self.keyring.as_dict()
        document["recovery"] = self.recovery.as_dict()
        document["payload"] = self.payload.as_dict()
        return json.dumps(document, indent=2, sort_keys=True).encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> "Envelope":
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("vault file is not valid JSON") from exc
        if document.get("format") != FORMAT:
            raise ValueError(f"not a Hecate vault: {document.get('format')!r}")
        if document.get("version") != VERSION:
            raise ValueError(
                f"unsupported vault version {document.get('version')!r}; "
                f"this build understands version {VERSION}"
            )
        return cls(
            params=kdf.Argon2Params.from_dict(document["kdf"]),
            master_salt=_b64d(document["master_salt"]),
            recovery_salt=_b64d(document["recovery_salt"]),
            keyring=_Blob.from_dict(document["keyring"]),
            recovery=_Blob.from_dict(document["recovery"]),
            payload=_Blob.from_dict(document["payload"]),
        )


def create(
    password: bytes,
    payload: bytes,
    *,
    totp_secret: str | None = None,
    params: kdf.Argon2Params | None = None,
) -> tuple[Envelope, str]:
    """Build a fresh envelope. Returns ``(envelope, recovery_key_text)``.

    The recovery key text is the only time that secret exists in a
    human-readable form -- it is never written to disk by Hecate.
    """
    params = params or kdf.DEFAULT_ARGON2
    dek = rng.generate_data_key()
    recovery_secret = rng.generate_recovery_secret()

    envelope = Envelope(
        params=params,
        master_salt=rng.generate_salt(),
        recovery_salt=rng.generate_salt(),
        keyring=_Blob(b"", b""),
        recovery=_Blob(b"", b""),
        payload=_Blob(b"", b""),
    )
    aad = envelope.aad()

    k_master = kdf.derive_master_key(password, envelope.master_salt, params)
    keyring_plain = json.dumps(
        {"dek": _b64e(dek), "totp_secret": totp_secret}
    ).encode("utf-8")
    envelope.keyring = _Blob(*aead.encrypt(k_master, keyring_plain, aad))

    k_recovery = kdf.derive_recovery_key(recovery_secret, envelope.recovery_salt)
    recovery_plain = json.dumps({"dek": _b64e(dek)}).encode("utf-8")
    envelope.recovery = _Blob(*aead.encrypt(k_recovery, recovery_plain, aad))

    envelope.payload = _Blob(*aead.encrypt(dek, payload, aad))
    return envelope, rng.format_recovery_key(recovery_secret)


def unwrap_with_password(envelope: Envelope, password: bytes) -> Keyring:
    """Unwrap the keyring. Raises :class:`~hecate.crypto.aead.DecryptionError`."""
    k_master = kdf.derive_master_key(password, envelope.master_salt, envelope.params)
    plain = aead.decrypt(
        k_master, envelope.keyring.nonce, envelope.keyring.ciphertext, envelope.aad()
    )
    data = json.loads(plain.decode("utf-8"))
    return Keyring(dek=_b64d(data["dek"]), totp_secret=data.get("totp_secret"))


def unwrap_with_recovery_key(envelope: Envelope, recovery_key_text: str) -> bytes:
    """Recover the DEK using the printed recovery key. Returns the DEK."""
    secret = rng.parse_recovery_key(recovery_key_text)
    k_recovery = kdf.derive_recovery_key(secret, envelope.recovery_salt)
    plain = aead.decrypt(
        k_recovery, envelope.recovery.nonce, envelope.recovery.ciphertext, envelope.aad()
    )
    return _b64d(json.loads(plain.decode("utf-8"))["dek"])


def decrypt_payload(envelope: Envelope, dek: bytes) -> bytes:
    return aead.decrypt(
        dek, envelope.payload.nonce, envelope.payload.ciphertext, envelope.aad()
    )


def reseal_payload(envelope: Envelope, dek: bytes, payload: bytes) -> None:
    """Re-encrypt the payload in place under a fresh nonce."""
    envelope.payload = _Blob(*aead.encrypt(dek, payload, envelope.aad()))


def seal_keyring(
    envelope: Envelope, master_key: bytes, dek: bytes, totp_secret: str | None
) -> None:
    """Re-seal the keyring in place under ``master_key``.

    Used when enrolling or removing an authenticator, which changes the
    keyring's contents but not the DEK or the payload.
    """
    plain = json.dumps({"dek": _b64e(dek), "totp_secret": totp_secret}).encode("utf-8")
    envelope.keyring = _Blob(*aead.encrypt(master_key, plain, envelope.aad()))
