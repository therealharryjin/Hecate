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
    envelope.keyring = _Blob(
        *aead.encrypt(k_master, _keyring_plaintext(dek, totp_secret), aad)
    )

    k_recovery = kdf.derive_recovery_key(recovery_secret, envelope.recovery_salt)
    envelope.recovery = _Blob(*aead.encrypt(k_recovery, _recovery_plaintext(dek), aad))

    envelope.payload = _Blob(*aead.encrypt(dek, payload, aad))
    return envelope, rng.format_recovery_key(recovery_secret)


def _keyring_plaintext(dek: bytes, totp_secret: str | None) -> bytes:
    return json.dumps({"dek": _b64e(dek), "totp_secret": totp_secret}).encode("utf-8")


def _recovery_plaintext(dek: bytes) -> bytes:
    return json.dumps({"dek": _b64e(dek)}).encode("utf-8")


def unwrap_with_password(envelope: Envelope, password: bytes) -> Keyring:
    """Unwrap the keyring. Raises :class:`~hecate.crypto.aead.DecryptionError`."""
    k_master = kdf.derive_master_key(password, envelope.master_salt, envelope.params)
    return open_keyring(envelope, k_master)


def open_keyring(envelope: Envelope, master_key: bytes) -> Keyring:
    """Unwrap the keyring with an already derived ``K_master``.

    Raises :class:`~hecate.crypto.aead.DecryptionError` for the wrong key.
    """
    plain = aead.decrypt(
        master_key, envelope.keyring.nonce, envelope.keyring.ciphertext, envelope.aad()
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
    keyring's contents, and when changing the master password, which changes
    the key it is sealed under. Neither touches the DEK, the header or the
    other two ciphertexts.
    """
    envelope.keyring = _Blob(
        *aead.encrypt(master_key, _keyring_plaintext(dek, totp_secret), envelope.aad())
    )


def rekey_with_recovery_key(
    envelope: Envelope,
    recovery_key_text: str,
    password: bytes,
    totp_secret: str | None,
) -> tuple[Envelope, bytes, bytes]:
    """Put the vault under a new master password and authenticator.

    Authorised by the recovery key alone, for when the authenticator is lost,
    the master password is forgotten, or both. Returns ``(new_envelope, dek,
    master_key)``. ``envelope`` is not modified, so a failure part-way leaves
    the caller holding the old vault, which still opens as before.

    Raises :class:`~hecate.crypto.aead.DecryptionError` if the key does not
    open this vault, and ``ValueError`` if it is malformed.

    The DEK is taken from the recovery wrap, never accepted from the caller.
    Re-wrapping a *different* key under the recovery key would break the
    recovery key silently, so that is made impossible rather than checked.

    The master salt is regenerated, so one Argon2id guess cannot be tested
    against an old copy of the file and the new one at once. The salt is part
    of the header, which is every ciphertext's AAD, so all three blobs are
    re-sealed. The DEK, recovery key, recovery salt and KDF parameters do not
    change: the recovery key keeps working afterwards.
    """
    dek = unwrap_with_recovery_key(envelope, recovery_key_text)
    payload = decrypt_payload(envelope, dek)
    recovery_secret = rng.parse_recovery_key(recovery_key_text)

    rekeyed = dataclasses.replace(envelope, master_salt=rng.generate_salt())
    aad = rekeyed.aad()

    master_key = kdf.derive_master_key(password, rekeyed.master_salt, rekeyed.params)
    rekeyed.keyring = _Blob(
        *aead.encrypt(master_key, _keyring_plaintext(dek, totp_secret), aad)
    )

    k_recovery = kdf.derive_recovery_key(recovery_secret, rekeyed.recovery_salt)
    rekeyed.recovery = _Blob(*aead.encrypt(k_recovery, _recovery_plaintext(dek), aad))

    rekeyed.payload = _Blob(*aead.encrypt(dek, payload, aad))
    return rekeyed, dek, master_key
