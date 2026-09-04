"""High-level vault lifecycle: create, unlock, mutate, save.

The unlock flow is deliberately two-stage so the CLI can prompt for the master
password, and only then for the authenticator code, without paying the
Argon2id cost twice:

    pending = vault.verify_password(password)   # stage 1: Argon2id + unwrap
    vault.complete_unlock(pending, code)        # stage 2: TOTP gate

Stage 1 already holds the DEK in memory. That is inherent to this design, not
an oversight -- see the "authorization gate, not a cryptographic factor" note
in README.md's threat model.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from ..auth import totp as totp_auth
from ..crypto import kdf
from ..crypto.aead import DecryptionError
from . import envelope as env_mod
from . import storage
from .model import Entry, VaultData


class VaultError(Exception):
    """Base class for vault-level failures."""


class VaultLockedError(VaultError):
    pass


class InvalidTotpCodeError(VaultError):
    """The master password was correct but the authenticator code was not."""


@dataclasses.dataclass
class PendingUnlock:
    """Stage-1 result. The master password was correct.

    Carrying this value around means carrying the DEK, so callers should not
    persist it beyond the unlock prompt.
    """

    keyring: env_mod.Keyring
    master_key: bytes

    @property
    def requires_totp(self) -> bool:
        return self.keyring.totp_secret is not None


class Vault:
    def __init__(self, path: Path, envelope: env_mod.Envelope) -> None:
        self.path = Path(path)
        self._envelope = envelope
        self._dek: bytes | None = None
        self._master_key: bytes | None = None
        self._data: VaultData | None = None

    # -- construction ----------------------------------------------------

    @classmethod
    def create(
        cls,
        path: Path,
        password: bytes,
        *,
        totp_secret: str | None = None,
        params: kdf.Argon2Params | None = None,
    ) -> tuple["Vault", str]:
        """Initialise a new vault. Returns ``(vault, recovery_key_text)``.

        The recovery key is returned, never stored. If the caller loses it,
        Hecate cannot reproduce it.
        """
        path = Path(path)
        if path.exists():
            raise VaultError(f"vault already exists at {path}")
        envelope, recovery_key = env_mod.create(
            password, VaultData().serialize(), totp_secret=totp_secret, params=params
        )
        storage.write_atomic(path, envelope.to_json())
        return cls(path, envelope), recovery_key

    @classmethod
    def load(cls, path: Path) -> "Vault":
        """Read a vault from disk without decrypting anything."""
        path = Path(path)
        if not path.exists():
            raise VaultError(f"no vault at {path}")
        return cls(path, env_mod.Envelope.from_json(storage.read(path)))

    # -- unlocking -------------------------------------------------------

    def verify_password(self, password: bytes) -> PendingUnlock:
        """Stage 1. Raises :class:`DecryptionError` if the password is wrong."""
        keyring = env_mod.unwrap_with_password(self._envelope, password)
        master_key = kdf.derive_master_key(
            password, self._envelope.master_salt, self._envelope.params
        )
        return PendingUnlock(keyring=keyring, master_key=master_key)

    def complete_unlock(self, pending: PendingUnlock, code: str | None = None) -> None:
        """Stage 2. Enforces the TOTP gate, then opens the vault."""
        secret = pending.keyring.totp_secret
        if secret is not None:
            if code is None:
                raise InvalidTotpCodeError("an authenticator code is required")
            if not totp_auth.verify(secret, code):
                raise InvalidTotpCodeError("authenticator code is incorrect or expired")
        self._dek = pending.keyring.dek
        self._master_key = pending.master_key
        self._data = VaultData.deserialize(
            env_mod.decrypt_payload(self._envelope, self._dek)
        )

    def unlock_with_recovery_key(self, recovery_key_text: str) -> None:
        """Bypass both factors using the printed recovery key.

        This intentionally skips TOTP: the recovery key exists precisely for
        the case where the authenticator device is gone.
        """
        self._dek = env_mod.unwrap_with_recovery_key(self._envelope, recovery_key_text)
        self._master_key = None
        self._data = VaultData.deserialize(
            env_mod.decrypt_payload(self._envelope, self._dek)
        )

    def lock(self) -> None:
        """Drop key material and plaintext from this object."""
        self._dek = None
        self._master_key = None
        self._data = None

    @property
    def is_unlocked(self) -> bool:
        return self._dek is not None

    # -- contents --------------------------------------------------------

    @property
    def data(self) -> VaultData:
        if self._data is None:
            raise VaultLockedError("vault is locked")
        return self._data

    def add(self, entry: Entry) -> None:
        self.data.entries.append(entry)

    def remove(self, entry: Entry) -> None:
        self.data.entries.remove(entry)

    # -- TOTP enrollment -------------------------------------------------

    def enroll_totp(self, secret: str) -> None:
        """Attach an authenticator secret to this vault, or replace one.

        Requires an unlock that went through the master password, because the
        keyring must be re-sealed under the master key.
        """
        if not self.is_unlocked:
            raise VaultLockedError("vault is locked")
        if self._master_key is None:
            raise VaultError(
                "enrolling an authenticator requires unlocking with the master "
                "password, not the recovery key"
            )
        self._reseal_keyring(totp_secret=secret)

    def disable_totp(self) -> None:
        if not self.is_unlocked:
            raise VaultLockedError("vault is locked")
        if self._master_key is None:
            raise VaultError("disabling the authenticator requires the master password")
        self._reseal_keyring(totp_secret=None)

    def _reseal_keyring(self, *, totp_secret: str | None) -> None:
        assert self._dek is not None and self._master_key is not None
        env_mod.seal_keyring(
            self._envelope, self._master_key, self._dek, totp_secret
        )

    # -- persistence -----------------------------------------------------

    def save(self) -> None:
        if self._dek is None or self._data is None:
            raise VaultLockedError("vault is locked")
        env_mod.reseal_payload(self._envelope, self._dek, self._data.serialize())
        storage.write_atomic(self.path, self._envelope.to_json())


__all__ = [
    "Vault",
    "VaultError",
    "VaultLockedError",
    "InvalidTotpCodeError",
    "PendingUnlock",
    "DecryptionError",
]
