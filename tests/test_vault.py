"""Vault-level tests: round-trips, tamper detection, and the TOTP gate."""

import json
import os
import time

import pytest

from hecate.auth import totp as totp_auth
from hecate.crypto import kdf
from hecate.crypto.aead import DecryptionError
from hecate.vault import envelope as env_mod
from hecate.vault import storage
from hecate.vault.model import Entry, VaultData
from hecate.vault.vault import InvalidTotpCodeError, Vault, VaultError, VaultLockedError

PASSWORD = b"correct horse battery staple"
FAST = kdf.FAST_ARGON2_FOR_TESTS


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "vault.hecate"


def _open(path, password=PASSWORD, code=None):
    vault = Vault.load(path)
    vault.complete_unlock(vault.verify_password(password), code)
    return vault


# --- round trips ----------------------------------------------------------


def test_create_and_reopen_round_trip(vault_path):
    vault, _recovery = Vault.create(vault_path, PASSWORD, params=FAST)
    vault.complete_unlock(vault.verify_password(PASSWORD))
    vault.add(Entry(title="github", username="harry", password="hunter2"))
    vault.save()

    reopened = _open(vault_path)
    entry = reopened.data.find("github")
    assert entry is not None
    assert entry.username == "harry"
    assert entry.password == "hunter2"


def test_vault_file_contains_no_plaintext(vault_path):
    vault, _ = Vault.create(vault_path, PASSWORD, params=FAST)
    vault.complete_unlock(vault.verify_password(PASSWORD))
    vault.add(Entry(title="github", username="harry", password="hunter2"))
    vault.save()

    raw = vault_path.read_bytes()
    for secret in (b"hunter2", b"harry", b"github", PASSWORD):
        assert secret not in raw


def test_wrong_password_fails_to_decrypt(vault_path):
    Vault.create(vault_path, PASSWORD, params=FAST)
    vault = Vault.load(vault_path)
    with pytest.raises(DecryptionError):
        vault.verify_password(b"wrong password")


def test_password_history_is_retained(vault_path):
    vault, _ = Vault.create(vault_path, PASSWORD, params=FAST)
    vault.complete_unlock(vault.verify_password(PASSWORD))
    entry = Entry(title="github", password="old")
    vault.add(entry)
    entry.set_password("new")
    vault.save()

    entry = _open(vault_path).data.find("github")
    assert entry.password == "new"
    assert [h.password for h in entry.password_history] == ["old"]


# --- tamper detection -----------------------------------------------------


def test_tampered_payload_fails_to_decrypt(vault_path):
    vault, _ = Vault.create(vault_path, PASSWORD, params=FAST)
    vault.complete_unlock(vault.verify_password(PASSWORD))
    vault.add(Entry(title="github", password="hunter2"))
    vault.save()

    document = json.loads(vault_path.read_text())
    ciphertext = bytearray(
        __import__("base64").b64decode(document["payload"]["ciphertext"])
    )
    ciphertext[0] ^= 0x01
    document["payload"]["ciphertext"] = (
        __import__("base64").b64encode(bytes(ciphertext)).decode()
    )
    vault_path.write_text(json.dumps(document))

    reloaded = Vault.load(vault_path)
    pending = reloaded.verify_password(PASSWORD)
    with pytest.raises(DecryptionError):
        reloaded.complete_unlock(pending)


def test_kdf_parameter_downgrade_is_detected(vault_path):
    """Weakening the stored Argon2 cost must invalidate the GCM tags.

    Without header-as-AAD binding, an attacker could rewrite memory_cost to
    something trivial and make offline cracking cheap.
    """
    Vault.create(vault_path, PASSWORD, params=FAST)
    document = json.loads(vault_path.read_text())
    document["kdf"]["memory_cost"] = 8
    vault_path.write_text(json.dumps(document))

    vault = Vault.load(vault_path)
    with pytest.raises(DecryptionError):
        vault.verify_password(PASSWORD)


# --- the TOTP gate --------------------------------------------------------


def test_unlock_requires_totp_code_when_enrolled(vault_path):
    secret = totp_auth.generate_secret()
    Vault.create(vault_path, PASSWORD, totp_secret=secret, params=FAST)

    vault = Vault.load(vault_path)
    pending = vault.verify_password(PASSWORD)
    assert pending.requires_totp
    with pytest.raises(InvalidTotpCodeError):
        vault.complete_unlock(pending, code=None)


def test_unlock_rejects_stale_totp_code_with_correct_password(vault_path):
    """The test you asked for: right password, expired code -> no unlock.

    The code is generated for a moment well outside the drift window, so it
    was valid once and is not any more.
    """
    secret = totp_auth.generate_secret()
    Vault.create(vault_path, PASSWORD, totp_secret=secret, params=FAST)

    stale_code = totp_auth.current_code(secret, at=int(time.time()) - 300)

    vault = Vault.load(vault_path)
    pending = vault.verify_password(PASSWORD)
    with pytest.raises(InvalidTotpCodeError):
        vault.complete_unlock(pending, code=stale_code)
    assert not vault.is_unlocked


def test_unlock_rejects_incorrect_totp_code(vault_path):
    secret = totp_auth.generate_secret()
    Vault.create(vault_path, PASSWORD, totp_secret=secret, params=FAST)

    wrong = "000000"
    if totp_auth.verify(secret, wrong):  # astronomically unlikely, but be exact
        wrong = "000001"

    vault = Vault.load(vault_path)
    pending = vault.verify_password(PASSWORD)
    with pytest.raises(InvalidTotpCodeError):
        vault.complete_unlock(pending, code=wrong)


def test_unlock_succeeds_with_current_totp_code(vault_path):
    secret = totp_auth.generate_secret()
    vault, _ = Vault.create(vault_path, PASSWORD, totp_secret=secret, params=FAST)
    vault.complete_unlock(
        vault.verify_password(PASSWORD), code=totp_auth.current_code(secret)
    )
    assert vault.is_unlocked


def test_totp_secret_is_never_stored_in_cleartext(vault_path):
    secret = totp_auth.generate_secret()
    Vault.create(vault_path, PASSWORD, totp_secret=secret, params=FAST)
    assert secret.encode() not in vault_path.read_bytes()


def test_documented_limitation_password_alone_recovers_the_payload(vault_path):
    """This SHOULD pass, and it is not a bug -- it is the threat model.

    The TOTP secret lives in the keyring, which the master password alone
    unwraps, so TOTP is an authorization gate rather than a second
    cryptographic factor. If this test ever starts failing, the key hierarchy
    changed and README.md's threat model must be updated to match.
    """
    secret = totp_auth.generate_secret()
    vault, _ = Vault.create(vault_path, PASSWORD, totp_secret=secret, params=FAST)
    vault.complete_unlock(
        vault.verify_password(PASSWORD), code=totp_auth.current_code(secret)
    )
    vault.add(Entry(title="github", password="hunter2"))
    vault.save()

    # An attacker with the file and the password, but no authenticator:
    envelope = env_mod.Envelope.from_json(vault_path.read_bytes())
    keyring = env_mod.unwrap_with_password(envelope, PASSWORD)
    payload = env_mod.decrypt_payload(envelope, keyring.dek)
    assert VaultData.deserialize(payload).find("github").password == "hunter2"


# --- enrollment -----------------------------------------------------------


def test_enroll_totp_after_creation(vault_path):
    vault, _ = Vault.create(vault_path, PASSWORD, params=FAST)
    vault.complete_unlock(vault.verify_password(PASSWORD))
    secret = totp_auth.generate_secret()
    vault.enroll_totp(secret)
    vault.save()

    reloaded = Vault.load(vault_path)
    pending = reloaded.verify_password(PASSWORD)
    assert pending.requires_totp
    reloaded.complete_unlock(pending, code=totp_auth.current_code(secret))
    assert reloaded.is_unlocked


def test_enrolling_totp_via_recovery_unlock_is_refused(vault_path):
    """Re-sealing the keyring needs the master key, which recovery does not give."""
    vault, recovery_key = Vault.create(vault_path, PASSWORD, params=FAST)
    vault.unlock_with_recovery_key(recovery_key)
    with pytest.raises(VaultError):
        vault.enroll_totp(totp_auth.generate_secret())


def test_provisioning_uri_is_scannable():
    secret = totp_auth.generate_secret()
    uri = totp_auth.provisioning_uri(secret, "harry@example.com")
    assert uri.startswith("otpauth://totp/")
    assert "issuer=Hecate" in uri
    assert secret in uri


# --- recovery key ---------------------------------------------------------


def test_recovery_key_unlocks_without_password_or_totp(vault_path):
    secret = totp_auth.generate_secret()
    vault, recovery_key = Vault.create(
        vault_path, PASSWORD, totp_secret=secret, params=FAST
    )
    vault.complete_unlock(
        vault.verify_password(PASSWORD), code=totp_auth.current_code(secret)
    )
    vault.add(Entry(title="github", password="hunter2"))
    vault.save()

    recovered = Vault.load(vault_path)
    recovered.unlock_with_recovery_key(recovery_key)
    assert recovered.data.find("github").password == "hunter2"


def test_wrong_recovery_key_fails(vault_path):
    from hecate.crypto import rng

    Vault.create(vault_path, PASSWORD, params=FAST)
    vault = Vault.load(vault_path)
    with pytest.raises(DecryptionError):
        vault.unlock_with_recovery_key(
            rng.format_recovery_key(rng.generate_recovery_secret())
        )


# --- storage hygiene ------------------------------------------------------


def test_vault_file_is_owner_only(vault_path):
    Vault.create(vault_path, PASSWORD, params=FAST)
    assert storage.permissions_are_safe(vault_path)
    assert os.stat(vault_path).st_mode & 0o777 == 0o600


def test_atomic_write_leaves_no_temp_file(vault_path):
    Vault.create(vault_path, PASSWORD, params=FAST)
    assert list(vault_path.parent.glob(".*tmp")) == []


def test_locked_vault_refuses_access(vault_path):
    Vault.create(vault_path, PASSWORD, params=FAST)
    vault = Vault.load(vault_path)
    with pytest.raises(VaultLockedError):
        _ = vault.data


def test_lock_clears_key_material(vault_path):
    vault, _ = Vault.create(vault_path, PASSWORD, params=FAST)
    vault.complete_unlock(vault.verify_password(PASSWORD))
    vault.lock()
    assert not vault.is_unlocked
    with pytest.raises(VaultLockedError):
        _ = vault.data


def test_create_refuses_to_clobber_existing_vault(vault_path):
    Vault.create(vault_path, PASSWORD, params=FAST)
    with pytest.raises(VaultError):
        Vault.create(vault_path, PASSWORD, params=FAST)
