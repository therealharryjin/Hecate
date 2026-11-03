"""`hecate recover`: getting back in with the recovery key.

The cases that matter are the lost authenticator and the forgotten master
password. In both, the recovery key has to end in a vault that the normal
unlock opens again -- and a mistake along the way must change nothing.
"""

import pytest
from click.testing import CliRunner

from hecate import config as config_mod
from hecate.auth import session as session_mod
from hecate.auth import totp as totp_auth
from hecate.cli.main import cli
from hecate.crypto import kdf, rng
from hecate.vault.model import Entry
from hecate.vault.vault import Vault

PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "a new master password after recovery"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv(config_mod.HOME_ENV, str(tmp_path / "home"))
    monkeypatch.delenv(config_mod.VAULT_ENV, raising=False)
    monkeypatch.setattr(kdf, "DEFAULT_ARGON2", kdf.FAST_ARGON2_FOR_TESTS)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def vault(tmp_path):
    """A vault behind password + authenticator, holding one entry."""
    path = tmp_path / "vault.hecate"
    secret = totp_auth.generate_secret()
    vault, recovery_key = Vault.create(path, PASSWORD.encode(), totp_secret=secret)
    vault.complete_unlock(
        vault.verify_password(PASSWORD.encode()), totp_auth.current_code(secret)
    )
    vault.add(Entry(title="github", username="harry", password="hunter2"))
    vault.save()
    return path, secret, recovery_key


@pytest.fixture
def new_secret(monkeypatch):
    """Pin the secret `recover` enrolls, so the test can answer its code."""
    secret = totp_auth.generate_secret()
    monkeypatch.setattr(totp_auth, "generate_secret", lambda: secret)
    return secret


def _recover_input(recovery_key, code):
    return f"{recovery_key}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\n\n{code}\n"


def _unlock(runner, path, password, code):
    return runner.invoke(
        cli, ["--vault", str(path), "unlock"], input=f"{password}\n{code}\n"
    )


def test_recover_after_losing_the_authenticator(runner, vault, new_secret):
    path, old_secret, recovery_key = vault
    result = runner.invoke(
        cli,
        ["--vault", str(path), "recover"],
        input=_recover_input(recovery_key, totp_auth.current_code(new_secret)),
    )
    assert result.exit_code == 0, result.output
    assert "Master password and authenticator replaced" in result.output

    unlocked = _unlock(runner, path, NEW_PASSWORD, totp_auth.current_code(new_secret))
    assert unlocked.exit_code == 0, unlocked.output
    listed = runner.invoke(cli, ["--vault", str(path), "get", "github"], input="")
    assert "harry" in listed.output


def test_old_credentials_stop_working_after_recovery(runner, vault, new_secret):
    path, old_secret, recovery_key = vault
    runner.invoke(
        cli,
        ["--vault", str(path), "recover"],
        input=_recover_input(recovery_key, totp_auth.current_code(new_secret)),
    )
    old = _unlock(runner, path, PASSWORD, totp_auth.current_code(old_secret))
    assert old.exit_code == 1
    assert "incorrect master password" in old.output


def test_recovery_can_keep_the_same_master_password(runner, vault, new_secret):
    """Lost phone, remembered password: re-entering it is allowed."""
    path, _old_secret, recovery_key = vault
    code = totp_auth.current_code(new_secret)
    result = runner.invoke(
        cli,
        ["--vault", str(path), "recover"],
        input=f"{recovery_key}\n{PASSWORD}\n{PASSWORD}\n\n{code}\n",
    )
    assert result.exit_code == 0, result.output
    assert _unlock(runner, path, PASSWORD, code).exit_code == 0


def test_recover_without_totp(runner, vault):
    path, _old_secret, recovery_key = vault
    result = runner.invoke(
        cli,
        ["--vault", str(path), "recover", "--no-totp"],
        input=f"{recovery_key}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\n",
    )
    assert result.exit_code == 0, result.output
    assert "no longer asks for an authenticator code" in result.output

    # Only the password is asked for; no code prompt follows.
    unlocked = runner.invoke(
        cli, ["--vault", str(path), "unlock"], input=f"{NEW_PASSWORD}\n"
    )
    assert unlocked.exit_code == 0, unlocked.output


@pytest.mark.parametrize(
    "bad_key, message",
    [
        ("random", "does not open this vault"),
        ("NOT-A-KEY", "nothing was changed"),
    ],
)
def test_bad_recovery_key_changes_nothing(runner, vault, bad_key, message):
    path, _old_secret, _recovery_key = vault
    if bad_key == "random":
        bad_key = rng.format_recovery_key(rng.generate_recovery_secret())
    original = path.read_bytes()

    result = runner.invoke(
        cli, ["--vault", str(path), "recover"], input=f"{bad_key}\n"
    )
    assert result.exit_code == 1
    assert message in result.output
    assert path.read_bytes() == original


def test_unverified_authenticator_code_changes_nothing(runner, vault, new_secret):
    """A mistyped secret must not leave the vault behind a code nobody has."""
    path, old_secret, recovery_key = vault
    original = path.read_bytes()

    result = runner.invoke(
        cli,
        ["--vault", str(path), "recover"],
        input=_recover_input(recovery_key, "000000"),
    )
    assert result.exit_code == 1
    assert "nothing was changed" in result.output
    assert path.read_bytes() == original
    assert _unlock(runner, path, PASSWORD, totp_auth.current_code(old_secret)).exit_code == 0


def test_recover_ends_any_live_session(runner, vault, new_secret):
    path, old_secret, recovery_key = vault
    _unlock(runner, path, PASSWORD, totp_auth.current_code(old_secret))
    assert session_mod.session_path().exists()

    runner.invoke(
        cli,
        ["--vault", str(path), "recover"],
        input=_recover_input(recovery_key, totp_auth.current_code(new_secret)),
    )
    assert not session_mod.session_path().exists()


def test_recovery_key_is_never_echoed(runner, vault, new_secret):
    path, _old_secret, recovery_key = vault
    result = runner.invoke(
        cli,
        ["--vault", str(path), "recover"],
        input=_recover_input(recovery_key, totp_auth.current_code(new_secret)),
    )
    assert result.exit_code == 0, result.output
    assert recovery_key not in result.output
    assert NEW_PASSWORD not in result.output


def test_recover_without_a_vault(runner, tmp_path):
    result = runner.invoke(
        cli, ["--vault", str(tmp_path / "missing.hecate"), "recover"], input=""
    )
    assert result.exit_code == 1
    assert "no vault at" in result.output
