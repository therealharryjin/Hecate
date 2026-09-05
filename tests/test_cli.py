"""CLI behaviour, focused on the session window and the settings surface."""

import json

import pytest
from click.testing import CliRunner

from hecate import config as config_mod
from hecate.auth import session as session_mod
from hecate.auth import totp as totp_auth
from hecate.cli.main import cli
from hecate.crypto import kdf
from hecate.vault.model import Entry
from hecate.vault.vault import Vault

PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv(config_mod.HOME_ENV, str(tmp_path / "home"))
    monkeypatch.delenv(config_mod.VAULT_ENV, raising=False)
    # Keep Argon2 cheap; these tests are about the CLI, not the KDF.
    monkeypatch.setattr(kdf, "DEFAULT_ARGON2", kdf.FAST_ARGON2_FOR_TESTS)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def vault(tmp_path):
    """A vault with an enrolled authenticator and one entry."""
    path = tmp_path / "vault.hecate"
    secret = totp_auth.generate_secret()
    vault, _recovery = Vault.create(path, PASSWORD.encode(), totp_secret=secret)
    vault.complete_unlock(
        vault.verify_password(PASSWORD.encode()), totp_auth.current_code(secret)
    )
    vault.add(Entry(title="github", username="harry", password="hunter2"))
    vault.save()
    return path, secret


# --- settings surface -----------------------------------------------------


def test_config_list_shows_the_default_timeout(runner):
    result = runner.invoke(cli, ["config", "list"])
    assert result.exit_code == 0
    assert "session-timeout" in result.output
    assert "10" in result.output


def test_config_get_returns_the_default(runner):
    result = runner.invoke(cli, ["config", "get", "session-timeout"])
    assert result.exit_code == 0
    assert result.output.strip() == "10"


def test_config_set_persists_across_invocations(runner):
    assert runner.invoke(cli, ["config", "set", "session-timeout", "30"]).exit_code == 0
    result = runner.invoke(cli, ["config", "get", "session-timeout"])
    assert result.output.strip() == "30"
    assert config_mod.load().session_timeout_minutes == 30


@pytest.mark.parametrize("bad", ["-1", "abc", "9999"])
def test_config_set_rejects_invalid_values(runner, bad):
    result = runner.invoke(cli, ["config", "set", "session-timeout", bad])
    assert result.exit_code == 1
    assert "error:" in result.output


def test_config_set_rejects_unknown_setting(runner):
    result = runner.invoke(cli, ["config", "set", "sesion-timeout", "10"])
    assert result.exit_code == 1
    assert "known settings" in result.output


def test_setting_timeout_to_zero_ends_the_session(runner, vault):
    path, secret = vault
    session_mod.start(path, b"\x11" * 32, 10)
    result = runner.invoke(cli, ["config", "set", "session-timeout", "0"])
    assert result.exit_code == 0
    assert not session_mod.session_path().exists()


# --- the session window ---------------------------------------------------


def test_unlock_then_run_commands_without_reauthenticating(runner, vault):
    """The point of the feature: unlock once, work for the window."""
    path, secret = vault
    unlocked = runner.invoke(
        cli,
        ["--vault", str(path), "unlock"],
        input=f"{PASSWORD}\n{totp_auth.current_code(secret)}\n",
    )
    assert unlocked.exit_code == 0, unlocked.output

    # No input supplied at all: any prompt would raise EOF and fail the test.
    listed = runner.invoke(cli, ["--vault", str(path), "list"], input="")
    assert listed.exit_code == 0, listed.output
    assert "github" in listed.output

    shown = runner.invoke(cli, ["--vault", str(path), "get", "github"], input="")
    assert shown.exit_code == 0
    assert "harry" in shown.output


def test_commands_prompt_again_once_the_window_lapses(runner, vault):
    path, secret = vault
    runner.invoke(
        cli,
        ["--vault", str(path), "unlock"],
        input=f"{PASSWORD}\n{totp_auth.current_code(secret)}\n",
    )

    data = json.loads(session_mod.session_path().read_text())
    data["expires_at"] = 0  # as if the idle window had elapsed
    session_mod.session_path().write_text(json.dumps(data))

    result = runner.invoke(cli, ["--vault", str(path), "list"], input="")
    assert result.exit_code != 0  # prompted for the master password, got EOF


def test_each_command_slides_the_window_forward(runner, vault):
    path, secret = vault
    runner.invoke(
        cli,
        ["--vault", str(path), "unlock"],
        input=f"{PASSWORD}\n{totp_auth.current_code(secret)}\n",
    )
    before = session_mod.load(path).seconds_remaining()

    live = session_mod.load(path)
    live.expires_at -= 120  # pretend two minutes of idling passed
    session_mod._write(live)

    runner.invoke(cli, ["--vault", str(path), "list"], input="")
    assert session_mod.load(path).seconds_remaining() > before - 60


def test_a_session_for_one_vault_does_not_open_another(runner, vault, tmp_path):
    path, secret = vault
    runner.invoke(
        cli,
        ["--vault", str(path), "unlock"],
        input=f"{PASSWORD}\n{totp_auth.current_code(secret)}\n",
    )
    other = tmp_path / "other.hecate"
    Vault.create(other, b"different password")

    result = runner.invoke(cli, ["--vault", str(other), "list"], input="")
    assert result.exit_code != 0


def test_lock_ends_the_session_immediately(runner, vault):
    path, secret = vault
    runner.invoke(
        cli,
        ["--vault", str(path), "unlock"],
        input=f"{PASSWORD}\n{totp_auth.current_code(secret)}\n",
    )
    assert runner.invoke(cli, ["lock"]).exit_code == 0
    assert runner.invoke(cli, ["--vault", str(path), "list"], input="").exit_code != 0


def test_zero_timeout_means_every_command_prompts(runner, vault):
    path, secret = vault
    runner.invoke(cli, ["config", "set", "session-timeout", "0"])

    result = runner.invoke(cli, ["--vault", str(path), "list"], input="")
    assert result.exit_code != 0
    assert not session_mod.session_path().exists()


def test_status_reports_locked_and_unlocked(runner, vault):
    path, secret = vault
    locked = runner.invoke(cli, ["--vault", str(path), "status"])
    assert "locked" in locked.output

    runner.invoke(
        cli,
        ["--vault", str(path), "unlock"],
        input=f"{PASSWORD}\n{totp_auth.current_code(secret)}\n",
    )
    unlocked = runner.invoke(cli, ["--vault", str(path), "status"])
    assert "unlocked" in unlocked.output
    assert "idle time left" in unlocked.output


def test_wrong_password_does_not_start_a_session(runner, vault):
    path, _secret = vault
    result = runner.invoke(
        cli, ["--vault", str(path), "unlock"], input="wrong password\n"
    )
    assert result.exit_code == 1
    assert "incorrect master password" in result.output
    assert not session_mod.session_path().exists()


def test_stale_totp_code_does_not_start_a_session(runner, vault):
    import time

    path, secret = vault
    stale = totp_auth.current_code(secret, at=int(time.time()) - 300)
    result = runner.invoke(
        cli, ["--vault", str(path), "unlock"], input=f"{PASSWORD}\n{stale}\n"
    )
    assert result.exit_code == 1
    assert not session_mod.session_path().exists()
