"""`hecate get --copy`: a stored password onto the clipboard, never the screen.

The clipboard is replaced with a recorder, so nothing touches the real one.
"""

import pytest
from click.testing import CliRunner

from hecate import clipboard
from hecate import config as config_mod
from hecate.cli.main import cli
from hecate.crypto import kdf
from hecate.vault.model import Entry
from hecate.vault.vault import Vault

PASSWORD = "correct horse battery staple"
STORED = "hunter2-but-longer"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv(config_mod.HOME_ENV, str(tmp_path / "home"))
    monkeypatch.delenv(config_mod.VAULT_ENV, raising=False)
    monkeypatch.setattr(kdf, "DEFAULT_ARGON2", kdf.FAST_ARGON2_FOR_TESTS)


@pytest.fixture(autouse=True)
def copies(monkeypatch):
    recorded = []
    monkeypatch.setattr(
        clipboard, "copy", lambda secret, *, clear_after: recorded.append((secret, clear_after))
    )
    return recorded


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def vault(tmp_path):
    """A password-only vault holding one entry, so unlocking needs one answer."""
    path = tmp_path / "vault.hecate"
    vault, _recovery = Vault.create(path, PASSWORD.encode())
    vault.complete_unlock(vault.verify_password(PASSWORD.encode()))
    vault.add(Entry(title="github", username="harry", password=STORED))
    vault.save()
    return path


def _get(runner, path, *args, input=f"{PASSWORD}\n"):
    return runner.invoke(cli, ["--vault", str(path), "get", "github", *args], input=input)


def test_copy_puts_the_password_on_the_clipboard_with_an_expiry(runner, vault, copies):
    result = _get(runner, vault, "--copy")
    assert result.exit_code == 0, result.output
    assert copies == [(STORED, config_mod.DEFAULT_CLIPBOARD_CLEAR_SECONDS)]
    assert "copied; cleared in 15 seconds" in result.output


def test_copy_never_prints_the_password(runner, vault):
    result = _get(runner, vault, "--copy")
    assert STORED not in result.output
    assert "Password: ********" in result.output


def test_the_expiry_follows_the_setting(runner, vault, copies):
    runner.invoke(cli, ["config", "set", "clipboard-clear", "45"])
    assert _get(runner, vault, "--copy").exit_code == 0
    assert copies[0][1] == 45


def test_copy_is_refused_before_unlocking_when_copying_is_off(runner, vault, copies):
    runner.invoke(cli, ["config", "set", "clipboard-clear", "0"])
    result = _get(runner, vault, "--copy", input="")
    assert result.exit_code == 1
    assert "copying is turned off" in result.output
    assert "Master password" not in result.output
    assert copies == []


def test_no_clipboard_is_an_error_not_a_silent_success(runner, vault, monkeypatch):
    def unavailable(_secret, *, clear_after):
        raise clipboard.ClipboardUnavailable("no xclip")

    monkeypatch.setattr(clipboard, "copy", unavailable)
    result = _get(runner, vault, "--copy")
    assert result.exit_code == 1
    assert "no clipboard is available here" in result.output
    assert STORED not in result.output


def test_show_and_copy_together_do_both(runner, vault, copies):
    result = _get(runner, vault, "--show", "--copy")
    assert result.exit_code == 0, result.output
    assert f"Password: {STORED}  (copied" in result.output
    assert copies[0][0] == STORED


def test_without_either_flag_nothing_is_copied_or_shown(runner, vault, copies):
    result = _get(runner, vault)
    assert result.exit_code == 0, result.output
    assert STORED not in result.output
    assert "--show to reveal, --copy to copy" in result.output
    assert copies == []


def test_show_alone_prints_without_copying(runner, vault, copies):
    result = _get(runner, vault, "--show")
    assert f"Password: {STORED}\n" in result.output
    assert copies == []


def test_copying_an_entry_with_no_password_is_refused(runner, tmp_path, copies):
    path = tmp_path / "empty.hecate"
    vault, _recovery = Vault.create(path, PASSWORD.encode())
    vault.complete_unlock(vault.verify_password(PASSWORD.encode()))
    vault.add(Entry(title="github", username="harry", password=""))
    vault.save()

    result = _get(runner, path, "--copy")
    assert result.exit_code == 1
    assert "has no password to copy" in result.output
    assert copies == []
