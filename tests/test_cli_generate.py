"""`hecate generate`: settings, overrides, the clipboard, and saving.

The clipboard is replaced with a recorder for every test here, so nothing
touches the real one.
"""

import re

import pytest
from click.testing import CliRunner

from hecate import clipboard
from hecate import config as config_mod
from hecate.auth import totp as totp_auth
from hecate.cli.main import cli
from hecate.crypto import kdf
from hecate.generator import passphrase as passphrase_mod
from hecate.vault.model import Entry
from hecate.vault.vault import Vault

PASSWORD = "correct horse battery staple"


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
    """A password-only vault holding one entry, so saving needs one prompt."""
    path = tmp_path / "vault.hecate"
    vault, _recovery = Vault.create(path, PASSWORD.encode())
    vault.complete_unlock(vault.verify_password(PASSWORD.encode()))
    vault.add(Entry(title="github", username="harry", password="old-password"))
    vault.save()
    return path


def _generate(runner, *args, input="", vault_path=None):
    prefix = ["--vault", str(vault_path)] if vault_path else []
    return runner.invoke(cli, [*prefix, "generate", *args], input=input)


def _secret(result):
    return result.stdout.splitlines()[0]


def _stored(path, title):
    vault = Vault.load(path)
    vault.complete_unlock(vault.verify_password(PASSWORD.encode()))
    return vault.data.find(title)


# --- output and the clipboard ---------------------------------------------


def test_stdout_carries_only_the_password(runner):
    result = _generate(runner, "--no-save")
    assert result.exit_code == 0, result.output
    assert result.stdout == _secret(result) + "\n"
    assert len(_secret(result)) == 20
    assert "bits of entropy" in result.stderr


def test_every_generated_password_is_copied_with_expiry(runner, copies):
    result = _generate(runner, "--no-save")
    assert copies == [(_secret(result), 15)]
    assert "cleared in 15 seconds" in result.output


def test_clipboard_clear_setting_sets_the_expiry(runner, copies):
    runner.invoke(cli, ["config", "set", "clipboard-clear", "45"])
    _generate(runner, "--no-save")
    assert copies[0][1] == 45


def test_no_copy_and_zero_clear_skip_the_clipboard(runner, copies):
    _generate(runner, "--no-save", "--no-copy")
    runner.invoke(cli, ["config", "set", "clipboard-clear", "0"])
    _generate(runner, "--no-save")
    assert copies == []


def test_missing_clipboard_still_shows_the_password(runner, monkeypatch):
    def unavailable(_secret, *, clear_after):
        raise clipboard.ClipboardUnavailable("no xclip")

    monkeypatch.setattr(clipboard, "copy", unavailable)
    result = _generate(runner, "--no-save")
    assert result.exit_code == 0
    assert len(_secret(result)) == 20
    assert "copy it from the line above" in result.output


# --- settings and overrides -----------------------------------------------


def test_passphrase_flag(runner):
    words = _secret(_generate(runner, "--passphrase", "--no-save")).split("-")
    assert len(words) == 6
    assert all(word in passphrase_mod.wordlist() for word in words)


def test_settings_change_what_is_generated(runner):
    for name, value in [
        ("generate-type", "passphrase"),
        ("passphrase-words", "8"),
        ("passphrase-separator", " "),
        ("passphrase-capitalize", "on"),
    ]:
        assert runner.invoke(cli, ["config", "set", name, value]).exit_code == 0
    words = _secret(_generate(runner, "--no-save")).split(" ")
    assert len(words) == 8
    assert all(word[0].isupper() for word in words)


def test_password_settings(runner):
    runner.invoke(cli, ["config", "set", "password-length", "32"])
    runner.invoke(cli, ["config", "set", "password-symbols", "@"])
    runner.invoke(cli, ["config", "set", "password-digits", "off"])
    value = _secret(_generate(runner, "--no-save"))
    assert re.fullmatch(r"[A-Za-z@]{32}", value)
    assert "@" in value


def test_options_override_settings_for_one_run_only(runner):
    value = _secret(_generate(runner, "--no-save", "--length", "12", "--no-symbols"))
    assert re.fullmatch(r"[A-Za-z0-9]{12}", value)
    assert len(_secret(_generate(runner, "--no-save"))) == 20


def test_passphrase_options(runner):
    value = _secret(
        _generate(runner, "--passphrase", "--no-save", "--words", "5", "--separator", ".", "--number")
    )
    parts = value.split(".")
    assert len(parts) == 5
    assert sum(part[-1].isdigit() for part in parts) == 1


@pytest.mark.parametrize(
    "args, message",
    [
        (["--length", "4"], "--length: must be between 8 and 128"),
        (["--symbols", "abc"], "not a special character"),
        (["--passphrase", "--separator", "x"], "letters or digits"),
        (["--passphrase", "--words", "99"], "--words: must be between 4 and 20"),
        (["--no-uppercase", "--no-lowercase", "--no-digits", "--no-symbols"], "no characters"),
    ],
)
def test_bad_options_are_refused(runner, copies, args, message):
    result = _generate(runner, "--no-save", *args)
    assert result.exit_code == 1
    assert message in result.output
    assert copies == []


def test_options_for_the_other_kind_are_refused(runner):
    result = _generate(runner, "--no-save", "--words", "5")
    assert result.exit_code == 2
    assert "--words: only for a passphrase" in result.output


def test_symbols_and_no_symbols_together_are_refused(runner):
    result = _generate(runner, "--no-save", "--symbols", "!", "--no-symbols")
    assert result.exit_code == 2


def test_config_shows_switches_and_text_readably(runner):
    runner.invoke(cli, ["config", "set", "passphrase-separator", " "])
    assert runner.invoke(cli, ["config", "get", "passphrase-separator"]).output.strip() == "' '"
    assert runner.invoke(cli, ["config", "get", "generate-save-prompt"]).output.strip() == "on"


# --- saving -----------------------------------------------------------------


def test_save_is_offered_and_defaults_to_yes(runner, vault):
    # enter (accept the default), master password, title, username
    result = _generate(
        runner, input=f"\n{PASSWORD}\ngitlab\nme\n", vault_path=vault
    )
    assert result.exit_code == 0, result.output
    assert "Save it to Hecate? [Y/n]" in result.output
    entry = _stored(vault, "gitlab")
    assert entry.password == _secret(result)
    assert entry.username == "me"


def test_declining_saves_nothing(runner, vault):
    result = _generate(runner, input="n\n", vault_path=vault)
    assert result.exit_code == 0
    assert _stored(vault, "gitlab") is None


def test_save_prompt_can_be_turned_off(runner, vault):
    runner.invoke(cli, ["config", "set", "generate-save-prompt", "off"])
    result = _generate(runner, input="", vault_path=vault)  # any prompt would hit EOF
    assert result.exit_code == 0, result.output
    assert "Save it to Hecate" not in result.output


def test_save_flag_skips_the_question(runner, vault):
    runner.invoke(cli, ["config", "set", "generate-save-prompt", "off"])
    result = _generate(runner, "--save", input=f"{PASSWORD}\ngitlab\n\n", vault_path=vault)
    assert result.exit_code == 0, result.output
    assert _stored(vault, "gitlab").password == _secret(result)


def test_saving_over_an_existing_entry_keeps_the_old_password_in_history(runner, vault):
    result = _generate(runner, input=f"\n{PASSWORD}\nGitHub\ny\n", vault_path=vault)
    assert result.exit_code == 0, result.output
    entry = _stored(vault, "github")
    assert entry.password == _secret(result)
    assert [item.password for item in entry.password_history] == ["old-password"]


def test_declining_to_replace_leaves_the_entry_alone(runner, vault):
    result = _generate(runner, input=f"\n{PASSWORD}\ngithub\n\n", vault_path=vault)
    assert result.exit_code == 0
    assert "Nothing was saved" in result.output
    assert _stored(vault, "github").password == "old-password"


def test_no_vault_means_no_question(runner, tmp_path):
    missing = tmp_path / "missing.hecate"
    result = _generate(runner, input="", vault_path=missing)
    assert result.exit_code == 0
    assert "hecate init" in result.output
    assert not missing.exists()


def test_save_flag_without_a_vault_fails(runner, tmp_path):
    result = _generate(runner, "--save", vault_path=tmp_path / "missing.hecate")
    assert result.exit_code == 1
    assert "no vault" in result.output


def test_saving_works_through_the_authenticator_gate(runner, tmp_path):
    path = tmp_path / "totp.hecate"
    secret = totp_auth.generate_secret()
    Vault.create(path, PASSWORD.encode(), totp_secret=secret)
    code = totp_auth.current_code(secret)
    result = _generate(runner, input=f"\n{PASSWORD}\n{code}\nbank\n\n", vault_path=path)
    assert result.exit_code == 0, result.output

    vault = Vault.load(path)
    vault.complete_unlock(vault.verify_password(PASSWORD.encode()), code)
    assert vault.data.find("bank").password == _secret(result)
