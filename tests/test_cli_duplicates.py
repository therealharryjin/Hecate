"""Password-reuse warnings on add and edit.

The rule under test is that Hecate warns and then gets out of the way: a
duplicate password is always reachable, it just costs a deliberate "y".
"""

import pytest
from click.testing import CliRunner

from hecate import config as config_mod
from hecate.audit import duplicates
from hecate.auth import session as session_mod
from hecate.auth import totp as totp_auth
from hecate.cli.main import cli
from hecate.crypto import kdf
from hecate.vault.model import Entry
from hecate.vault.vault import Vault

PASSWORD = "correct horse battery staple"
SHARED = "hunter2"
UNIQUE = "a different secret entirely"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv(config_mod.HOME_ENV, str(tmp_path / "home"))
    monkeypatch.delenv(config_mod.VAULT_ENV, raising=False)
    monkeypatch.setattr(kdf, "DEFAULT_ARGON2", kdf.FAST_ARGON2_FOR_TESTS)


@pytest.fixture
def vault(tmp_path):
    """A vault where two entries already share a password, plus a live session."""
    path = tmp_path / "vault.hecate"
    secret = totp_auth.generate_secret()
    v, _recovery = Vault.create(path, PASSWORD.encode(), totp_secret=secret)
    v.complete_unlock(
        v.verify_password(PASSWORD.encode()), totp_auth.current_code(secret)
    )
    v.add(Entry(title="github", username="harry", password=SHARED))
    v.add(Entry(title="gitlab", password=SHARED))
    v.add(Entry(title="email", username="harry", password=UNIQUE))
    v.save()
    session_mod.start(path, v.dek, 10)
    return path


def _reopen(path):
    v = Vault.load(path)
    v.unlock_with_dek(session_mod.load(path).dek)
    return v


@pytest.fixture
def runner():
    return CliRunner()


# --- add ------------------------------------------------------------------


def test_add_warns_and_lists_the_entries_already_using_it(runner, vault):
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "add", "forgejo"],
        input=f"{SHARED}\n{SHARED}\ny\n",
    )
    assert result.exit_code == 0, result.output
    assert "already used by 2 other entries" in result.output
    assert "github (harry)" in result.output
    assert "gitlab" in result.output


def test_add_accepts_the_duplicate_when_the_user_says_yes(runner, vault):
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "add", "forgejo"],
        input=f"{SHARED}\n{SHARED}\ny\n",
    )
    assert result.exit_code == 0, result.output
    assert _reopen(vault).data.find("forgejo").password == SHARED


def test_add_saves_nothing_when_the_user_says_no(runner, vault):
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "add", "forgejo"],
        input=f"{SHARED}\n{SHARED}\nn\n",
    )
    assert result.exit_code == 1
    assert _reopen(vault).data.find("forgejo") is None


def test_add_defaults_to_no_on_a_bare_enter(runner, vault):
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "add", "forgejo"],
        input=f"{SHARED}\n{SHARED}\n\n",
    )
    assert result.exit_code == 1
    assert _reopen(vault).data.find("forgejo") is None


def test_add_does_not_prompt_for_a_unique_password(runner, vault):
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "add", "forgejo"],
        input="something nobody else has\nsomething nobody else has\n",
    )
    assert result.exit_code == 0, result.output
    assert "already used by" not in result.output
    assert _reopen(vault).data.find("forgejo") is not None


def test_the_warning_never_echoes_the_password(runner, vault):
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "add", "forgejo"],
        input=f"{SHARED}\n{SHARED}\nn\n",
    )
    assert SHARED not in result.output


# --- edit -----------------------------------------------------------------


def test_edit_warns_when_rotating_into_an_existing_password(runner, vault):
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "edit", "email", "--password"],
        input=f"{SHARED}\n{SHARED}\ny\n",
    )
    assert result.exit_code == 0, result.output
    assert "already used by 2 other entries" in result.output
    assert _reopen(vault).data.find("email").password == SHARED


def test_edit_declining_keeps_the_old_password(runner, vault):
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "edit", "email", "--password"],
        input=f"{SHARED}\n{SHARED}\nn\n",
    )
    assert result.exit_code == 0, result.output
    entry = _reopen(vault).data.find("email")
    assert entry.password == UNIQUE
    assert entry.password_history == []


def test_edit_declining_still_applies_the_other_changes(runner, vault):
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "edit", "email", "--password", "--username", "newname"],
        input=f"{SHARED}\n{SHARED}\nn\n",
    )
    assert result.exit_code == 0, result.output
    entry = _reopen(vault).data.find("email")
    assert entry.username == "newname"
    assert entry.password == UNIQUE


def test_an_entry_is_not_a_duplicate_of_itself(runner, vault):
    """Re-entering github's own password hits the unchanged path, not a warning."""
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "edit", "github", "--password"],
        input=f"{SHARED}\n{SHARED}\n",
    )
    assert result.exit_code == 0, result.output
    assert "Password is unchanged" in result.output
    assert "already used by" not in result.output


# --- the matching rule itself ---------------------------------------------


def test_empty_passwords_are_never_duplicates():
    entries = [Entry(title="a", password=""), Entry(title="b", password="")]
    assert duplicates.entries_sharing_password(entries, "") == []
    assert duplicates.entries_sharing_password(entries, "x") == []


def test_matching_is_case_sensitive():
    entries = [Entry(title="a", password="Password1")]
    assert duplicates.entries_sharing_password(entries, "password1") == []
    assert duplicates.entries_sharing_password(entries, "Password1") == entries


def test_history_is_not_searched():
    entry = Entry(title="a", password="current")
    entry.set_password("rotated")
    assert entry.password_history[0].password == "current"
    assert duplicates.entries_sharing_password([entry], "current") == []
