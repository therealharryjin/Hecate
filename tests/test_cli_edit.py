"""The edit and history commands.

The behaviour that matters here is that editing preserves what delete-then-add
destroys: the entry's creation time and its password history.
"""

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
    monkeypatch.setattr(kdf, "DEFAULT_ARGON2", kdf.FAST_ARGON2_FOR_TESTS)


@pytest.fixture
def vault(tmp_path):
    """An unlocked vault with one entry, and a live session."""
    path = tmp_path / "vault.hecate"
    secret = totp_auth.generate_secret()
    v, _recovery = Vault.create(path, PASSWORD.encode(), totp_secret=secret)
    v.complete_unlock(
        v.verify_password(PASSWORD.encode()), totp_auth.current_code(secret)
    )
    v.add(
        Entry(
            title="github",
            username="harry",
            password="hunter2",
            url="https://github.com",
            tags=["dev"],
        )
    )
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


# --- editing scalar fields ------------------------------------------------


def test_edit_username(runner, vault):
    result = runner.invoke(
        cli, ["--vault", str(vault), "edit", "github", "--username", "newname"], input=""
    )
    assert result.exit_code == 0, result.output
    assert _reopen(vault).data.find("github").username == "newname"


def test_edit_can_clear_a_field(runner, vault):
    runner.invoke(cli, ["--vault", str(vault), "edit", "github", "--notes", ""], input="")
    assert _reopen(vault).data.find("github").notes == ""


def test_edit_preserves_creation_time(runner, vault):
    before = _reopen(vault).data.find("github").created_at
    runner.invoke(
        cli, ["--vault", str(vault), "edit", "github", "--username", "x"], input=""
    )
    assert _reopen(vault).data.find("github").created_at == before


def test_edit_updates_modified_time(runner, vault):
    stale = "2000-01-01T00:00:00+00:00"
    v = _reopen(vault)
    v.data.find("github").modified_at = stale
    v.save()

    runner.invoke(
        cli, ["--vault", str(vault), "edit", "github", "--username", "x"], input=""
    )
    assert _reopen(vault).data.find("github").modified_at != stale


# --- renaming -------------------------------------------------------------


def test_edit_renames(runner, vault):
    result = runner.invoke(
        cli, ["--vault", str(vault), "edit", "github", "--title", "github-work"], input=""
    )
    assert result.exit_code == 0
    data = _reopen(vault).data
    assert data.find("github-work") is not None
    assert data.find("github") is None


def test_rename_onto_an_existing_title_is_refused(runner, vault):
    v = _reopen(vault)
    v.add(Entry(title="gitlab", password="other"))
    v.save()

    result = runner.invoke(
        cli, ["--vault", str(vault), "edit", "github", "--title", "gitlab"], input=""
    )
    assert result.exit_code == 1
    assert "already exists" in result.output
    assert _reopen(vault).data.find("github") is not None


# --- tags -----------------------------------------------------------------


def test_add_and_remove_tags(runner, vault):
    runner.invoke(
        cli,
        ["--vault", str(vault), "edit", "github", "--add-tag", "work", "--remove-tag", "dev"],
        input="",
    )
    assert _reopen(vault).data.find("github").tags == ["work"]


def test_adding_an_existing_tag_does_not_duplicate_it(runner, vault):
    runner.invoke(
        cli, ["--vault", str(vault), "edit", "github", "--add-tag", "dev"], input=""
    )
    assert _reopen(vault).data.find("github").tags == ["dev"]


# --- password rotation ----------------------------------------------------


def test_password_change_rotates_into_history(runner, vault):
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "edit", "github", "--password"],
        input="newsecret\nnewsecret\n",
    )
    assert result.exit_code == 0, result.output
    entry = _reopen(vault).data.find("github")
    assert entry.password == "newsecret"
    assert [h.password for h in entry.password_history] == ["hunter2"]


def test_setting_the_same_password_records_no_history(runner, vault):
    result = runner.invoke(
        cli,
        ["--vault", str(vault), "edit", "github", "--password"],
        input="hunter2\nhunter2\n",
    )
    assert result.exit_code == 0
    assert _reopen(vault).data.find("github").password_history == []
    assert "unchanged" in result.output


def test_password_is_not_accepted_as_an_argument(runner, vault):
    """--password is a flag; a value after it must not be swallowed as the secret."""
    result = runner.invoke(
        cli, ["--vault", str(vault), "edit", "github", "--password", "letmein"], input=""
    )
    # "letmein" is parsed as a stray argument, not as the new password.
    assert result.exit_code != 0
    assert _reopen(vault).data.find("github").password == "hunter2"


# --- guard rails ----------------------------------------------------------


def test_edit_with_no_options_is_an_error(runner, vault):
    result = runner.invoke(cli, ["--vault", str(vault), "edit", "github"], input="")
    assert result.exit_code == 1
    assert "nothing to change" in result.output


def test_edit_unknown_entry_is_an_error(runner, vault):
    result = runner.invoke(
        cli, ["--vault", str(vault), "edit", "nope", "--username", "x"], input=""
    )
    assert result.exit_code == 1
    assert "no entry titled" in result.output


# --- history --------------------------------------------------------------


def test_history_masks_passwords_by_default(runner, vault):
    runner.invoke(
        cli,
        ["--vault", str(vault), "edit", "github", "--password"],
        input="newsecret\nnewsecret\n",
    )
    result = runner.invoke(cli, ["--vault", str(vault), "history", "github"], input="")
    assert result.exit_code == 0
    assert "hunter2" not in result.output
    assert "newsecret" not in result.output
    assert "--show" in result.output


def test_history_reveals_with_show(runner, vault):
    runner.invoke(
        cli,
        ["--vault", str(vault), "edit", "github", "--password"],
        input="newsecret\nnewsecret\n",
    )
    result = runner.invoke(
        cli, ["--vault", str(vault), "history", "github", "--show"], input=""
    )
    assert "hunter2" in result.output
    assert "newsecret" in result.output


def test_history_is_newest_first(runner, vault):
    for password in ("second", "third"):
        runner.invoke(
            cli,
            ["--vault", str(vault), "edit", "github", "--password"],
            input=f"{password}\n{password}\n",
        )
    result = runner.invoke(
        cli, ["--vault", str(vault), "history", "github", "--show"], input=""
    )
    assert result.output.index("second") < result.output.index("hunter2")


def test_history_for_an_untouched_entry(runner, vault):
    result = runner.invoke(cli, ["--vault", str(vault), "history", "github"], input="")
    assert "No previous passwords recorded" in result.output
