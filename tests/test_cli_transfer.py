"""`hecate export` and `hecate import`, end to end.

Backups are complete vault files under the same keys. Imports only ever add,
show what they will add before saving, and never bring in an authenticator
secret.
"""

import json
import os

import pytest
from click.testing import CliRunner

from hecate import config as config_mod
from hecate.auth import ratelimit
from hecate.auth import totp as totp_auth
from hecate.cli.main import cli
from hecate.crypto import kdf
from hecate.vault.model import Entry, PasswordHistoryItem
from hecate.vault.vault import Vault

PASSWORD = "correct horse battery staple"
BACKUP_PASSWORD = "the password the backup was made under"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv(config_mod.HOME_ENV, str(tmp_path / "home"))
    monkeypatch.delenv(config_mod.VAULT_ENV, raising=False)
    monkeypatch.setattr(kdf, "DEFAULT_ARGON2", kdf.FAST_ARGON2_FOR_TESTS)


@pytest.fixture
def runner():
    return CliRunner()


def _make_vault(path, password, entries, *, totp_secret=None):
    vault, _recovery = Vault.create(path, password.encode(), totp_secret=totp_secret)
    pending = vault.verify_password(password.encode())
    vault.complete_unlock(pending, totp_auth.current_code(totp_secret) if totp_secret else None)
    for entry in entries:
        vault.add(entry)
    vault.save()
    return path


def _open(path, password=PASSWORD):
    vault = Vault.load(path)
    vault.complete_unlock(vault.verify_password(password.encode()))
    return vault


@pytest.fixture
def vault(tmp_path):
    """A password-only vault holding one entry, so unlocking takes one answer."""
    return _make_vault(
        tmp_path / "vault.hecate",
        PASSWORD,
        [Entry(title="github", username="harry", password="hunter2")],
    )


def _run(runner, vault, *args, input=""):
    return runner.invoke(cli, ["--vault", str(vault), *args], input=input)


def _titles(path):
    return sorted(e.title for e in _open(path).data.entries)


# --- export ---------------------------------------------------------------


def test_export_writes_a_backup_that_opens_with_the_same_password(runner, vault, tmp_path):
    backup = tmp_path / "backups" / "vault-2026-11-08.hecate"
    result = _run(runner, vault, "export", str(backup), input=f"{PASSWORD}\n")
    assert result.exit_code == 0, result.output
    assert "Encrypted backup of 1 entry written" in result.output

    assert [e.title for e in _open(backup).data.entries] == ["github"]
    assert os.stat(backup).st_mode & 0o777 == 0o600
    raw = backup.read_bytes()
    for plaintext in (b"hunter2", b"harry", b"github"):
        assert plaintext not in raw


def test_export_will_not_replace_a_file_unless_told_to(runner, vault, tmp_path):
    backup = tmp_path / "backup.hecate"
    backup.write_text("something precious")

    refused = _run(runner, vault, "export", str(backup), input=f"{PASSWORD}\n")
    assert refused.exit_code == 1
    assert "already exists" in refused.output
    assert "Master password" not in refused.output
    assert backup.read_text() == "something precious"

    forced = _run(runner, vault, "export", str(backup), "--force", input=f"{PASSWORD}\n")
    assert forced.exit_code == 0, forced.output
    assert _titles(backup) == ["github"]


def test_export_refuses_to_write_over_the_vault(runner, vault):
    result = _run(runner, vault, "export", str(vault), "--force")
    assert result.exit_code == 1
    assert "that is the vault itself" in result.output


def test_export_uses_a_live_session(runner, vault, tmp_path):
    _run(runner, vault, "unlock", input=f"{PASSWORD}\n")
    result = _run(runner, vault, "export", str(tmp_path / "b.hecate"))  # no input at all
    assert result.exit_code == 0, result.output


def test_a_vault_that_no_longer_decrypts_is_not_backed_up(runner, vault, tmp_path):
    document = json.loads(vault.read_text())
    payload = bytearray(document["payload"]["ciphertext"].encode())
    payload[10] = ord("A") if payload[10] != ord("A") else ord("B")
    document["payload"]["ciphertext"] = payload.decode()
    vault.write_text(json.dumps(document))

    backup = tmp_path / "b.hecate"
    result = _run(runner, vault, "export", str(backup), input=f"{PASSWORD}\n")
    assert result.exit_code != 0
    assert not backup.exists()


# --- import from CSV ------------------------------------------------------

CSV = (
    "name,url,username,password,totp\n"
    "gitlab,https://gitlab.com,harry,gl-pass,\n"
    f"bank,https://bank.example,harry,bank-pass,otpauth://totp/Bank?secret={TOTP_SECRET}\n"
)


@pytest.fixture
def export_csv(tmp_path):
    path = tmp_path / "chrome-export.csv"
    path.write_text(CSV)
    return path


def test_csv_import_shows_its_plan_then_adds_entries(runner, vault, export_csv):
    result = _run(runner, vault, "import", str(export_csv), input=f"{PASSWORD}\ny\n\n")
    assert result.exit_code == 0, result.output
    assert "Read 2 rows from chrome-export.csv" in result.output
    assert "password -> password" in result.output
    assert "Import 2 entries?" in result.output
    assert "Imported 2 entries" in result.output
    assert _titles(vault) == ["bank", "github", "gitlab"]
    assert _open(vault).data.find("gitlab").password == "gl-pass"


def test_csv_import_never_prints_a_password(runner, vault, export_csv):
    result = _run(runner, vault, "import", str(export_csv), input=f"{PASSWORD}\ny\n\n")
    for secret in ("gl-pass", "bank-pass", TOTP_SECRET):
        assert secret not in result.output


def test_authenticator_secrets_never_reach_the_vault(runner, vault, export_csv):
    result = _run(runner, vault, "import", str(export_csv), input=f"{PASSWORD}\ny\n\n")
    assert "Not imported: authenticator (TOTP) secrets in 1 row" in result.output
    stored = _open(vault).data.serialize().decode()
    assert TOTP_SECRET not in stored


def test_declining_imports_nothing(runner, vault, export_csv):
    result = _run(runner, vault, "import", str(export_csv), input=f"{PASSWORD}\nn\n")
    assert result.exit_code == 0, result.output
    assert "Nothing was imported" in result.output
    assert _titles(vault) == ["github"]


def test_importing_the_same_csv_twice_adds_nothing_new(runner, vault, export_csv):
    _run(runner, vault, "import", str(export_csv), input=f"{PASSWORD}\ny\n\n")
    again = _run(runner, vault, "import", str(export_csv), input=f"{PASSWORD}\n\n")
    assert again.exit_code == 0, again.output
    assert "Already in the vault, skipped: 2" in again.output
    assert "Nothing new to import" in again.output
    assert _titles(vault) == ["bank", "github", "gitlab"]


def test_a_taken_title_is_numbered_and_reported(runner, vault, tmp_path):
    path = tmp_path / "e.csv"
    path.write_text("name,username,password\ngithub,work-account,work-pass\n")
    result = _run(runner, vault, "import", str(path), input=f"{PASSWORD}\ny\n\n")
    assert "'github' is taken; it will be added as 'github (2)'" in result.output
    assert _titles(vault) == ["github", "github (2)"]
    assert _open(vault).data.find("github").password == "hunter2"  # untouched


def test_an_imported_password_already_in_use_is_flagged(runner, vault, tmp_path):
    path = tmp_path / "e.csv"
    path.write_text("name,username,password\nforum,harry,hunter2\n")
    result = _run(runner, vault, "import", str(path), input=f"{PASSWORD}\ny\n\n")
    assert "1 imported entry shares a password with another entry" in result.output


def test_the_csv_is_kept_unless_you_say_delete(runner, vault, export_csv):
    result = _run(runner, vault, "import", str(export_csv), input=f"{PASSWORD}\ny\n\n")
    assert "holds its passwords in plain text" in result.output
    assert "Delete it now? [y/N]" in result.output
    assert export_csv.exists()


def test_saying_delete_removes_the_csv(runner, vault, export_csv):
    result = _run(runner, vault, "import", str(export_csv), input=f"{PASSWORD}\ny\ny\n")
    assert result.exit_code == 0, result.output
    assert not export_csv.exists()
    assert "best effort" in result.output


def test_an_unreadable_csv_is_refused_before_unlocking(runner, vault, tmp_path):
    path = tmp_path / "e.csv"
    path.write_text("name,username\ngithub,harry\n")
    result = _run(runner, vault, "import", str(path), input=f"{PASSWORD}\n")
    assert result.exit_code == 1
    assert "no password column" in result.output
    assert "Master password" not in result.output


def test_import_refuses_the_vault_itself(runner, vault):
    result = _run(runner, vault, "import", str(vault))
    assert result.exit_code == 1
    assert "that is the vault itself" in result.output


# --- import from a backup -------------------------------------------------


def test_a_backup_restores_a_deleted_entry_with_its_history(runner, vault, tmp_path):
    current = _open(vault)
    current.data.find("github").password_history.append(
        PasswordHistoryItem(password="older", replaced_at="2025-01-01T00:00:00+00:00")
    )
    current.save()
    backup = tmp_path / "b.hecate"
    _run(runner, vault, "export", str(backup), input=f"{PASSWORD}\n")
    _run(runner, vault, "delete", "github", "--yes", input=f"{PASSWORD}\n")
    assert _titles(vault) == []

    result = _run(runner, vault, "import", str(backup), input=f"{PASSWORD}\n{PASSWORD}\ny\n")
    assert result.exit_code == 0, result.output
    restored = _open(vault).data.find("github")
    assert restored.password == "hunter2"
    assert [h.password for h in restored.password_history] == ["older"]
    assert "plain text" not in result.output  # a backup is not plaintext


def test_a_backup_is_unlocked_with_its_own_password(runner, vault, tmp_path):
    other = _make_vault(
        tmp_path / "other.hecate", BACKUP_PASSWORD, [Entry(title="bank", password="bank-pass")]
    )
    result = _run(
        runner, vault, "import", str(other), input=f"{BACKUP_PASSWORD}\n{PASSWORD}\ny\n"
    )
    assert result.exit_code == 0, result.output
    assert "Master password for the backup" in result.output
    assert _titles(vault) == ["bank", "github"]


def test_a_backup_behind_an_authenticator_asks_for_its_code(runner, vault, tmp_path):
    secret = totp_auth.generate_secret()
    other = _make_vault(
        tmp_path / "other.hecate",
        BACKUP_PASSWORD,
        [Entry(title="bank", password="bank-pass")],
        totp_secret=secret,
    )
    code = totp_auth.current_code(secret)
    result = _run(
        runner, vault, "import", str(other), input=f"{BACKUP_PASSWORD}\n{code}\n{PASSWORD}\ny\n"
    )
    assert result.exit_code == 0, result.output
    assert "Authenticator code for the backup" in result.output


def test_guessing_a_backups_password_is_rate_limited(runner, vault, tmp_path):
    other = _make_vault(tmp_path / "other.hecate", BACKUP_PASSWORD, [])
    for _ in range(ratelimit.FREE_ATTEMPTS):
        result = _run(runner, vault, "import", str(other), input="wrong\n")
        assert "incorrect master password" in result.output

    refused = _run(runner, vault, "import", str(other), input=f"{BACKUP_PASSWORD}\n")
    assert "too many failed unlock attempts" in refused.output
    assert ratelimit.check(vault) == 0  # the vault itself is not held up


def test_json_that_is_not_a_hecate_vault_is_refused(runner, vault, tmp_path):
    path = tmp_path / "bitwarden.json"
    path.write_text('{"encrypted": false, "items": []}')
    result = _run(runner, vault, "import", str(path))
    assert result.exit_code == 1
    assert "is not a Hecate vault or backup, nor a CSV file" in result.output
