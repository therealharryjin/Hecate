"""`hecate change-password` and `hecate remove-authenticator`.

Both check the current master password and, if one is enrolled, the
authenticator code first, through the same throttled path as `unlock`, even
when a session is live. A wrong
answer, a mistyped confirmation or a "no" must leave the vault file untouched.
"""

import time

import pytest
from click.testing import CliRunner

from hecate import config as config_mod
from hecate.auth import ratelimit
from hecate.auth import session as session_mod
from hecate.auth import totp as totp_auth
from hecate.cli.main import cli
from hecate.crypto import kdf
from hecate.vault.model import Entry
from hecate.vault.vault import Vault

PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "a different and longer master password"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv(config_mod.HOME_ENV, str(tmp_path / "home"))
    monkeypatch.delenv(config_mod.VAULT_ENV, raising=False)
    monkeypatch.setattr(kdf, "DEFAULT_ARGON2", kdf.FAST_ARGON2_FOR_TESTS)


@pytest.fixture
def runner():
    return CliRunner()


def _make_vault(path, *, totp):
    secret = totp_auth.generate_secret() if totp else None
    vault, _recovery = Vault.create(path, PASSWORD.encode(), totp_secret=secret)
    vault.complete_unlock(
        vault.verify_password(PASSWORD.encode()),
        totp_auth.current_code(secret) if secret else None,
    )
    vault.add(Entry(title="github", username="harry", password="hunter2"))
    vault.save()
    return path, secret


@pytest.fixture
def vault(tmp_path):
    """A vault behind password + authenticator, holding one entry."""
    return _make_vault(tmp_path / "vault.hecate", totp=True)


def _wrong_code(secret):
    """A code that cannot verify now, even with clock drift."""
    now = int(time.time())
    near = {totp_auth.current_code(secret, at=now + step) for step in range(-90, 91, 30)}
    return next(code for code in (f"{n:06d}" for n in range(10**6)) if code not in near)


def _run(runner, path, *command, answers=()):
    return runner.invoke(
        cli, ["--vault", str(path), *command], input="".join(f"{a}\n" for a in answers)
    )


def _unlock(runner, path, *answers):
    return _run(runner, path, "unlock", answers=answers)


def _change(runner, path, secret, current=PASSWORD, new=NEW_PASSWORD, repeat=None):
    answers = [current, totp_auth.current_code(secret), new, new if repeat is None else repeat]
    return _run(runner, path, "change-password", answers=answers)


# --- change-password ------------------------------------------------------


def test_change_password(runner, vault):
    path, secret = vault
    result = _change(runner, path, secret)
    assert result.exit_code == 0, result.output
    assert "Master password changed" in result.output
    assert "authenticator and recovery key have not changed" in result.output

    unlocked = _unlock(runner, path, NEW_PASSWORD, totp_auth.current_code(secret))
    assert unlocked.exit_code == 0, unlocked.output
    assert "Authenticator code" in unlocked.output  # still asked for
    shown = _run(runner, path, "get", "github")
    assert "harry" in shown.output


def test_the_old_password_stops_working(runner, vault):
    path, secret = vault
    _change(runner, path, secret)
    old = _unlock(runner, path, PASSWORD, totp_auth.current_code(secret))
    assert old.exit_code == 1
    assert "incorrect master password" in old.output


def test_change_password_asks_even_during_a_session(runner, vault):
    """A session holds the DEK, not K_master, and is no proof of who is typing."""
    path, secret = vault
    _unlock(runner, path, PASSWORD, totp_auth.current_code(secret))
    result = _run(runner, path, "change-password")  # no answers at all
    assert result.exit_code != 0
    assert "Current master password" in result.output


def test_change_password_ends_any_live_session(runner, vault):
    path, secret = vault
    _unlock(runner, path, PASSWORD, totp_auth.current_code(secret))
    assert session_mod.session_path().exists()
    assert _change(runner, path, secret).exit_code == 0
    assert not session_mod.session_path().exists()


def test_a_wrong_current_password_changes_nothing_and_counts(runner, vault):
    path, secret = vault
    original = path.read_bytes()
    result = _change(runner, path, secret, current="wrong password")
    assert result.exit_code == 1
    assert "incorrect master password" in result.output
    assert "New master password" not in result.output
    assert path.read_bytes() == original
    assert ratelimit.status(path).failures == 1


def test_a_wrong_code_changes_nothing(runner, vault):
    path, secret = vault
    original = path.read_bytes()
    answers = [PASSWORD, _wrong_code(secret), NEW_PASSWORD, NEW_PASSWORD]
    result = _run(runner, path, "change-password", answers=answers)
    assert result.exit_code == 1
    assert "authenticator code is incorrect" in result.output
    assert path.read_bytes() == original


def test_change_password_is_refused_while_waiting(runner, vault):
    """It checks the same password and code as unlock, so it waits like unlock."""
    path, secret = vault
    for _ in range(ratelimit.FREE_ATTEMPTS):
        _unlock(runner, path, "wrong password")
    result = _change(runner, path, secret)
    assert result.exit_code == 1
    assert "too many failed unlock attempts" in result.output
    assert "Current master password" not in result.output


def test_a_mistyped_confirmation_changes_nothing(runner, vault):
    path, secret = vault
    original = path.read_bytes()
    result = _change(runner, path, secret, repeat="something else")
    assert result.exit_code != 0
    assert path.read_bytes() == original
    assert _unlock(runner, path, PASSWORD, totp_auth.current_code(secret)).exit_code == 0


def test_the_same_password_is_refused(runner, vault):
    path, secret = vault
    original = path.read_bytes()
    result = _change(runner, path, secret, new=PASSWORD)
    assert result.exit_code == 1
    assert "same as the current one; nothing was changed" in result.output
    assert path.read_bytes() == original


def test_passwords_are_never_echoed(runner, vault):
    path, secret = vault
    result = _change(runner, path, secret)
    assert PASSWORD not in result.output
    assert NEW_PASSWORD not in result.output


def test_a_backup_from_before_keeps_the_old_password(runner, vault, tmp_path):
    """What the closing message and the README promise about older copies."""
    path, secret = vault
    backup = tmp_path / "backup.hecate"
    _run(runner, path, "export", str(backup), answers=[PASSWORD, totp_auth.current_code(secret)])
    _change(runner, path, secret)

    old = Vault.load(backup)
    old.complete_unlock(old.verify_password(PASSWORD.encode()), totp_auth.current_code(secret))
    assert old.data.find("github").password == "hunter2"


def test_a_password_only_vault_is_not_asked_for_a_code(runner, tmp_path):
    path, _ = _make_vault(tmp_path / "plain.hecate", totp=False)
    result = _run(runner, path, "change-password", answers=[PASSWORD, NEW_PASSWORD, NEW_PASSWORD])
    assert result.exit_code == 0, result.output
    assert "Authenticator code" not in result.output
    assert _unlock(runner, path, NEW_PASSWORD).exit_code == 0


def test_change_password_without_a_vault(runner, tmp_path):
    result = _run(runner, tmp_path / "missing.hecate", "change-password")
    assert result.exit_code == 1
    assert "no vault at" in result.output


# --- remove-authenticator -------------------------------------------------


def _remove(runner, path, secret, *, confirm="y"):
    answers = [PASSWORD, totp_auth.current_code(secret), confirm]
    return _run(runner, path, "remove-authenticator", answers=answers)


def test_remove_authenticator(runner, vault):
    path, secret = vault
    result = _remove(runner, path, secret)
    assert result.exit_code == 0, result.output
    assert "anyone with the master password can unlock" in result.output
    assert "Authenticator removed" in result.output

    unlocked = _unlock(runner, path, PASSWORD)
    assert unlocked.exit_code == 0, unlocked.output
    assert "Authenticator code" not in unlocked.output


def test_declining_keeps_the_authenticator(runner, vault):
    path, secret = vault
    original = path.read_bytes()
    result = _remove(runner, path, secret, confirm="n")
    assert result.exit_code == 0, result.output
    assert "Nothing was changed" in result.output
    assert path.read_bytes() == original


def test_the_default_answer_is_no(runner, vault):
    path, secret = vault
    original = path.read_bytes()
    result = _remove(runner, path, secret, confirm="")
    assert "Remove the authenticator? [y/N]" in result.output
    assert path.read_bytes() == original


def test_removing_needs_a_current_code(runner, vault):
    path, secret = vault
    original = path.read_bytes()
    answers = [PASSWORD, _wrong_code(secret), "y"]
    result = _run(runner, path, "remove-authenticator", answers=answers)
    assert result.exit_code == 1
    assert "authenticator code is incorrect" in result.output
    assert path.read_bytes() == original
    assert ratelimit.status(path).failures == 1


def test_remove_authenticator_ends_any_live_session(runner, vault):
    path, secret = vault
    _unlock(runner, path, PASSWORD, totp_auth.current_code(secret))
    assert _remove(runner, path, secret).exit_code == 0
    assert not session_mod.session_path().exists()


def test_a_password_only_vault_has_nothing_to_remove(runner, tmp_path):
    path, _ = _make_vault(tmp_path / "plain.hecate", totp=False)
    original = path.read_bytes()
    result = _run(runner, path, "remove-authenticator", answers=[PASSWORD])
    assert result.exit_code == 0, result.output
    assert "no authenticator to remove; nothing was changed" in result.output
    assert path.read_bytes() == original


def test_an_authenticator_can_be_enrolled_again(runner, vault, monkeypatch):
    path, secret = vault
    _remove(runner, path, secret)

    again = totp_auth.generate_secret()
    monkeypatch.setattr(totp_auth, "generate_secret", lambda: again)
    enrolled = _run(
        runner, path, "enroll-authenticator",
        answers=[PASSWORD, "", totp_auth.current_code(again)],
    )
    assert enrolled.exit_code == 0, enrolled.output
    unlocked = _unlock(runner, path, PASSWORD, totp_auth.current_code(again))
    assert unlocked.exit_code == 0, unlocked.output
