"""Failed unlocks through the CLI: when Hecate waits, and what resets the wait.

The case that matters most is the second factor. Someone who knows the master
password must not get unlimited guesses at the 6-digit code, so a correct
password alone never clears the count -- only a full unlock does.
"""

import json
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


def _wrong_code(secret):
    """A code that cannot verify now, even with clock drift."""
    now = int(time.time())
    near = {totp_auth.current_code(secret, at=now + step) for step in range(-90, 91, 30)}
    return next(code for code in (f"{n:06d}" for n in range(10**6)) if code not in near)


def _unlock(runner, path, *answers, command=("unlock",)):
    return runner.invoke(
        cli, ["--vault", str(path), *command], input="".join(f"{a}\n" for a in answers)
    )


def _fail_with_wrong_passwords(runner, path, times=ratelimit.FREE_ATTEMPTS):
    for _ in range(times):
        result = _unlock(runner, path, "wrong password")
        assert result.exit_code == 1
        assert "incorrect master password" in result.output


def _let_the_wait_pass():
    """Backdate every failure, as if the user had waited it out."""
    path = ratelimit.attempts_path()
    data = json.loads(path.read_text())
    for record in data.values():
        record["last_failure_at"] -= ratelimit.MAX_DELAY_SECONDS + 1
    path.write_text(json.dumps(data))


# --- the wait -------------------------------------------------------------


def test_a_few_typos_cost_nothing(runner, vault):
    path, secret, _ = vault
    _fail_with_wrong_passwords(runner, path, ratelimit.FREE_ATTEMPTS - 1)
    result = _unlock(runner, path, PASSWORD, totp_auth.current_code(secret))
    assert result.exit_code == 0, result.output


def test_too_many_failures_refuse_the_next_attempt_before_any_prompt(runner, vault):
    path, secret, _ = vault
    _fail_with_wrong_passwords(runner, path)

    # The right answers do not help: nothing is asked, so nothing is checked.
    refused = _unlock(runner, path, PASSWORD, totp_auth.current_code(secret))
    assert refused.exit_code == 1
    assert "too many failed unlock attempts; try again in" in refused.output
    assert "hecate recover" in refused.output
    assert "Master password" not in refused.output
    assert not session_mod.session_path().exists()


def test_the_failure_that_starts_a_wait_says_how_long(runner, vault):
    path, _secret, _ = vault
    _fail_with_wrong_passwords(runner, path, ratelimit.FREE_ATTEMPTS - 1)
    result = _unlock(runner, path, "wrong password")
    assert "wait 30s before trying again" in result.output


def test_waiting_it_out_lets_the_owner_back_in(runner, vault):
    path, secret, _ = vault
    _fail_with_wrong_passwords(runner, path)
    _let_the_wait_pass()

    result = _unlock(runner, path, PASSWORD, totp_auth.current_code(secret))
    assert result.exit_code == 0, result.output
    assert ratelimit.status(path).failures == 0


def test_a_password_only_vault_is_throttled_too(runner, tmp_path):
    path = tmp_path / "no-totp.hecate"
    Vault.create(path, PASSWORD.encode())
    _fail_with_wrong_passwords(runner, path)
    assert "too many failed" in _unlock(runner, path, PASSWORD).output


# --- the second factor ----------------------------------------------------


def test_a_correct_password_alone_does_not_reset_the_count(runner, vault):
    """Otherwise knowing the password would buy unlimited guesses at the code."""
    path, secret, _ = vault
    for _ in range(ratelimit.FREE_ATTEMPTS):
        result = _unlock(runner, path, PASSWORD, _wrong_code(secret))
        assert result.exit_code == 1
        assert "authenticator code is incorrect or expired" in result.output

    refused = _unlock(runner, path, PASSWORD, totp_auth.current_code(secret))
    assert refused.exit_code == 1
    assert "too many failed unlock attempts" in refused.output


def test_an_attempt_abandoned_at_the_code_prompt_still_counts(runner, vault):
    """The password was checked, so walking away before the code is a failure."""
    path, _secret, _ = vault
    result = _unlock(runner, path, PASSWORD)  # input ends at the code prompt
    assert result.exit_code != 0
    assert ratelimit.status(path).failures == 1


# --- telling the owner ----------------------------------------------------


def test_unlocking_after_failures_warns_about_them(runner, vault):
    path, secret, _ = vault
    _fail_with_wrong_passwords(runner, path, 2)
    result = _unlock(runner, path, PASSWORD, totp_auth.current_code(secret))
    assert result.exit_code == 0, result.output
    assert "2 failed unlock attempts since the vault was last unlocked" in result.output


def test_a_clean_unlock_warns_about_nothing(runner, vault):
    path, secret, _ = vault
    result = _unlock(runner, path, PASSWORD, totp_auth.current_code(secret))
    assert result.exit_code == 0, result.output
    assert "failed unlock" not in result.output


def test_status_shows_failed_unlocks_and_the_wait(runner, vault):
    path, _secret, _ = vault
    assert "Failed unlocks" not in runner.invoke(cli, ["--vault", str(path), "status"]).output

    _fail_with_wrong_passwords(runner, path)
    result = runner.invoke(cli, ["--vault", str(path), "status"])
    assert "Failed unlocks:  3 (next attempt in" in result.output


# --- other ways in --------------------------------------------------------


def test_enroll_authenticator_is_refused_while_waiting(runner, vault):
    """It checks the same password and code, so it must not be a way around."""
    path, secret, _ = vault
    _fail_with_wrong_passwords(runner, path)
    result = _unlock(
        runner, path, PASSWORD, totp_auth.current_code(secret),
        command=("enroll-authenticator",),
    )
    assert result.exit_code == 1
    assert "too many failed unlock attempts" in result.output


def test_enroll_authenticator_failures_count_against_unlock(runner, vault):
    path, secret, _ = vault
    for _ in range(ratelimit.FREE_ATTEMPTS):
        _unlock(runner, path, "wrong password", command=("enroll-authenticator",))
    refused = _unlock(runner, path, PASSWORD, totp_auth.current_code(secret))
    assert "too many failed unlock attempts" in refused.output


def test_recover_does_not_wait_and_clears_the_count(runner, vault, monkeypatch):
    """The recovery key is 160 bits, so there is nothing to slow down."""
    path, _secret, recovery_key = vault
    _fail_with_wrong_passwords(runner, path)
    assert ratelimit.check(path) > 0  # unlock would be refused now

    new_secret = totp_auth.generate_secret()
    monkeypatch.setattr(totp_auth, "generate_secret", lambda: new_secret)
    recovered = _unlock(
        runner, path, recovery_key, NEW_PASSWORD, NEW_PASSWORD, "",
        totp_auth.current_code(new_secret), command=("recover",),
    )
    assert recovered.exit_code == 0, recovered.output
    assert ratelimit.status(path).failures == 0

    unlocked = _unlock(runner, path, NEW_PASSWORD, totp_auth.current_code(new_secret))
    assert unlocked.exit_code == 0, unlocked.output
