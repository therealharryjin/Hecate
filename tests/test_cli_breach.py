"""`hecate check-breach`: what it reports, and that it never prints a password.

The network is replaced with a fake session built from {password: times seen}.
"""

import pytest
import requests
from click.testing import CliRunner

from hecate import config as config_mod
from hecate.breach import hibp
from hecate.cli.main import cli
from hecate.crypto import kdf
from hecate.vault.model import Entry
from hecate.vault.vault import Vault

PASSWORD = "correct horse battery staple"
BREACHED = {"hunter2": 17043, "123456": 37359195}
ENTRIES = [
    Entry(title="github", username="harry", password="hunter2"),
    Entry(title="forum", password="123456"),
    Entry(title="bank", username="harry", password="v8#Lq2-unique-and-unbreached"),
]


class FakeResponse:
    def __init__(self, text):
        self.status_code = 200
        self.text = text


class FakeSession:
    def __init__(self, breached):
        self.bodies = {}
        for password, times in breached.items():
            digest = hibp.sha1_hex(password)
            self.bodies.setdefault(digest[:5], []).append(f"{digest[5:]}:{times}")
        self.calls = []

    def get(self, url, **_kwargs):
        prefix = url.rsplit("/", 1)[-1]
        self.calls.append(prefix)
        return FakeResponse("\r\n".join(self.bodies.get(prefix, [])))


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv(config_mod.HOME_ENV, str(tmp_path / "home"))
    monkeypatch.delenv(config_mod.VAULT_ENV, raising=False)
    monkeypatch.setattr(kdf, "DEFAULT_ARGON2", kdf.FAST_ARGON2_FOR_TESTS)


@pytest.fixture
def service(monkeypatch):
    session = FakeSession(BREACHED)
    monkeypatch.setattr(hibp, "_new_session", lambda: session)
    return session


@pytest.fixture
def runner():
    return CliRunner()


def _vault(tmp_path, entries):
    path = tmp_path / "vault.hecate"
    vault, _recovery = Vault.create(path, PASSWORD.encode())
    vault.complete_unlock(vault.verify_password(PASSWORD.encode()))
    for entry in entries:
        vault.add(Entry(title=entry.title, username=entry.username, password=entry.password))
    vault.save()
    return path


@pytest.fixture
def vault(tmp_path):
    return _vault(tmp_path, ENTRIES)


def _check(runner, path, *args):
    return runner.invoke(
        cli, ["--vault", str(path), "check-breach", *args], input=f"{PASSWORD}\n"
    )


# --- the whole vault ------------------------------------------------------


def test_breached_entries_are_listed_most_seen_first(runner, vault, service):
    result = _check(runner, vault)
    assert result.exit_code == 0, result.output
    assert "2 of 3 passwords appear in known breaches" in result.output
    forum = result.output.index("forum: seen 37,359,195 times")
    github = result.output.index("github (harry): seen 17,043 times")
    assert forum < github
    assert "bank" not in result.stdout


def test_no_password_is_ever_printed(runner, vault, service):
    result = _check(runner, vault)
    for entry in ENTRIES:
        assert entry.password not in result.output


def test_a_clean_vault_says_so_without_overclaiming(runner, tmp_path, service):
    path = _vault(tmp_path, [ENTRIES[2]])
    result = _check(runner, path)
    assert result.exit_code == 0, result.output
    assert "None of the 1 password appear in known breaches" in result.output
    assert "not proof of strength" in result.output


def test_the_user_is_told_what_is_sent(runner, vault, service):
    result = _check(runner, vault)
    assert "Only the first 5 characters of each SHA-1 hash are sent" in result.stderr


def test_a_password_shared_by_entries_is_looked_up_once(runner, tmp_path, service):
    path = _vault(
        tmp_path,
        [Entry(title=t, password="hunter2") for t in ("a", "b", "c")],
    )
    result = _check(runner, path)
    assert result.exit_code == 0, result.output
    assert service.calls == [hibp.sha1_hex("hunter2")[:5]]
    assert "3 of 3 passwords appear" in result.output


def test_an_empty_vault_sends_nothing(runner, tmp_path, service):
    path = _vault(tmp_path, [])
    result = _check(runner, path)
    assert result.exit_code == 0, result.output
    assert "No passwords to check" in result.output
    assert service.calls == []


# --- one entry ------------------------------------------------------------


def test_one_breached_entry(runner, vault, service):
    result = _check(runner, vault, "github")
    assert result.exit_code == 0, result.output
    assert "github (harry): seen 17,043 times in known breaches. Change it." in result.output
    assert len(service.calls) == 1


def test_one_clean_entry(runner, vault, service):
    result = _check(runner, vault, "bank")
    assert result.exit_code == 0, result.output
    assert "bank (harry): not found in known breaches." in result.output


def test_an_unknown_entry_is_an_error(runner, vault, service):
    result = _check(runner, vault, "nope")
    assert result.exit_code == 1
    assert "no entry titled 'nope'" in result.output
    assert service.calls == []


# --- failure and scope ----------------------------------------------------


def test_an_unreachable_service_fails_cleanly(runner, vault, monkeypatch):
    class Down:
        def get(self, url, **_kwargs):
            raise requests.ConnectionError(url)

    monkeypatch.setattr(hibp, "_new_session", Down)
    result = _check(runner, vault)
    assert result.exit_code == 1
    assert "could not reach Have I Been Pwned (ConnectionError)" in result.output
    assert "the check did not finish" in result.output
    assert hibp.API_URL not in result.output


def test_no_other_command_checks_breaches(runner, vault, monkeypatch):
    """The only network request is the one you ask for."""

    def forbidden():
        raise AssertionError("a breach check ran without being asked for")

    monkeypatch.setattr(hibp, "_new_session", forbidden)
    for args in (["list"], ["get", "github"], ["get", "github", "--show"]):
        result = runner.invoke(cli, ["--vault", str(vault), *args], input=f"{PASSWORD}\n")
        assert result.exit_code == 0, result.output
