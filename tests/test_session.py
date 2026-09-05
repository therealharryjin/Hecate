"""Unlock sessions: expiry, binding, and failing closed."""

import os
import time

import pytest

from hecate import config as config_mod
from hecate.auth import session as session_mod

DEK = b"\x11" * 32


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv(config_mod.HOME_ENV, str(tmp_path / "home"))
    return tmp_path / "home"


@pytest.fixture
def vault_path(tmp_path):
    path = tmp_path / "vault.hecate"
    path.write_bytes(b"{}")
    return path


def test_start_then_load_round_trip(vault_path):
    session_mod.start(vault_path, DEK, 10)
    live = session_mod.load(vault_path)
    assert live is not None
    assert live.dek == DEK


def test_default_window_is_ten_minutes(vault_path):
    started = session_mod.start(vault_path, DEK, 10)
    assert 9 * 60 < started.seconds_remaining() <= 10 * 60


def test_expired_session_is_refused_and_removed(vault_path):
    session_mod.start(vault_path, DEK, 10)
    assert session_mod.load(vault_path, now=time.time() + 11 * 60) is None
    assert not session_mod.session_path().exists()


def test_session_is_bound_to_one_vault(vault_path, tmp_path):
    session_mod.start(vault_path, DEK, 10)
    other = tmp_path / "other.hecate"
    other.write_bytes(b"{}")
    assert session_mod.load(other) is None


def test_zero_timeout_writes_no_session(vault_path):
    assert session_mod.start(vault_path, DEK, 0) is None
    assert not session_mod.session_path().exists()


def test_refresh_slides_the_idle_window(vault_path):
    live = session_mod.start(vault_path, DEK, 10)
    live.expires_at = time.time() + 30
    session_mod._write(live)

    session_mod.refresh(session_mod.load(vault_path), 10)
    assert session_mod.load(vault_path).seconds_remaining() > 9 * 60


def test_clear_ends_the_session(vault_path):
    session_mod.start(vault_path, DEK, 10)
    session_mod.clear()
    assert not session_mod.session_path().exists()
    assert session_mod.load(vault_path) is None


def test_session_file_is_owner_only(vault_path):
    session_mod.start(vault_path, DEK, 10)
    assert os.stat(session_mod.session_path()).st_mode & 0o777 == 0o600


def test_loosened_permissions_invalidate_the_session(vault_path):
    """A session readable by anyone else is treated as compromised."""
    session_mod.start(vault_path, DEK, 10)
    os.chmod(session_mod.session_path(), 0o644)
    assert session_mod.load(vault_path) is None
    assert not session_mod.session_path().exists()


def test_corrupt_session_fails_closed(vault_path):
    session_mod.start(vault_path, DEK, 10)
    session_mod.session_path().write_text("{ not json")
    os.chmod(session_mod.session_path(), 0o600)
    assert session_mod.load(vault_path) is None


def test_tampering_with_expiry_requires_forging_the_file(vault_path):
    """Expiry lives inside the session file, not in its mtime."""
    import json

    session_mod.start(vault_path, DEK, 10)
    path = session_mod.session_path()
    data = json.loads(path.read_text())
    assert "expires_at" in data
    os.utime(path, (0, 0))  # backdating the file must not matter
    assert session_mod.load(vault_path) is not None
