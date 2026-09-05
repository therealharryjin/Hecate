"""User settings: defaults, validation, and persistence."""

import json
import os

import pytest

from hecate import config as config_mod


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv(config_mod.HOME_ENV, str(tmp_path / "home"))
    monkeypatch.delenv(config_mod.VAULT_ENV, raising=False)
    return tmp_path / "home"


def test_session_timeout_defaults_to_ten_minutes():
    assert config_mod.load().session_timeout_minutes == 10
    assert config_mod.DEFAULT_SESSION_TIMEOUT_MINUTES == 10


def test_defaults_apply_with_no_config_file(isolated_home):
    assert not config_mod.config_path().exists()
    assert config_mod.load().session_enabled


def test_set_and_reload_round_trip():
    cfg = config_mod.load()
    cfg.set("session-timeout", "25")
    config_mod.save(cfg)
    assert config_mod.load().session_timeout_minutes == 25


def test_zero_disables_the_session():
    cfg = config_mod.load()
    cfg.set("session-timeout", "0")
    assert not cfg.session_enabled


@pytest.mark.parametrize("bad", ["-1", "abc", "", "1441", "3.5"])
def test_invalid_session_timeouts_are_rejected(bad):
    cfg = config_mod.load()
    with pytest.raises(ValueError):
        cfg.set("session-timeout", bad)


def test_upper_bound_is_accepted_but_beyond_is_not():
    cfg = config_mod.load()
    cfg.set("session-timeout", str(config_mod.MAX_SESSION_TIMEOUT_MINUTES))
    with pytest.raises(ValueError):
        cfg.set("session-timeout", str(config_mod.MAX_SESSION_TIMEOUT_MINUTES + 1))


def test_unknown_setting_is_rejected_with_a_helpful_message():
    cfg = config_mod.load()
    with pytest.raises(KeyError, match="known settings"):
        cfg.set("sesion-timeout", "10")


def test_invalid_value_does_not_mutate_the_config():
    cfg = config_mod.load()
    with pytest.raises(ValueError):
        cfg.set("session-timeout", "-5")
    assert cfg.session_timeout_minutes == 10


def test_config_file_is_owner_only():
    config_mod.save(config_mod.load())
    assert os.stat(config_mod.config_path()).st_mode & 0o777 == 0o600


def test_unknown_keys_in_the_file_are_ignored():
    path = config_mod.config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"session_timeout_minutes": 7, "from_future": True}))
    assert config_mod.load().session_timeout_minutes == 7


def test_corrupt_config_raises_a_clear_error():
    path = config_mod.config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        config_mod.load()


def test_vault_path_honours_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv(config_mod.VAULT_ENV, str(tmp_path / "elsewhere.hecate"))
    assert config_mod.default_vault_path() == tmp_path / "elsewhere.hecate"


def test_every_setting_documents_itself():
    for name, setting in config_mod.SETTINGS.items():
        assert setting.help.strip(), f"{name} has no help text"
