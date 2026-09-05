"""User settings, stored as JSON under the Hecate home directory.

Settings are deliberately a small, explicit registry rather than a free-form
dict: every key that ``hecate config set`` accepts is declared here with a
parser and a validator, so an unknown or out-of-range value is rejected at the
boundary instead of being written to disk and blowing up on next read.

Nothing secret belongs in this file. It is still written 0600, because the
vault path alone is worth not advertising.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from typing import Any, Callable, NamedTuple

HOME_ENV = "HECATE_HOME"
VAULT_ENV = "HECATE_VAULT"

DEFAULT_SESSION_TIMEOUT_MINUTES = 10
#: A day is already generous for a password manager; beyond this the setting
#: is indistinguishable from "never lock", which `lock` and 0 already express.
MAX_SESSION_TIMEOUT_MINUTES = 1440

DEFAULT_CLIPBOARD_CLEAR_SECONDS = 15
MAX_CLIPBOARD_CLEAR_SECONDS = 300

DIR_MODE = 0o700
FILE_MODE = 0o600


def hecate_home() -> Path:
    """Directory holding the config, the default vault, and the session."""
    override = os.environ.get(HOME_ENV)
    return Path(override).expanduser() if override else Path.home() / ".hecate"


def config_path() -> Path:
    return hecate_home() / "config.json"


def default_vault_path() -> Path:
    override = os.environ.get(VAULT_ENV)
    return Path(override).expanduser() if override else hecate_home() / "vault.hecate"


def _parse_bounded_int(low: int, high: int) -> Callable[[str], int]:
    def parse(raw: str) -> int:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise ValueError(f"expected a whole number, got {raw!r}") from None
        if not low <= value <= high:
            raise ValueError(f"must be between {low} and {high}, got {value}")
        return value

    return parse


class Setting(NamedTuple):
    field: str
    parse: Callable[[str], Any]
    help: str


#: CLI name -> setting. The CLI surface is generated from this, so adding a
#: setting here is enough to make it settable and listable.
SETTINGS: dict[str, Setting] = {
    "session-timeout": Setting(
        field="session_timeout_minutes",
        parse=_parse_bounded_int(0, MAX_SESSION_TIMEOUT_MINUTES),
        help=(
            "Minutes of inactivity before the vault re-locks and both factors "
            "are required again. 0 disables the session entirely, prompting on "
            "every command."
        ),
    ),
    "clipboard-clear": Setting(
        field="clipboard_clear_seconds",
        parse=_parse_bounded_int(0, MAX_CLIPBOARD_CLEAR_SECONDS),
        help="Seconds before a copied secret is cleared from the clipboard. 0 disables copying.",
    ),
}


@dataclasses.dataclass
class Config:
    session_timeout_minutes: int = DEFAULT_SESSION_TIMEOUT_MINUTES
    clipboard_clear_seconds: int = DEFAULT_CLIPBOARD_CLEAR_SECONDS

    @property
    def session_enabled(self) -> bool:
        return self.session_timeout_minutes > 0

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    def get(self, name: str) -> Any:
        return getattr(self, _setting(name).field)

    def set(self, name: str, raw: str) -> Any:
        setting = _setting(name)
        value = setting.parse(raw)
        setattr(self, setting.field, value)
        return value


def _setting(name: str) -> Setting:
    try:
        return SETTINGS[name]
    except KeyError:
        known = ", ".join(sorted(SETTINGS))
        raise KeyError(f"unknown setting {name!r}; known settings: {known}") from None


def load() -> Config:
    """Read the config, falling back to defaults for anything missing.

    An unreadable or corrupt config must not lock the user out of their own
    vault, so unknown keys are ignored and a malformed file raises a clear
    error rather than a JSON traceback.
    """
    path = config_path()
    if not path.exists():
        return Config()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"config file at {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"config file at {path} must contain a JSON object")

    known = {f.name for f in dataclasses.fields(Config)}
    return Config(**{k: v for k, v in data.items() if k in known})


def save(config: Config) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(config.as_dict(), handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(path, FILE_MODE)
