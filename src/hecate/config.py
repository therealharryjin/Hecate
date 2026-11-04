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

from .generator import passphrase as passphrase_gen
from .generator import password as password_gen

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


_TRUE = {"on", "true", "yes", "1"}
_FALSE = {"off", "false", "no", "0"}


def _parse_switch(raw: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ValueError(f"expected on or off, got {raw!r}")


def _parse_choice(*choices: str) -> Callable[[str], str]:
    def parse(raw: str) -> str:
        lowered = raw.strip().lower()
        if lowered not in choices:
            raise ValueError(f"expected one of {', '.join(choices)}, got {raw!r}")
        return lowered

    return parse


def _show_switch(value: bool) -> str:
    return "on" if value else "off"


def _show_text(value: str) -> str:
    # Quoted, so an empty value or a lone space is still visible.
    return f"'{value}'"


class Setting(NamedTuple):
    field: str
    parse: Callable[[str], Any]
    help: str
    show: Callable[[Any], str] = str


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
    # --- hecate generate ---------------------------------------------------
    "generate-type": Setting(
        field="generate_type",
        parse=_parse_choice("password", "passphrase"),
        help="What 'hecate generate' makes by default: password (random characters) or passphrase (random words).",
    ),
    "generate-save-prompt": Setting(
        field="generate_save_prompt",
        parse=_parse_switch,
        help="Whether 'hecate generate' asks to save what it made into the vault. off never asks.",
        show=_show_switch,
    ),
    "password-length": Setting(
        field="password_length",
        parse=_parse_bounded_int(password_gen.MIN_LENGTH, password_gen.MAX_LENGTH),
        help=f"Characters in a generated password ({password_gen.MIN_LENGTH}-{password_gen.MAX_LENGTH}).",
    ),
    "password-uppercase": Setting(
        field="password_uppercase",
        parse=_parse_switch,
        help="Use uppercase letters (A-Z) in generated passwords.",
        show=_show_switch,
    ),
    "password-lowercase": Setting(
        field="password_lowercase",
        parse=_parse_switch,
        help="Use lowercase letters (a-z) in generated passwords.",
        show=_show_switch,
    ),
    "password-digits": Setting(
        field="password_digits",
        parse=_parse_switch,
        help="Use digits (0-9) in generated passwords.",
        show=_show_switch,
    ),
    "password-symbols": Setting(
        field="password_symbols",
        parse=password_gen.parse_symbols,
        help="Special characters generated passwords may use. '' leaves them out. Letters, digits and spaces are refused; repeats are dropped.",
        show=_show_text,
    ),
    "passphrase-words": Setting(
        field="passphrase_words",
        parse=_parse_bounded_int(passphrase_gen.MIN_WORDS, passphrase_gen.MAX_WORDS),
        help=f"Words in a generated passphrase ({passphrase_gen.MIN_WORDS}-{passphrase_gen.MAX_WORDS}).",
    ),
    "passphrase-separator": Setting(
        field="passphrase_separator",
        parse=passphrase_gen.parse_separator,
        help=f"What goes between passphrase words: up to {passphrase_gen.MAX_SEPARATOR_LENGTH} spaces or punctuation characters, or '' for nothing.",
        show=_show_text,
    ),
    "passphrase-capitalize": Setting(
        field="passphrase_capitalize",
        parse=_parse_switch,
        help="Capitalise the first letter of every passphrase word.",
        show=_show_switch,
    ),
    "passphrase-number": Setting(
        field="passphrase_number",
        parse=_parse_switch,
        help="Add one random digit to one random passphrase word, for sites that demand a number.",
        show=_show_switch,
    ),
}


@dataclasses.dataclass
class Config:
    session_timeout_minutes: int = DEFAULT_SESSION_TIMEOUT_MINUTES
    clipboard_clear_seconds: int = DEFAULT_CLIPBOARD_CLEAR_SECONDS
    generate_type: str = "password"
    generate_save_prompt: bool = True
    password_length: int = password_gen.DEFAULT_LENGTH
    password_uppercase: bool = True
    password_lowercase: bool = True
    password_digits: bool = True
    password_symbols: str = password_gen.DEFAULT_SYMBOLS
    passphrase_words: int = passphrase_gen.DEFAULT_WORDS
    passphrase_separator: str = passphrase_gen.DEFAULT_SEPARATOR
    passphrase_capitalize: bool = False
    passphrase_number: bool = False

    @property
    def session_enabled(self) -> bool:
        return self.session_timeout_minutes > 0

    def password_policy(self) -> password_gen.PasswordPolicy:
        return password_gen.PasswordPolicy(
            length=self.password_length,
            uppercase=self.password_uppercase,
            lowercase=self.password_lowercase,
            digits=self.password_digits,
            symbols=self.password_symbols,
        )

    def passphrase_policy(self) -> passphrase_gen.PassphrasePolicy:
        return passphrase_gen.PassphrasePolicy(
            words=self.passphrase_words,
            separator=self.passphrase_separator,
            capitalize=self.passphrase_capitalize,
            number=self.passphrase_number,
        )

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    def get(self, name: str) -> Any:
        return getattr(self, _setting(name).field)

    def show(self, name: str) -> str:
        """The value as ``config list`` and ``config get`` print it."""
        return _setting(name).show(self.get(name))

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
