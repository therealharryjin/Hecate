"""Backoff on failed unlock attempts.

What this buys, and what it does not
------------------------------------
Every unlock through Hecate's own prompts -- master password, then
authenticator code -- is counted. After a few consecutive failures the next
attempt is refused until a wait has passed, and the wait doubles with each
further failure, up to a cap. Only a full unlock, both factors, resets it.

That slows guessing *through Hecate*: someone at your keyboard trying master
passwords, or someone who watched you type the password trying authenticator
codes. Without it, a 6-digit code falls to about 333,000 guesses on average,
each costing one Argon2id derivation -- hours to days of scripting. With it,
once the wait reaches its cap, about 24 guesses a day get through.

It is a gate, not cryptography. It does nothing against:

  * An attacker with a copy of the vault file. They never go through these
    prompts; Argon2id and the master password's strength stand in their way.
  * Anyone who can run commands as you. The count lives in a file you own, so
    they can delete it -- and they could copy the vault file anyway.

Counting before checking
------------------------
An attempt is recorded as failed *before* the guess is checked, and the record
is cleared only once both factors have passed. Killing the process mid-check,
or racing many processes at once, therefore cannot get a guess checked without
it being counted. The count is read and rewritten under an exclusive lock
where the platform has one (``fcntl``).

Not a setting
-------------
The thresholds are constants on purpose: ``hecate config set`` needs no
unlock, so a setting would be an off switch for whoever is guessing.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import time
from pathlib import Path
from typing import IO, Iterator

from ..config import DIR_MODE, FILE_MODE, hecate_home

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows has no fcntl
    fcntl = None  # type: ignore[assignment]

#: Consecutive failures allowed with no wait, so a typo or two costs nothing.
FREE_ATTEMPTS = 3
#: The wait after the first failure beyond the free ones. It doubles from there.
BASE_DELAY_SECONDS = 30
#: The longest wait. Reached after 10 consecutive failures; past it, an
#: attempt an hour is about 24 a day, which puts guessing a 6-digit code
#: decades away.
MAX_DELAY_SECONDS = 60 * 60


def attempts_path() -> Path:
    return hecate_home() / "unlock-attempts.json"


class Throttled(Exception):
    """Too many recent failures: this attempt is refused without being checked."""

    def __init__(self, wait_seconds: float) -> None:
        super().__init__(f"try again in {wait_seconds:.0f} seconds")
        self.wait_seconds = wait_seconds


def delay_after(failures: int) -> int:
    """Seconds to wait after this many consecutive failures."""
    if failures < FREE_ATTEMPTS:
        return 0
    # Clamp the exponent, so a doctored count cannot make this a huge number.
    doublings = min(failures - FREE_ATTEMPTS, 32)
    return min(MAX_DELAY_SECONDS, BASE_DELAY_SECONDS * 2**doublings)


@dataclasses.dataclass(frozen=True)
class Record:
    """Consecutive failed unlocks of one vault, and when the last one began."""

    failures: int = 0
    last_failure_at: float = 0.0

    def wait_seconds(self, *, now: float | None = None) -> float:
        """Seconds until the next attempt is allowed; 0 means now."""
        delay = delay_after(self.failures)
        if delay == 0:
            return 0.0
        elapsed = (time.time() if now is None else now) - self.last_failure_at
        # A clock that has gone backwards makes elapsed negative. Cap the wait
        # at one full delay, so a clock change cannot lock anyone out for days.
        return max(0.0, min(float(delay), delay - elapsed))


def status(vault_path: Path) -> Record:
    """The current record for this vault, for display."""
    if not attempts_path().exists():
        return Record()
    with _locked_file() as handle:
        return _read(handle).get(_key(vault_path), Record())


def check(vault_path: Path, *, now: float | None = None) -> float:
    """Seconds until this vault may be tried again; 0 means now.

    For refusing before the user types anything. :func:`begin` checks again,
    under the lock, because another process may have failed in between.
    """
    return status(vault_path).wait_seconds(now=now)


def begin(vault_path: Path, *, now: float | None = None) -> int:
    """Count an attempt as failed before it is checked.

    Returns how many consecutive failures came before this one. Raises
    :class:`Throttled`, recording nothing, if an attempt is not allowed yet.
    Call :func:`reset` once both factors have passed.
    """
    now = time.time() if now is None else now
    key = _key(vault_path)
    with _locked_file() as handle:
        records = _read(handle)
        current = records.get(key, Record())
        wait = current.wait_seconds(now=now)
        if wait > 0:
            raise Throttled(wait)
        records[key] = Record(failures=current.failures + 1, last_failure_at=now)
        _write(handle, records)
    return current.failures


def reset(vault_path: Path) -> None:
    """Forget this vault's failures, after a full unlock or a recovery."""
    if not attempts_path().exists():
        return
    key = _key(vault_path)
    with _locked_file() as handle:
        records = _read(handle)
        if records.pop(key, None) is not None:
            _write(handle, records)


def _key(vault_path: Path) -> str:
    return str(Path(vault_path).resolve())


@contextlib.contextmanager
def _locked_file() -> Iterator[IO[bytes]]:
    """Open the record file, creating it 0600, and hold an exclusive lock.

    The file is rewritten in place rather than replaced, so every process
    locks the same file. The file is never deleted for the same reason.
    """
    path = attempts_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, FILE_MODE)
    with os.fdopen(fd, "r+b") as handle:
        os.chmod(path, FILE_MODE)
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield handle  # closing the file releases the lock


def _read(handle: IO[bytes]) -> dict[str, Record]:
    """Parse the records, dropping anything malformed.

    An unreadable record counts as no failures. Anyone able to corrupt the
    file could delete it instead, so refusing to unlock would punish only the
    owner.
    """
    handle.seek(0)
    try:
        data = json.loads(handle.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}

    records: dict[str, Record] = {}
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        failures = value.get("failures")
        last = value.get("last_failure_at")
        if (
            isinstance(failures, int)
            and not isinstance(failures, bool)
            and failures >= 0
            and isinstance(last, (int, float))
            and not isinstance(last, bool)
        ):
            records[key] = Record(failures=failures, last_failure_at=float(last))
    return records


def _write(handle: IO[bytes], records: dict[str, Record]) -> None:
    payload = json.dumps(
        {key: dataclasses.asdict(record) for key, record in records.items()},
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    handle.seek(0)
    handle.truncate()
    handle.write(payload)
    handle.flush()
    os.fsync(handle.fileno())
