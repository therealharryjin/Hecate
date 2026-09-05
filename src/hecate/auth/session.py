"""Unlock sessions: hold the DEK for a bounded idle window.

What a session actually costs
-----------------------------
A session exists so that ``hecate get github`` does not demand a password and
a phone every single time. That convenience has one unavoidable consequence:
for the length of the window, the data-encryption key must be recoverable by a
later process **with no user input**. Anything recoverable with no input is
recoverable by any process running as that user.

So the session file is a genuine reduction in security, and no amount of
encrypting-it-with-a-key-stored-next-to-it would change that -- that would be
theatre, not defence. What actually helps is kept small and real:

  * ``0600`` on the file, ``0700`` on its directory, applied at ``open()``.
  * A refusal to load a session whose permissions have been loosened.
  * The expiry stored *inside* the file, so extending a session means forging
    it rather than touching a timestamp.
  * Binding to one vault path, so a session for one vault cannot open another.
  * A short default window, and ``session-timeout 0`` to opt out entirely.

Users who want no key at rest should set ``session-timeout`` to 0.

The window is *idle* time, not absolute: each successful use pushes the expiry
out again, so a working session does not expire mid-task, while a walked-away-
from terminal locks on schedule.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import time
from pathlib import Path

from ..config import DIR_MODE, FILE_MODE, hecate_home


def session_path() -> Path:
    return hecate_home() / "session.json"


class SessionError(Exception):
    pass


@dataclasses.dataclass
class Session:
    vault_path: str
    dek: bytes
    expires_at: float

    def seconds_remaining(self, *, now: float | None = None) -> float:
        return max(0.0, self.expires_at - (time.time() if now is None else now))

    def is_valid_for(self, vault_path: Path, *, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return (
            self.vault_path == str(Path(vault_path).resolve())
            and self.expires_at > now
        )


def start(vault_path: Path, dek: bytes, timeout_minutes: int) -> Session | None:
    """Persist a session. Returns ``None`` when sessions are disabled."""
    if timeout_minutes <= 0:
        clear()
        return None
    session = Session(
        vault_path=str(Path(vault_path).resolve()),
        dek=dek,
        expires_at=time.time() + timeout_minutes * 60,
    )
    _write(session)
    return session


def load(vault_path: Path, *, now: float | None = None) -> Session | None:
    """Return a live session for this vault, or ``None``.

    Any problem -- missing, corrupt, expired, wrong vault, loose permissions --
    resolves to ``None`` and a re-prompt. Failing closed here costs one
    password entry; failing open would cost the vault.
    """
    path = session_path()
    if not path.exists():
        return None
    if not _permissions_are_safe(path):
        clear()
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        session = Session(
            vault_path=data["vault_path"],
            dek=base64.b64decode(data["dek"]),
            expires_at=float(data["expires_at"]),
        )
    except (KeyError, ValueError, TypeError, json.JSONDecodeError, OSError):
        clear()
        return None

    if not session.is_valid_for(vault_path, now=now):
        clear()
        return None
    return session


def refresh(session: Session, timeout_minutes: int) -> None:
    """Slide the idle window forward after a successful command."""
    if timeout_minutes <= 0:
        clear()
        return
    session.expires_at = time.time() + timeout_minutes * 60
    _write(session)


def clear() -> None:
    """End the session. Best-effort overwrite before unlinking.

    Overwriting a file's bytes does not reliably erase them on a
    copy-on-write or log-structured filesystem, so this reduces the window
    rather than guaranteeing erasure.
    """
    path = session_path()
    try:
        size = path.stat().st_size
        with open(path, "r+b") as handle:
            handle.write(b"\x00" * size)
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, ValueError):
        pass
    finally:
        path.unlink(missing_ok=True)


def _write(session: Session) -> None:
    path = session_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    payload = json.dumps(
        {
            "vault_path": session.vault_path,
            "dek": base64.b64encode(session.dek).decode("ascii"),
            "expires_at": session.expires_at,
        }
    ).encode("utf-8")

    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, FILE_MODE)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _permissions_are_safe(path: Path) -> bool:
    return not (path.stat().st_mode & 0o077)
