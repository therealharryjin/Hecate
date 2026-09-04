"""Atomic, owner-only vault file I/O.

A password manager that corrupts its vault on a badly-timed crash is worse
than no password manager, so writes go to a temporary file in the same
directory, are flushed to physical storage, and only then replace the target
via ``os.replace`` (atomic within a filesystem). The containing directory is
fsynced afterwards so the rename itself survives a power loss.
"""

from __future__ import annotations

import os
from pathlib import Path

VAULT_FILE_MODE = 0o600  # owner read/write only
DIR_MODE = 0o700


def write_atomic(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    tmp = path.with_name(f".{path.name}.tmp")

    # Open with the restrictive mode already applied, so the secret is never
    # briefly world-readable between creation and a later chmod.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, VAULT_FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, VAULT_FILE_MODE)  # defensive: umask cannot loosen it
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def read(path: Path) -> bytes:
    return Path(path).read_bytes()


def permissions_are_safe(path: Path) -> bool:
    """True when the file is not readable or writable by group or others."""
    return not (Path(path).stat().st_mode & 0o077)
