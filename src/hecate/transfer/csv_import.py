"""Read password exports from other managers, which are CSV files.

Every manager names its columns differently, so columns are matched by name:
case, spaces, underscores and hyphens are ignored, and each Hecate field has a
list of names it answers to, best first. Where several columns could fill a
field -- Proton Pass has both ``username`` and ``email`` -- the first one with
a value in that row wins.

Never imported
--------------
One-time-password secrets (``totp``, ``login_totp``, ``otpauth`` ...). Hecate
is not an authenticator app and has no per-entry TOTP field, so those columns
are counted, reported, and dropped. Passwords are kept exactly as exported,
surrounding spaces included.

The file itself
---------------
An export holds every password in plain text. Hecate reads it and never writes
it anywhere, but it is still on disk afterwards, so the CLI offers to delete it
with :func:`remove_plaintext`.
"""

from __future__ import annotations

import csv
import dataclasses
import os
import re
import urllib.parse
from pathlib import Path

from ..vault.model import Entry

#: Hecate field -> the column names it answers to, best first, normalised.
FIELDS: dict[str, tuple[str, ...]] = {
    "title": ("title", "name", "item name", "account"),
    "username": ("username", "login username", "user name", "login name", "user", "email", "e mail"),
    "password": ("password", "login password"),
    "url": ("url", "login uri", "uri", "login url", "website", "web site"),
    "notes": ("notes", "note", "extra", "comments", "comment"),
    "tags": ("tags", "folder", "grouping", "group", "category"),
}

#: Columns holding one-time-password secrets, which are never imported.
TOTP_COLUMNS = frozenset(
    {"totp", "login totp", "otpauth", "otp", "otpsecret", "otp secret", "one time password", "2fa"}
)

FALLBACK_TITLE = "Imported entry"


class ImportFormatError(ValueError):
    """The file is not a CSV export Hecate can read. Never quotes a value."""


@dataclasses.dataclass
class CsvImport:
    entries: list[Entry]
    #: Hecate field -> the columns that fed it, as spelled in the file.
    columns: dict[str, list[str]]
    ignored_columns: list[str]
    rows: int
    skipped_without_password: int
    rows_with_totp: int


def normalise(header: str) -> str:
    return re.sub(r"[\s_\-]+", " ", header.strip().lower())


def read_csv(path: Path) -> CsvImport:
    path = Path(path)
    try:
        # newline="" keeps line breaks inside quoted values intact.
        with open(path, encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = [h for h in (reader.fieldnames or []) if h is not None]
            rows = list(reader)
    except UnicodeDecodeError:
        raise ImportFormatError(f"{path.name} is not UTF-8 text.") from None
    except csv.Error as exc:
        raise ImportFormatError(f"{path.name} is not a readable CSV file ({exc}).") from None

    if not headers:
        raise ImportFormatError(f"{path.name} is empty.")

    by_name = {normalise(h): h for h in headers}
    columns = {
        field: [by_name[name] for name in names if name in by_name]
        for field, names in FIELDS.items()
    }
    if not columns["password"]:
        names = ", ".join(FIELDS["password"])
        raise ImportFormatError(
            f"{path.name} has no password column. Hecate looks for a column named {names}."
        )
    totp_headers = [h for h in headers if normalise(h) in TOTP_COLUMNS]
    used = {h for found in columns.values() for h in found}
    ignored = [h for h in headers if h not in used and h not in totp_headers]

    entries: list[Entry] = []
    skipped = 0
    with_totp = 0
    for row in rows:
        password, _ = _first(row, columns["password"], strip=False)
        if any((row.get(h) or "").strip() for h in totp_headers):
            with_totp += 1
        if not password.strip():
            skipped += 1
            continue
        username, _ = _first(row, columns["username"])
        url, _ = _first(row, columns["url"])
        title, _ = _first(row, columns["title"])
        notes, _ = _first(row, columns["notes"])
        tag_value, tag_column = _first(row, columns["tags"])
        entries.append(
            Entry(
                title=title or _fallback_title(url, username),
                username=username,
                password=password,
                url=url,
                notes=notes,
                tags=_tags(tag_value, tag_column),
            )
        )

    return CsvImport(
        entries=entries,
        columns={field: found for field, found in columns.items() if found},
        ignored_columns=ignored,
        rows=len(rows),
        skipped_without_password=skipped,
        rows_with_totp=with_totp,
    )


def _first(row: dict, headers: list[str], *, strip: bool = True) -> tuple[str, str | None]:
    """The first non-blank value among these columns, and the column it came from."""
    for header in headers:
        value = row.get(header) or ""
        if value.strip():
            return (value.strip() if strip else value), header
    return "", None


def _tags(value: str, column: str | None) -> list[str]:
    if not value:
        return []
    if column is not None and normalise(column) == "tags":
        return [tag.strip() for tag in value.split(",") if tag.strip()]
    return [value]  # a folder or group is one tag, path and all


def _fallback_title(url: str, username: str) -> str:
    if url:
        try:
            host = urllib.parse.urlsplit(url if "//" in url else f"//{url}").hostname
        except ValueError:
            host = None
        if host:
            return host
    return username or FALLBACK_TITLE


def remove_plaintext(path: Path) -> None:
    """Overwrite an export with zeros, then delete it. Best effort.

    Overwriting does not reliably erase data on copy-on-write or log-structured
    filesystems, SSDs that remap writes, or anything a backup or sync tool has
    already copied, so this narrows the window rather than guaranteeing erasure.
    """
    path = Path(path)
    try:
        size = path.stat().st_size
        with open(path, "r+b") as handle:
            handle.write(b"\x00" * size)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        path.unlink()
