"""Work out what an import adds to a vault, without changing what is there.

The rules, for every incoming entry:

  * The same title (ignoring case and a trailing " (2)"-style number),
    username and password as an entry already in the vault, or earlier in the
    same import: skipped. Importing the same file twice adds nothing.
  * Otherwise, if its title is taken: added under the next free number,
    "github (2)", so nothing is overwritten and nothing is lost.
  * Otherwise: added as it is.

Existing entries are never modified, and every added entry gets a fresh id so
no two entries ever share one. Everything else -- notes, tags, timestamps,
password history -- comes across unchanged.

Entries are compared through a keyed digest under a per-call pepper, the same
hygiene as :mod:`hecate.audit.duplicates`: raw passwords never become set
members or show up in a traceback.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import uuid
from collections.abc import Iterable

from ..crypto import rng
from ..vault.model import Entry

_NUMBERED = re.compile(r"\s\((\d+)\)$")


@dataclasses.dataclass
class MergePlan:
    added: list[Entry]
    #: (title in the import, title it was added under), for taken titles.
    renamed: list[tuple[str, str]]
    already_present: int


def _base_title(title: str) -> str:
    return _NUMBERED.sub("", title).lower()


def _identity(entry: Entry, pepper: bytes) -> bytes:
    material = json.dumps([_base_title(entry.title), entry.username, entry.password])
    return hashlib.blake2b(material.encode("utf-8"), key=pepper, digest_size=16).digest()


def plan_merge(existing: Iterable[Entry], incoming: Iterable[Entry]) -> MergePlan:
    existing = list(existing)
    pepper = rng.random_bytes(32)
    seen = {_identity(entry, pepper) for entry in existing}
    taken = {entry.title.lower() for entry in existing}

    added: list[Entry] = []
    renamed: list[tuple[str, str]] = []
    already = 0
    for entry in incoming:
        identity = _identity(entry, pepper)
        if identity in seen:
            already += 1
            continue
        seen.add(identity)

        title = entry.title
        if title.lower() in taken:
            number = 2
            while f"{title} ({number})".lower() in taken:
                number += 1
            title = f"{title} ({number})"
            renamed.append((entry.title, title))
        taken.add(title.lower())
        added.append(
            dataclasses.replace(
                entry,
                title=title,
                id=str(uuid.uuid4()),
                tags=list(entry.tags),
                password_history=list(entry.password_history),
            )
        )
    return MergePlan(added=added, renamed=renamed, already_present=already)
