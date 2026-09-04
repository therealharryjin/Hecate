"""Entry data model.

Note what is deliberately absent: there is no per-entry TOTP field. Hecate
guards passwords; it is not an authenticator app for other services. The only
TOTP in this system is the one gating Hecate's own unlock.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclasses.dataclass
class PasswordHistoryItem:
    password: str
    replaced_at: str

    def as_dict(self) -> dict[str, str]:
        return {"password": self.password, "replaced_at": self.replaced_at}

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "PasswordHistoryItem":
        return cls(password=data["password"], replaced_at=data["replaced_at"])


@dataclasses.dataclass
class Entry:
    title: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = dataclasses.field(default_factory=list)
    id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = dataclasses.field(default_factory=_now)
    modified_at: str = dataclasses.field(default_factory=_now)
    password_history: list[PasswordHistoryItem] = dataclasses.field(
        default_factory=list
    )

    def set_password(self, new_password: str) -> None:
        """Rotate the password, retaining the previous one in history."""
        if self.password and self.password != new_password:
            self.password_history.append(
                PasswordHistoryItem(password=self.password, replaced_at=_now())
            )
        self.password = new_password
        self.touch()

    def touch(self) -> None:
        self.modified_at = _now()

    def as_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["password_history"] = [h.as_dict() for h in self.password_history]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Entry":
        history = [
            PasswordHistoryItem.from_dict(h) for h in data.get("password_history", [])
        ]
        return cls(
            id=data["id"],
            title=data["title"],
            username=data.get("username", ""),
            password=data.get("password", ""),
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            tags=list(data.get("tags", [])),
            created_at=data["created_at"],
            modified_at=data["modified_at"],
            password_history=history,
        )


@dataclasses.dataclass
class VaultData:
    """The decrypted contents of a vault."""

    entries: list[Entry] = dataclasses.field(default_factory=list)

    def serialize(self) -> bytes:
        return json.dumps(
            {"entries": [e.as_dict() for e in self.entries]}, sort_keys=True
        ).encode("utf-8")

    @classmethod
    def deserialize(cls, raw: bytes) -> "VaultData":
        data = json.loads(raw.decode("utf-8"))
        return cls(entries=[Entry.from_dict(e) for e in data.get("entries", [])])

    def find(self, needle: str) -> Entry | None:
        """Look up by exact id, then by case-insensitive title."""
        for entry in self.entries:
            if entry.id == needle:
                return entry
        lowered = needle.lower()
        for entry in self.entries:
            if entry.title.lower() == lowered:
                return entry
        return None
