"""Entry model: one stored secret with metadata."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timezone
from typing import Any, Optional

ENTRY_VERSION = 1


def parse_expires(value: Optional[str]) -> Optional[date]:
    """Parse a user-supplied expiry as YYYY-MM-DD. Returns None for empty input."""
    if not value:
        return None
    return date.fromisoformat(value.strip())


@dataclass
class Entry:
    name: str
    secret: str
    username: str = ""
    url: str = ""
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    env_var: str = ""
    expires_at: Optional[date] = None
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def default_env_var(self) -> str:
        if self.env_var:
            return self.env_var
        cleaned = re.sub(r"[^A-Za-z0-9]+", "_", self.name).strip("_").upper()
        return cleaned or "KEYSTASH_ENTRY"

    def is_expired(self, today: Optional[date] = None) -> bool:
        if self.expires_at is None:
            return False
        return self.expires_at <= (today or date.today())

    def days_left(self, today: Optional[date] = None) -> Optional[int]:
        if self.expires_at is None:
            return None
        return (self.expires_at - (today or date.today())).days

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": ENTRY_VERSION,
            "name": self.name,
            "secret": self.secret,
            "username": self.username,
            "url": self.url,
            "tags": list(self.tags),
            "notes": self.notes,
            "env_var": self.env_var,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Entry":
        known = {f for f in cls.__dataclass_fields__}  # noqa: C416
        payload = {k: v for k, v in data.items() if k in known and k != "version"}
        payload["expires_at"] = parse_expires(payload.get("expires_at"))
        payload["created_at"] = datetime.fromisoformat(payload["created_at"])
        payload["updated_at"] = datetime.fromisoformat(payload["updated_at"])
        payload["tags"] = [str(t) for t in payload.get("tags") or []]
        return cls(**payload)

    def with_updates(self, **changes: Any) -> "Entry":
        changes["updated_at"] = datetime.now(timezone.utc)
        return replace(self, **changes)
