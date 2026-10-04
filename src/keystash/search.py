"""Dependency-free fuzzy scoring used by `ls` and selection prompts."""

from __future__ import annotations

from typing import Optional

from .model import Entry


def _is_subsequence(needle: str, haystack: str) -> bool:
    it = iter(haystack)
    return all(ch in it for ch in needle)


def score_entry(query: str, entry: Entry) -> Optional[int]:
    """Return a relevance score, or None when the entry does not match at all."""
    q = query.strip().lower()
    if not q:
        return 0
    name = entry.name.lower()
    if name == q:
        return 100
    if name.startswith(q):
        return 90
    if q in name:
        return 80
    for tag in entry.tags:
        if tag.lower() == q:
            return 75
        if q in tag.lower():
            return 70
    for text in (entry.username, entry.url, entry.notes, entry.default_env_var):
        if text and q in text.lower():
            return 50
    if _is_subsequence(q, name):
        return 60
    return None


def search(entries: dict, query: str) -> list[Entry]:
    scored = []
    for entry in entries.values():
        s = score_entry(query, entry)
        if s is not None:
            scored.append((s, entry.name.lower(), entry))
    scored.sort(key=lambda t: (-t[0], t[1]))
    return [entry for _, _, entry in scored]
