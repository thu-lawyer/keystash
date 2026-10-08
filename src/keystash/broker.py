"""keystash broker — the AI gets references, never values.

Storage model (v0.4.0):

  * **Values** live in the macOS login keychain, one generic-password item per
    entry (service ``keystash``). They are read without a biometric gate,
    because the caller that reads them is an allow-listed outbound request,
    not a human.
  * **Metadata** (name, tags, rotation, allow-list) lives in a 0600 JSON file.
    It is deliberately *not* secret — the whole point is that the AI can read
    and manage metadata while never holding a value.

There is no "read" operation. :func:`use` is the only path by which a value
leaves this process, and it leaves as an HTTP Authorization header aimed at a
URL that the entry's own allow-list already names.

Invariant (do not weaken): no function here writes a secret to stdout, stderr,
a log line, an exception message, or a file. The only exception is
:func:`scrub`, whose job is to *remove* secrets from text that is about to be
handed back.

Honest boundary: the login keychain protects against *other users* and against
a locked filesystem — not against other processes running as you. Any process
in your session can read these items with ``security find-generic-password``.
What the AI cannot do is obtain a value through keystash, because keystash has
no way to hand one over.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets as _secrets
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Sequence

from . import keychain

SCHEMA_VERSION = 1
KEYCHAIN_SERVICE = "keystash"
AUDIT_FILENAME = "audit.log"
MAX_OUTPUT_CHARS = 20_000
DEFAULT_TIMEOUT = 30.0
MAX_TIMEOUT = 300.0
REDACTED = "[redacted]"

_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class BrokerError(Exception):
    """A request was refused, or could not be completed."""


# --------------------------------------------------------------------------
# metadata
# --------------------------------------------------------------------------


def meta_path(path: Optional[str] = None) -> Path:
    if path is not None:
        return Path(path).expanduser()
    raw = os.environ.get("KEYSTASH_META", "~/.keystash/entries.json")
    return Path(raw).expanduser()


def validate_name(name: str) -> str:
    """Enforce the SERVICE_ENV_PURPOSE convention."""
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise BrokerError(
            "entry name must look like SERVICE_ENV_PURPOSE "
            "(uppercase A-Z, digits, underscore; e.g. OPENAI_PROD_READONLY)"
        )
    return name


@dataclass
class Entry:
    name: str
    tags: List[str] = field(default_factory=list)
    rotate_every_days: Optional[int] = None
    last_rotated: Optional[str] = None
    allowed_urls: List[str] = field(default_factory=list)
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "tags": list(self.tags),
            "rotate_every_days": self.rotate_every_days,
            "last_rotated": self.last_rotated,
            "allowed_urls": list(self.allowed_urls),
            "auth_header": self.auth_header,
            "auth_prefix": self.auth_prefix,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Entry":
        return cls(
            name=data["name"],
            tags=list(data.get("tags") or []),
            rotate_every_days=data.get("rotate_every_days"),
            last_rotated=data.get("last_rotated"),
            allowed_urls=list(data.get("allowed_urls") or []),
            auth_header=data.get("auth_header") or "Authorization",
            auth_prefix=data.get("auth_prefix") or "",
            created_at=data.get("created_at"),
        )

    def rotate_due(self, today: Optional[date] = None) -> Optional[bool]:
        """True/False when a rotation policy exists, else None."""
        if not self.rotate_every_days or not self.last_rotated:
            return None
        try:
            last = date.fromisoformat(self.last_rotated)
        except ValueError:
            return None
        return (today or date.today()) >= last + timedelta(days=int(self.rotate_every_days))

    def describe(self) -> Dict[str, Any]:
        """The AI-visible view: no value, not even a hint of one."""
        out = self.to_dict()
        out["rotate_due"] = self.rotate_due()
        return out


def load_meta(path: Optional[str] = None) -> Dict[str, Entry]:
    p = meta_path(path)
    if not p.exists():
        return {}
    try:
        doc = json.loads(p.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BrokerError(f"metadata file is unreadable: {p}") from exc
    if not isinstance(doc, dict) or doc.get("version") != SCHEMA_VERSION:
        raise BrokerError(f"metadata file has an unsupported format: {p}")
    entries: Dict[str, Entry] = {}
    for name, blob in (doc.get("entries") or {}).items():
        try:
            entries[name] = Entry.from_dict(blob)
        except (KeyError, TypeError) as exc:
            raise BrokerError(f"metadata entry {name!r} is malformed") from exc
    return entries


def save_meta(entries: Dict[str, Entry], path: Optional[str] = None) -> Path:
    p = meta_path(path)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    doc = {
        "version": SCHEMA_VERSION,
        "entries": {n: e.to_dict() for n, e in sorted(entries.items())},
    }
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".entries-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return p


def normalise_url(url: str) -> str:
    parts = urllib.parse.urlsplit((url or "").strip())
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise BrokerError(f"only http/https is allowed, got {parts.scheme or '(none)'!r}")
    if not parts.hostname:
        raise BrokerError("url has no host")
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{scheme}://{parts.hostname.lower()}{port}{path}{query}"


def normalise_allow_prefix(url: str) -> str:
    got = normalise_url(url)
    if not got.endswith("/"):
        raise BrokerError(
            f"allow-list entries must end with '/': {url!r} -> {got!r}. "
            "Add the trailing slash to mean 'this host/path and below'."
        )
    return got


def check_allowed(url: str, allowed: Sequence[str]) -> str:
    """Return the target URL, or raise.

    The AI may name any URL; it may not name a *host*. Because every
    allow-list entry keeps its own ``scheme://host/``, a prefix match cannot
    be tricked by a lookalike host — ``https://api.openai.com.evil.com/``
    does not start with ``https://api.openai.com/``.
    """
    if not allowed:
        raise BrokerError(
            "this entry has no allowed_urls, so keystash refuses to send its "
            "value anywhere; set allowed_urls first"
        )
    target = normalise_url(url)
    for raw in allowed:
        prefix = normalise_allow_prefix(raw)
        if target.startswith(prefix):
            return target
    raise BrokerError("url is not covered by this entry's allowed_urls")


# --------------------------------------------------------------------------
# secret stores
# --------------------------------------------------------------------------


class SecretStore(Protocol):
    def get(self, name: str) -> Optional[str]: ...
    def set(self, name: str, value: str) -> None: ...
    def delete(self, name: str) -> bool: ...


class KeychainStore:
    """The real store: macOS login keychain, no biometric gate on read."""

    def __init__(self, service: str = KEYCHAIN_SERVICE) -> None:
        self.service = service

    def get(self, name: str) -> Optional[str]:
        return keychain.retrieve(self.service, name, gate=False)

    def set(self, name: str, value: str) -> None:
        keychain.store(self.service, name, value)

    def delete(self, name: str) -> bool:
        return keychain.delete(self.service, name)


class MemoryStore:
    """In-process store, for tests."""

    def __init__(self, initial: Optional[Dict[str, str]] = None) -> None:
        self._data: Dict[str, str] = dict(initial or {})

    def get(self, name: str) -> Optional[str]:
        return self._data.get(name)

    def set(self, name: str, value: str) -> None:
        self._data[name] = value

    def delete(self, name: str) -> bool:
        return self._data.pop(name, None) is not None


# --------------------------------------------------------------------------
# scrubbing
# --------------------------------------------------------------------------


def _variants(secret: str) -> List[str]:
    """Encodings a value realistically turns into once it leaks.

    Note that ``quote`` leaves unreserved characters (letters, digits, ``-._~``)
    alone, so for a key made only of those the "url-encoded" form *is* the raw
    form — harmless, it just adds no new needle. The forms that genuinely
    differ are the base64 ones and their percent-encodings, because base64
    introduces ``+ / =``.
    """
    out = {secret}
    try:
        raw = secret.encode("utf-8")
        b64 = base64.b64encode(raw).decode("ascii")
        b64u = base64.urlsafe_b64encode(raw).decode("ascii")
        out.update({b64, b64u})
        out.update(
            {
                urllib.parse.quote(secret, safe=""),
                urllib.parse.quote_plus(secret, safe=""),
                urllib.parse.quote(b64, safe=""),
                urllib.parse.quote_plus(b64u, safe=""),
                raw.hex(),
            }
        )
    except Exception:  # pragma: no cover - defensive
        pass
    return sorted(out, key=len, reverse=True)


def scrub(text: str, secrets_in: Sequence[str]) -> str:
    """Remove every value (and its common encodings) from `text`.

    Ordered longest-first so a base64 form is not half-eaten by the raw form.
    """
    if not text:
        return text
    needles = set()
    for secret in secrets_in:
        if not secret:
            continue
        needles.add(secret)
        if len(secret) >= 8:  # short values would redact innocuous text
            needles.update(_variants(secret))
    for needle in sorted(needles, key=len, reverse=True):
        text = text.replace(needle, REDACTED)
    return text


# --------------------------------------------------------------------------
# outbound request
# --------------------------------------------------------------------------


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect would move the Authorization header to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise BrokerError(f"refusing to follow a redirect to {newurl!r} (HTTP {code})")


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_RefuseRedirects)


def _audit(name: str, method: str, url: str, status: Any, path: Optional[str]) -> None:
    """One line per use: who used which entry, where, and what came back.

    Never the header, never the body, never the value.
    """
    try:
        p = meta_path(path).parent / AUDIT_FILENAME
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(f"{stamp}\t{name}\t{method}\t{url}\t{status}\n")
        os.chmod(p, 0o600)
    except OSError:
        pass  # auditing must never break the call


def use(
    name: str,
    url: str,
    method: str = "GET",
    body: Optional[Any] = None,
    timeout: float = DEFAULT_TIMEOUT,
    store: Optional[SecretStore] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    """Send one allow-listed request with the entry's value as its credential.

    Returns ``{"status", "url", "body", "truncated"}``. The value never appears
    in the return value: the response is scrubbed before it is handed back.
    """
    entries = load_meta(path)
    entry = entries.get(name)
    if entry is None:
        raise BrokerError(f"unknown entry {name!r}")
    target = check_allowed(url, entry.allowed_urls)

    secret = (store or KeychainStore()).get(name)
    if not secret:
        raise BrokerError(f"no value is stored for {name!r}")

    method = (method or "GET").upper()
    payload: Optional[bytes]
    if body is None:
        payload = None
    elif isinstance(body, (bytes, bytearray)):
        payload = bytes(body)
    elif isinstance(body, str):
        payload = body.encode("utf-8")
    else:
        payload = json.dumps(body).encode("utf-8")

    request = urllib.request.Request(target, data=payload, method=method)
    request.add_header(entry.auth_header, entry.auth_prefix + secret)
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json, text/plain;q=0.9, */*;q=0.8")

    timeout = max(1.0, min(float(timeout or DEFAULT_TIMEOUT), MAX_TIMEOUT))
    status: Any
    try:
        with _opener().open(request, timeout=timeout) as response:
            status = response.status
            raw = response.read(MAX_OUTPUT_CHARS * 8)
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx is still an answer; the AI needs to see it to self-correct.
        status = exc.code
        raw = exc.read(MAX_OUTPUT_CHARS * 8) if hasattr(exc, "read") else b""
    except urllib.error.URLError as exc:
        raise BrokerError(f"request failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise BrokerError(f"request timed out after {timeout:g}s") from exc

    text = raw.decode("utf-8", errors="replace")
    text = scrub(text, [secret])
    truncated = len(text) > MAX_OUTPUT_CHARS
    _audit(name, method, target, status, path)
    return {
        "status": status,
        "url": target,
        "body": text[:MAX_OUTPUT_CHARS],
        "truncated": truncated,
    }


# --------------------------------------------------------------------------
# convenience operations used by the CLI and the MCP layer
# --------------------------------------------------------------------------


def generate_value(length: int = 43) -> str:
    """A high-entropy URL-safe value. 43 chars ≈ 256 bits."""
    return _secrets.token_urlsafe(max(16, int(length)))[: max(16, int(length))]


def put(
    name: str,
    value: str,
    tags: Optional[Sequence[str]] = None,
    rotate_every_days: Optional[int] = None,
    allowed_urls: Optional[Sequence[str]] = None,
    auth_header: str = "Authorization",
    auth_prefix: str = "Bearer ",
    store: Optional[SecretStore] = None,
    path: Optional[str] = None,
) -> Entry:
    """Store a value and (re)write its metadata. Rotating = calling this again."""
    validate_name(name)
    if not value:
        raise BrokerError("refusing to store an empty value")
    normalised = [normalise_allow_prefix(u) for u in (allowed_urls or [])]

    entries = load_meta(path)
    previous = entries.get(name)
    entry = Entry(
        name=name,
        tags=sorted({*(tags or [])}),
        rotate_every_days=rotate_every_days,
        last_rotated=date.today().isoformat(),
        allowed_urls=normalised,
        auth_header=auth_header or "Authorization",
        auth_prefix=auth_prefix if auth_prefix is not None else "",
        created_at=(previous.created_at if previous else None) or date.today().isoformat(),
    )
    (store or KeychainStore()).set(name, value)
    entries[name] = entry
    save_meta(entries, path)
    return entry


def forget(
    name: str,
    store: Optional[SecretStore] = None,
    path: Optional[str] = None,
) -> bool:
    """Delete both the value and its metadata. True if anything existed."""
    entries = load_meta(path)
    existed = entries.pop(name, None) is not None
    if existed:
        save_meta(entries, path)
    removed = (store or KeychainStore()).delete(name)
    return existed or removed


def list_entries(
    tag: Optional[str] = None,
    path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    entries = load_meta(path)
    rows = [e.describe() for e in entries.values()]
    if tag:
        rows = [r for r in rows if tag in (r.get("tags") or [])]
    rows.sort(key=lambda r: r["name"])
    return rows


def metadata_for(name: str, path: Optional[str] = None) -> Dict[str, Any]:
    entry = load_meta(path).get(name)
    if entry is None:
        raise BrokerError(f"unknown entry {name!r}")
    return entry.describe()
