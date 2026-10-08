"""keystash MCP server — the AI-facing surface.

Design invariant (v0.4.0)
------------------------
**There is no tool that returns a secret value, and no code path that prints
one.** The AI is treated as an untrusted party that happens to hold a shell, so
the guarantee cannot rest on the tool list alone: it rests on the fact that no
value ever reaches stdout, the metadata file, or the audit log.

Concretely:

* values enter through a native macOS dialog (`keystash.prompt`) that the AI
  cannot read, and live in the login Keychain;
* `secret_use` sends a request *from this process* using a per-entry URL
  allow-list, so the AI never chooses the destination host and never sees the
  credential;
* `secret_delete` confirms through a native two-button dialog;
* responses are scrubbed of the value and of its common encodings.

The honest boundary is documented in the README: any process running as the
same user can read the Keychain. What this buys is the removal of plaintext,
not the removal of trust.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from . import __version__, broker, prompt
from .broker import (
    DEFAULT_TIMEOUT,
    MAX_TIMEOUT,
    BrokerError,
)

PROTOCOL_VERSION = "2025-06-18"

DIALOG_TIMEOUT = 180.0

_UNAVAILABLE = (
    "the native macOS input dialog is unavailable in this session, so no value "
    "can be collected. Run keystash from a logged-in macOS GUI session."
)

# --------------------------------------------------------------------------
# tool schema
# --------------------------------------------------------------------------


def _tools_schema() -> List[Dict[str, Any]]:
    return [
        {
            "name": "secret_list",
            "description": (
                "List stored secrets as metadata only: name, tags, rotation "
                "policy, last rotation, allowed URLs. Never returns a value."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Return only this entry."},
                    "tag": {"type": "string", "description": "Return only entries carrying this tag."},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "secret_store",
            "description": (
                "Store a secret. The value is collected from the human through a "
                "native macOS dialog; it is never passed as an argument and never "
                "returned. Use this only when the human is present."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Reference name, SERVICE_ENV_PURPOSE, e.g. OPENAI_PROD_KEY.",
                    },
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "rotate_every_days": {"type": "integer", "minimum": 1},
                    "allowed_urls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "URL prefixes this entry may be sent to, each ending with '/'. "
                            "secret_use refuses every other destination."
                        ),
                    },
                    "auth_header": {"type": "string", "description": "Default 'Authorization'."},
                    "auth_prefix": {"type": "string", "description": "Default 'Bearer '."},
                },
                "required": ["name"],
                "additionalProperties": False,
            },
        },
        {
            "name": "secret_rotate",
            "description": (
                "Replace an existing secret's value with a new one collected from the "
                "human through a native macOS dialog. Metadata is preserved unless "
                "overridden."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "rotate_every_days": {"type": "integer", "minimum": 1},
                    "allowed_urls": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["name"],
                "additionalProperties": False,
            },
        },
        {
            "name": "secret_generate",
            "description": (
                "Generate a high-entropy value, store it, and return only a short "
                "fingerprint. The value is never returned; the human retrieves it "
                "with `keystash copy NAME` (clipboard, auto-cleared)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "rotate_every_days": {"type": "integer", "minimum": 1},
                    "allowed_urls": {"type": "array", "items": {"type": "string"}},
                    "length": {"type": "integer", "minimum": 16, "maximum": 128},
                },
                "required": ["name"],
                "additionalProperties": False,
            },
        },
        {
            "name": "secret_use",
            "description": (
                "Send one HTTP request to an allow-listed URL with the entry's value "
                "as its credential. Returns the status and the scrubbed response "
                "body. The AI does not choose the credential and cannot read it."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "url": {"type": "string", "description": "Must be covered by the entry's allowed_urls."},
                    "method": {"type": "string", "description": "Default GET."},
                    "body": {"description": "Request body: object, string, or omitted."},
                    "timeout": {"type": "number", "description": f"Seconds, max {MAX_TIMEOUT:g}."},
                },
                "required": ["name", "url"],
                "additionalProperties": False,
            },
        },
        {
            "name": "secret_delete",
            "description": (
                "Delete a secret and its metadata. Requires a native confirmation "
                "dialog from the human; without it nothing is deleted."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": False,
            },
        },
    ]


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------


def _fingerprint(value: str) -> str:
    """A short, non-invertible label for a *generated* value.

    Only ever applied to values this process generated (>=256 bits of entropy),
    where leaking 32 bits reveals nothing usable. Human-entered values are never
    fingerprinted: a weak password's hash prefix would be an offline oracle.
    """
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


class KeystashMCPServer:
    """One stdio session. Holds no secret material between calls."""

    def __init__(self, meta_path: Optional[os.PathLike | str] = None) -> None:
        self.meta_path = str(meta_path) if meta_path else None

    # -- JSON-RPC plumbing --------------------------------------------------

    def handle(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle one JSON-RPC message. Returns a response dict, or None for notifications."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "Invalid Request")
        request_id = message.get("id")
        if request_id is None:  # notification — no response ever
            return None
        method = str(message.get("method") or "")
        if method not in {"initialize", "ping", "tools/list", "tools/call"}:
            return self._error(request_id, -32601, f"Method not found: {method}")
        try:
            result = self._dispatch(method, message.get("params") or {})
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except Exception as exc:  # defensive: never crash the stdio loop
            return self._tool_error(request_id, f"internal error: {exc}")

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    @staticmethod
    def _tool_error(request_id: Any, text: str) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": True},
        }

    def _dispatch(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if method == "initialize":
            requested = params.get("protocolVersion")
            return {
                "protocolVersion": requested if isinstance(requested, str) else PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "keystash", "version": __version__},
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": _tools_schema()}
        if method == "tools/call":
            arguments = params.get("arguments")
            text, is_error = self._call_tool(str(params.get("name")), arguments or {})
            return {"content": [{"type": "text", "text": text}], "isError": is_error}
        raise KeyError(method)

    # -- tools --------------------------------------------------------------

    def _call_tool(self, name: str, args: Dict[str, Any]) -> Tuple[str, bool]:
        handler = {
            "secret_list": self._secret_list,
            "secret_store": self._secret_store,
            "secret_rotate": self._secret_rotate,
            "secret_generate": self._secret_generate,
            "secret_use": self._secret_use,
            "secret_delete": self._secret_delete,
        }.get(name)
        if handler is None:
            return f"Unknown tool '{name}'.", True
        try:
            return handler(args), False
        except BrokerError as exc:
            return str(exc), True
        except prompt.InputUnavailable:
            return _UNAVAILABLE, True
        except (KeyError, TypeError, ValueError) as exc:
            return f"invalid arguments: {exc}", True

    # -- internal helpers ---------------------------------------------------

    def _ask(self, name: str, prompt_text: str) -> str:
        """Collect a value from the human. Raises on cancel — never returns ''."""
        if not prompt.available():
            raise prompt.InputUnavailable("no dialog channel")
        value = prompt.ask_secret(
            prompt_text,
            title=f"keystash — {name}",
            timeout=DIALOG_TIMEOUT,
        )
        if value is None:
            raise BrokerError("cancelled: no value was entered, nothing was stored")
        if not value:
            raise BrokerError("refusing to store an empty value")
        return value

    @staticmethod
    def _json(payload: Any) -> str:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    # -- tool implementations ----------------------------------------------

    def _secret_list(self, args: Dict[str, Any]) -> str:
        """Metadata only. Touches no value, so it needs no unlock and no dialog."""
        name = args.get("name")
        tag = args.get("tag")
        if name:
            return self._json(broker.metadata_for(str(name), path=self.meta_path))
        rows = broker.list_entries(tag=str(tag) if tag else None, path=self.meta_path)
        return self._json({"count": len(rows), "entries": rows})

    def _secret_store(self, args: Dict[str, Any]) -> str:
        name = broker.validate_name(str(args.get("name") or ""))
        value = self._ask(name, f"Enter the value for {name}\n(it is stored in the login Keychain and never shown to the AI)")
        entry = broker.put(
            name,
            value,
            tags=args.get("tags") or [],
            rotate_every_days=args.get("rotate_every_days"),
            allowed_urls=args.get("allowed_urls") or [],
            auth_header=str(args.get("auth_header") or "Authorization"),
            auth_prefix=str(args.get("auth_prefix") if args.get("auth_prefix") is not None else "Bearer "),
            path=self.meta_path,
        )
        return self._json({"stored": entry.name, "entry": entry.describe(), "value_returned": False})

    def _secret_rotate(self, args: Dict[str, Any]) -> str:
        name = broker.validate_name(str(args.get("name") or ""))
        existing = broker.load_meta(self.meta_path).get(name)
        if existing is None:
            raise BrokerError(f"unknown entry {name!r}; use secret_store first")
        value = self._ask(name, f"Enter the NEW value for {name}\n(it replaces the stored one and is never shown to the AI)")
        entry = broker.put(
            name,
            value,
            tags=args.get("tags") if args.get("tags") is not None else existing.tags,
            rotate_every_days=(
                args.get("rotate_every_days")
                if args.get("rotate_every_days") is not None
                else existing.rotate_every_days
            ),
            allowed_urls=(
                args.get("allowed_urls")
                if args.get("allowed_urls") is not None
                else existing.allowed_urls
            ),
            auth_header=existing.auth_header,
            auth_prefix=existing.auth_prefix,
            path=self.meta_path,
        )
        return self._json({"rotated": entry.name, "entry": entry.describe(), "value_returned": False})

    def _secret_generate(self, args: Dict[str, Any]) -> str:
        name = broker.validate_name(str(args.get("name") or ""))
        value = broker.generate_value(int(args.get("length") or 43))
        entry = broker.put(
            name,
            value,
            tags=args.get("tags") or [],
            rotate_every_days=args.get("rotate_every_days"),
            allowed_urls=args.get("allowed_urls") or [],
            path=self.meta_path,
        )
        return self._json(
            {
                "generated": entry.name,
                "fingerprint": _fingerprint(value),
                "entry": entry.describe(),
                "value_returned": False,
                "human_retrieval": f"keystash copy {entry.name}",
            }
        )

    def _secret_use(self, args: Dict[str, Any]) -> str:
        name = str(args.get("name") or "")
        url = str(args.get("url") or "")
        result = broker.use(
            name,
            url,
            method=str(args.get("method") or "GET"),
            body=args.get("body"),
            timeout=float(args.get("timeout") or DEFAULT_TIMEOUT),
            path=self.meta_path,
        )
        return self._json(result)

    def _secret_delete(self, args: Dict[str, Any]) -> str:
        name = broker.validate_name(str(args.get("name") or ""))
        if broker.load_meta(self.meta_path).get(name) is None:
            raise BrokerError(f"unknown entry {name!r}")
        if not prompt.available():
            raise prompt.InputUnavailable("no dialog channel")
        if not prompt.confirm(
            f"Delete {name}?\nThe stored value is erased from the Keychain.",
            ok_label="删除",
            title=f"keystash — {name}",
            timeout=DIALOG_TIMEOUT,
        ):
            raise BrokerError(f"not deleted: {name} was not confirmed by the human")
        broker.forget(name, path=self.meta_path)
        return self._json({"deleted": name})


def serve(meta_path: Optional[os.PathLike | str] = None) -> None:
    """Read JSON-RPC lines from stdin, write responses to stdout. Nothing else."""
    server = KeystashMCPServer(meta_path)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response = server._error(None, -32700, "Parse error")
        else:
            response = server.handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()
