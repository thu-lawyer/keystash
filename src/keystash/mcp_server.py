"""Minimal Model Context Protocol (MCP) server: `keystash mcp`.

Lets AI agents orchestrate the vault over stdio JSON-RPC while keeping the
zero-plaintext invariant: no tool returns secret values.

- list_entries / status      → metadata only (names, tags, expiry)
- run_command                → secrets injected as env vars, tool output is
                               scrubbed of every injected value before the
                               agent sees it; obvious dumpers (printenv, env,
                               /proc/*/environ) are refused outright
- copy_secret                → clipboard only (auto-clears), never in the reply
- generate_and_store         → strong random secret stored; value never exists
                               in the conversation at all
- add_secret                 → the ONE intentional exception, for keys the
                               human already pasted into the chat; documented
                               in the tool description

What this cannot prevent: an agent deliberately writing code that exfiltrates
(transformed, split, encoded). That is out of scope — it is visible in the
agent transcript and auditable by the human. Lock the vault when done.

Protocol notes: newline-delimited JSON-RPC 2.0 per the MCP stdio transport.
Notifications get no reply; unknown methods get error -32601. Subprocess
output is ALWAYS captured — inheriting stdout would corrupt the MCP channel.
The session password resolves lazily: nothing touches the keychain (and no
Touch ID prompt appears) until the first tool call that actually needs the
vault; within a session the password is resolved at most once.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__, clipboard, keychain
from .model import Entry, parse_expires
from .vault import Vault

PROTOCOL_VERSION = "2025-06-18"
MAX_OUTPUT_CHARS = 50_000
DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 3600
KEYCHAIN_SERVICE = "keystash"

_UNRESOLVED = object()  # sentinel: session password not attempted yet

LOCKED_HINT = (
    "Vault locked: run `keystash unlock` in a terminal first (Touch ID), or set "
    "KEYSTASH_PASSWORD for this MCP server, then reconnect the session."
)

BLOCKED_TOKENS = {"env", "printenv"}
BLOCKED_SUBSTRINGS = ("printenv", "/proc/self/environ", "/proc/" + str(os.getpid()) + "/environ")


def _tools_schema() -> List[Dict[str, Any]]:
    return [
        {
            "name": "list_entries",
            "description": (
                "List vault entries. Metadata only — secret values are never "
                "returned. Use query (fuzzy) or tag to narrow down."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Fuzzy search pattern."},
                    "tag": {"type": "string", "description": "Filter by tag."},
                },
            },
        },
        {
            "name": "run_command",
            "description": (
                "Run a command with selected secrets injected as environment "
                "variables (env var name = entry's env_var). The output is "
                "scrubbed of secret values before the AI sees it. Guards reject "
                "obvious secret-dumping commands (printenv, env, /proc environ). "
                "Intended for running programs, not for reading secrets."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Entry names to inject.",
                    },
                    "tag": {"type": "string", "description": "Inject every entry with this tag."},
                    "command": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "The command and its arguments.",
                    },
                    "cwd": {"type": "string", "description": "Working directory (optional)."},
                    "timeout": {
                        "type": "number",
                        "description": f"Seconds before the command is killed (default {DEFAULT_TIMEOUT}, max {MAX_TIMEOUT}).",
                    },
                },
                "required": ["command"],
            },
        },
        {
            "name": "copy_secret",
            "description": (
                "Copy an entry's secret to the system clipboard (auto-clears "
                "after 30 s) for the human to paste. The value is never included "
                "in the tool response."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        },
        {
            "name": "generate_and_store",
            "description": (
                "Generate a strong random secret and store it as a new entry. "
                "The value is never shown to the AI — the human can retrieve it "
                "with `keystash get <name> -c` when needed."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "length": {"type": "integer", "minimum": 8, "maximum": 128},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "expires": {"type": "string", "description": "YYYY-MM-DD"},
                    "env_var": {"type": "string"},
                },
                "required": ["name"],
            },
        },
        {
            "name": "add_secret",
            "description": (
                "⚠️ Store a secret whose VALUE IS ALREADY VISIBLE in this AI "
                "conversation (e.g. the human pasted it). Using it for values "
                "the human has not shared would expose them to the AI — prefer "
                "generate_and_store or the CLI instead."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "secret": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "expires": {"type": "string"},
                    "env_var": {"type": "string"},
                },
                "required": ["name", "secret"],
            },
        },
        {
            "name": "update_entry",
            "description": (
                "Update entry metadata (tags, expiry, notes, env_var, username, "
                "url). Cannot read or change the secret value."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "expires": {"type": "string", "description": "YYYY-MM-DD, or empty string to clear"},
                    "notes": {"type": "string"},
                    "env_var": {"type": "string"},
                    "username": {"type": "string"},
                    "url": {"type": "string"},
                },
                "required": ["name"],
            },
        },
        {
            "name": "delete_entry",
            "description": "Delete an entry. Requires confirm=true.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "confirm": {"type": "boolean"},
                },
                "required": ["name", "confirm"],
            },
        },
        {
            "name": "status",
            "description": "Vault stats: entry count, expired and expiring-soon entries.",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]


class KeystashMCPServer:
    def __init__(self, vault_path: Optional[os.PathLike | str] = None) -> None:
        self.vault_path = Path(vault_path) if vault_path else None
        # Unresolved until the first tool that needs the vault: the Touch ID
        # prompt must appear when a password is actually needed, not whenever
        # a session starts (most conversations never touch the vault).
        self.password: Any = _UNRESOLVED

    # -- session password ---------------------------------------------------

    def _resolve_password(self) -> None:
        if self.password is not _UNRESOLVED:
            return  # already resolved (a value, or known-locked None)
        env = os.environ.get("KEYSTASH_PASSWORD")
        if env:
            self.password = env
            return
        if keychain.AVAILABLE:
            try:
                self.password = keychain.retrieve(KEYCHAIN_SERVICE, str(self.vault_path or "~/.keystash/vault.json"))
            except keychain.KeychainError:
                self.password = None  # declined → stay locked
        else:
            self.password = None

    def _vault(self) -> Vault:
        self._resolve_password()
        if not self.password:
            raise PermissionError(LOCKED_HINT)
        vault = Vault(self.vault_path)
        vault.load(self.password)
        return vault

    # -- JSON-RPC plumbing --------------------------------------------------

    def handle(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle one JSON-RPC message. Returns a response dict, or None for notifications."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "Invalid Request")
        request_id = message.get("id")
        if request_id is None:  # notification — no response ever
            return None
        method = str(message.get("method") or "")
        known = {"initialize", "ping", "tools/list", "tools/call"}
        if method not in known:
            return self._error(request_id, -32601, f"Method not found: {method}")
        try:
            result = self._dispatch(method, message.get("params") or {})
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except PermissionError as e:
            return self._tool_error(request_id, str(e))
        except (ValueError, KeyError) as e:
            return self._tool_error(request_id, str(e) or "invalid arguments")
        except Exception as e:  # defensive: never crash the stdio loop
            return self._tool_error(request_id, f"internal error: {e}")

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
            name = params.get("name")
            arguments = params.get("arguments") or {}
            text, is_error = self._call_tool(str(name), arguments)
            return {"content": [{"type": "text", "text": text}], "isError": is_error}
        raise KeyError(method)

    # -- tool implementations -------------------------------------------------

    def _call_tool(self, name: str, args: Dict[str, Any]) -> Tuple[str, bool]:
        if name == "list_entries":
            return self._tool_list_entries(args), False
        if name == "run_command":
            return self._tool_run_command(args)
        if name == "copy_secret":
            return self._tool_copy_secret(args)
        if name == "generate_and_store":
            return self._tool_generate_and_store(args), False
        if name == "add_secret":
            return self._tool_add_secret(args), False
        if name == "update_entry":
            return self._tool_update_entry(args)
        if name == "delete_entry":
            return self._tool_delete_entry(args)
        if name == "status":
            return self._tool_status(), False
        return f"Unknown tool: {name}", True

    def _tool_list_entries(self, args: Dict[str, Any]) -> str:
        vault = self._vault()
        from .search import search as fuzzy_search

        entries = fuzzy_search(vault.entries, args.get("query") or "")
        tag = args.get("tag")
        if tag:
            entries = [e for e in entries if tag in e.tags]
        return json.dumps(
            [
                {
                    "name": e.name,
                    "env_var": e.default_env_var,
                    "username": e.username,
                    "url": e.url,
                    "tags": e.tags,
                    "notes": e.notes,
                    "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                    "expired": e.is_expired(),
                }
                for e in entries
            ],
            indent=2,
        )

    @staticmethod
    def _scrub(text: str, secrets: List[str]) -> str:
        for s in sorted(secrets, key=len, reverse=True):
            if s:
                text = text.replace(s, "[redacted]")
        return text

    def _tool_run_command(self, args: Dict[str, Any]) -> Tuple[str, bool]:
        command = args.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(c, str) for c in command):
            return "command must be a non-empty array of strings", True
        first = Path(command[0]).name
        joined = " ".join(command)
        if first in BLOCKED_TOKENS or any(b in joined for b in BLOCKED_SUBSTRINGS):
            return (
                "Refused: this command looks like a secret dumper. The AI must not read "
                "secret values; use copy_secret (clipboard) if the human needs one.",
                True,
            )
        vault = self._vault()
        names = [n for n in args.get("names") or [] if isinstance(n, str)]
        tag = args.get("tag")
        selected = []
        if names:
            missing = [n for n in names if n not in vault.entries]
            if missing:
                return f"No such entries: {', '.join(missing)}", True
            selected = [vault.entries[n] for n in names]
        elif tag:
            selected = [e for e in vault.entries.values() if tag in e.tags]
            if not selected:
                return f"No entries tagged '{tag}'.", True
        else:
            return "Provide names or tag: which entries should be injected?", True

        environ = dict(os.environ)
        injected = [entry.default_env_var for entry in selected]
        secrets = [entry.secret for entry in selected] + ([self.password] if self.password else [])
        for entry in selected:
            environ[entry.default_env_var] = entry.secret

        cwd = args.get("cwd")
        try:
            timeout = float(args.get("timeout") or DEFAULT_TIMEOUT)
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT
        timeout = min(max(timeout, 1), MAX_TIMEOUT)
        try:
            completed = subprocess.run(
                command,
                env=environ,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                capture_output=True,  # NEVER inherit stdout: it is the MCP channel
                timeout=timeout,
                text=True,
                errors="replace",
            )
        except FileNotFoundError:
            return f"Command not found: {command[0]}", True
        except subprocess.TimeoutExpired as e:
            partial = ((e.stdout or "") + (e.stderr or "")) if isinstance(e.stdout, str) else ""
            return self._scrub(f"Timeout after {timeout:.0f}s.\n{partial}", secrets), True

        out = ""
        if completed.stdout:
            out += completed.stdout
        if completed.stderr:
            out += ("\n[stderr]\n" + completed.stderr)
        out = self._scrub(out, secrets)
        if len(out) > MAX_OUTPUT_CHARS:
            out = out[:MAX_OUTPUT_CHARS] + f"\n…[truncated {len(out) - MAX_OUTPUT_CHARS} chars]"
        header = f"exit code: {completed.returncode}   injected: {', '.join(injected)}\n"
        return header + out, False

    def _tool_copy_secret(self, args: Dict[str, Any]) -> Tuple[str, bool]:
        vault = self._vault()
        name = args.get("name")
        try:
            entry = vault.get(str(name))
        except Exception:
            return f"No entry named '{name}'.", True
        if clipboard.copy(entry.secret):
            return (
                f"Copied '{entry.name}' to the system clipboard (auto-clears in "
                f"{clipboard.CLEAR_AFTER_SECONDS}s). The value was NOT shown to the AI.",
                False,
            )
        return (
            "No clipboard helper found on this machine. Have the human run: "
            f"`keystash get {entry.name} -c`",
            True,
        )

    def _tool_generate_and_store(self, args: Dict[str, Any]) -> str:
        from .gen import generate

        vault = self._vault()
        name = str(args.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        length = int(args.get("length") or 24)
        expires = parse_expires(args.get("expires"))
        entry = Entry(
            name=name,
            secret=generate(length, symbols=True),
            tags=[str(t) for t in args.get("tags") or []],
            env_var=str(args.get("env_var") or ""),
            expires_at=expires,
        )
        vault.add(entry, overwrite=False)
        vault.save(self.password or "")
        return (
            f"Generated and stored '{name}' ({length} chars, env {entry.default_env_var}). "
            "The value was never revealed; retrieve with `keystash get "
            f"{name} -c` when needed."
        )

    def _tool_add_secret(self, args: Dict[str, Any]) -> str:
        vault = self._vault()
        name = str(args.get("name") or "").strip()
        secret = args.get("secret")
        if not name or not secret:
            raise ValueError("name and secret are required")
        expires = parse_expires(args.get("expires"))
        entry = Entry(
            name=name,
            secret=str(secret),
            tags=[str(t) for t in args.get("tags") or []],
            env_var=str(args.get("env_var") or ""),
            expires_at=expires,
        )
        vault.add(entry, overwrite=False)
        vault.save(self.password or "")
        return f"Stored '{name}' (env {entry.default_env_var}). Use --force via CLI to overwrite."

    def _tool_update_entry(self, args: Dict[str, Any]) -> Tuple[str, bool]:
        vault = self._vault()
        name = str(args.get("name") or "")
        try:
            entry = vault.get(name)
        except Exception:
            return f"No entry named '{name}'.", True
        changes: Dict[str, Any] = {}
        if args.get("tags") is not None:
            changes["tags"] = [str(t) for t in args["tags"]]
        if args.get("notes") is not None:
            changes["notes"] = str(args["notes"])
        if args.get("env_var") is not None:
            changes["env_var"] = str(args["env_var"])
        if args.get("username") is not None:
            changes["username"] = str(args["username"])
        if args.get("url") is not None:
            changes["url"] = str(args["url"])
        if args.get("expires") is not None:
            raw = str(args["expires"]).strip()
            changes["expires_at"] = parse_expires(raw) if raw else None
        if not changes:
            return "Nothing to update.", True
        vault.add(entry.with_updates(**changes), overwrite=True)
        vault.save(self.password or "")
        return f"Updated '{name}'.", False

    def _tool_delete_entry(self, args: Dict[str, Any]) -> Tuple[str, bool]:
        if not args.get("confirm"):
            return "Refused: pass confirm=true to delete an entry.", True
        vault = self._vault()
        name = str(args.get("name") or "")
        try:
            vault.remove(name)
        except Exception:
            return f"No entry named '{name}'.", True
        vault.save(self.password or "")
        return f"Deleted '{name}'.", False

    def _tool_status(self) -> str:
        vault = self._vault()
        entries = list(vault.entries.values())
        expired = [e.name for e in entries if e.is_expired()]
        soon = [
            f"{e.name} ({e.days_left()}d)"
            for e in entries
            if not e.is_expired() and e.days_left() is not None and e.days_left() <= 7
        ]
        return json.dumps(
            {
                "vault": str(vault.path),
                "entries": len(entries),
                "expired": expired,
                "expiring_within_7_days": soon,
            },
            indent=2,
        )


def serve(vault_path: Optional[os.PathLike | str] = None) -> None:
    server = KeystashMCPServer(vault_path)
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
