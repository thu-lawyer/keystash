"""Encrypted vault storage.

On-disk format (single JSON file, safe to sync through any cloud drive):

    {
      "version": 1,
      "kdf": {"name": "PBKDF2-HMAC-SHA256", "salt": "<hex>", "iterations": 600000},
      "cipher": "Fernet",
      "payload": "<fernet token>"
    }

The Fernet token encrypts a JSON document ``{"entries": {name: entry_dict}}``.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import Dict, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .model import Entry

VAULT_VERSION = 1
DEFAULT_ITERATIONS = 600_000
DEFAULT_VAULT_PATH = Path(os.environ.get("KEYSTASH_VAULT", "~/.keystash/vault.json"))

VAULT_EXISTS = "vault_exists"
BAD_PASSWORD = "bad_password"
NOT_FOUND = "not_found"


class VaultError(Exception):
    """Raised with a machine-readable ``code`` and a human message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


class Vault:
    def __init__(self, path: Optional[os.PathLike | str] = None) -> None:
        self.path = Path(path or DEFAULT_VAULT_PATH).expanduser()
        self.entries: Dict[str, Entry] = {}
        self.iterations = DEFAULT_ITERATIONS

    # -- lifecycle ---------------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists()

    def create(self, password: str) -> None:
        if self.exists():
            raise VaultError(VAULT_EXISTS, f"Vault already exists at {self.path}")
        self._write(password, {})

    def load(self, password: str) -> None:
        raw = self._read_file()
        salt = bytes.fromhex(raw["kdf"]["salt"])
        self.iterations = int(raw["kdf"].get("iterations", DEFAULT_ITERATIONS))
        key = derive_key(password, salt, self.iterations)
        try:
            plaintext = Fernet(key).decrypt(raw["payload"].encode("ascii"))
        except InvalidToken:
            raise VaultError(BAD_PASSWORD, "Wrong master password.") from None
        data = json.loads(plaintext.decode("utf-8"))
        self.entries = {
            name: Entry.from_dict(d) for name, d in data.get("entries", {}).items()
        }

    def save(self, password: str) -> None:
        if not self.exists():
            raise VaultError(NOT_FOUND, "Vault not initialized — run `keystash init` first.")
        self._write(password, self.entries)

    # -- entry operations --------------------------------------------------

    def add(self, entry: Entry, *, overwrite: bool = False) -> None:
        if entry.name in self.entries and not overwrite:
            raise VaultError(
                VAULT_EXISTS, f"Entry '{entry.name}' already exists (use --force to overwrite)."
            )
        self.entries[entry.name] = entry

    def get(self, name: str) -> Entry:
        if name not in self.entries:
            raise VaultError(NOT_FOUND, f"No entry named '{name}'.")
        return self.entries[name]

    def remove(self, name: str) -> Entry:
        entry = self.get(name)
        del self.entries[name]
        return entry

    # -- internals -----------------------------------------------------------

    def _write(self, password: str, entries: Dict[str, Entry]) -> None:
        salt = os.urandom(16)
        key = derive_key(password, salt, DEFAULT_ITERATIONS)
        payload = json.dumps(
            {"entries": {name: e.to_dict() for name, e in entries.items()}}
        ).encode("utf-8")
        doc = {
            "version": VAULT_VERSION,
            "kdf": {
                "name": "PBKDF2-HMAC-SHA256",
                "salt": salt.hex(),
                "iterations": DEFAULT_ITERATIONS,
            },
            "cipher": "Fernet",
            "payload": Fernet(key).encrypt(payload).decode("ascii"),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            pass
        tmp.replace(self.path)

    def _read_file(self) -> dict:
        if not self.exists():
            raise VaultError(
                NOT_FOUND, f"No vault at {self.path} — run `keystash init` first."
            )
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raise VaultError("corrupt", f"Vault file {self.path} is not valid JSON.") from None
