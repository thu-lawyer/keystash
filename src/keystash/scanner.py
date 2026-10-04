"""Plaintext secret discovery for `keystash doctor`.

Gitleaks-style rules tuned for developer machines: LLM/cloud/SCM tokens with
known prefixes, plus a low-confidence generic assignment rule that catches
`API_KEY=...` shapes in .env files, shell rc/history and code.

Design goals: zero dependencies, fast enough for whole-project scans, and
noisy by default only where it matters — high-confidence findings are
reported as such, generic ones are marked "suspect".
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional

MAX_FILE_BYTES = 2_000_000
MAX_FINDINGS_PER_FILE = 50

EXCLUDED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "dist", "build", ".eggs", ".idea", ".tox",
    ".coverage", "site-packages",
}

# Values that look like secrets but never are one.
PLACEHOLDER_RE = re.compile(
    r"(?i)^(x{3,}|\.+|<?(?:your|my|insert|paste|replace|add)[_-]?.*>?|"
    r"\$\{[^}]*\}|\$[A-Z_]+|%(?:\w+)%|changeme|change[-_]?me|example|"
    r"dummy|placeholder|none|null|nil|true|false|0+)$"
)


@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    secret_group: int = 0  # 0 = whole match; else capture-group index
    suspect: bool = False  # True = low-confidence (generic shapes)


def _entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(value))
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


RULES: List[Rule] = [
    Rule("openai", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{30,}\b")),
    Rule("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b")),
    Rule("github", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b")),
    Rule("github-finegrained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    Rule("aws-access-key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    Rule("google-api", re.compile(r"\bAIza[0-9A-Za-z_-]{35,}\b")),
    Rule("slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Rule("stripe", re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{20,}\b")),
    Rule("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{34}\b")),
    Rule("sendgrid", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}\b")),
    Rule("twilio", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    Rule("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\b"),
         suspect=True),
    Rule(
        "generic-assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|"
            r"token|passwd|password|pwd)\b['\"]?\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9_.\-/+=]{12,})"
        ),
        secret_group=2,
        suspect=True,
    ),
]

HOME_HINT_FILES = [
    ".zshrc", ".zsh_history", ".bashrc", ".bash_history", ".profile", ".env",
]


@dataclass
class Finding:
    rule: str
    suspect: bool
    file: str
    line: int
    secret: str
    stored: bool = False
    suggestion: str = field(default="")

    @property
    def preview(self) -> str:
        s = self.secret
        if self.rule == "private-key":
            return "-----BEGIN ... KEY-----"
        if len(s) > 12:
            return s[:6] + "…" + s[-4:]
        return "•" * len(s)

    def to_json(self) -> dict:
        return {
            "rule": self.rule, "suspect": self.suspect, "file": self.file,
            "line": self.line, "preview": self.preview,
            "stored": self.stored, "suggestion": self.suggestion,
        }


def default_scan_targets() -> List[Path]:
    """Current directory plus the usual dotfiles where keys leak."""
    targets = [Path.cwd()]
    home = Path.home()
    for name in HOME_HINT_FILES:
        p = home / name
        if p.exists():
            targets.append(p)
    return targets


def iter_files(roots: List[Path], vault_path: Optional[Path] = None) -> Iterator[Path]:
    vault = vault_path.expanduser().resolve() if vault_path else None
    seen: set[Path] = set()
    for root in roots:
        root = Path(root).expanduser()
        if root.is_file():
            files = [root]
        elif root.is_dir():
            files = _walk(root)
        else:
            continue
        for f in files:
            try:
                resolved = f.resolve()
            except OSError:
                continue
            if vault and resolved == vault:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            yield f


def _walk(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for name in sorted(filenames):
            p = Path(dirpath) / name
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def _is_probably_text(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(8192)
    except OSError:
        return False
    return b"\x00" not in chunk


def _suggestion(rule: str, file: str, taken: set[str]) -> str:
    stem = re.sub(r"^\.", "", Path(file).stem) or "key"
    base = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{rule}-{stem}").strip("-").lower()
    name, n = base, 2
    while name in taken:
        name, n = f"{base}-{n}", n + 1
    taken.add(name)
    return name


def scan_paths(roots: List[Path], vault_path: Optional[Path] = None) -> List[Finding]:
    findings: List[Finding] = []
    for path in iter_files(roots, vault_path):
        if not _is_probably_text(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(text, str(path)))
    return findings


def scan_text(text: str, filename: str) -> List[Finding]:
    taken: set[str] = set()
    found: List[Finding] = []
    seen: set[tuple] = set()
    for rule in RULES:
        count = 0
        for m in rule.pattern.finditer(text):
            secret = m.group(rule.secret_group) if rule.secret_group else m.group(0)
            if not secret or PLACEHOLDER_RE.match(secret):
                continue
            if rule.suspect and _entropy(secret) < 3.3 and rule.name != "jwt":
                continue
            line = text.count("\n", 0, m.start()) + 1
            key = (filename, line, secret)
            if key in seen:
                continue
            seen.add(key)
            found.append(Finding(
                rule=rule.name,
                suspect=rule.suspect,
                file=filename,
                line=line,
                secret=secret,
                suggestion=_suggestion(rule.name, filename, taken),
            ))
            count += 1
            if count >= MAX_FINDINGS_PER_FILE:
                break
    return found


def mark_stored(findings: List[Finding], vault_secrets: set[str]) -> None:
    for f in findings:
        f.stored = f.secret in vault_secrets


def shred(findings: List[Finding]) -> int:
    """Replace the secret values in their files with redaction placeholders.

    Groups by file and replaces longest-first so overlapping matches cannot
    partially survive. Returns the number of files rewritten.
    """
    by_file: dict[str, dict[str, str]] = {}
    for f in findings:
        by_file.setdefault(f.file, {})[f.secret] = f"[redacted→keystash:{f.suggestion}]"
    rewritten = 0
    for filename, replacements in by_file.items():
        try:
            text = Path(filename).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        original = text
        for secret in sorted(replacements, key=len, reverse=True):
            text = text.replace(secret, replacements[secret])
        if text != original:
            try:
                Path(filename).write_text(text, encoding="utf-8")
                rewritten += 1
            except OSError:
                pass
    return rewritten
