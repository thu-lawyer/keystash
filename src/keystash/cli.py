"""keystash command line — the human's tool.

v0.4.0 rules
------------
* Secrets are collected through a native macOS dialog (:mod:`keystash.prompt`)
  or, for scripts, an explicit ``--stdin`` pipe. Never from argv: arguments are
  visible to every process on the machine via ``ps``.
* **No command prints a secret to stdout.** ``copy`` puts the value on the
  clipboard and clears it after 30 seconds; everything else prints metadata.
* Names follow ``SERVICE_ENV_PURPOSE`` — ``^[A-Z][A-Z0-9_]{0,63}$``.
"""

from __future__ import annotations

import dataclasses
import getpass
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__, broker, clipboard, keychain, prompt, vault
from .broker import BrokerError

app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Local-first secret broker. The AI gets references; the Keychain gets values.",
)
console = Console()


class State:
    meta_path: Optional[str] = None
    vault_path: Optional[str] = None


state = State()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"keystash {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=version_callback, is_eager=True, help="Show the version."
    ),
    meta: Optional[Path] = typer.Option(
        None,
        "--meta",
        "-m",
        envvar="KEYSTASH_META",
        help="Metadata file (default ~/.keystash/entries.json).",
    ),
    vault_file: Optional[Path] = typer.Option(
        None,
        "--vault",
        "-V",
        envvar="KEYSTASH_VAULT",
        help="Legacy v0.3 vault file — only used by `migrate`.",
    ),
) -> None:
    """Global options go before the subcommand: `keystash --meta P list`."""
    state.meta_path = str(meta) if meta else None
    state.vault_path = str(vault_file) if vault_file else None


def fail(message: str, code: int = 1) -> "typer.Exit":
    console.print(f"[red]error:[/red] {message}")
    return typer.Exit(code)


# --------------------------------------------------------------------------
# input helpers — one dialog, one pipe, never argv
# --------------------------------------------------------------------------


def _require_dialog() -> None:
    if not prompt.available():
        raise BrokerError(
            "the native input dialog is unavailable (no macOS GUI session). "
            "Pipe the value with --stdin instead."
        )


def collect_value(name: str, *, use_stdin: bool, purpose: str) -> str:
    if use_stdin:
        value = sys.stdin.read().strip()
        if not value:
            raise BrokerError("--stdin was given but nothing was piped in")
        return value
    _require_dialog()
    value = prompt.ask_secret(
        f"{purpose}\n(it goes to the login Keychain and is never printed)",
        title=f"keystash — {name}",
        timeout=180.0,
    )
    if value is None:
        raise BrokerError("cancelled — nothing was stored")
    if not value:
        raise BrokerError("refusing to store an empty value")
    return value


def _entry(name: str) -> broker.Entry:
    entry = broker.load_meta(state.meta_path).get(name)
    if entry is None:
        raise BrokerError(f"unknown entry {name!r}")
    return entry


# --------------------------------------------------------------------------
# read-only views — metadata only, no dialog, no value
# --------------------------------------------------------------------------


@app.command("list")
def list_cmd(
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Only entries with this tag."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """List entries. Touches metadata only — never a value."""
    entries = broker.load_meta(state.meta_path)
    rows = [e for e in entries.values() if not tag or tag in e.tags]
    if as_json:
        console.print_json(
            json.dumps({"count": len(rows), "entries": [e.describe() for e in rows]})
        )
        return
    if not rows:
        console.print("[dim]no entries[/dim]")
        return
    table = Table(show_header=True, header_style="bold")
    for column in ("name", "tags", "last rotated", "every (d)", "due", "allowed urls"):
        table.add_column(column)
    for entry in sorted(rows, key=lambda e: e.name):
        due = "[yellow]rotate now[/yellow]" if entry.rotate_due() else "—"
        table.add_row(
            entry.name,
            ", ".join(entry.tags) or "—",
            entry.last_rotated or "—",
            str(entry.rotate_every_days or "—"),
            due,
            "\n".join(entry.allowed_urls) or "[dim]none — use disabled[/dim]",
        )
    console.print(table)


@app.command()
def show(name: str = typer.Argument(..., help="Entry name.")) -> None:
    """Show one entry's metadata."""
    try:
        entry = _entry(name)
    except BrokerError as exc:
        raise fail(str(exc)) from None
    console.print_json(json.dumps(entry.describe()))


# --------------------------------------------------------------------------
# write operations
# --------------------------------------------------------------------------


@app.command()
def add(
    name: str = typer.Argument(..., help="SERVICE_ENV_PURPOSE, e.g. OPENAI_PROD_KEY."),
    tags: List[str] = typer.Option([], "--tag", "-t", help="Repeatable."),
    rotate_every_days: Optional[int] = typer.Option(None, "--rotate-every", "-r", min=1),
    allowed_urls: List[str] = typer.Option(
        [], "--allow", "-a", help="URL prefix ending in '/'. Repeatable; required by `use`."
    ),
    auth_header: str = typer.Option("Authorization", "--auth-header"),
    auth_prefix: str = typer.Option("Bearer ", "--auth-prefix"),
    use_stdin: bool = typer.Option(
        False, "--stdin", help="Read the value from stdin instead of the dialog."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing entry."),
) -> None:
    """Store a new secret. The value is never echoed."""
    try:
        broker.validate_name(name)
        if not force and name in broker.load_meta(state.meta_path):
            raise BrokerError(f"{name} already exists — use `keystash rotate {name}`, or --force")
        value = collect_value(name, use_stdin=use_stdin, purpose=f"Enter the value for {name}")
        entry = broker.put(
            name,
            value,
            tags=tags,
            rotate_every_days=rotate_every_days,
            allowed_urls=allowed_urls,
            auth_header=auth_header,
            auth_prefix=auth_prefix,
            path=state.meta_path,
        )
    except BrokerError as exc:
        raise fail(str(exc)) from None
    console.print(f"[green]stored[/green] {entry.name}  (rotated {entry.last_rotated})")


@app.command()
def rotate(
    name: str = typer.Argument(...),
    use_stdin: bool = typer.Option(False, "--stdin"),
) -> None:
    """Replace an existing value; metadata is preserved."""
    try:
        existing = _entry(name)
        value = collect_value(name, use_stdin=use_stdin, purpose=f"Enter the NEW value for {name}")
        entry = broker.put(
            name,
            value,
            tags=existing.tags,
            rotate_every_days=existing.rotate_every_days,
            allowed_urls=existing.allowed_urls,
            auth_header=existing.auth_header,
            auth_prefix=existing.auth_prefix,
            path=state.meta_path,
        )
    except BrokerError as exc:
        raise fail(str(exc)) from None
    console.print(f"[green]rotated[/green] {entry.name} → {entry.last_rotated}")


@app.command()
def generate(
    name: str = typer.Argument(...),
    tags: List[str] = typer.Option([], "--tag", "-t"),
    rotate_every_days: Optional[int] = typer.Option(None, "--rotate-every", "-r", min=1),
    allowed_urls: List[str] = typer.Option([], "--allow", "-a"),
    length: int = typer.Option(43, "--length", "-l", min=16, max=128),
) -> None:
    """Generate a random value and store it. Prints a fingerprint, not the value.

    Read it back with `keystash copy NAME` when you must paste it into a
    service's web console.
    """
    try:
        value = broker.generate_value(length)
        entry = broker.put(
            name,
            value,
            tags=tags,
            rotate_every_days=rotate_every_days,
            allowed_urls=allowed_urls,
            path=state.meta_path,
        )
    except BrokerError as exc:
        raise fail(str(exc)) from None
    fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    console.print(f"[green]generated[/green] {entry.name}  sha256:{fingerprint}  ({length} chars)")


@app.command()
def edit(
    name: str = typer.Argument(...),
    tags: Optional[List[str]] = typer.Option(None, "--tag", "-t", help="Replaces all tags."),
    rotate_every_days: Optional[int] = typer.Option(None, "--rotate-every", "-r"),
    allowed_urls: Optional[List[str]] = typer.Option(None, "--allow", "-a", help="Replaces all."),
) -> None:
    """Change metadata only. The stored value is never read and never rewritten."""
    try:
        entries = broker.load_meta(state.meta_path)
        if name not in entries:
            raise BrokerError(f"unknown entry {name!r}")
        entry = entries[name]
        updated = dataclasses.replace(
            entry,
            tags=list(entry.tags if tags is None else tags),
            rotate_every_days=(
                entry.rotate_every_days if rotate_every_days is None else rotate_every_days
            ),
            allowed_urls=[
                broker.normalise_allow_prefix(u)
                for u in (entry.allowed_urls if allowed_urls is None else allowed_urls)
            ],
        )
        entries[name] = updated
        broker.save_meta(entries, path=state.meta_path)
    except BrokerError as exc:
        raise fail(str(exc)) from None
    console.print_json(json.dumps(updated.describe()))


@app.command()
def copy(
    name: str = typer.Argument(...),
    seconds: int = typer.Option(30, "--clear-after", min=0, help="0 disables the auto-clear."),
) -> None:
    """Copy a value to the clipboard (auto-cleared). Nothing is printed."""
    try:
        if name not in broker.load_meta(state.meta_path):
            raise BrokerError(f"unknown entry {name!r}")
        secret = broker.KeychainStore().get(name)
    except BrokerError as exc:
        raise fail(str(exc)) from None
    if not secret:
        raise fail(f"no value stored for {name!r}")
    if not clipboard.copy(secret, auto_clear_after=seconds):
        raise fail("no clipboard helper available (pbcopy missing)")
    note = f"auto-clears in {seconds}s" if seconds else "auto-clear disabled"
    console.print(f"[green]copied[/green] {name} to the clipboard ({note})")


@app.command()
def use(
    name: str = typer.Argument(...),
    url: str = typer.Argument(..., help="Must be covered by the entry's allowed URLs."),
    method: str = typer.Option("GET", "--method", "-X"),
    body: Optional[str] = typer.Option(None, "--body", "-d", help="Raw string or JSON object."),
    timeout: float = typer.Option(broker.DEFAULT_TIMEOUT, "--timeout"),
) -> None:
    """Call an allow-listed URL with the stored credential and show the reply."""
    parsed_body: object = body
    if body:
        try:
            parsed_body = json.loads(body)
        except json.JSONDecodeError:
            parsed_body = body
    try:
        result = broker.use(
            name, url, method=method, body=parsed_body, timeout=timeout, path=state.meta_path
        )
    except BrokerError as exc:
        raise fail(str(exc)) from None
    console.print(f"[bold]{result['status']}[/bold] {result['url']}")
    console.print(result["body"] or "[dim](empty body)[/dim]")
    if result["truncated"]:
        console.print("[dim]…truncated[/dim]")


@app.command()
def rm(
    name: str = typer.Argument(...),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation dialog."),
) -> None:
    """Delete an entry and erase its value from the Keychain."""
    try:
        _entry(name)
        confirmed = yes
        if not confirmed:
            _require_dialog()
            confirmed = prompt.confirm(
                f"Delete {name}?\nThe stored value is erased from the Keychain.",
                ok_label="删除",
                title=f"keystash — {name}",
            )
        if not confirmed:
            raise BrokerError("not deleted — not confirmed")
        broker.forget(name, path=state.meta_path)
    except BrokerError as exc:
        raise fail(str(exc)) from None
    console.print(f"[green]deleted[/green] {name}")


# --------------------------------------------------------------------------
# migration from the v0.3 encrypted vault
# --------------------------------------------------------------------------


def _migrated_name(name: str, taken: set) -> str:
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in name).strip("_").upper()
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "K_" + cleaned
    cleaned = cleaned[:64]
    candidate = cleaned
    index = 2
    while candidate in taken:
        suffix = f"_{index}"
        candidate = cleaned[: 64 - len(suffix)] + suffix
        index += 1
    return candidate


def _legacy_password(path: Path) -> str:
    """The master password of a v0.3 vault: env → login Keychain → prompt.

    v0.3's ``ask_password()`` read that password from the login Keychain, keyed by
    the vault's absolute path, so most users never typed it by hand. Looking it up
    again here keeps that promise: a v0.3 vault can still be migrated by someone
    who does not know the password by heart.
    """
    from_env = os.environ.get("KEYSTASH_MASTER_PASSWORD")
    if from_env:
        return from_env
    if keychain.AVAILABLE:
        accounts = [str(path)]
        if path.name.endswith(".migrated"):
            accounts.append(str(path.with_name(path.name[: -len(".migrated")])))
        for account in accounts:
            try:
                stored = keychain.retrieve(broker.KEYCHAIN_SERVICE, account)
            except keychain.KeychainError as exc:
                console.print(f"[yellow]master-password lookup skipped:[/yellow] {exc}")
                break
            if stored:
                console.print(
                    "[green]using the master password held in the Keychain[/green] "
                    f"for {account}"
                )
                return stored
    return getpass.getpass("Master password: ")


@app.command()
def migrate(
    source: Optional[Path] = typer.Option(
        None, "--source", "-s", help="Legacy vault file (default ~/.keystash/vault.json)."
    ),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Read each value back."),
    retire: bool = typer.Option(
        False, "--retire-vault", help="Rename the old vault to *.migrated after success."
    ),
) -> None:
    """Move every entry from the v0.3 encrypted vault into the Keychain.

    Values pass through memory only; nothing prints but names and counts.
    """
    path = Path(source or state.vault_path or vault.DEFAULT_VAULT_PATH).expanduser()
    if not path.exists():
        raise fail(f"no vault at {path}")

    password = _legacy_password(path)
    old = vault.Vault(path)
    try:
        old.load(password)
    except vault.VaultError as exc:
        raise fail(str(exc)) from None
    if not old.entries:
        console.print(f"[yellow]vault at {path} is empty — nothing to do[/yellow]")
        raise typer.Exit(0)

    taken = set(broker.load_meta(state.meta_path))
    store = broker.KeychainStore()
    table = Table(show_header=True, header_style="bold")
    for column in ("old name", "new name", "tags", "verified"):
        table.add_column(column)

    failures = 0
    for old_name, entry in sorted(old.entries.items()):
        new_name = _migrated_name(old_name, taken)
        taken.add(new_name)
        try:
            broker.put(
                new_name,
                entry.secret,
                tags=entry.tags,
                rotate_every_days=None,
                allowed_urls=[],  # deny by default: add prefixes later, deliberately
                path=state.meta_path,
            )
        except BrokerError as exc:
            failures += 1
            table.add_row(old_name, new_name, ", ".join(entry.tags) or "—", f"[red]{exc}[/red]")
            continue
        verdict = "[dim]skipped[/dim]"
        if verify:
            verdict = (
                "[green]yes[/green]"
                if store.get(new_name) == entry.secret
                else "[red]MISMATCH[/red]"
            )
            if "MISMATCH" in verdict:
                failures += 1
        table.add_row(old_name, new_name, ", ".join(entry.tags) or "—", verdict)

    console.print(table)
    total = len(old.entries)
    console.print(
        f"migrated [bold]{total - failures}[/bold]/{total} entries into the Keychain; "
        f"metadata at {broker.meta_path(state.meta_path)}"
    )
    console.print(
        "[yellow]allowed_urls were left empty[/yellow] — add prefixes with "
        "`keystash edit NAME --allow https://host/` before `use` can work."
    )
    if failures:
        raise fail(f"{failures} entr{'y' if failures == 1 else 'ies'} failed — vault kept as is")
    if retire:
        retired = path.with_name(path.name + ".migrated")
        path.replace(retired)
        console.print(f"[yellow]old vault renamed to[/yellow] {retired}")


# --------------------------------------------------------------------------
# diagnostics & the MCP entrypoint
# --------------------------------------------------------------------------


@app.command()
def doctor() -> None:
    """Check this machine's prerequisites."""
    meta = broker.meta_path(state.meta_path)
    checks = [
        ("platform", sys.platform, "darwin"),
        ("keychain backend", str(keychain.AVAILABLE), "True"),
        ("osascript", shutil.which("osascript") or "missing", None),
        ("security", shutil.which("security") or "missing", None),
        ("pbcopy", shutil.which("pbcopy") or "missing", None),
    ]
    table = Table(show_header=True, header_style="bold")
    table.add_column("check")
    table.add_column("found")
    for label, found, want in checks:
        ok = (found == want) if want is not None else found != "missing"
        table.add_row(label, f"[{'green' if ok else 'red'}]{found}[/{'green' if ok else 'red'}]")
    console.print(table)

    console.print(f"metadata      {meta}  ({'exists' if Path(meta).exists() else 'not created yet'})")
    console.print(f"audit log     {Path(meta).parent / broker.AUDIT_FILENAME}")
    console.print(f"legacy vault  {Path(state.vault_path or vault.DEFAULT_VAULT_PATH).expanduser()}")
    if Path(meta).exists():
        try:
            entries = broker.load_meta(state.meta_path)
        except BrokerError as exc:
            console.print(f"[red]metadata unreadable:[/red] {exc}")
            return
        due = sorted(e.name for e in entries.values() if e.rotate_due())
        console.print(f"entries       {len(entries)}")
        if due:
            console.print(f"[yellow]rotation due[/yellow] {', '.join(due)}")


@app.command()
def mcp() -> None:
    """Serve the MCP stdio interface: six tools, no read tool, ever."""
    from .mcp_server import serve

    serve(state.meta_path)


def cli() -> None:
    app()


if __name__ == "__main__":
    cli()
