"""keystash command-line interface."""

from __future__ import annotations

import getpass
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__, clipboard, keychain
from .gen import generate
from .model import Entry, parse_expires
from .scanner import default_scan_targets, mark_stored, scan_paths, shred
from .search import search as fuzzy_search
from .vault import (
    BAD_PASSWORD,
    Vault,
    VaultError,
)

app = typer.Typer(
    name="keystash",
    help="Local-first encrypted vault for API keys, tokens and passwords.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}
KEYCHAIN_SERVICE = "keystash"


class State:
    vault_path: Optional[Path] = None
    no_keychain: bool = False


state = State()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"keystash {__version__}")
        raise typer.Exit()


@app.callback(context_settings=CONTEXT_SETTINGS)
def main(
    vault: Optional[Path] = typer.Option(
        None,
        "--vault",
        "-V",
        help="Path to the vault file (default: $KEYSTASH_VAULT or ~/.keystash/vault.json).",
        envvar="KEYSTASH_VAULT",
    ),
    no_keychain: bool = typer.Option(
        False,
        "--no-keychain",
        help="Skip the keychain / Touch ID unlock and prompt for the master password.",
    ),
    version: bool = typer.Option(
        False, "--version", callback=version_callback, is_eager=True
    ),
) -> None:
    state.vault_path = vault
    state.no_keychain = no_keychain


# ---------------------------------------------------------------- helpers


def resolve_vault() -> Vault:
    return Vault(state.vault_path)


def ask_password() -> str:
    password = os.environ.get("KEYSTASH_PASSWORD")
    if password is not None:
        return password
    if not state.no_keychain and keychain.AVAILABLE:
        try:
            stored = keychain.retrieve(KEYCHAIN_SERVICE, str(resolve_vault().path))
            if stored:
                return stored
        except keychain.KeychainError:
            pass  # declined / no UI context → fall through to the prompt
    try:
        return getpass.getpass("Master password: ")
    except (EOFError, KeyboardInterrupt):
        raise typer.Exit(1) from None


def fail(message: str, code: int = 1) -> "typer.Exit":
    err_console.print(f"[red]error:[/red] {message}")
    return typer.Exit(code)


def load_vault() -> Vault:
    vault = resolve_vault()
    try:
        vault.load(ask_password())
    except VaultError as e:
        if e.code == BAD_PASSWORD:
            raise fail(str(e)) from None
        raise fail(str(e)) from None
    return vault


def _mask(secret: str) -> str:
    if len(secret) <= 8:
        return "•" * len(secret)
    return secret[:4] + "•" * (len(secret) - 8) + secret[-4:]


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _expiry_markup(entry: Entry) -> str:
    if entry.expires_at is None:
        return "[dim]—[/dim]"
    left = entry.days_left() or 0
    if entry.is_expired():
        return f"[red]{entry.expires_at} (expired)[/red]"
    if left <= 7:
        return f"[yellow]{entry.expires_at} ({left}d)[/yellow]"
    return str(entry.expires_at)


def _parse_tags(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip()]


def _confirm(message: str) -> bool:
    return typer.confirm(message, default=False)


# ---------------------------------------------------------------- commands


@app.command()
def unlock() -> None:
    """Verify the master password once, then keep it behind Touch ID (macOS).

    Afterwards every command costs one fingerprint instead of a typed
    password. Undo with `keystash lock`, bypass with --no-keychain.
    """
    if not keychain.AVAILABLE:
        raise fail("Keychain unlock is only available on macOS.")
    vault = resolve_vault()
    if not vault.exists():
        raise fail(f"No vault at {vault.path} — run `keystash init` first.", code=3)
    password = os.environ.get("KEYSTASH_PASSWORD") or getpass.getpass("Master password: ")
    try:
        vault.load(password)
    except VaultError as e:
        raise fail(str(e)) from None
    try:
        mode = keychain.store(KEYCHAIN_SERVICE, str(vault.path), password)
    except keychain.KeychainError as e:
        raise fail(f"Keychain write failed: {e}") from None
    console.print(f"[green]Unlocked.[/green] Master password stored ({mode}-gated).")
    if keychain.biometric_available():
        console.print("Next commands will ask for Touch ID instead of the password.")
    console.print("[dim]`keystash lock` removes it; --no-keychain bypasses it.[/dim]")


@app.command()
def lock() -> None:
    """Remove the master password from the keychain (undo `unlock`)."""
    if not keychain.AVAILABLE:
        raise fail("Keychain is only available on macOS.")
    vault = resolve_vault()
    removed = keychain.delete(KEYCHAIN_SERVICE, str(vault.path))
    console.print("[green]Locked.[/green]" if removed else "[dim]Nothing was stored.[/dim]")


@app.command()
def init() -> None:
    """Create a new vault with a master password."""
    vault = resolve_vault()
    if vault.exists():
        raise fail(f"Vault already exists at {vault.path}")
    if os.environ.get("KEYSTASH_PASSWORD"):
        password = os.environ["KEYSTASH_PASSWORD"]
    else:
        password = getpass.getpass("Set master password: ")
        confirm = getpass.getpass("Confirm master password: ")
        if password != confirm:
            raise fail("Passwords do not match.")
    if not password:
        raise fail("Master password cannot be empty.")
    vault.create(password)
    console.print(f"[green]Vault created at {vault.path}[/green]")
    console.print(
        "Tip: point [bold]KEYSTASH_VAULT[/bold] at a cloud-synced folder "
        "(iCloud/SeaDrive/Dropbox) to keep multiple machines in sync — the file "
        "is encrypted, so syncing it is safe."
    )


@app.command()
def add(
    name: str = typer.Argument(..., help="Entry name, e.g. openai-prod."),
    secret: Optional[str] = typer.Option(
        None, "--secret", "-s", help="The secret value (will prompt if omitted)."
    ),
    generate_len: Optional[int] = typer.Option(
        None, "--generate", "-g", help="Generate a random secret of this length instead."
    ),
    username: Optional[str] = typer.Option(None, "--username", "-u"),
    url: Optional[str] = typer.Option(None, "--url"),
    tags: Optional[str] = typer.Option(None, "--tags", "-t", help="Comma-separated tags."),
    notes: Optional[str] = typer.Option(None, "--notes", "-n"),
    env_var: Optional[str] = typer.Option(
        None, "--env-var", "-e", help="Env var name used by `run` and `env`."
    ),
    expires: Optional[str] = typer.Option(
        None, "--expires", help="Expiry date, YYYY-MM-DD."
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing entry."),
) -> None:
    """Add a new entry."""
    if expires:
        try:
            parse_expires(expires)
        except ValueError:
            raise fail("--expires must be YYYY-MM-DD") from None
    vault = load_vault()
    if secret is None and generate_len is None:
        secret = getpass.getpass(f"Secret for '{name}': ")
    if generate_len is not None:
        try:
            secret = generate(generate_len)
        except ValueError as e:
            raise fail(str(e)) from None
    if not secret:
        raise fail("Secret cannot be empty.")
    entry = Entry(
        name=name,
        secret=secret,
        username=username or "",
        url=url or "",
        tags=_parse_tags(tags),
        notes=notes or "",
        env_var=env_var or "",
        expires_at=parse_expires(expires),
    )
    try:
        vault.add(entry, overwrite=force)
    except VaultError as e:
        raise fail(str(e)) from None
    vault.save(ask_password())
    console.print(f"[green]Added[/green] {name} [dim]→ env {entry.default_env_var}[/dim]")


@app.command()
def get(
    name: str = typer.Argument(...),
    copy: bool = typer.Option(False, "--copy", "-c", help="Copy to clipboard instead of printing."),
    reveal: bool = typer.Option(False, "--reveal", "-r", help="Show the full secret."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Print only the raw secret (for scripting)."),
) -> None:
    """Show / copy an entry's secret."""
    vault = load_vault()
    try:
        entry = vault.get(name)
    except VaultError as e:
        raise fail(str(e), code=3) from None
    if entry.is_expired() and not quiet:
        console.print(
            f"[yellow]warning:[/yellow] '{entry.name}' expired on {entry.expires_at}",
            style="dim",
        )
    if copy:
        if clipboard.copy(entry.secret):
            console.print(
                f"[green]Copied '{entry.name}' to clipboard[/green] "
                f"[dim](auto-clears in {clipboard.CLEAR_AFTER_SECONDS}s)[/dim]"
            )
        else:
            raise fail("No clipboard helper found (pbcopy/wl-copy/xclip/clip).")
        return
    if quiet:
        typer.echo(entry.secret)
        return
    shown = entry.secret if reveal else _mask(entry.secret)
    body = (
        f"[bold]secret:[/bold] {shown}\n"
        f"[bold]env:[/bold] {entry.default_env_var}\n"
        f"[bold]username:[/bold] {entry.username or '—'}\n"
        f"[bold]url:[/bold] {entry.url or '—'}\n"
        f"[bold]tags:[/bold] {', '.join(entry.tags) or '—'}\n"
        f"[bold]expires:[/bold] {entry.expires_at or '—'}\n"
        f"[bold]notes:[/bold] {entry.notes or '—'}"
    )
    console.print(Panel(body, title=entry.name, subtitle=f"updated {entry.updated_at:%Y-%m-%d}"))
    if not reveal:
        console.print("[dim]Use --reveal to show, --copy to copy.[/dim]")


@app.command("ls")
def list_entries(
    query: Optional[str] = typer.Argument(None, help="Fuzzy search pattern."),
    tag: Optional[str] = typer.Option(None, "--tag", help="Filter by tag."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """List entries, optionally fuzzy-searching."""
    vault = load_vault()
    entries = fuzzy_search(vault.entries, query or "")
    if tag:
        entries = [e for e in entries if tag in e.tags]
    if json_out:
        typer.echo(
            json.dumps(
                [
                    {
                        "name": e.name,
                        "env_var": e.default_env_var,
                        "tags": e.tags,
                        "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                        "expired": e.is_expired(),
                    }
                    for e in entries
                ],
                indent=2,
            )
        )
        return
    if not entries:
        console.print("[dim]No matching entries.[/dim]")
        return
    table = Table(title=f"{vault.path} · {len(entries)} entry(ies)")
    table.add_column("Name", style="cyan")
    table.add_column("Env var", style="green")
    table.add_column("Tags")
    table.add_column("Expires")
    table.add_column("Updated", style="dim")
    for e in entries:
        table.add_row(
            e.name,
            e.default_env_var,
            ", ".join(e.tags),
            _expiry_markup(e),
            f"{e.updated_at:%Y-%m-%d}",
        )
    console.print(table)


@app.command()
def rm(
    name: str = typer.Argument(...),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
) -> None:
    """Delete an entry."""
    vault = load_vault()
    try:
        vault.get(name)
    except VaultError as e:
        raise fail(str(e), code=3) from None
    if not force and not _confirm(f"Delete '{name}' permanently?"):
        raise typer.Abort()
    vault.remove(name)
    vault.save(ask_password())
    console.print(f"[green]Deleted[/green] {name}")


@app.command()
def edit(
    name: str = typer.Argument(...),
    secret: Optional[str] = typer.Option(None, "--secret", "-s", help="Replace the secret."),
    username: Optional[str] = typer.Option(None, "--username", "-u"),
    url: Optional[str] = typer.Option(None, "--url"),
    tags: Optional[str] = typer.Option(None, "--tags", "-t"),
    notes: Optional[str] = typer.Option(None, "--notes", "-n"),
    env_var: Optional[str] = typer.Option(None, "--env-var", "-e"),
    expires: Optional[str] = typer.Option(None, "--expires"),
    clear_expires: bool = typer.Option(False, "--clear-expires"),
) -> None:
    """Update fields of an existing entry (only provided fields change)."""
    if expires:
        try:
            parse_expires(expires)
        except ValueError:
            raise fail("--expires must be YYYY-MM-DD") from None
    vault = load_vault()
    try:
        entry = vault.get(name)
    except VaultError as e:
        raise fail(str(e), code=3) from None
    changes = {}
    if secret is not None:
        changes["secret"] = secret
    if username is not None:
        changes["username"] = username
    if url is not None:
        changes["url"] = url
    if tags is not None:
        changes["tags"] = _parse_tags(tags)
    if notes is not None:
        changes["notes"] = notes
    if env_var is not None:
        changes["env_var"] = env_var
    if clear_expires:
        changes["expires_at"] = None
    elif expires is not None:
        changes["expires_at"] = parse_expires(expires)
    if not changes:
        raise fail("Nothing to change — pass at least one field option.")
    vault.add(entry.with_updates(**changes), overwrite=True)
    vault.save(ask_password())
    console.print(f"[green]Updated[/green] {name}")


@app.command()
def gen(
    length: int = typer.Argument(24, min=8, help="Secret length."),
    no_symbols: bool = typer.Option(False, "--no-symbols", help="Alphanumeric only."),
    save_name: Optional[str] = typer.Option(
        None, "--save", help="Save the generated secret as a new entry with this name."
    ),
    tags: Optional[str] = typer.Option(None, "--tags", "-t"),
    expires: Optional[str] = typer.Option(None, "--expires"),
) -> None:
    """Generate a strong random secret (optionally save it)."""
    try:
        value = generate(length, symbols=not no_symbols)
    except ValueError as e:
        raise fail(str(e)) from None
    if not save_name:
        typer.echo(value)
        return
    vault = load_vault()
    entry = Entry(
        name=save_name,
        secret=value,
        tags=_parse_tags(tags),
        expires_at=parse_expires(expires),
    )
    try:
        vault.add(entry, overwrite=False)
    except VaultError as e:
        raise fail(str(e)) from None
    vault.save(ask_password())
    console.print(f"[green]Generated & saved[/green] {save_name} ({length} chars)")


def _select_entries(vault: Vault, names: List[str], tag: Optional[str]) -> List[Entry]:
    if names:
        missing = [n for n in names if n not in vault.entries]
        if missing:
            raise fail(f"No such entr{'y' if len(missing) == 1 else 'ies'}: {', '.join(missing)}", code=3)
        return [vault.entries[n] for n in names]
    if tag:
        selected = [e for e in vault.entries.values() if tag in e.tags]
        if not selected:
            raise fail(f"No entries tagged '{tag}'.", code=3)
        return selected
    raise fail("Specify entry names or --tag.")


@app.command()
def env(
    names: List[str] = typer.Argument(None, help="Entry names."),
    tag: Optional[str] = typer.Option(None, "--tag", help="All entries with this tag."),
) -> None:
    """Print `export` lines so you can run: eval "$(keystash env openai)". """
    vault = load_vault()
    for entry in _select_entries(vault, list(names or []), tag):
        typer.echo(f"export {entry.default_env_var}={_shell_quote(entry.secret)}")


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(
    ctx: typer.Context,
    name: List[str] = typer.Option(
        None, "--name", "-n", help="Entry to inject (repeatable)."
    ),
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Inject all entries with this tag."),
    quiet: bool = typer.Option(True, "--quiet/--no-quiet", help="Hide which vars are injected."),
) -> None:
    """Run a command with selected secrets injected as env vars.

    Everything after `--` is the command to run:

        keystash run -n openai -n anthropic -- python train.py
        keystash run --tag llm -- python train.py
    """
    cmd = list(ctx.args)
    if cmd and cmd[0] == "--":  # defensive: some click versions keep the separator
        cmd = cmd[1:]
    if not cmd:
        raise fail("Usage: keystash run [-n NAME]... [--tag TAG] -- COMMAND [ARGS...]")
    vault = load_vault()
    selected = _select_entries(vault, name, tag)
    environ = dict(os.environ)
    for entry in selected:
        environ[entry.default_env_var] = entry.secret
        if not quiet:
            console.print(f"[dim]+ {entry.default_env_var}[/dim]")
    try:
        completed = subprocess.run(cmd, env=environ, check=False)
    except FileNotFoundError:
        raise fail(f"Command not found: {cmd[0]}") from None
    raise typer.Exit(completed.returncode)


@app.command("import")
def import_entries(
    file: Path = typer.Argument(..., exists=True, readable=True, help=".env or JSON file."),
    prefix: str = typer.Option("", "--prefix", help="Strip this prefix from names."),
    tags: Optional[str] = typer.Option("imported", "--tags", "-t"),
    force: bool = typer.Option(False, "--force", "-f"),
) -> None:
    """Bulk-import entries from a .env or JSON file (and delete the source file's risk)."""
    text = file.read_text(encoding="utf-8")
    pairs: List[tuple[str, str]] = []
    if file.suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise fail("Invalid JSON file.") from None
        items = data.items() if isinstance(data, dict) else None
        if items is None:
            raise fail("JSON must be an object mapping name → secret.")
        for k, v in items:
            if isinstance(v, dict) and "secret" in v:
                pairs.append((str(k), str(v["secret"])))
            else:
                pairs.append((str(k), str(v)))
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip("'\"")
            pairs.append((key.strip(), value))
    if prefix:
        pairs = [(k[len(prefix):] if k.startswith(prefix) else k, v) for k, v in pairs]
    vault = load_vault()
    now = datetime.now(timezone.utc)
    count = 0
    for name, secret in pairs:
        if not name or not secret:
            continue
        entry = Entry(
            name=name,
            secret=secret,
            tags=_parse_tags(tags),
            created_at=now,
            updated_at=now,
        )
        vault.add(entry, overwrite=force)
        count += 1
    vault.save(ask_password())
    console.print(f"[green]Imported {count} entr{'y' if count == 1 else 'ies'}[/green]")
    console.print(
        "[yellow]Remember to delete the plaintext source file and remove it from any git history.[/yellow]"
    )


@app.command()
def export(
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write to file instead of stdout."),
    format: str = typer.Option("json", "--format", "-f", help="json or dotenv."),
    include_secrets: bool = typer.Option(False, "--with-secrets", help="Include secret values."),
) -> None:
    """Export entries (metadata by default, secrets only with --with-secrets)."""
    if format not in ("json", "dotenv"):
        raise fail("--format must be json or dotenv.")
    vault = load_vault()
    entries = sorted(vault.entries.values(), key=lambda e: e.name)
    if format == "dotenv":
        lines = []
        for e in entries:
            if include_secrets:
                lines.append(f"{e.default_env_var}={e.secret}")
            else:
                lines.append(f"{e.default_env_var}=")
        payload = "\n".join(lines) + "\n"
    else:
        payload = json.dumps(
            {
                e.name: {
                    **{k: v for k, v in e.to_dict().items() if k != "secret"},
                    "secret": e.secret if include_secrets else None,
                }
                for e in entries
            },
            indent=2,
        )
    if out:
        out.write_text(payload, encoding="utf-8")
        console.print(f"[green]Exported {len(entries)} entries to {out}[/green]")
    else:
        typer.echo(payload, nl=False)


@app.command()
def doctor(
    paths: List[Path] = typer.Argument(
        None, help="Files/directories to scan (default: current directory + shell dotfiles)."
    ),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable report."),
    import_all: bool = typer.Option(
        False, "--import-all", help="Import every not-yet-stored finding into the vault."
    ),
    shred_files: bool = typer.Option(
        False, "--shred", help="With --import-all: redact imported secrets in their files."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Hunt down plaintext secrets scattered outside the vault.

    Scans .env files, shell rc/history and project directories for API keys
    and tokens, reports which are already stored, and can import + redact.
    """
    roots = [Path(p) for p in paths] if paths else default_scan_targets()
    findings = scan_paths(roots, resolve_vault().path)
    vault = None
    vault_secrets: set = set()
    if resolve_vault().exists():
        vault = load_vault()
        vault_secrets = {e.secret for e in vault.entries.values()}
    mark_stored(findings, vault_secrets)
    if json_out:
        typer.echo(json.dumps([f.to_json() for f in findings], indent=2))
        return
    fresh = [f for f in findings if not f.stored]
    console.print(
        f"Scanned [bold]{len(findings)}[/bold] finding(s): "
        f"[yellow]{len(fresh)} new[/yellow], {len(findings) - len(fresh)} already stored."
    )
    if not findings:
        console.print("[green]No plaintext secrets found. Clean machine.[/green]")
        return
    table = Table(title="findings (newest pain first)")
    table.add_column("Rule")
    table.add_column("Where", style="dim")
    table.add_column("Preview")
    table.add_column("Status")
    for f in sorted(findings, key=lambda f: (f.stored, f.suspect, f.file, f.line)):
        rule = f.rule + (" (suspect)" if f.suspect else "")
        status = "[green]in vault[/green]" if f.stored else "[yellow]NEW[/yellow]"
        table.add_row(rule, f"{f.file}:{f.line}", f.preview, status)
    console.print(table)
    if not fresh:
        return
    if import_all:
        if vault is None:
            raise fail("No vault to import into — run `keystash init` first.", code=3)
        if not yes and not _confirm(f"Import {len(fresh)} finding(s) into the vault?"):
            raise typer.Abort()
        now = datetime.now(timezone.utc)
        taken = set(vault.entries)
        for f in fresh:
            name = f.suggestion
            n = 2
            while name in taken:
                name, n = f"{f.suggestion}-{n}", n + 1
            taken.add(name)
            vault.add(
                Entry(
                    name=name,
                    secret=f.secret,
                    tags=["doctor", f.rule],
                    notes=f"imported from {f.file}:{f.line}",
                    created_at=now,
                    updated_at=now,
                ),
                overwrite=True,
            )
        vault.save(ask_password())
        console.print(f"[green]Imported {len(fresh)} entr{'y' if len(fresh) == 1 else 'ies'}[/green]")
        if shred_files:
            count = shred(fresh)
            console.print(
                f"[green]Redacted secrets in {count} file(s)[/green] "
                "[dim](placeholders keep the file structure intact)[/dim]"
            )
    else:
        console.print("[dim]Re-run with --import-all to store the new ones"
                      " (+ --shred to redact them in place).[/dim]")


@app.command()
def status() -> None:
    """Show vault status and expiring entries."""
    vault = resolve_vault()
    if not vault.exists():
        raise fail(f"No vault at {vault.path} — run `keystash init` first.", code=3)
    console.print(f"[bold]Vault:[/bold] {vault.path}")
    vault.load(ask_password())
    total = len(vault.entries)
    expired = [e for e in vault.entries.values() if e.is_expired()]
    soon = [
        e
        for e in vault.entries.values()
        if not e.is_expired() and e.days_left() is not None and (e.days_left() or 0) <= 7
    ]
    console.print(f"[bold]Entries:[/bold] {total}")
    if expired:
        console.print(
            Panel(
                "\n".join(f"• {e.name} — expired {e.expires_at}" for e in expired),
                title="[red]Expired[/red]",
            )
        )
    if soon:
        console.print(
            Panel(
                "\n".join(f"• {e.name} — {e.days_left()}d left" for e in soon),
                title="[yellow]Expiring within 7 days[/yellow]",
            )
        )
    if not expired and not soon:
        console.print("[green]No expired or expiring entries.[/green]")


def cli() -> None:
    try:
        app()
    except VaultError as e:  # defensive: surface as friendly error
        err_console.print(f"[red]error:[/red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli()
