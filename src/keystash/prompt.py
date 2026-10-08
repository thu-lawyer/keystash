"""Native secure input — the only place a secret is ever typed.

Why a dialog instead of a terminal prompt: the AI-facing half of keystash is
an MCP stdio server, which has no controlling terminal. `osascript` renders a
real dialog from such a process (verified on this machine: a non-TTY child
showed the hidden-answer dialog and honoured `giving up after`), and that
clause doubles as the timeout we need anyway.

Why a dialog instead of a CLI/tool argument: `--value sk-...` would land in
shell history, in `ps` output, and — when the AI is the caller — in the chat
transcript. A value must never travel through argv.

Invariant (do not weaken):
  * a secret leaves this module only as a Python return value;
  * it is never written to our stdout/stderr, never logged, and never echoed
    in an error message;
  * the AppleScript program text never contains it;
  * argv carries only the title, the prompt and the timeout.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Optional

IS_DARWIN = sys.platform == "darwin"

#: Returned by the dialogs instead of a value. The "OK:" prefix makes the
#: sentinel unambiguous — a user who literally types CANCEL still comes back
#: as "OK:CANCEL".
_CANCEL = "CANCEL"
_OK = "OK:"

_ASK_SECRET = """
on run argv
    set dlgTitle to item 1 of argv
    set dlgMessage to item 2 of argv
    set dlgSeconds to (item 3 of argv) as integer
    try
        set r to display dialog dlgMessage with title dlgTitle default answer "" with hidden answer buttons {"取消", "确定"} default button "确定" with icon caution giving up after dlgSeconds
        if gave up of r then return "CANCEL"
        if button returned of r is "取消" then return "CANCEL"
        return "OK:" & (text returned of r)
    on error number -128
        return "CANCEL"
    end try
end run
"""

_CONFIRM = """
on run argv
    set dlgTitle to item 1 of argv
    set dlgMessage to item 2 of argv
    set dlgSeconds to (item 3 of argv) as integer
    set okLabel to item 4 of argv
    try
        set r to display dialog dlgMessage with title dlgTitle buttons {"取消", okLabel} default button okLabel with icon caution giving up after dlgSeconds
        if gave up of r then return "NO"
        if button returned of r is okLabel then return "YES"
        return "NO"
    on error number -128
        return "NO"
    end try
end run
"""


class InputUnavailable(RuntimeError):
    """No way to ask the human for a secret on this machine."""


def available() -> bool:
    """True when a native secure-input dialog can be shown."""
    return IS_DARWIN and shutil.which("osascript") is not None


def _run(script: str, args: list, timeout: float) -> str:
    if not available():
        raise InputUnavailable(
            "no secure input channel: this needs macOS with /usr/bin/osascript"
        )
    try:
        proc = subprocess.run(
            ["osascript", "-e", script, "--", *args],
            capture_output=True,
            text=True,
            timeout=timeout + 15.0,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:  # the dialog outlived its budget
        raise InputUnavailable("secure input dialog timed out") from exc
    if proc.returncode != 0:
        # stderr from osascript never contains the typed value — the dialog
        # either failed to open or was dismissed.
        raise InputUnavailable(
            "osascript failed: " + (proc.stderr or "").strip()[:200]
        )
    return proc.stdout.strip()


def ask_secret(
    prompt: str,
    title: str = "keystash",
    timeout: float = 120.0,
) -> Optional[str]:
    """Show a masked input dialog. Returns the text, or None if cancelled.

    An empty string means the user confirmed an empty value; callers decide
    whether that is acceptable.
    """
    out = _run(_ASK_SECRET, [title, prompt, str(int(timeout))], timeout)
    if out == _CANCEL:
        return None
    if not out.startswith(_OK):
        raise InputUnavailable("unexpected reply from secure input dialog")
    return out[len(_OK):]


def confirm(
    prompt: str,
    ok_label: str = "删除",
    title: str = "keystash",
    timeout: float = 120.0,
) -> bool:
    """Two-button confirmation. Never uses text-matching for consent."""
    out = _run(_CONFIRM, [title, prompt, str(int(timeout)), ok_label], timeout)
    return out == "YES"
