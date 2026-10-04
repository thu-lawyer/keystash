"""Clipboard copy with best-effort delayed clear.

The delayed clear runs in a detached child process so it survives this CLI's
exit. Best-effort by design: if no clipboard helper is found, copy still
succeeds and we simply skip the auto-clear.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

CLEAR_AFTER_SECONDS = 30


def _copy_cmd() -> list[str] | None:
    if sys.platform == "darwin":
        if shutil.which("pbcopy"):
            return ["pbcopy"]
        return None
    if sys.platform == "win32":
        if shutil.which("clip"):
            return ["clip"]
        return None
    for candidate in ("wl-copy", "xclip", "xsel"):
        if shutil.which(candidate):
            return [candidate]
    return None


def _clear_cmd(seconds: int) -> list[str] | None:
    if sys.platform == "darwin" and shutil.which("pbcopy"):
        return ["bash", "-c", f'sleep {seconds}; printf "" | pbcopy']
    if sys.platform == "win32" and shutil.which("clip"):
        return ["cmd", "/c", f"timeout /t {seconds} >nul & cls & echo off | clip"]
    for wl, xs in (("wl-copy", "wl-copy"), ("xclip", "xclip"), ("xsel", "xsel")):
        if shutil.which(wl):
            if xs == "xclip":
                return ["bash", "-c", f'sleep {seconds}; printf "" | xclip -selection clipboard']
            if xs == "xsel":
                return ["bash", "-c", f'sleep {seconds}; printf "" | xsel --clipboard --input']
            return ["bash", "-c", f'sleep {seconds}; printf "" | wl-copy']
    return None


def copy(text: str, *, auto_clear_after: int = CLEAR_AFTER_SECONDS) -> bool:
    cmd = _copy_cmd()
    if cmd is None:
        return False
    subprocess.run(cmd, input=text.encode("utf-8"), check=True)
    if auto_clear_after > 0:
        clear = _clear_cmd(auto_clear_after)
        if clear:
            try:
                subprocess.Popen(
                    clear,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except OSError:
                pass
    return True
