"""Ask for the passphrase.

The native host has its stdin/stdout wired to the browser, so it can never read a terminal
prompt - a GUI dialog is the only option there. Order: zenity (desktop), systemd-ask-password,
then getpass, which only works when a real tty is attached.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

from ..errors import AppleError


class PromptError(AppleError):
    pass


# A background timer must never be able to raise a modal password box on someone's desktop.
# `icp sync --no-prompt` turns this off for the whole process, and ask_passphrase() then fails
# instead of prompting, so the caller can skip and try again when the person is actually there.
_allowed = True


def set_allowed(value: bool) -> None:
    global _allowed
    _allowed = bool(value)


def is_allowed() -> bool:
    return _allowed


def _has_display() -> bool:
    return bool(os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"))


def ask_passphrase(title: str = "iCloud Keychain", text: str = "Unlock your keychain") -> str:
    if not _allowed:
        raise PromptError("keychain is locked and prompting is disabled for this run")
    if _has_display() and shutil.which("zenity"):
        p = subprocess.run(
            ["zenity", "--password", "--title", title, "--text", text],
            capture_output=True, text=True,
        )
        if p.returncode != 0:
            raise PromptError("passphrase prompt cancelled")
        return p.stdout.rstrip("\n")

    if shutil.which("systemd-ask-password"):
        p = subprocess.run(
            ["systemd-ask-password", "--no-tty" if not sys.stdin.isatty() else "--echo=no", text],
            capture_output=True, text=True,
        )
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.rstrip("\n")

    if sys.stdin.isatty():
        import getpass
        return getpass.getpass(f"{text}: ")

    raise PromptError("no way to prompt for the passphrase (no display, no tty)")
