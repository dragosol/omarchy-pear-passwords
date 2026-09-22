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


def _has_display() -> bool:
    return bool(os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"))


def ask_passphrase(title: str = "iCloud Keychain", text: str = "Unlock your keychain") -> str:
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
