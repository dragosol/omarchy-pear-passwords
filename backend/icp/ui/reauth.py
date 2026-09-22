"""Presence check before opening the keychain viewer.

Opens Omarchy's polkit overlay (the fingerprint card) via org.icp.unlock.
`pkcheck` is not used: it cannot pass ALWAYS_CHECK, so a logged-in session can
come back authorized without the overlay ever appearing.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess

POLICY_PATH = "/usr/share/polkit-1/actions/org.icp.unlock.policy"
GATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "polkit_gate.py")
SYSTEM_PYTHON = os.environ.get("ICP_SYSTEM_PYTHON", "/usr/bin/python3")


def policy_installed() -> bool:
    return os.path.exists(POLICY_PATH)


def available() -> bool:
    return (
        policy_installed()
        and os.path.isfile(GATE)
        and os.access(SYSTEM_PYTHON, os.X_OK)
    )


# The child in flight, so a SIGTERM to the caller can take the prompt down with it. Without
# this, retrying a stuck unlock left the first dialog on screen beside the second.
_current = None


def _run(argv, timeout):
    """(returncode or None, stderr text). None means it never finished - spawn failure or
    timeout - which callers treat as the gate having broken."""
    global _current
    try:
        _current = subprocess.Popen(argv, start_new_session=True,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except OSError as e:
        return None, str(e)
    try:
        _, err = _current.communicate(timeout=timeout)
        return _current.returncode, (err or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        kill_current()
        return None, "timed out"
    finally:
        _current = None


def kill_current() -> None:
    p = _current
    if p is None or p.poll() is not None:
        return
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except OSError:
        pass


def challenge_status(timeout: int = 120) -> str:
    """'authed', 'denied' or 'error'.

    The whole point is telling "a person said no" apart from "the gate broke": the first must
    be respected, the second is a malfunction to route around. See polkit_gate.py's exit codes.
    """
    if not available():
        return "error"
    rc, _ = _run([SYSTEM_PYTHON, GATE], timeout)
    if rc == 0:
        return "authed"
    if rc == 1:
        return "denied"
    return "error"


def challenge(timeout: int = 120) -> bool:
    """True if the user authenticated. False if they cancelled, failed, or it is unavailable."""
    return challenge_status(timeout) == "authed"


def pkexec_challenge(timeout: int = 90) -> str:
    """Last resort for when the polkit gate itself is broken: authenticate through pkexec,
    which raises the same desktop agent via the stock exec action on a harmless `true`.

    Weaker than the gate, and only acceptable because it runs when the gate cannot: that
    action is auth_admin_keep, so polkit may skip the prompt within a few minutes of a previous
    success, where the gate's ALWAYS_CHECK never does. pkexec exits 126 when the dialog is
    dismissed and 127 for both a refused password and "no agent", told apart by stderr.
    """
    pk, true = shutil.which("pkexec"), shutil.which("true")
    if not pk or not true:
        return "error"
    rc, err = _run([pk, true], timeout)
    if rc == 0:
        return "authed"
    if rc == 126:
        return "denied"
    if rc == 127 and "agent" not in err.lower():
        return "denied"
    return "error"


def install_hint() -> str:
    return ("Optional: allow unlocking with your system password (and, once the fingerprint\n"
            "reader works, a fingerprint) instead of retyping the passphrase:\n\n"
            f"    pkexec install -m 0644 {os.path.expanduser('~/icp/polkit/org.icp.unlock.policy')} \\\n"
            f"        {POLICY_PATH}\n")
