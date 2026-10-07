"""Key agent: holds the derived master key in memory and forgets it after an idle timeout.

Lives on a unix socket under $XDG_RUNTIME_DIR, which is already 0700, so only your own user can
reach it. That is also the honest limit of this design: while unlocked, anything running as you
can ask for the key, exactly as anything running as you can scrape an unlocked Bitwarden. Only
used once a passphrase is set.

Releasing the key goes through polkit (`org.icp.unlock`, ALWAYS_CHECK), so day to day it is a
fingerprint, or the account password in the same dialog where there is no reader - the prompt
every other privileged action on the desktop uses. A successful check opens a grace window of
ICP_LOCK_TIMEOUT seconds, so opening the app scans once rather than once per read.

That check is defence in depth, not a boundary: the socket is reachable only by this user, and
this user is exactly who polkit would approve. It raises the cost of a background process
quietly draining the key; it does not stop code running as you that is willing to ask.

Two commands exist because the caller's situation differs:
  GET   someone is at the keyboard - may scan a finger, may open a dialog
  PEEK  nobody is - answers only from an open grace window, never prompts
The unattended sync uses PEEK, which is why a timer can no longer put a password box on screen.

Where the polkit action is not installed, the key keeps the previous idle-timeout behaviour
instead, so a machine without the policy is never locked out of its own vault.

Auto-spawns on first use; no systemd unit to install.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import sys
import time

from . import lockbox
from ..errors import AppleError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 900  # seconds of idleness before the key is dropped


class AgentError(AppleError):
    pass


def _timeout() -> int:
    try:
        return max(0, int(os.environ.get("ICP_LOCK_TIMEOUT", DEFAULT_TIMEOUT)))
    except ValueError:
        return DEFAULT_TIMEOUT


def socket_path() -> str:
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    d = os.path.join(base, "icp")
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    return os.path.join(d, "agent.sock")


# --------------------------------------------------------------------------- server


# How the key is protected once the agent holds it:
#   polkit   a check before each release, with a grace window (fingerprint, or the account
#            password in the same dialog). The key stays in memory until LOCK or logout.
#   timeout  no check; the key is wiped after ICP_LOCK_TIMEOUT seconds of idleness.
# "auto" picks polkit where the action is installed. ICP_KEY_GATE forces one, which is also how
# the tests exercise each path without a prompt on screen.
GATE_TIMEOUT = 20  # seconds to wait for the gate inside the socket loop


def _gate_usable() -> bool:
    """Whether to protect the key with polkit rather than an idle timeout.

    Checked per request, so installing the policy takes effect without restarting the agent.
    False keeps the previous behaviour, because a machine with no polkit action must not end up
    locked out of its own vault.
    """
    choice = os.environ.get("ICP_KEY_GATE", "auto").strip().lower()
    if choice == "timeout":
        return False
    if choice == "polkit":
        return True
    try:
        from ..ui import reauth
        return reauth.available()
    except Exception:
        return False


def _authorize() -> str:
    """Run the gate. Returns "authed", "denied" or "error".

    Bounded by GATE_TIMEOUT, because this runs inside the loop that serves every other client,
    and it deliberately does NOT fall through to pkexec the way cmd_app_auth does: pkexec waits
    up to 90s more, which is far too long to hold the socket. A gate that is merely *broken*
    reports "error" and the caller degrades to the idle-timeout rule instead of refusing, so a
    damaged policy costs residency time rather than access to the vault.
    """
    try:
        from ..ui import reauth
        return reauth.challenge_status(timeout=GATE_TIMEOUT)
    except Exception as e:
        logger.warning("key release gate could not run (%s)", e)
        return "error"


def _serve() -> int:
    path = socket_path()
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o600)
    srv.listen(8)
    srv.settimeout(60)

    key = None              # bytearray so it can be wiped; bytes are immutable
    expires = 0.0           # idle expiry, used only where the polkit gate is unavailable
    authorized_until = 0.0  # grace window opened by a successful polkit check

    def wipe():
        nonlocal key, expires, authorized_until
        if key is not None:
            for i in range(len(key)):
                key[i] = 0
        key, expires, authorized_until = None, 0.0, 0.0

    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            if key is not None and not _gate_usable() and time.monotonic() >= expires:
                wipe()
            continue
        with conn:
            conn.settimeout(30)
            try:
                line = conn.makefile("rb").readline().decode("utf-8", "replace").rstrip("\n")
            except OSError:
                continue
            cmd, _, arg = line.partition(" ")

            gated = _gate_usable()
            if key is not None and not gated and time.monotonic() >= expires:
                wipe()

            if cmd in ("GET", "PEEK"):
                now = time.monotonic()
                if key is None:
                    conn.sendall(b"LOCKED\n")
                elif not gated:
                    expires = now + _timeout()  # idle timeout, so refresh on use
                    conn.sendall(b"OK " + bytes(key).hex().encode() + b"\n")
                elif now < authorized_until:
                    expires = now + _timeout()
                    conn.sendall(b"OK " + bytes(key).hex().encode() + b"\n")
                elif cmd == "PEEK":
                    # Nobody is at the keyboard. Report locked rather than prompt.
                    conn.sendall(b"LOCKED\n")
                else:
                    verdict = _authorize()
                    if verdict == "authed":
                        authorized_until = time.monotonic() + _timeout()
                        conn.sendall(b"OK " + bytes(key).hex().encode() + b"\n")
                    elif verdict == "error" and now < expires:
                        # The gate is broken, not refusing. Fall back to the idle-timeout rule
                        # rather than locking someone out of their own passwords.
                        expires = now + _timeout()
                        conn.sendall(b"OK " + bytes(key).hex().encode() + b"\n")
                    else:
                        conn.sendall(b"DENIED\n")
            elif cmd == "AUTHORIZED":
                # The window just passed the same polkit check in its own process (cmd_app_auth).
                # Trust it rather than prompting twice for one deliberate unlock; the socket is
                # reachable only by this user, which is who polkit would have approved anyway.
                if key is None:
                    conn.sendall(b"LOCKED\n")
                else:
                    authorized_until = time.monotonic() + _timeout()
                    conn.sendall(b"OK\n")
            elif cmd == "UNLOCK":
                try:
                    key = bytearray(lockbox.unlock(arg))
                    expires = time.monotonic() + _timeout()
                    # Typing the passphrase is a stronger proof than the gate asks for, so do
                    # not demand a fingerprint immediately afterwards.
                    authorized_until = time.monotonic() + _timeout()
                    conn.sendall(b"OK\n")
                except lockbox.WrongPassphrase:
                    conn.sendall(b"ERR wrong passphrase\n")
                except AppleError as e:
                    conn.sendall(b"ERR " + str(e).replace("\n", " ").encode() + b"\n")
            elif cmd == "LOAD":
                try:
                    raw = bytes.fromhex(arg.strip())
                except ValueError:
                    conn.sendall(b"ERR bad key\n")
                    continue
                if not lockbox.verify(raw):
                    conn.sendall(b"ERR bad key\n")
                else:
                    key = bytearray(raw)
                    expires = time.monotonic() + _timeout()
                    authorized_until = time.monotonic() + _timeout()
                    conn.sendall(b"OK\n")
            elif cmd == "LOCK":
                wipe()
                conn.sendall(b"OK\n")
            elif cmd == "STATUS":
                if key is None:
                    conn.sendall(b"locked\n")
                else:
                    conn.sendall(f"unlocked {int(expires - time.monotonic())}\n".encode())
            elif cmd == "QUIT":
                conn.sendall(b"OK\n")
                wipe()
                return 0
            else:
                conn.sendall(b"ERR unknown command\n")


# --------------------------------------------------------------------------- client


def _request(line: str, autostart: bool = True) -> str:
    path = socket_path()
    try:
        return _send(path, line)
    except (FileNotFoundError, ConnectionRefusedError):
        if not autostart:
            raise AgentError("agent not running")
        _spawn()
        return _send(path, line)


def _send(path: str, line: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(30)
        s.connect(path)
        s.sendall(line.encode("utf-8") + b"\n")
        return s.makefile("rb").readline().decode("utf-8", "replace").rstrip("\n")


def _spawn() -> None:
    subprocess.Popen(
        [sys.executable, "-m", "icp.auth.agent", "--serve"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    path = socket_path()
    for _ in range(100):  # up to ~5s for the socket to appear
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise AgentError("key agent did not start")


def get_key() -> bytes | None:
    """The cached key, or None if the agent is locked."""
    resp = _request("GET")
    if resp.startswith("OK "):
        return bytes.fromhex(resp[3:])
    return None


def peek_key() -> bytes | None:
    """The cached key, but only while the agent is inside an open grace window.

    Never prompts and never scans, so an unattended caller gets None instead of putting a
    dialog on someone's screen. `autostart=False`: a timer has no business starting an agent
    that could only answer "locked" anyway.
    """
    try:
        resp = _request("PEEK", autostart=False)
    except AgentError:
        return None
    if resp.startswith("OK "):
        return bytes.fromhex(resp[3:])
    return None


def mark_authorized() -> None:
    """Record that the caller has just passed the polkit check itself. Best effort."""
    try:
        _request("AUTHORIZED", autostart=False)
    except (AgentError, OSError):
        pass


def unlock(passphrase: str) -> None:
    resp = _request("UNLOCK " + passphrase)
    if resp != "OK":
        raise AgentError(resp.removeprefix("ERR ") or "unlock failed")


def load_key(key: bytes) -> None:
    resp = _request("LOAD " + key.hex())
    if resp != "OK":
        raise AgentError(resp.removeprefix("ERR ") or "load failed")


def lock() -> None:
    try:
        _request("LOCK", autostart=False)
    except (AgentError, OSError):
        pass  # not running == already locked


def status() -> str:
    try:
        return _request("STATUS", autostart=False)
    except (AgentError, OSError):
        return "locked"


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--serve" in argv:
        return _serve()
    print(status())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
