"""Native-messaging host exposed on a unix socket, for sandboxed browsers.

A Flatpak browser cannot exec our venv: its /usr is the runtime's, and the compiled deps are
built against the host Python's ABI. The usual workaround is to grant the browser
org.freedesktop.Flatpak and let it spawn host commands - which is a full sandbox escape.

Instead the host stays out here and the sandbox gets a stdlib-only relay (host/relay.py) that
pipes the browser's stdio to this socket. The only thing crossing the boundary is the credential
protocol: no shell, no filesystem, no arbitrary exec. A fully compromised browser gets the vault's
API surface and nothing else.

The vault is re-loaded per connection on purpose - that routes through the key agent, so a locked
keychain prompts instead of silently serving stale credentials.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading

from .host import CredentialStore, serve

logger = logging.getLogger(__name__)


def socket_dir() -> str:
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    d = os.path.join(base, "icp")
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def socket_path() -> str:
    return os.environ.get("ICP_HOST_SOCKET") or os.path.join(socket_dir(), "host.sock")


_UCRED = struct.calcsize("3i")


def peer_of(conn: socket.socket) -> tuple[int, int, int] | None:
    """(pid, uid, gid) of the connecting process via SO_PEERCRED, or None."""
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED)
        return struct.unpack("3i", raw)
    except OSError:
        return None


def peer_exe(pid: int) -> str:
    """Best-effort name for a peer process.

    /proc/<pid>/exe is the trustworthy one but needs PTRACE_MODE_READ, which this
    unit's hardening denies (EACCES), so fall back to comm/cmdline. Those are
    self-reported - a process can set either - so treat the result as a label for
    reading the journal, never as proof of identity. Against a same-uid peer no
    identifier here is authoritative anyway.
    """
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    for name, clean in (("cmdline", lambda s: s.replace("\0", " ").strip()),
                        ("comm", str.strip)):
        try:
            with open(f"/proc/{pid}/{name}", "r") as fh:
                v = clean(fh.read())[:120]
            if v:
                return f"{v} (self-reported)"
        except OSError:
            continue
    return "?"


def peer_allowed(conn: socket.socket) -> bool:
    """Gate a connection on the peer's uid, and log who it was.

    Be honest about what this buys. The socket is already 0600 in a 0700 directory,
    so the uid check can only ever fail if those modes were widened by mistake - it is
    a guard against our own error, not against an attacker. It cannot defend against
    code already running as this user: such code can read vault.key directly and skip
    the socket entirely.

    The logging is the part with real value. Every consumer of the vault is now named
    in the journal with its pid and exe, so snooping through this socket stops being
    invisible. ICP_HOST_ALLOW_EXE (colon-separated) additionally pins the acceptable
    executables when you know exactly which relay should be connecting.
    """
    cred = peer_of(conn)
    if cred is None:
        logger.warning("refusing a connection with no SO_PEERCRED")
        return False
    pid, uid, gid = cred
    exe = peer_exe(pid)
    if uid != os.getuid():
        logger.warning("refusing connection from uid %d (pid %d, %s)", uid, pid, exe)
        return False
    allow = [e for e in (os.environ.get("ICP_HOST_ALLOW_EXE") or "").split(":") if e]
    if allow and exe not in allow:
        logger.warning("refusing connection from unlisted exe %s (pid %d)", exe, pid)
        return False
    logger.warning("vault served to pid %d uid %d - %s", pid, uid, exe)
    return True


def _load():
    """Vault + aliases, degrading to empty so the extension can still connect and ping."""
    try:
        from .store import load_vault
        store = load_vault()
    except Exception as e:
        logger.warning("could not load vault: %s", e)
        store = CredentialStore([])
    try:
        from ..hme.store import load_aliases
        aliases = load_aliases()
    except Exception:
        aliases = []
    return store, aliases


def _client(conn: socket.socket) -> None:
    with conn:
        if not peer_allowed(conn):
            return
        try:
            store, aliases = _load()
            with conn.makefile("rb") as rf, conn.makefile("wb") as wf:
                serve(store, aliases=aliases, instream=rf, outstream=wf)
        except Exception as e:
            logger.warning("client error: %s", e)


def main(argv=None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    path = socket_path()
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o600)
    srv.listen(4)
    logger.warning("icp host listening on %s", path)

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(main())
