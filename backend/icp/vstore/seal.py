"""Sealing the two key blobs to this machine, and telling the ways an unseal fails apart.

Primary path (spec section 6, gate G1): the daemon, as uid `pear-passwords`, runs

    systemd-creds --user encrypt --with-key=auto --tpm2-pcrs= --tpm2-public-key= \\
                  --name=pear.<tier>.u<uid> - -

with the secret on a pipe, never in argv or a file. `--user` binds the blob to the daemon's
uid, so even another root-less process that got hold of the file cannot decrypt it, and
`--with-key=auto` means the host key today and host+TPM2 as soon as a TPM2 is usable. The two
empty flags matter: no PCRs (Secure Boot is off and the boot is unmeasured, so any firmware,
Limine or kernel update would break a PCR-bound blob) and no signed PCR policy (so a future
UKI cannot silently bind the blobs). Both were checked to be accepted in uid scope on
systemd 261.

Fallback (if G1 fails in the hardened unit): a root oneshot does system-scope sealing for the
daemon over a socket (`SealServiceBackend`). It is selected with PEAR_SEAL_BACKEND=seal-service
in the unit's environment, which only root can set; everything above it is unchanged, so the
UX states stay the same.

Sealing is lazy: nothing here runs at daemon start, only at unlock, so a missing or replaced
TPM shows up as a state in the app instead of a service that will not start.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
from typing import Protocol

from ..daemon import paths as system_paths
from . import StoreError

SYSTEMD_CREDS = "/usr/bin/systemd-creds"
SYSTEMD_ANALYZE = "/usr/bin/systemd-analyze"
TPM_SYSFS = "/sys/class/tpm/tpm0"
TIMEOUT_S = 60                       # a TPM2 operation through the varlink service can be slow

# The G1 fallback service. Only consulted when PEAR_SEAL_BACKEND=seal-service.
SEAL_SERVICE_SOCKET = system_paths.SEAL_SOCKET_PATH
BACKEND_ENV = "PEAR_SEAL_BACKEND"
BACKEND_USER_CREDS = "user-creds"
BACKEND_SEAL_SERVICE = "seal-service"

# A child gets nothing of the daemon's environment: no locale tricks, no LD_*, no PATH search.
_CHILD_ENV = {"PATH": "/usr/bin", "LANG": "C.UTF-8", "SYSTEMD_LOG_LEVEL": "warning"}


class SealUnavailable(StoreError):
    """The sealing mechanism itself could not run (binary missing, timeout, service down).
    Transient: it says nothing about the blobs, so it never becomes a seal state."""


class UnsealRefused(Exception):
    """The mechanism ran and refused this blob: wrong key, missing TPM, wrong name, corrupt.
    `classify()` turns it into a SealError kind."""


class SealBackend(Protocol):
    def encrypt(self, name: str, plaintext: bytes) -> bytes: ...
    def decrypt(self, name: str, blob: bytes) -> bytes: ...
    def tpm_present(self) -> bool: ...
    def srk_fingerprint(self) -> str | None: ...


# --- platform probes (shared by both backends) ----------------------------------------------

def tpm_present() -> bool:
    """A usable TPM2: `systemd-analyze has-tpm2` exits 0 (firmware, driver, subsystem and
    libraries all present) and the kernel has a TPM device.

    The device check accepts sysfs as well as /dev/tpmrm0 because the daemon runs with
    PrivateDevices=yes and never sees /dev/tpm*; it does not need to, since the TPM work is
    done by systemd's own credentials service."""
    if not (os.path.exists(system_paths.TPM_DEVICE) or os.path.isdir(TPM_SYSFS)):
        return False
    try:
        r = subprocess.run([SYSTEMD_ANALYZE, "has-tpm2", "-q"], env=_CHILD_ENV,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=TIMEOUT_S, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def srk_fingerprint() -> str | None:
    """SHA-256 of the TPM's storage root key (systemd-tpm2-setup's PEM), hex. None without
    one. Recorded at sealing time so "the TPM was cleared" can be told apart from "the TPM
    is switched off"."""
    try:
        with open(system_paths.TPM_SRK_PUBLIC_KEY, "rb") as f:
            pem = f.read(16384)
    except OSError:
        return None
    body = b"".join(line.strip() for line in pem.splitlines()
                    if line.strip() and not line.startswith(b"-----"))
    try:
        der = base64.b64decode(body, validate=True)
    except ValueError:
        return None
    return hashlib.sha256(der).hexdigest() if der else None


# --- primary: systemd-creds --user -----------------------------------------------------------

class SystemdCredsBackend:
    """`systemd-creds --user` as the daemon's own uid (gate G1)."""

    def encrypt_argv(self, name: str) -> list[str]:
        return [SYSTEMD_CREDS, "--user", "encrypt", "--with-key=auto", "--tpm2-pcrs=",
                "--tpm2-public-key=", f"--name={name}", "-", "-"]

    def decrypt_argv(self, name: str) -> list[str]:
        return [SYSTEMD_CREDS, "--user", "decrypt", f"--name={name}", "-", "-"]

    def _run(self, argv: list[str], data: bytes) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(argv, input=bytes(data), env=_CHILD_ENV,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=TIMEOUT_S, check=False)
        except FileNotFoundError:
            raise SealUnavailable(f"{argv[0]} is not installed") from None
        except subprocess.TimeoutExpired:
            raise SealUnavailable("systemd-creds timed out") from None
        except OSError as e:
            raise SealUnavailable(f"systemd-creds could not run ({e.strerror})") from None

    def encrypt(self, name: str, plaintext: bytes) -> bytes:
        r = self._run(self.encrypt_argv(name), plaintext)
        if r.returncode != 0 or not r.stdout:
            # Sealing failing is never a statement about existing blobs.
            raise SealUnavailable(f"systemd-creds encrypt failed ({_why(r.stderr)})")
        return r.stdout

    def decrypt(self, name: str, blob: bytes) -> bytes:
        r = self._run(self.decrypt_argv(name), blob)
        if r.returncode < 0:
            raise SealUnavailable(f"systemd-creds killed by signal {-r.returncode}")
        if r.returncode != 0:
            raise UnsealRefused(_why(r.stderr))
        return r.stdout

    def tpm_present(self) -> bool:
        return tpm_present()

    def srk_fingerprint(self) -> str | None:
        return srk_fingerprint()


# --- fallback: root seal service (G1 fails) --------------------------------------------------

class SealServiceBackend:
    """Talks to the root `pear-passwords-seal` socket service, which runs system-scope
    `systemd-creds encrypt|decrypt --with-key=auto --tpm2-pcrs= --tpm2-public-key=` for the
    daemon. One request per connection, one JSON line each way:

        {"op":"encrypt"|"decrypt","name":"pear.list.u1000","b64":"..."}
        {"b64":"..."}  |  {"error":"refused"|"bad-request"|"internal","detail":"..."}

    The service accepts only SO_PEERCRED uid `pear-passwords` and names matching
    pear.(list|secret).u<digits>; it holds nothing between requests."""

    def __init__(self, path: str = SEAL_SERVICE_SOCKET):
        self.path = path

    def _call(self, op: str, name: str, data: bytes) -> bytes:
        req = json.dumps({"op": op, "name": name,
                          "b64": base64.b64encode(bytes(data)).decode()}).encode() + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC) as s:
                s.settimeout(TIMEOUT_S)
                s.connect(self.path)
                s.sendall(req)
                s.shutdown(socket.SHUT_WR)
                buf = bytearray()
                while len(buf) < 1 << 20:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
        except OSError as e:
            raise SealUnavailable(f"seal service unreachable ({e.strerror or e})") from None
        try:
            reply = json.loads(bytes(buf).split(b"\n", 1)[0])
        except ValueError:
            raise SealUnavailable("seal service sent garbage") from None
        if not isinstance(reply, dict):
            raise SealUnavailable("seal service sent garbage")
        if "b64" in reply:
            try:
                return base64.b64decode(reply["b64"], validate=True)
            except (TypeError, ValueError):
                raise SealUnavailable("seal service sent garbage") from None
        if reply.get("error") == "refused" and op == "decrypt":
            raise UnsealRefused(str(reply.get("detail", ""))[:200])
        raise SealUnavailable(f"seal service error {reply.get('error')!r}")

    def encrypt(self, name: str, plaintext: bytes) -> bytes:
        return self._call("encrypt", name, plaintext)

    def decrypt(self, name: str, blob: bytes) -> bytes:
        return self._call("decrypt", name, blob)

    def tpm_present(self) -> bool:
        return tpm_present()

    def srk_fingerprint(self) -> str | None:
        return srk_fingerprint()


# --- selection -------------------------------------------------------------------------------

_backend: SealBackend | None = None


def get_backend() -> SealBackend:
    global _backend
    if _backend is None:
        choice = os.environ.get(BACKEND_ENV, BACKEND_USER_CREDS)
        if choice == BACKEND_SEAL_SERVICE:
            _backend = SealServiceBackend()
        elif choice == BACKEND_USER_CREDS:
            _backend = SystemdCredsBackend()
        else:
            raise StoreError(f"{BACKEND_ENV}={choice!r} is not a seal backend")
    return _backend


def set_backend(backend: SealBackend | None) -> None:
    """Replace the backend (tests use a fake; None goes back to the environment's choice)."""
    global _backend
    _backend = backend


# --- what a failed unseal means --------------------------------------------------------------

def sealed_with_now(backend: SealBackend) -> str:
    """What `--with-key=auto` picks at this moment."""
    return "host+tpm2" if backend.tpm_present() else "host"


def classify(backend: SealBackend, sealed_with: str | None, recorded_srk: str | None) -> str:
    """The seal state for an unseal the backend refused (spec section 6):

    - blobs sealed with host+tpm2 and no TPM now: "tpm-missing" (turn PTT back on);
    - blobs sealed with host+tpm2, a TPM present, and its SRK differs from the one recorded
      at sealing time: "tpm-cleared" (the keys are gone for good);
    - anything else (host-only blob refused, same SRK and still refused): "damaged".
    """
    if sealed_with == "host+tpm2":
        if not backend.tpm_present():
            return "tpm-missing"
        now = backend.srk_fingerprint()
        if recorded_srk and now and now != recorded_srk:
            return "tpm-cleared"
    return "damaged"


def _why(stderr: bytes) -> str:
    """A short, printable reason for logs. systemd-creds never echoes the secret."""
    text = (stderr or b"").decode("utf-8", "replace").strip().splitlines()
    line = text[-1] if text else "no message"
    return "".join(c for c in line if c.isprintable())[:200]
