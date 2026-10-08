"""Sealing the key blobs: the systemd-creds command line, the TPM pickup with its rollback
window, and the three ways an unseal can fail.

The real systemd-creds is never run: a fake executable stands in for the command line tests,
and tests/fixtures/fake_seal.py for everything that needs a TPM to appear, vanish or change.
"""

import base64
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from fixtures import FakeSealBackend, vstore_env

from icp import vstore
from icp.daemon import paths as system_paths
from icp.vstore import seal

from test_store_v2 import UID, StoreCase, item

FAKE_CREDS = """#!{python}
import base64, sys
argv = sys.argv[1:]
with open({log!r}, "a") as f:
    f.write(repr(argv) + "\\n")
data = sys.stdin.buffer.read()
if argv[:2] == ["--user", "encrypt"]:
    sys.stdout.buffer.write(b"ENC:" + base64.b64encode(data))
elif argv[:2] == ["--user", "decrypt"]:
    if not data.startswith(b"ENC:"):
        sys.stderr.write("Failed to decrypt: refused\\n")
        sys.exit(1)
    sys.stdout.buffer.write(base64.b64decode(data[4:]))
else:
    sys.exit(2)
"""


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        d = Path(self._tmp.name)
        self.log = d / "argv.log"
        exe = d / "systemd-creds"
        exe.write_text(FAKE_CREDS.format(python=sys.executable, log=str(self.log)))
        exe.chmod(0o755)
        self._patch = mock.patch.object(seal, "SYSTEMD_CREDS", str(exe))
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()

    def argvs(self):
        return [eval(line) for line in self.log.read_text().splitlines()]

    def test_encrypt_argv_and_pipe(self):
        b = seal.SystemdCredsBackend()
        secret = bytes(range(32))
        blob = b.encrypt("pear.list.u1000", secret)
        self.assertEqual(b.decrypt("pear.list.u1000", blob), secret)
        enc, dec = self.argvs()
        self.assertEqual(enc, ["--user", "encrypt", "--with-key=auto", "--tpm2-pcrs=",
                               "--tpm2-public-key=", "--name=pear.list.u1000", "-", "-"])
        self.assertEqual(dec, ["--user", "decrypt", "--name=pear.list.u1000", "-", "-"])
        # The secret travels on the pipe only.
        for argv in (enc, dec):
            joined = " ".join(argv)
            self.assertNotIn(secret.hex(), joined)
            self.assertNotIn(base64.b64encode(secret).decode(), joined)

    def test_refusal_and_absence_are_different(self):
        b = seal.SystemdCredsBackend()
        with self.assertRaises(seal.UnsealRefused):
            b.decrypt("pear.list.u1000", b"not a credential")
        with mock.patch.object(seal, "SYSTEMD_CREDS", "/nonexistent/systemd-creds"):
            with self.assertRaises(seal.SealUnavailable):
                b.decrypt("pear.list.u1000", b"x")
            with self.assertRaises(seal.SealUnavailable):
                b.encrypt("pear.list.u1000", b"x")
        self.assertTrue(issubclass(seal.SealUnavailable, vstore.StoreError))

    def test_store_end_to_end_through_the_command(self):
        with tempfile.TemporaryDirectory() as root, \
                vstore_env(root, seal.SystemdCredsBackend()), \
                mock.patch.object(seal, "tpm_present", return_value=False):
            s = vstore.UserStore.create(UID)
            s.apply_sync([item("a.example.test", "me", "TEST-pw")], set())
            s.lock()
            s2 = vstore.UserStore.open(UID)
            s2.unlock()
            self.assertEqual(s2.open_entry(s2.list_meta()[0].id).password, "TEST-pw")
        names = [a[5] for a in self.argvs() if a[1] == "encrypt"]
        self.assertEqual(names, [f"--name=pear.list.u{UID}", f"--name=pear.secret.u{UID}"])


class SelectionTests(unittest.TestCase):
    def tearDown(self):
        seal.set_backend(None)

    def test_environment_picks_the_backend(self):
        for value, cls in (("user-creds", seal.SystemdCredsBackend),
                           ("seal-service", seal.SealServiceBackend)):
            seal.set_backend(None)
            with mock.patch.dict(os.environ, {seal.BACKEND_ENV: value}):
                self.assertIsInstance(seal.get_backend(), cls)
        seal.set_backend(None)
        with mock.patch.dict(os.environ, {seal.BACKEND_ENV: "bogus"}):
            with self.assertRaises(vstore.StoreError):
                seal.get_backend()

    def test_default_is_systemd_creds(self):
        seal.set_backend(None)
        env = {k: v for k, v in os.environ.items() if k != seal.BACKEND_ENV}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIsInstance(seal.get_backend(), seal.SystemdCredsBackend)


class SealServiceTests(unittest.TestCase):
    """The G1 fallback client against a stand-in for the root seal service."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "seal.sock")
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(4)
        self.seen = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.srv.close()
        self._tmp.cleanup()

    def serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                req = json.loads(buf)
                self.seen.append((req["op"], req["name"]))
                data = base64.b64decode(req["b64"])
                if req["op"] == "encrypt":
                    reply = {"b64": base64.b64encode(b"S" + data).decode()}
                elif data.startswith(b"S"):
                    reply = {"b64": base64.b64encode(data[1:]).decode()}
                else:
                    reply = {"error": "refused", "detail": "no"}
                conn.sendall(json.dumps(reply).encode() + b"\n")

    def test_round_trip_and_refusal(self):
        b = seal.SealServiceBackend(self.path)
        blob = b.encrypt("pear.secret.u1000", b"k" * 32)
        self.assertEqual(b.decrypt("pear.secret.u1000", blob), b"k" * 32)
        with self.assertRaises(seal.UnsealRefused):
            b.decrypt("pear.secret.u1000", b"garbage")
        self.assertEqual(self.seen[0], ("encrypt", "pear.secret.u1000"))

    def test_unreachable_is_unavailable(self):
        b = seal.SealServiceBackend(os.path.join(self._tmp.name, "nope.sock"))
        with self.assertRaises(seal.SealUnavailable):
            b.decrypt("pear.list.u1000", b"x")


class ProbeTests(unittest.TestCase):
    def test_srk_fingerprint_reads_the_pem(self):
        der = b"\x30\x59" + bytes(89)
        pem = (b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der) +
               b"\n-----END PUBLIC KEY-----\n")
        with tempfile.NamedTemporaryFile() as f:
            f.write(pem)
            f.flush()
            with mock.patch.object(system_paths, "TPM_SRK_PUBLIC_KEY", f.name):
                import hashlib
                self.assertEqual(seal.srk_fingerprint(), hashlib.sha256(der).hexdigest())
        with mock.patch.object(system_paths, "TPM_SRK_PUBLIC_KEY", "/nonexistent.pem"):
            self.assertIsNone(seal.srk_fingerprint())

    def test_tpm_present_needs_a_device_and_has_tpm2(self):
        with mock.patch.object(system_paths, "TPM_DEVICE", "/nonexistent/tpmrm0"), \
                mock.patch.object(seal, "TPM_SYSFS", "/nonexistent/tpm0"):
            self.assertFalse(seal.tpm_present())
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(seal, "TPM_SYSFS", d), \
                mock.patch.object(seal, "SYSTEMD_ANALYZE", "/bin/false"):
            self.assertFalse(seal.tpm_present())
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(seal, "TPM_SYSFS", d), \
                mock.patch.object(seal, "SYSTEMD_ANALYZE", "/bin/true"):
            self.assertTrue(seal.tpm_present())

    def test_classify(self):
        b = FakeSealBackend(tpm=False)
        self.assertEqual(seal.classify(b, "host+tpm2", "srk-one"), "tpm-missing")
        self.assertEqual(seal.classify(b, "host", None), "damaged")
        b = FakeSealBackend(tpm=True, srk="srk-two")
        self.assertEqual(seal.classify(b, "host+tpm2", "srk-one"), "tpm-cleared")
        b.srk = "srk-one"
        self.assertEqual(seal.classify(b, "host+tpm2", "srk-one"), "damaged")


class ResealTests(StoreCase):
    def keyfiles(self):
        kd = self.udir / "keys"
        return {p.name: p.read_bytes() for p in sorted(kd.iterdir())}

    def datafiles(self):
        return {k: v for k, v in self.snapshot().items() if "/keys/" not in k}

    def test_no_tpm_no_reseal(self):
        s = self.populated(1)
        self.assertFalse(s.reseal_if_tpm_available())
        self.assertEqual(s.status()["sealed_with"], "host")

    def test_tpm_appears_and_keys_are_resealed(self):
        s = self.populated(2)
        old_keys, old_data = self.keyfiles(), self.datafiles()
        self.backend.tpm = True
        s.lock()
        s.unlock()
        self.assertTrue(s.reseal_if_tpm_available())
        kj = json.loads((self.udir / "keys" / "keys.json").read_bytes())
        self.assertEqual(kj["sealed_with"], "host+tpm2")
        self.assertEqual(kj["tpm_srk_fp"], "srk-one")
        new = self.keyfiles()
        # The old blobs are kept, byte for byte, as the rollback copies.
        for name in ("list.cred", "secret.cred", "keys.json"):
            self.assertEqual(new[name + ".prev"], old_keys[name])
            self.assertNotEqual(new[name], old_keys[name])
        self.assertEqual(self.datafiles(), old_data)       # data files untouched
        self.assertFalse(any(n.endswith(".new") for n in new))
        self.assertFalse(s.reseal_if_tpm_available())        # already host+tpm2
        # The next successful unlock closes the rollback window.
        s.lock()
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertFalse(any(n.endswith(".prev") for n in self.keyfiles()))
        self.assertEqual(s2.status()["sealed_with"], "host+tpm2")
        self.assertEqual(s2.open_entry(s2.list_meta()[0].id).password, "pw-0")

    def test_failed_verification_changes_nothing(self):
        s = self.populated(1)
        before = self.snapshot()
        self.backend.tpm = True
        self.backend.corrupt_next_encrypts = 2
        self.assertFalse(s.reseal_if_tpm_available())
        self.assertEqual(self.snapshot(), before)            # no .new, no .prev, same blobs
        self.assertEqual(s.status()["sealed_with"], "host")
        s.lock()
        vstore.UserStore.open(UID).unlock()                   # still opens

    def test_prev_kept_if_reseal_is_followed_by_failure(self):
        s = self.populated(1)
        self.backend.tpm = True
        self.assertTrue(s.reseal_if_tpm_available())
        s.lock()
        # The TPM goes away again before the next unlock: the host+tpm2 blobs are refused,
        # the host-only .prev blobs still open, and the store rolls back to them.
        self.backend.tpm = False
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertEqual(s2.status()["sealed_with"], "host")
        names = self.keyfiles()
        self.assertFalse(any(n.endswith(".prev") for n in names))
        self.assertEqual(s2.open_entry(s2.list_meta()[0].id).password, "pw-0")

    def test_reseal_needs_unlock(self):
        s = vstore.UserStore.create(UID)
        s.lock()
        with self.assertRaises(vstore.StoreLocked):
            s.reseal_if_tpm_available()


class SealStateTests(StoreCase):
    tpm = True

    def test_created_with_a_tpm_records_it(self):
        s = vstore.UserStore.create(UID)
        kj = json.loads((self.udir / "keys" / "keys.json").read_bytes())
        self.assertEqual((kj["sealed_with"], kj["tpm_srk_fp"]), ("host+tpm2", "srk-one"))
        self.assertFalse(s.reseal_if_tpm_available())

    def locked_store(self):
        s = self.populated(1)
        s.lock()
        return vstore.UserStore.open(UID)

    def test_tpm_switched_off_is_tpm_missing(self):
        s = self.locked_store()
        before = self.snapshot()
        self.backend.tpm = False
        with self.assertRaises(vstore.SealError) as cm:
            s.unlock()
        self.assertEqual(cm.exception.kind, "tpm-missing")
        self.assertEqual(s.state(), "tpm-missing")
        self.assertEqual(self.snapshot(), before)
        # Switching it back on is the whole recovery.
        self.backend.tpm = True
        s.unlock()
        self.assertEqual(s.state(), "unlocked")

    def test_tpm_cleared_is_not_tpm_missing(self):
        s = self.locked_store()
        before = self.snapshot()
        self.backend.srk = "srk-two"          # a TPM is there, but it is not the same one
        with self.assertRaises(vstore.SealError) as cm:
            s.unlock()
        self.assertEqual(cm.exception.kind, "tpm-cleared")
        self.assertEqual(s.status()["state"], "tpm-cleared")
        self.assertEqual(self.snapshot(), before)

    def test_host_key_lost_is_damaged(self):
        s = self.locked_store()
        self.backend.host_key = os.urandom(32)
        with self.assertRaises(vstore.SealError) as cm:
            s.unlock()
        self.assertEqual(cm.exception.kind, "damaged")

    def test_tool_unavailable_is_not_a_seal_state(self):
        s = self.locked_store()
        self.backend.unavailable = True
        with self.assertRaises(seal.SealUnavailable):
            s.unlock()
        self.assertEqual(s.state(), "locked")

    def test_entry_key_refused_mid_session(self):
        s = self.populated(1)
        self.backend.tpm = False
        with self.assertRaises(vstore.SealError) as cm:
            s.open_entry(s.list_meta()[0].id)
        self.assertEqual(cm.exception.kind, "tpm-missing")


if __name__ == "__main__":
    unittest.main()
