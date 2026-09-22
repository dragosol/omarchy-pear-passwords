"""Server half of Apple's SecretSession PAKE.

The client here is written from the same transcription of their `background.js` as the server,
so a green run proves the server is self-consistent and that the SRP algebra closes - NOT that
we interoperate with Apple. If the transcription is wrong, both halves are wrong together.
Only pairing with the real extension settles that.

Run: PYTHONPATH=. .venv/bin/python -m unittest tests.test_secretsession
"""

import hashlib
import secrets
import unittest

from icp.applehost import secretsession as ss


def _h(*chunks):
    d = hashlib.sha256()
    for c in chunks:
        d.update(c)
    return d.digest()


class Client:
    """Mirrors the extension: picks I and a, sends MSG0, answers MSG1 with MSG2, checks HAMK."""

    def __init__(self, pin):
        self.pin = pin
        self.I = secrets.token_bytes(16)
        # bitsToString() renders with a leading 0x by default, and x and M1 hash that exact
        # string - so the prefix is part of the protocol, not decoration.
        self.identity_str = "0x" + self.I.hex()
        self.a = int.from_bytes(secrets.token_bytes(32), "big")
        self.A = pow(ss.G, self.a, ss.N)
        self.K = None

    def msg0(self):
        return {"TID": self.identity_str, "MSG": ss.MSG0,
                "A": "0x" + format(self.A, "x"), "VER": "1.0",
                "PROTO": [ss.SRP_OLD_VERIFICATION, ss.SRP_RFC_VERIFICATION]}

    def msg2(self, msg1):
        salt = ss._unhex(msg1["s"])
        B = int.from_bytes(ss._unhex(msg1["B"]), "big")
        x = ss.compute_x(salt, self.identity_str, self.pin)
        v = pow(ss.G, x, ss.N)
        u = ss.compute_u(self.A, B)
        S = pow((B - ss.compute_k() * v) % ss.N, self.a + u * x, ss.N)
        self.K = _h(ss._int_bytes(S))
        m1, self.hamk = ss.compute_M(self.identity_str, salt, self.A, B, self.K)
        return {"TID": self.identity_str, "MSG": ss.MSG2, "M": m1.hex()}

    def check_msg3(self, msg3):
        return secrets.compare_digest(ss._unhex(msg3["HAMK"]), self.hamk)


class HandshakeTests(unittest.TestCase):
    PIN = "418239"

    def _pair(self, client_pin=None):
        server = ss.SecretSessionServer(self.PIN)
        client = Client(client_pin or self.PIN)
        msg1 = server.handle(client.msg0())
        msg3 = server.handle(client.msg2(msg1))
        return server, client, msg1, msg3

    def test_both_sides_derive_the_same_session_key(self):
        server, client, _, _ = self._pair()
        self.assertIsNotNone(server.K)
        self.assertEqual(server.K, client.K, "SRP did not converge on a shared key")

    def test_client_accepts_the_server_proof(self):
        _server, client, _, msg3 = self._pair()
        self.assertEqual(msg3["ErrCode"], 0)
        self.assertTrue(client.check_msg3(msg3), "HAMK did not verify")

    def test_wrong_pin_is_rejected_at_msg2(self):
        server = ss.SecretSessionServer(self.PIN)
        client = Client("000000")                      # user typed the wrong code
        msg1 = server.handle(client.msg0())
        with self.assertRaises(ss.SecretSessionError):
            server.handle(client.msg2(msg1))

    def test_wrong_pin_does_not_yield_the_same_key(self):
        server = ss.SecretSessionServer(self.PIN)
        client = Client("000000")
        client.msg2(server.handle(client.msg0()))
        self.assertNotEqual(server.K, client.K)

    def test_msg1_carries_what_the_client_requires(self):
        _server, _client, msg1, _ = self._pair()
        for field in ("s", "B", "TID", "PROTO"):
            self.assertIn(field, msg1)
        self.assertEqual(msg1["MSG"], ss.MSG1)

    def test_tid_is_echoed_verbatim(self):
        """The client rejects a message whose TID is not its own identity."""
        _server, client, msg1, msg3 = self._pair()
        self.assertEqual(msg1["TID"], client.identity_str)
        self.assertEqual(msg3["TID"], client.identity_str)

    def test_msg2_before_msg0_is_refused(self):
        server = ss.SecretSessionServer(self.PIN)
        with self.assertRaises(ss.SecretSessionError):
            server.handle({"TID": "0x00", "MSG": ss.MSG2, "M": "00"})

    def test_A_divisible_by_N_is_refused(self):
        """The classic SRP abort: A ≡ 0 mod N forces S to 0 on the server."""
        server = ss.SecretSessionServer(self.PIN)
        with self.assertRaises(ss.SecretSessionError):
            server.handle({"TID": "0x01", "MSG": ss.MSG0, "A": format(ss.N, "x")})

    def test_hex_is_accepted_with_and_without_the_0x_prefix(self):
        """sjcl's codec strips 0x, so values arrive both ways."""
        self.assertEqual(ss._unhex("0xdeadbeef"), ss._unhex("deadbeef"))

    def test_separate_pairings_do_not_share_a_key(self):
        s1, _, _, _ = self._pair()
        s2, _, _, _ = self._pair()
        self.assertNotEqual(s1.K, s2.K, "salt/b are not being regenerated per session")


class DataChannelTests(unittest.TestCase):
    def _paired(self):
        server = ss.SecretSessionServer("123456")
        client = Client("123456")
        server.handle(client.msg2(server.handle(client.msg0())))
        return server

    def test_round_trip(self):
        server = self._paired()
        for text in ('{"cmd":"ping"}', "", "unicode: café ✓", "x" * 4000):
            self.assertEqual(server.decrypt(server.encrypt(text)), text)

    def test_key_is_128_bits(self):
        """The client slices keyLen bits off the session key; AES-128 is what that yields."""
        self.assertEqual(len(self._paired().enc_key), 16)

    def test_ciphertext_is_not_the_plaintext(self):
        server = self._paired()
        blob = server.encrypt("hunter2")
        self.assertNotIn("hunter2", blob["SDATA"])
        self.assertIn("TID", blob)

    def test_tampering_is_detected(self):
        server = self._paired()
        blob = server.encrypt('{"cmd":"ping"}')
        raw = bytearray(ss._unhex(blob["SDATA"]))
        raw[-1] ^= 0x01                                # flip a bit in the GCM tag
        with self.assertRaises(Exception):
            server.decrypt({"SDATA": raw.hex()})

    def test_encrypt_before_handshake_is_refused(self):
        with self.assertRaises(ss.SecretSessionError):
            ss.SecretSessionServer("123456").encrypt("nope")


if __name__ == "__main__":
    unittest.main()
