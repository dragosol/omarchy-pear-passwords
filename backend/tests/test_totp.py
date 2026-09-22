"""TOTP generation and the metadata split.

Run: PYTHONPATH=. .venv/bin/python -m unittest tests.test_totp
"""

import plistlib
import unittest

from icp import totp
from icp.keychain import metadata
from icp.vault.host import CredentialStore

# RFC 6238 Appendix B. The published vectors use the ASCII seed "12345678901234567890".
RFC_SECRET = b"12345678901234567890"
RFC_VECTORS = [                       # (unix time, expected 8-digit SHA1 code)
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


class TotpTests(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for at, expected in RFC_VECTORS:
            self.assertEqual(totp.code(RFC_SECRET, digits=8, period=30, at=at), expected,
                             f"RFC 6238 vector at t={at}")

    def test_stored_bytes_are_the_key_verbatim(self):
        """Apple stores the decoded key. Confirmed against its own originalURL: on every entry
        carrying one, stored == b32decode(url secret), 14/14."""
        raw = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a" * 2
        self.assertEqual(totp.key_bytes(raw), raw)

    def test_base32_looking_bytes_are_not_decoded(self):
        """The bug that produced wrong codes.

        A raw key whose bytes all happen to fall in the base32 alphabet used to be decoded as
        text, silently substituting a different key. 20- and 32-byte keys hit this by chance
        often enough that this happens on real vaults."""
        import base64
        looks_like_b32 = b"ABCDEFGHIJKLMNOPQRST"          # every byte is a base32 character
        decoded = base64.b32decode(looks_like_b32 + b"====")   # 20 chars needs padding to 24
        self.assertEqual(totp.key_bytes(looks_like_b32), looks_like_b32)
        self.assertNotEqual(totp.key_bytes(looks_like_b32), decoded)
        self.assertNotEqual(totp.code(looks_like_b32, at=1234567890),
                            totp.code(decoded, at=1234567890))

    def test_base32_text_is_decoded(self):
        """A str is what a human pastes out of an otpauth:// URI, so it is base32 text."""
        import base64
        raw = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a" * 2
        self.assertEqual(totp.key_bytes(base64.b32encode(raw).decode()), raw)
        self.assertEqual(totp.code(base64.b32encode(raw).decode(), at=1234567890),
                         totp.code(raw, at=1234567890))

    def test_digits_and_period_respected(self):
        self.assertEqual(len(totp.code(RFC_SECRET, digits=6, at=59)), 6)
        self.assertEqual(len(totp.code(RFC_SECRET, digits=8, at=59)), 8)
        # A 60s period halves the counter, so it must differ from the 30s code here.
        self.assertNotEqual(totp.code(RFC_SECRET, period=30, at=59),
                            totp.code(RFC_SECRET, period=60, at=59))

    def test_seconds_remaining(self):
        self.assertEqual(totp.seconds_remaining(30, at=1000.0), 20)
        self.assertEqual(totp.seconds_remaining(30, at=1020.0), 30)


def _meta_item(domain, acct, **attrs):
    return {"srvr": domain, "acct": acct, "v_Data": plistlib.dumps(attrs, fmt=plistlib.FMT_BINARY)}


def _login_item(domain, acct, password):
    return {"srvr": domain, "acct": acct, "v_Data": password.encode(), "labl": domain}


class MetadataSplitTests(unittest.TestCase):
    def test_metadata_never_becomes_a_credential(self):
        """The regression that mattered: a bplist must never be served as a password."""
        items = [
            _login_item("example.com", "me", "hunter2"),
            _meta_item("example.com", "me", notes="a note"),
        ]
        store = CredentialStore.from_items(items)
        self.assertEqual(len(store), 1)
        self.assertEqual(store.all()[0].password, "hunter2")
        self.assertFalse(any(c.password.startswith("bplist00") for c in store.all()))

    def test_totp_attaches_to_the_matching_login(self):
        items = [
            _login_item("example.com", "me", "hunter2"),
            _meta_item("example.com", "me",
                       totp={"secret": RFC_SECRET, "digits": 8, "period": 30, "algorithm": 0}),
            _login_item("other.com", "me", "pw"),
        ]
        creds = {c.domain: c for c in CredentialStore.from_items(items).all()}
        self.assertIsNotNone(creds["example.com"].totp)
        self.assertIsNone(creds["other.com"].totp, "TOTP leaked onto an unrelated account")
        code, remaining = creds["example.com"].totp_code()
        self.assertEqual(len(code), 8)
        self.assertTrue(0 < remaining <= 30)

    def test_secret_never_reaches_the_browser(self):
        items = [
            _login_item("example.com", "me", "hunter2"),
            _meta_item("example.com", "me", totp={"secret": RFC_SECRET, "digits": 6}),
        ]
        pub = CredentialStore.from_items(items).all()[0].public_dict()
        self.assertTrue(pub["has_totp"])
        self.assertNotIn("totp", pub)
        self.assertNotIn(RFC_SECRET.decode(), repr(pub))

    def test_storage_round_trip_keeps_totp(self):
        items = [
            _login_item("example.com", "me", "hunter2"),
            _meta_item("example.com", "me", totp={"secret": RFC_SECRET, "digits": 8}),
        ]
        original = CredentialStore.from_items(items).all()[0]
        import json
        from icp.vault.host import Credential
        d = json.loads(json.dumps(original.storage_dict()))   # bytes must survive JSON
        restored = Credential(domain=d["domain"], username=d["username"],
                              password=d["password"], title=d["title"], mdat=d["mdat"],
                              totp=d.get("totp"), notes=d.get("notes", ""))
        self.assertEqual(restored.totp_code()[0], original.totp_code()[0])

    def test_card_data_is_recognised_and_not_a_credential(self):
        items = [_meta_item("bank.example", "me", CardNumber="4111111111111111",
                            CardSecurityCode="123")]
        self.assertEqual(len(CredentialStore.from_items(items)), 0)
        self.assertTrue(metadata.has_card_data(metadata.parse(items[0]["v_Data"])))



class AliasInferenceTests(unittest.TestCase):
    """Metadata stubs name a domain for an account but hold no password. Apple stores no
    pointer to the real credential, so the domain is offered as an inferred alias."""

    def test_stub_domain_is_offered_for_the_same_account(self):
        from icp.vault.host import CredentialStore as CS
        items = [
            _login_item("server.local", "alice", "pw1"),
            _meta_item("nas.example.com", "alice", ctxt={"": {"lUsed": 1.0}}),
        ]
        store = CS.from_items(items)
        self.assertEqual(len(store), 1)
        cred = store.all()[0]
        self.assertIn("nas.example.com", cred.aliases)
        self.assertEqual([c.domain for c in store.match("nas.example.com")],
                         ["server.local"])

    def test_alias_never_outranks_a_real_domain_match(self):
        from icp.vault.host import CredentialStore as CS
        items = [
            _login_item("nas.example.com", "someoneelse", "real"),
            _login_item("server.local", "alice", "pw1"),
            _meta_item("nas.example.com", "alice", ctxt={"": {"lUsed": 1.0}}),
        ]
        hits = CS.from_items(items).match("nas.example.com")
        self.assertEqual(hits[0].domain, "nas.example.com",
                         "an inferred alias outranked the credential that owns the domain")

    def test_credential_is_not_aliased_onto_its_own_domain(self):
        from icp.vault.host import CredentialStore as CS
        items = [
            _login_item("example.com", "bob", "pw"),
            _meta_item("example.com", "bob", ctxt={"": {"lUsed": 1.0}}),
        ]
        self.assertEqual(CS.from_items(items).all()[0].aliases, ())

    def test_aliases_survive_the_storage_round_trip(self):
        import json
        from icp.vault.host import Credential, CredentialStore as CS
        items = [
            _login_item("server.local", "alice", "pw1"),
            _meta_item("nas.example.com", "alice", ctxt={"": {"lUsed": 1.0}}),
        ]
        d = json.loads(json.dumps(CS.from_items(items).all()[0].storage_dict()))
        restored = Credential(domain=d["domain"], username=d["username"],
                              password=d["password"], title=d["title"], mdat=d["mdat"],
                              aliases=tuple(d.get("aliases") or ()))
        self.assertIn("nas.example.com", restored.aliases)

if __name__ == "__main__":
    unittest.main()
