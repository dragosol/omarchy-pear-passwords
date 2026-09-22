"""Offline tests for the native-messaging host: framing, domain matching, dispatch.

Run: .venv/bin/python -m unittest tests.test_host
"""

import io
import json
import struct
import unittest

from icp.hme.client import HmeAlias
from icp.vault import host
from icp.vault.host import Credential, CredentialStore


class DomainMatchTests(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(host.domains_match("example.com", "example.com"))

    def test_www_normalized(self):
        self.assertTrue(host.domains_match("www.example.com", "example.com"))

    def test_subdomain_either_way(self):
        self.assertTrue(host.domains_match("login.example.com", "example.com"))
        self.assertTrue(host.domains_match("example.com", "accounts.example.com"))

    def test_url_input_normalized(self):
        self.assertTrue(host.domains_match("https://login.example.com/path?x=1", "example.com"))

    def test_no_false_suffix(self):
        self.assertFalse(host.domains_match("notexample.com", "example.com"))
        self.assertFalse(host.domains_match("example.com.evil.com", "example.com"))

    def test_empty(self):
        self.assertFalse(host.domains_match("", "example.com"))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.store = CredentialStore([
            Credential("example.com", "alice", "pw1", "Example"),
            Credential("login.example.com", "bob", "pw2", "Example Login"),
            Credential("other.org", "carol", "pw3", "Other"),
        ])

    def test_match_returns_relevant(self):
        hits = self.store.match("www.example.com")
        self.assertEqual({c.username for c in hits}, {"alice", "bob"})

    def test_exact_host_first(self):
        hits = self.store.match("example.com")
        self.assertEqual(hits[0].username, "alice")  # exact host sorts before subdomain

    def test_no_match(self):
        self.assertEqual(self.store.match("nowhere.test"), [])

    def test_label_only_item_matches_hostname_label(self):
        store = CredentialStore([Credential("", "me@example.com", "pw", "Cloudflare")])
        hits = store.match("dash.cloudflare.com")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].username, "me@example.com")

    def test_generic_label_only_item_does_not_match(self):
        store = CredentialStore([Credential("", "me@example.com", "pw", "Login")])
        self.assertEqual(store.match("login.example.com"), [])


def _alias(domain, address="quiet-otter@icloud.com", label="Claude"):
    return HmeAlias(anonymous_id="a1", address=address, label=label, note="",
                    forward_to="me@example.com", is_active=True, domain=domain,
                    created_at=0.0)


class MatchAliasesTests(unittest.TestCase):
    def test_matches_same_domains_match_rule_as_credentials(self):
        aliases = [_alias("claude.ai"), _alias("other.org", address="x@icloud.com")]
        hits = host.match_aliases("www.claude.ai", aliases)
        self.assertEqual([a.address for a in hits], ["quiet-otter@icloud.com"])

    def test_no_domain_never_matches(self):
        aliases = [_alias("")]
        self.assertEqual(host.match_aliases("claude.ai", aliases), [])

    def test_no_match(self):
        self.assertEqual(host.match_aliases("nowhere.test", [_alias("claude.ai")]), [])

    def test_service_field_can_act_as_label_only_domain(self):
        store = CredentialStore.from_items([
            {"svce": "Cloudflare", "acct": "me@example.com", "v_Data": b"pw",
             "labl": "Cloudflare"},
        ])
        self.assertEqual(store.match("dash.cloudflare.com")[0].password, "pw")

    def test_from_items_drops_internal_records(self):
        # PCS service blobs and per-site "Website Metadata" sync alongside real logins but are
        # not credentials.
        store = CredentialStore.from_items([
            {"srvr": "idmsa.apple.com", "acct": "me@gmail.com", "v_Data": b"pw",
             "labl": "idmsa.apple.com", "class": "inet"},
            {"acct": "0Z825FXfO144", "labl": "PCS com.apple.Accessibility - 0Z825FXf",
             "svce": "com.apple.Accessibility"},
            {"srvr": "apple.com", "labl": "Website Metadata for apple.com"},  # no user/pw
        ])
        self.assertEqual(len(store), 1)  # only the real login survives ingest
        self.assertEqual(store.match("idmsa.apple.com")[0].username, "me@gmail.com")
        # the page still matches just the one real login - no PCS/metadata noise
        self.assertEqual([c.username for c in store.match("apple.com")], ["me@gmail.com"])

    def test_match_sorts_recent_first_within_tier(self):
        store = CredentialStore([
            Credential("example.com", "old", "p", "Example", mdat=1000),
            Credential("example.com", "new", "p", "Example", mdat=2000),
        ])
        self.assertEqual([c.username for c in store.match("example.com")], ["new", "old"])

    def test_from_items_carries_mdat(self):
        import datetime
        when = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
        store = CredentialStore.from_items([
            {"srvr": "ex.com", "acct": "a", "v_Data": b"p", "mdat": when},
        ])
        self.assertEqual(store.all()[0].mdat, when.timestamp())

    def test_from_items_apple_fields(self):
        store = CredentialStore.from_items([
            # the real iCloud web-login shape: an `inet` item uses `srvr`, not `server`.
            {"srvr": "accounts.google.com", "acct": "me@gmail.com", "v_Data": b"hunter2",
             "labl": "Google", "class": "inet", "agrp": "com.apple.cfnetwork"},
            {"server": "apple.com", "acct": "me@icloud.com", "v_Data": b"secret", "labl": "Apple"},
            {"domain": "git.example", "username": "dev", "password": "hunter2"},
            {"acct": "noserver"},  # kept (has username)
            {},                    # dropped (no domain/username)
        ])
        self.assertEqual(len(store), 4)
        g = store.match("accounts.google.com")[0]
        self.assertEqual((g.domain, g.username, g.password),
                         ("accounts.google.com", "me@gmail.com", "hunter2"))
        apple = store.match("apple.com")[0]
        self.assertEqual(apple.username, "me@icloud.com")
        self.assertEqual(apple.password, "secret")


class FramingTests(unittest.TestCase):
    def _encode(self, obj):
        data = json.dumps(obj).encode()
        return struct.pack("<I", len(data)) + data

    def test_read_write_round_trip(self):
        buf_in = io.BytesIO(self._encode({"cmd": "ping"}))
        self.assertEqual(host.read_message(buf_in), {"cmd": "ping"})
        buf_out = io.BytesIO()
        host.write_message({"ok": True, "count": 2}, buf_out)
        buf_out.seek(0)
        self.assertEqual(host.read_message(buf_out), {"ok": True, "count": 2})

    def test_read_eof_returns_none(self):
        self.assertIsNone(host.read_message(io.BytesIO(b"")))

    def test_partial_length_returns_none(self):
        self.assertIsNone(host.read_message(io.BytesIO(b"\x01\x02")))


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.store = CredentialStore([Credential("example.com", "alice", "pw1")])

    def test_ping(self):
        self.assertEqual(host.handle({"cmd": "ping"}, self.store), {"ok": True, "count": 1})

    def test_match(self):
        r = host.handle({"cmd": "match", "domain": "example.com"}, self.store)
        self.assertTrue(r["ok"])
        self.assertEqual(r["credentials"][0]["password"], "pw1")

    def test_match_with_no_aliases_arg_returns_empty_alias_list(self):
        r = host.handle({"cmd": "match", "domain": "example.com"}, self.store)
        self.assertEqual(r["aliases"], [])

    def test_match_includes_matching_aliases(self):
        r = host.handle({"cmd": "match", "domain": "claude.ai"}, self.store,
                        [_alias("claude.ai")])
        self.assertEqual(r["aliases"], [{"address": "quiet-otter@icloud.com",
                                        "label": "Claude", "domain": "claude.ai"}])

    def test_match_excludes_non_matching_aliases(self):
        r = host.handle({"cmd": "match", "domain": "other.org"}, self.store,
                        [_alias("claude.ai")])
        self.assertEqual(r["aliases"], [])

    def test_match_missing_domain(self):
        self.assertFalse(host.handle({"cmd": "match"}, self.store)["ok"])

    def test_unknown_cmd(self):
        self.assertFalse(host.handle({"cmd": "frobnicate"}, self.store)["ok"])

    def test_serve_loop_processes_until_eof(self):
        msgs = self._stream([{"cmd": "ping"}, {"cmd": "match", "domain": "example.com"}])
        out = io.BytesIO()
        host.serve(self.store, instream=msgs, outstream=out)
        out.seek(0)
        r1 = host.read_message(out)
        r2 = host.read_message(out)
        self.assertEqual(r1["count"], 1)
        self.assertEqual(r2["credentials"][0]["username"], "alice")
        self.assertIsNone(host.read_message(out))  # nothing more

    def _stream(self, objs):
        b = io.BytesIO()
        for o in objs:
            host.write_message(o, b)
        b.seek(0)
        return b


if __name__ == "__main__":
    unittest.main()
