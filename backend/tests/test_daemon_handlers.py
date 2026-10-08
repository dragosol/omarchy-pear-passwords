"""The ui, clip and migrate ops end to end over the real server, with fake store, polkit and
Apple pipeline (docs/protocol.md 2.2, 6-9)."""

import asyncio
import base64
import hashlib
import unittest
from unittest import mock

from daemon_fakes import UID, FakeStore, Harness, meta, secrets

from icp import vstore
from icp.daemon import handlers, paths, polkit, protocol
from icp.daemon.context import NeedsLogin
from icp.errors import AppleError


class Base(unittest.IsolatedAsyncioTestCase):
    seed = True

    async def asyncSetUp(self):
        self.h = await Harness().start()
        self.st = self.h.seed() if self.seed else self.h.store()
        self.ui, self.peer = await self.h.ui()

    async def asyncTearDown(self):
        await self.h.stop()

    def dialogs(self):
        return self.h.authority.actions()


class HelloAndUnlockTests(Base):
    async def test_ui_hello_while_locked(self):
        hello = self.ui.hello
        self.assertEqual(hello, {"rid": 0, "proto": 2, "version": handlers.VERSION,
                                 "state": "locked", "signed_in": True, "sealed_with": "host",
                                 "synced_at": None, "needs_login": None,
                                 "settings": {"grant_s": 120, "idle_lock_s": 0,
                                              "clip_timeout_s": 30},
                                 "migration_pending": False,
                                 "autofill": {"enabled": False, "hosts": 0},
                                 "old_copy": None})

    async def test_unlock_then_sync_event_after_the_reply(self):
        r = await self.ui.call("unlock")
        self.assertEqual([e["id"] for e in r["entries"]], ["e.0", "e.1"])
        self.assertEqual(set(r), {"rid", "entries", "synced_at", "needs_login", "tpm_move"})
        e = r["entries"][0]
        for key in ("password", "notes", "totp_secret", "pwmac"):
            self.assertNotIn(key, e)
        self.assertEqual(e["primary"], "Site 0")
        ev = await self.ui.event("synced")
        self.assertLess(self.ui.raw.index(r), self.ui.raw.index(ev))
        self.assertEqual(ev["counts"], {"added": 0, "changed": 1, "deleted": 0, "unchanged": 1})
        self.assertEqual(self.dialogs(), [paths.ACTION_UNLOCK])

    async def test_second_unlock_on_the_same_window_does_not_prompt(self):
        await self.ui.call("unlock")
        await self.ui.call("unlock")
        self.assertEqual(self.dialogs(), [paths.ACTION_UNLOCK])

    async def test_internal_records_hidden_unless_all(self):
        self.st.metas["x"] = meta("x", title="", domain="", username="com.apple.account.x")
        self.st.secrets["x"] = secrets()
        r = await self.ui.call("unlock")
        self.assertNotIn("x", [e["id"] for e in r["entries"]])
        r = await self.ui.call("unlock", all=True)
        self.assertIn("x", [e["id"] for e in r["entries"]])

    async def test_ambiguous_and_nickname(self):
        self.st.metas["e.1"].title = "Site 0"
        self.st.metas["e.1"].username = "user0"
        self.st.metas["e.1"].nickname = "Work"
        self.st.metas["e.2"] = meta("e.2", title="Site 0", domain="site0.example",
                                    username="user0")
        r = await self.ui.call("unlock")
        by = {e["id"]: e for e in r["entries"]}
        self.assertEqual(by["e.1"]["primary"], "Work")
        self.assertTrue(by["e.0"]["ambiguous"] and by["e.2"]["ambiguous"])
        self.assertFalse(by["e.1"]["ambiguous"])

    async def test_refusals_are_replies(self):
        self.h.authority.outcome = "dismissed"
        self.assertEqual(await self.ui.call("unlock"),
                         {"rid": self.ui.rid, "locked": True, "reason": "dismissed"})

    async def test_seal_state_is_reported_and_remembered(self):
        self.st.seal_error = "tpm-missing"
        r = await self.ui.call("unlock")
        self.assertEqual((r["locked"], r["reason"]), (True, "tpm-missing"))
        self.ui.close()
        await asyncio.sleep(0.05)
        ui2, _ = await self.h.ui()
        self.assertEqual(ui2.hello["state"], "tpm-missing")

    async def test_a_window_opened_while_a_wipe_is_pending_is_not_refused(self):
        # Round 2 audit note (a): the lock of the last window was still waiting for a store
        # call; the new window's hello must say "locked", not fail.
        self.ui.close()
        await asyncio.sleep(0.05)
        s = self.h.reg.get(UID)
        s.wipe_after = True
        try:
            ui2, _ = await self.h.ui()
            self.assertEqual(ui2.hello["state"], "locked")
            # A keyed call is still refused until the wipe happened.
            self.assertEqual((await ui2.call("unlock"))["error"], "seal-unavailable")
            self.assertEqual(self.dialogs(), [])
        finally:
            s.wipe_after = False

    async def test_ui_ops_need_tier1(self):
        for op, extra in (("grant", {"id": "e.0"}), ("copy", {"id": "e.0", "field": "username"}),
                          ("create", {"fields": {"password": "x"}}), ("delete", {"id": "e.0"}),
                          ("signout", {}), ("clip-history-check", {"items": []}),
                          ("totp-preview", {"setup": "JBSWY3DPEHPK3PXP"})):
            self.assertEqual((await self.ui.call(op, **extra))["error"], "locked", op)
        self.assertEqual(self.dialogs(), [])
        self.assertEqual(await self.ui.call("sync"), {"rid": self.ui.rid, "skipped": "locked"})


class EmptyStoreTests(Base):
    seed = False

    async def test_empty(self):
        self.assertEqual(self.ui.hello["state"], "empty")
        self.assertEqual(self.ui.hello["sealed_with"], None)
        self.assertEqual(await self.ui.call("unlock"),
                         {"rid": self.ui.rid, "locked": True, "reason": "empty"})
        self.assertEqual(self.dialogs(), [])

    async def test_fresh_signin_with_questions(self):
        asked = []

        def script(ctx):
            asked.append(ctx.ui.ask("Apple ID: ", kind="apple_id"))
            asked.append(ctx.ui.secret("Password: ", kind="password"))
            asked.append(ctx.ui.choose("Device", ["Mac", "iPhone"], kind="device"))
            ctx.ui.stage("verify", via="device")
        self.h.apple.login_script = script
        pending = self.ui.send("signin", mode="login")
        rid = self.ui.rid
        ask = await self.ui.event("ask")
        self.assertEqual((ask["rid"], ask["need"], ask["kind"]), (rid, "text", "apple_id"))
        self.assertEqual(await self.ui.call("answer", ask_id=ask["ask_id"], value=" me@x "),
                         {"rid": self.ui.rid, "ok": True})
        ask = await self.ui.event("ask")
        self.assertEqual(ask["need"], "secret")
        await self.ui.call("answer", ask_id=ask["ask_id"], value="fake-pass")
        self.assertEqual((await self.ui.call("answer", ask_id=ask["ask_id"], value="again"))
                         ["error"], "invalid")
        ask = await self.ui.event("ask")
        self.assertEqual(ask["options"], ["Mac", "iPhone"])
        await self.ui.call("answer", ask_id=ask["ask_id"], value="1")
        self.assertEqual(await asyncio.wait_for(pending, 5), {"rid": rid, "ok": True})
        self.assertEqual(asked, ["me@x", "fake-pass", 1])
        stage = await self.ui.event("stage")
        self.assertEqual((stage["rid"], stage["stage"], stage["info"]),
                         (rid, "verify", {"via": "device"}))
        self.assertEqual(self.dialogs(), [paths.ACTION_MANAGE])
        self.assertTrue(self.h.reg.get(UID).unlocked())
        self.assertIn("create", self.h.store().calls)

    async def test_signin_cancel(self):
        self.h.apple.login_script = lambda ctx: ctx.ui.ask("Apple ID: ")
        pending = self.ui.send("signin", mode="login")
        rid = self.ui.rid
        ask = await self.ui.event("ask")
        await self.ui.call("answer", ask_id=ask["ask_id"], cancel=True)
        self.assertEqual(await asyncio.wait_for(pending, 5), {"rid": rid, "error": "cancelled"})
        self.assertIsNone(self.h.reg.get(UID).busy)

    async def test_signin_cancel_op_and_eof(self):
        self.h.apple.login_script = lambda ctx: ctx.ui.ask("Apple ID: ")
        pending = self.ui.send("signin", mode="login")
        rid = self.ui.rid
        await self.ui.event("ask")
        self.assertEqual((await self.ui.call("cancel", target=rid))["cancelled"], True)
        self.assertEqual((await asyncio.wait_for(pending, 5))["error"], "cancelled")

    async def test_relogin_needs_a_session(self):
        self.assertEqual((await self.ui.call("signin", mode="relogin"))["error"], "locked")
        self.assertEqual((await self.ui.call("signin", mode="sideways"))["error"], "invalid")


class MigrationTests(Base):
    seed = False

    async def migrate(self):
        r = await self.ui.call("migrate-begin")
        self.assertEqual(r["ttl"], 10)
        m, hello = await self.h.hello("migrate", peer=self.h.peer(ppid=self.peer.pid),
                                      ticket=r["ticket"])
        self.assertEqual(hello["purpose"], "import")
        return m

    async def send_file(self, m, name, data, chunk=protocol.IMPORT_CHUNK_MAX):
        parts = [data[i:i + chunk] for i in range(0, len(data), chunk)] or [b""]
        for seq, part in enumerate(parts):
            r = await m.call("import-file", name=name, seq=seq,
                             b64=base64.b64encode(part).decode(), eof=seq == len(parts) - 1)
        return r

    async def test_full_import_and_purge(self):
        m = await self.migrate()
        self.assertEqual(self.dialogs(), [paths.ACTION_MANAGE])
        big = bytes(range(256)) * 300                      # several chunks
        r = await self.send_file(m, "vault.enc", big)
        self.assertEqual((r["size"], r["sha256"]), (len(big), hashlib.sha256(big).hexdigest()))
        self.assertEqual((await m.call("import-commit"))["error"], "incomplete")
        await self.send_file(m, "kdf.json", b'{"fake": true}')
        # No check.enc yet: the key is checked against vault.enc (a keyring vault), which
        # this one does not open.
        self.assertEqual((await m.call("import-key", key_b64=base64.b64encode(b"k" * 32)
                                       .decode()))["error"], "wrong-passphrase")
        await self.send_file(m, "check.enc", b"check")
        with mock.patch.object(vstore, "v1_key_verifies", lambda files, key: key == b"k" * 32):
            r = await m.call("import-key", key_b64=base64.b64encode(b"j" * 32).decode())
            self.assertEqual(r["error"], "wrong-passphrase")
            r = await m.call("import-key", key_b64=base64.b64encode(b"k" * 32).decode())
            self.assertEqual(r, {"rid": m.rid, "ok": True})
        r = await m.call("import-commit", backup_dir="/home/u/.config/icp.v1-backup-20261008")
        self.assertEqual(r["counts"]["credentials"], 2)
        files, key = self.h.store().imported
        self.assertEqual((files["vault.enc"], key), (big, b"k" * 32))
        ev = await self.ui.event("migrated")
        self.assertEqual(ev["counts"]["credentials"], 2)
        oc = self.h.store().settings["old_copy"]
        self.assertEqual(oc["dir"], "/home/u/.config/icp.v1-backup-20261008")
        self.assertEqual([f["name"] for f in oc["files"]], ["check.enc", "kdf.json", "vault.enc"])
        self.assertNotIn("migration_pending", self.h.store().settings)

        r = await self.ui.call("purge-old-copy")
        p, hello = await self.h.hello("migrate", peer=self.h.peer(ppid=self.peer.pid),
                                      ticket=r["ticket"])
        self.assertEqual((hello["purpose"], hello["dir"]), ("purge", oc["dir"]))
        self.assertEqual(hello["files"], oc["files"])
        self.assertEqual((await p.call("import-file", name="vault.enc", seq=0, b64=""))["error"],
                         "forbidden")
        self.assertEqual(await p.call("purge-result", removed=["vault.enc"], kept=[]),
                         {"rid": p.rid, "ok": True})
        self.assertNotIn("old_copy", self.h.store().settings)
        self.assertEqual((await self.ui.call("purge-old-copy"))["error"], "not-found")

    async def test_passphrase_path(self):
        m = await self.migrate()
        for name in ("vault.enc", "kdf.json", "check.enc"):
            await self.send_file(m, name, b"x")
        with mock.patch.object(vstore, "v1_key_from_passphrase",
                               lambda kdf, pw: b"k" * 32 if pw == "right" else b"w" * 32), \
                mock.patch.object(vstore, "v1_key_verifies", lambda files, key: key == b"k" * 32):
            self.assertEqual((await m.call("import-key", passphrase="wrong"))["error"],
                             "wrong-passphrase")
            self.assertTrue((await m.call("import-key", passphrase="right"))["ok"])

    async def test_chunk_rules(self):
        m = await self.migrate()
        ok = base64.b64encode(b"a").decode()
        self.assertEqual((await m.call("import-file", name="vault.enc", seq=1, b64=ok))["error"],
                         "invalid")
        self.assertEqual((await m.call("import-file", name="evil.enc", seq=0, b64=ok))["field"],
                         "name")
        self.assertEqual((await m.call("import-file", name="vault.enc", seq=0, b64="!!"))
                         ["field"], "b64")
        big = base64.b64encode(b"a" * (protocol.IMPORT_CHUNK_MAX + 1)).decode()
        r = await m.call("import-file", name="vault.enc", seq=0, b64=big)
        self.assertEqual((r["error"], r["field"]), ("invalid", "b64"))
        await self.send_file(m, "kdf.json", b"x")
        self.assertEqual((await m.call("import-file", name="kdf.json", seq=1, b64=ok))["error"],
                         "invalid")                       # a repeated name after eof

    async def test_mismatch_keeps_nothing_and_can_retry(self):
        m = await self.migrate()
        for name, data in (("vault.enc", b"mismatch"), ("kdf.json", b"x"), ("check.enc", b"x")):
            await self.send_file(m, name, data)
        with mock.patch.object(vstore, "v1_key_verifies", lambda f, k: True):
            await m.call("import-key", key_b64=base64.b64encode(b"k" * 32).decode())
        self.assertEqual((await m.call("import-commit"))["error"], "mismatch")
        self.assertEqual((await m.call("import-commit"))["error"], "incomplete")
        m2 = await self.migrate()                         # same window: started over
        self.assertIsNotNone(m2)
        self.assertIn("reset", self.h.store().calls)

    async def test_an_uncommitted_migration_is_offered_again_after_the_window_closed(self):
        # function-migration-never-reoffered: the window closed at the passphrase step.
        m = await self.migrate()
        await self.send_file(m, "vault.enc", b"x")
        m.close()
        self.ui.close()
        await asyncio.sleep(0.1)
        self.ui, self.peer = await self.h.ui()
        hello = self.ui.hello
        self.assertEqual(hello["state"], "locked")            # keys exist now
        self.assertTrue(hello["migration_pending"])
        # No fresh iCloud sign-in (and its escrow join) over the half-done import...
        await self.ui.call("unlock")
        r = await self.ui.call("signin", mode="login")
        self.assertEqual(r.get("error"), "migration-pending")
        self.assertNotIn(paths.ACTION_MANAGE, self.dialogs()[1:])
        # ...but migrate-begin starts it over.
        m2 = await self.migrate()
        self.assertIsNotNone(m2)
        self.assertIn("reset", self.h.store().calls)

    async def test_a_keyring_vault_imports_with_its_key_checked_against_vault_enc(self):
        # audit: keyring-keyed 1.x vaults (no kdf.json, no check.enc) could not be imported.
        m = await self.migrate()
        await self.send_file(m, "vault.enc", b"V" * 64)
        self.assertEqual((await m.call("import-key", passphrase="x"))["error"], "incomplete")
        seen = []

        def verifies(files, key):
            seen.append(sorted(files))
            return key == b"k" * 32
        with mock.patch.object(vstore, "v1_key_verifies", verifies):
            r = await m.call("import-key", key_b64=base64.b64encode(b"j" * 32).decode())
            self.assertEqual(r["error"], "wrong-passphrase")
            r = await m.call("import-key", key_b64=base64.b64encode(b"k" * 32).decode())
            self.assertEqual(r, {"rid": m.rid, "ok": True})
        self.assertEqual(seen, [["vault.enc"], ["vault.enc"]])
        r = await m.call("import-commit", backup_dir="/home/u/.config/icp.v1-backup-20261008")
        self.assertIn("counts", r)
        self.assertEqual(self.dialogs(), [paths.ACTION_MANAGE])        # nothing else asked

    async def _pending_after_a_closed_window(self):
        m = await self.migrate()
        m.close()
        self.ui.close()
        await asyncio.sleep(0.1)
        self.ui, self.peer = await self.h.ui()
        self.assertTrue(self.ui.hello["migration_pending"])
        self.dialogs_before = len(self.dialogs())

    async def test_no_v1_vault_left_clears_the_pending_import(self):
        # audit: migration_pending dead end. ~/.config/icp is gone, so the window cannot
        # offer the move again; without a way out every "Sign in to iCloud" failed with
        # migration-pending. The window abandons the record (no dialog) and signs in.
        await self._pending_after_a_closed_window()
        r = await self.ui.call("migrate-abandon")
        self.assertEqual(r, {"rid": self.ui.rid, "migration_pending": False})
        self.assertEqual(len(self.dialogs()), self.dialogs_before)     # no dialog
        self.assertNotIn("migration_pending", self.h.store().settings)
        await self.ui.call("unlock")
        r = await self.ui.call("signin", mode="login")
        self.assertNotEqual(r.get("error"), "migration-pending")
        ui2_hello = self.ui.hello
        del ui2_hello
        self.ui.close()
        await asyncio.sleep(0.1)
        self.ui, self.peer = await self.h.ui()
        self.assertFalse(self.ui.hello["migration_pending"])

    async def test_abandon_with_nothing_pending_is_a_no_op(self):
        self.h.seed()
        r = await self.ui.call("migrate-abandon")
        self.assertEqual(r["migration_pending"], False)
        self.assertEqual(self.dialogs(), [])

    async def test_reset_leaves_a_pending_import(self):
        await self._pending_after_a_closed_window()
        r = await self.ui.call("reset")
        self.assertEqual(r, {"rid": self.ui.rid, "state": "empty"})
        self.assertEqual(self.dialogs()[self.dialogs_before:], [paths.ACTION_MANAGE])
        self.assertIn("reset", self.h.store().calls)
        self.assertNotIn("migration_pending", self.h.store().settings)
        r = await self.ui.call("signin", mode="login")
        self.assertNotEqual(r.get("error"), "migration-pending")

    async def test_migrate_begin_refused_with_a_store(self):
        self.h.seed()
        self.assertEqual((await self.ui.call("migrate-begin"))["error"], "not-locked")
        self.assertEqual(self.dialogs(), [])

    # --- round 2 audit, problem 3: no dead end after an abandoned or reset import ---------
    async def test_an_abandoned_import_can_be_started_again(self):
        # The window abandons the record whenever it cannot see vault.enc, and "Start fresh
        # instead" does too. The store then holds keys and nothing else; when the 1.x vault
        # is (still) there, Continue must work, not answer not-locked for ever.
        await self._pending_after_a_closed_window()
        await self.ui.call("migrate-abandon")
        self.assertNotIn("migration_pending", self.h.store().settings)
        m = await self.migrate()
        self.assertIsNotNone(m)
        self.assertIn("reset", self.h.store().calls)
        self.assertEqual(self.dialogs()[self.dialogs_before:], [paths.ACTION_MANAGE])

    async def test_a_store_that_holds_nothing_can_take_a_migration(self):
        self.h.seed(n=0, signed_in=False)            # e.g. after Start over, never signed in
        m = await self.migrate()
        self.assertIsNotNone(m)
        self.assertIn("reset", self.h.store().calls)
        self.assertEqual(self.dialogs(), [paths.ACTION_MANAGE])

    async def test_a_store_that_holds_nothing_can_be_reset(self):
        self.h.seed(n=0, signed_in=False)
        r = await self.ui.call("reset")
        self.assertEqual(r, {"rid": self.ui.rid, "state": "empty"})

    async def test_a_signed_in_store_without_entries_is_not_replaced(self):
        self.h.seed(n=0, signed_in=True)
        self.assertEqual((await self.ui.call("migrate-begin"))["error"], "not-locked")
        self.assertEqual((await self.ui.call("reset"))["error"], "not-locked")
        self.assertEqual(self.dialogs(), [])

    async def test_a_certain_pcr_policy_refusal_comes_before_the_dialog(self):
        # Gate finding 1 / audit note (b): the user approved a .manage dialog and only then
        # got seal-refused/pcr-policy.
        FakeStore.blocked_reason = "pcr-policy"
        r = await self.ui.call("migrate-begin")
        self.assertEqual((r["error"], r.get("reason")), ("seal-refused", "pcr-policy"))
        self.assertEqual(self.dialogs(), [])
        self.assertNotIn("create", self.h.store().calls)

    async def test_lock_withdraws_the_importer(self):
        m = await self.migrate()
        await self.ui.call("lock")
        self.assertEqual((await m.event("withdraw"))["event"], "withdraw")
        await asyncio.wait_for(m.closed.wait(), 5)


class EditTests(Base):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.ui.call("unlock")
        # Let the sync the unlock started finish: while it runs every edit is busy-sync, and
        # its end clears `busy` (a race that made test_busy_sync flaky under load).
        await self.ui.event("synced")

    async def test_set_with_generate(self):
        await self.ui.call("grant", id="e.0")
        r = await self.ui.call("set", id="e.0", fields={}, generate={})
        self.assertEqual(r, {"rid": self.ui.rid, "id": "e.0", "synced": True})
        new = self.st.secrets["e.0"].password
        self.assertNotEqual(new, "pw-0-fake")
        self.assertRegex(new, r"^[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}$")
        self.assertNotIn(new, str(self.ui.raw))
        self.assertEqual((await self.ui.call("reveal", id="e.0", field="password"))["value"], new)
        self.assertEqual(self.dialogs(), [paths.ACTION_UNLOCK, paths.ACTION_REVEAL])

    async def test_set_validation(self):
        await self.ui.call("grant", id="e.0")
        bad = [({"password": "x"}, {}, "generate"), ({"colour": "red"}, None, "colour"),
               ({"password": ""}, None, "password"), ({"sites": ["not a host"]}, None, "sites"),
               ({"totp": {"setup": "not base32!"}}, None, "totp"),
               ({"nickname": "a‮b"}, None, "nickname")]
        for fields, gen, field in bad:
            kw = {"fields": fields} if gen is None else {"fields": fields, "generate": gen}
            r = await self.ui.call("set", id="e.0", **kw)
            self.assertEqual((r["error"], r.get("field")), ("invalid", field), fields)
        self.assertEqual([c for c in self.h.apple.calls if c != "sync"], [])

    async def test_nickname_apple_cannot_hold_stays_local(self):
        await self.ui.call("grant", id="e.0")
        r = await self.ui.call("set", id="e.0", fields={"nickname": "Home"})
        self.assertEqual(r["synced"], False)
        self.assertEqual(self.st.nicknames, {"e.0": "Home"})
        self.assertIn(("push_set", "e.0", ["nickname"]), self.h.apple.calls)

    async def test_nickname_goes_to_icloud_when_it_can(self):
        self.h.apple.apple_named.add("e.0")
        await self.ui.call("grant", id="e.0")
        r = await self.ui.call("set", id="e.0", fields={"nickname": "Home"})
        self.assertEqual(r["synced"], True)
        self.assertEqual(self.st.nicknames, {})

    async def test_nickname_without_icloud_is_local_and_offline(self):
        self.st.session = {}
        await self.ui.call("grant", id="e.0")
        r = await self.ui.call("set", id="e.0", fields={"nickname": "Home"})
        self.assertEqual(r["synced"], False)
        self.assertEqual(self.st.nicknames, {"e.0": "Home"})
        self.assertNotIn("push_set", str(self.h.apple.calls))
        r = await self.ui.call("set", id="e.0", fields={"notes": "n"})
        self.assertEqual(r["error"], "not-signed-in")

    async def test_set_needs_a_grant(self):
        self.assertEqual((await self.ui.call("set", id="e.0", fields={"notes": "n"}))["error"],
                         "no-grant")

    async def test_create_and_delete(self):
        r = await self.ui.call("create", fields={"domain": "New.Example", "username": "me"},
                               generate={})
        self.assertEqual(r["id"], "new.1")
        self.assertIn(("create", ["domain", "password", "username"]), self.h.apple.calls)
        self.assertEqual((await self.ui.call("create", fields={"domain": "a.b"}))["field"],
                         "password")
        self.assertEqual((await self.ui.call("delete", id="nope"))["error"], "not-found")
        self.assertEqual(await self.ui.call("delete", id="e.1"),
                         {"rid": self.ui.rid, "deleted": True})
        self.assertEqual(self.dialogs(), [paths.ACTION_UNLOCK, paths.ACTION_MANAGE,
                                          paths.ACTION_MANAGE])

    async def test_apple_errors(self):
        await self.ui.call("grant", id="e.0")
        import requests
        from icp.daemon.apple import FieldError, NotSignedIn
        from icp.vstore.seal import SealUnavailable
        cases = [(NeedsLogin("pw"), "needs-login"),
                 (AppleError("refused\x1b[2J by iCloud\n"), "apple"),
                 (ConnectionError("down"), "network"),
                 (requests.exceptions.SSLError("bad cert"), "network"),
                 (NotSignedIn("not joined"), "not-signed-in"),
                 (FieldError("device_passcode"), "invalid"),
                 (vstore.EntryNotFound("x"), "not-found"),
                 (SealUnavailable("systemd-creds timed out"), "seal-unavailable"),
                 (NotImplementedError(), "internal")]
        for exc, code in cases:
            def boom(ctx, id, fields, exc=exc):
                raise exc
            self.h.apple.push_set = boom
            r = await self.ui.call("set", id="e.0", fields={"notes": "n"})
            self.assertEqual(r["error"], code, exc)
            if code == "apple":
                self.assertEqual(r["detail"], "refused [2J by iCloud")
            if code == "invalid":
                self.assertEqual(r["field"], "device_passcode")
        self.assertTrue(self.st.needs_login)

    async def test_busy_sync(self):
        self.h.reg.get(UID).busy = "sync"
        await self.ui.call("grant", id="e.0")
        self.assertEqual((await self.ui.call("set", id="e.0", fields={"notes": "n"}))["error"],
                         "busy-sync")
        self.assertEqual((await self.ui.call("sync"))["skipped"], "running")
        self.h.reg.get(UID).busy = None

    async def test_signout(self):
        r = await self.ui.call("signout")
        self.assertEqual(r["signed_out"], True)
        self.assertEqual((await self.ui.event("locked"))["reason"], "signout")
        self.assertEqual(self.st.session, {})
        self.assertFalse(self.st.keys)

    async def test_totp_preview(self):
        r = await self.ui.call("totp-preview",
                               setup="otpauth://totp/Ex:me?secret=JBSWY3DPEHPK3PXP&issuer=Ex")
        self.assertRegex(r["code"], r"^\d{6}$")
        self.assertEqual((r["issuer"], r["account"]), ("Ex", "me"))
        self.assertTrue(1 <= r["seconds"] <= 30)
        self.assertEqual((await self.ui.call("totp-preview", setup="nope"))["error"], "invalid")
        self.assertEqual(self.st.unseal_count, 0)

    async def test_clip_history_check(self):
        r = await self.ui.call("clip-history-check", items=["x", "pw-1-fake", "pw-0-fake"])
        self.assertEqual(r["matches"], [1, 2])
        self.assertEqual(self.dialogs()[-1], paths.ACTION_MANAGE)
        r = await self.ui.call("clip-history-check", items=["x" * 1025])
        self.assertEqual(r["error"], "invalid")

    async def test_settings(self):
        r = await self.ui.call("settings", set={"grant_s": 60, "clip_timeout_s": 5})
        self.assertEqual(r["settings"], {"grant_s": 60, "idle_lock_s": 0, "clip_timeout_s": 5})
        self.assertEqual(self.st.settings["grant_s"], 60)
        for bad in ({"grant_s": 601}, {"idle_lock_s": 60}, {"clip_timeout_s": 4},
                    {"grant_s": True}, {"sync_lease_h": 2}, {"grant_s": 10, "x": 1}):
            r = await self.ui.call("settings", set=bad)
            self.assertEqual(r["error"], "invalid", bad)
        self.assertEqual((await self.ui.call("settings", get=True))["settings"]["grant_s"], 60)
        self.assertEqual((await self.ui.call("settings"))["error"], "bad-request")
        r = await self.ui.call("grant", id="e.0")
        self.assertEqual(r["grant_s"], 60)


class TpmMoveTests(Base):
    """audit: the PTT rotation opened every entry and history box under polkit #1 alone, on
    the first unlock after a TPM appeared. It now runs only on a click, behind .manage."""

    async def test_unlock_never_rotates_it_only_offers(self):
        self.st.tpm_state = "available"
        r = await self.ui.call("unlock")
        self.assertIs(r["tpm_move"], True)
        self.assertNotIn("reseal", self.st.calls)
        self.assertEqual(self.dialogs(), [paths.ACTION_UNLOCK])

    async def test_the_move_is_its_own_manage_dialog(self):
        self.st.tpm_state = "available"
        await self.ui.call("unlock")
        await self.ui.event("synced")          # the unlock's sync holds `busy` until it ends
        r = await self.ui.call("tpm-move")
        self.assertEqual(r, {"rid": self.ui.rid, "sealed_with": "host+tpm2"})
        self.assertEqual(self.dialogs(), [paths.ACTION_UNLOCK, paths.ACTION_MANAGE])
        self.assertEqual(self.st.calls.count("reseal"), 1)

    async def test_a_refused_dialog_moves_nothing(self):
        self.st.tpm_state = "available"
        await self.ui.call("unlock")
        await self.ui.event("synced")
        self.h.authority.outcome = polkit.DENIED
        r = await self.ui.call("tpm-move")
        self.assertEqual(r["error"], "denied")
        self.assertNotIn("reseal", self.st.calls)

    async def test_refused_before_any_dialog_when_it_cannot_run(self):
        for state, err in (("no-tpm", "invalid"), ("sealed", "invalid"),
                           ("pcr-policy", "seal-refused")):
            self.st.tpm_state = state
            if not self.h.reg.get(UID).unlocked():
                await self.ui.call("unlock")
            n = len(self.dialogs())
            r = await self.ui.call("tpm-move")
            self.assertEqual(r["error"], err, state)
            self.assertEqual(len(self.dialogs()), n, state)
        self.assertNotIn("reseal", self.st.calls)

    async def test_needs_the_list_open(self):
        self.st.tpm_state = "available"
        r = await self.ui.call("tpm-move")
        self.assertEqual(r["error"], "locked")
        self.assertEqual(self.dialogs(), [])


class ResetTests(Base):
    async def test_reset_says_pcr_policy_before_the_dialog(self):
        self.st.seal_error = "damaged"
        await self.ui.call("unlock")
        n = len(self.dialogs())
        FakeStore.blocked_reason = "pcr-policy"
        r = await self.ui.call("reset")
        self.assertEqual((r["error"], r.get("reason")), ("seal-refused", "pcr-policy"))
        self.assertEqual(len(self.dialogs()), n)
        self.assertNotIn("reset", self.h.store().calls)

    async def test_reset_only_from_a_broken_store(self):
        self.assertEqual((await self.ui.call("reset"))["error"], "not-locked")
        self.st.seal_error = "damaged"
        await self.ui.call("unlock")
        r = await self.ui.call("reset")
        self.assertEqual(r, {"rid": self.ui.rid, "state": "empty"})
        self.assertIn("reset", self.h.store().calls)
        self.assertTrue(self.h.reg.get(UID).unlocked())
        self.assertEqual(self.dialogs(), [paths.ACTION_UNLOCK, paths.ACTION_MANAGE])


class AutofillDispatchTests(Base):
    async def test_registry_satisfies_the_handler_contract(self):
        seen = {}

        async def fake_query(reg, conn, req):
            seen["types"] = (isinstance(reg, protocol.SessionRegistry),
                             isinstance(conn, protocol.Connection),
                             isinstance(reg.get(conn.uid), protocol.Session))
            seen["role"] = conn.role
            return {"state": "locked"}
        await self.ui.call("autofill-enable", enabled=True)
        af, hello = await self.h.hello("autofill")
        self.assertEqual(hello["state"], "locked")
        from icp.daemon import autofill
        with mock.patch.object(autofill, "handle_autofill_query", fake_query):
            r = await af.call("autofill-query", origin="https://github.com")
        self.assertEqual(r, {"rid": af.rid, "state": "locked"})
        self.assertEqual(seen, {"types": (True, True, True), "role": "autofill"})
        await self.ui.call("unlock")
        self.assertEqual((await af.event("state"))["state"], "unlocked")
        for op in ("unlock", "grant", "redeem", "import-file"):
            self.assertEqual((await af.call(op))["error"], "forbidden")


class AutofillOptInTests(Base):
    """escape-autofill-role-ungated: the daemon, not the browser manifest, is the opt-in."""

    async def test_autofill_hello_is_refused_until_turned_on_in_the_window(self):
        af, hello = await self.h.hello("autofill")
        self.assertEqual(hello.get("error"), "forbidden")
        self.assertEqual(self.dialogs(), [])
        self.assertFalse(self.ui.hello["autofill"]["enabled"])

    async def test_turning_it_on_asks_once_and_off_never_asks_and_disconnects(self):
        r = await self.ui.call("autofill-enable", enabled=True)
        self.assertEqual(r["autofill"], {"enabled": True, "hosts": 0})
        self.assertEqual(self.dialogs(), [paths.ACTION_MANAGE])
        self.assertTrue(self.h.store().load_settings().get("autofill_enabled"))
        af, hello = await self.h.hello("autofill")
        self.assertNotIn("error", hello)
        self.assertEqual((await self.ui.event("autofill-hosts"))["count"], 1)
        await self.ui.call("autofill-enable", enabled=True)       # already on: no dialog
        self.assertEqual(self.dialogs(), [paths.ACTION_MANAGE])
        r = await self.ui.call("autofill-enable", enabled=False)
        self.assertEqual(r["autofill"]["enabled"], False)
        self.assertEqual(self.dialogs(), [paths.ACTION_MANAGE])  # off never asks
        self.assertNotIn("autofill_enabled", self.h.store().load_settings())
        af2, hello = await self.h.hello("autofill")
        self.assertEqual(hello.get("error"), "forbidden")

    async def test_a_denied_dialog_leaves_it_off(self):
        self.h.authority.outcome = polkit.DENIED
        r = await self.ui.call("autofill-enable", enabled=True)
        self.assertEqual(r.get("error"), "denied")
        af, hello = await self.h.hello("autofill")
        self.assertEqual(hello.get("error"), "forbidden")

    async def test_only_the_window_may_turn_it_on(self):
        await self.ui.call("autofill-enable", enabled=True)
        af, _ = await self.h.hello("autofill")
        self.assertEqual((await af.call("autofill-enable", enabled=True))["error"],
                         "forbidden")


if __name__ == "__main__":
    unittest.main()
