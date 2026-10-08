"""A lock never waits on the event loop (audit: event-loop stall in lock()).

Registry.lock() runs on the event loop, which serves every uid. A store call can sit in
systemd-creds for up to a minute on a slow TPM. The lock must return at once: wipe now when
nothing holds the store, otherwise flag wipe-after, refuse new store calls for that uid, and
wipe the moment the running call returns. PrepareForSleep holds the suspend back for about a
second at the most.
"""

import asyncio
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from fixtures import FakeSealBackend, vstore_env

from icp import vstore
from icp.daemon import logind
from icp.daemon.protocol import OpError
from icp.daemon.sessions import Registry, Session
from icp.vstore import entries as E
from icp.vstore import ids

UID = 1000


def item(domain, username, pw):
    id = ids.entry_id(domain, username)
    meta = vstore.Meta(id=id, title=domain, domain=domain, sites=[], username=username,
                       nickname="", has_totp=False, has_notes=False, mdat=1.0,
                       history_count=0)
    return vstore.SyncItem(id=id, meta=meta, secrets=vstore.Secrets(
        password=pw, notes="", totp_secret=None, apple_history=[], totp_params={}))


class RegistryLockTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = vstore_env(Path(self._tmp.name), FakeSealBackend(tpm=False))
        self._env.__enter__()
        self.store = vstore.UserStore.create(UID)
        self.store.apply_sync([item("a.example.test", "me", "pw-a")], set())
        self.reg = Registry(store_cls=vstore.UserStore)
        self.s = Session(UID, self.store)
        self.s.settings_loaded = True
        self.reg.sessions[UID] = self.s

    def tearDown(self):
        self.reg.shutdown()
        self._env.__exit__(None, None, None)
        self._tmp.cleanup()

    async def test_lock_returns_at_once_while_a_store_call_runs(self):
        started, proceed = threading.Event(), threading.Event()
        real = E.EntryFiles.write

        def slow_write(files, id, blob):          # a systemd-creds call that hangs
            real(files, id, blob)
            started.set()
            proceed.wait(10)
        with mock.patch.object(E.EntryFiles, "write", slow_write):
            call = asyncio.ensure_future(self.reg.run_store(
                UID, self.store.apply_sync, [item("a.example.test", "me", "pw-a2")], set()))
            self.assertTrue(await asyncio.to_thread(started.wait, 5))
            t0 = time.monotonic()
            self.reg.lock(UID, "sleep")
            self.assertLess(time.monotonic() - t0, 0.5, "lock() waited for the store call")
            self.assertTrue(self.s.wipe_after)
            self.assertTrue(self.reg.wipes_pending())
            # Any new store call for this uid is refused at once, not queued.
            with self.assertRaises(OpError) as cm:
                await asyncio.wait_for(self.reg.run_store(UID, self.store.list_meta), 0.5)
            self.assertEqual(cm.exception.code, "locked")
            proceed.set()
            await asyncio.wait_for(call, 5)
        self.assertEqual(self.store.state(), "locked")      # wiped as the call returned
        self.assertFalse(self.s.wipe_after)
        self.assertFalse(self.reg.wipes_pending())
        # Nothing was half-applied.
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertEqual(s2.open_entry(ids.entry_id("a.example.test", "me")).password, "pw-a2")

    async def test_lock_with_nothing_running_wipes_now(self):
        self.reg.lock(UID, "user")
        self.assertEqual(self.store.state(), "locked")
        self.assertFalse(self.s.wipe_after)


class SleepWaitTests(unittest.TestCase):
    def test_prepare_for_sleep_never_holds_the_suspend_past_about_a_second(self):
        log = []

        class Inh:
            def close(self):
                log.append("released")
        w = logind.LogindWatcher(on_lock=lambda *a: None, on_sleep=lambda: log.append("wipe"),
                                 call_in_loop=lambda fn, **kw: fn(),
                                 take_inhibitor=lambda: Inh(),
                                 pending=lambda: True)     # a store call that never returns
        w.take_inhibitor()
        t0 = time.monotonic()
        w.before_sleep()
        self.assertLess(time.monotonic() - t0, 1.5)
        self.assertEqual(log, ["wipe", "released"])
        self.assertLessEqual(logind.SLEEP_WAIT_S, 1.0)

    def test_sleep_waits_for_a_pending_wipe_that_finishes(self):
        state = {"n": 0}

        def pending():
            state["n"] += 1
            return state["n"] < 3
        w = logind.LogindWatcher(on_lock=lambda *a: None, on_sleep=lambda: None,
                                 call_in_loop=lambda fn, **kw: fn(), take_inhibitor=lambda: None,
                                 pending=pending)
        w.before_sleep()
        self.assertGreaterEqual(state["n"], 3)


if __name__ == "__main__":
    unittest.main()
