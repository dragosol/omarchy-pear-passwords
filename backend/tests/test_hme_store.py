"""Offline test for the encrypted Hide My Email alias cache (round-trip via a temp config
dir). Mirrors test_vault.py exactly - same encryption, same "empty until saved" contract.

Run: .venv/bin/python -m unittest tests.test_hme_store
"""

import importlib
import os
import tempfile
import unittest

from icp.hme.client import HmeAlias


class AliasesRoundTripTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name
        self._old_dbus = os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
        os.environ["ICP_ALLOW_KEYFILE"] = "1"  # fallback is opt-in; this test wants it

    def tearDown(self):
        if self._old_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._old_xdg
        if self._old_dbus is not None:
            os.environ["DBUS_SESSION_BUS_ADDRESS"] = self._old_dbus
        self._tmp.cleanup()

    def test_save_then_load(self):
        from icp.hme import store as aliases_store
        importlib.reload(aliases_store)

        self.assertEqual(aliases_store.load_aliases(), [])  # empty before save

        alias = HmeAlias(anonymous_id="a1", address="quiet-otter@icloud.com", label="Claude",
                         note="signup", forward_to="me@example.com", is_active=True,
                         domain="claude.ai", created_at=1700000000.0)
        aliases_store.save_aliases([alias])

        loaded = aliases_store.load_aliases()
        self.assertEqual(loaded, [alias])

    def test_missing_file_returns_empty_list(self):
        from icp.hme import store as aliases_store
        importlib.reload(aliases_store)
        self.assertEqual(aliases_store.load_aliases(), [])


if __name__ == "__main__":
    unittest.main()
