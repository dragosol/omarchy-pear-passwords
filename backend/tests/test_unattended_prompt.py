"""The background timer must never be able to put a password box on someone's desktop.

This is a regression suite for a real defect: before 1.3.1 the 2-hourly sync unit ran with
DISPLAY and WAYLAND_DISPLAY in its environment, so the passphrase prompt found zenity and
opened a modal dialog every two hours. The user had never seen it because their installed
backend predated the change that stopped keeping the derived key on disk.

Each test here fails if that path reopens.
"""

import os
import unittest
from unittest import mock

from icp.auth import prompt


class PromptGateTest(unittest.TestCase):
    def tearDown(self):
        prompt.set_allowed(True)

    def test_disallowed_prompt_raises_instead_of_spawning_anything(self):
        prompt.set_allowed(False)
        with mock.patch.object(prompt.subprocess, "run") as run, \
             mock.patch.object(prompt.shutil, "which", return_value="/usr/bin/zenity"), \
             mock.patch.dict(os.environ, {"WAYLAND_DISPLAY": "wayland-1"}, clear=False):
            with self.assertRaises(prompt.PromptError):
                prompt.ask_passphrase()
        run.assert_not_called()  # no zenity, no systemd-ask-password, nothing

    def test_allowed_by_default_so_a_person_at_the_keyboard_is_still_asked(self):
        self.assertTrue(prompt.is_allowed())
        with mock.patch.object(prompt.shutil, "which", return_value="/usr/bin/zenity"), \
             mock.patch.dict(os.environ, {"WAYLAND_DISPLAY": "wayland-1"}, clear=False), \
             mock.patch.object(prompt.subprocess, "run",
                               return_value=mock.Mock(returncode=0, stdout="hunter2\n")) as run:
            self.assertEqual("hunter2", prompt.ask_passphrase())
        run.assert_called_once()


class UnattendedKeyPathTest(unittest.TestCase):
    """_master_key must use PEEK, not GET, when prompting is off: GET can raise a polkit
    dialog, which is the same defect wearing a different hat."""

    def tearDown(self):
        prompt.set_allowed(True)

    def test_locked_and_unattended_asks_nothing_and_reports_locked(self):
        from icp.auth import session
        prompt.set_allowed(False)
        with mock.patch("icp.auth.lockbox.is_initialised", return_value=True), \
             mock.patch("icp.auth.held_key.purge"), \
             mock.patch("icp.auth.agent.peek_key", return_value=None) as peek, \
             mock.patch("icp.auth.agent.get_key") as get, \
             mock.patch("icp.auth.agent.unlock") as unlock, \
             mock.patch.object(prompt, "ask_passphrase") as ask:
            with self.assertRaises(session.SessionError):
                session._master_key()
        peek.assert_called_once()
        get.assert_not_called()
        unlock.assert_not_called()
        ask.assert_not_called()

    def test_unattended_inside_the_grace_window_still_works(self):
        from icp.auth import session
        prompt.set_allowed(False)
        with mock.patch("icp.auth.lockbox.is_initialised", return_value=True), \
             mock.patch("icp.auth.held_key.purge"), \
             mock.patch("icp.auth.agent.peek_key", return_value=b"k" * 32), \
             mock.patch.object(prompt, "ask_passphrase") as ask:
            self.assertEqual(b"k" * 32, session._master_key())
        ask.assert_not_called()


class SyncUnitTest(unittest.TestCase):
    ROOT = os.path.join(os.path.dirname(__file__), "..", "..")

    def _read(self, *parts):
        with open(os.path.join(self.ROOT, *parts)) as fh:
            return fh.read()

    def test_the_timer_unit_passes_no_prompt(self):
        # 2.0 (WP5): the user sync timer is deleted, so nothing unattended can prompt at all.
        # Sync runs inside the daemon, only while unlocked.
        for name in ("pear-passwords-sync.service", "pear-passwords-sync.timer"):
            self.assertFalse(os.path.exists(os.path.join(self.ROOT, "systemd", name)), name)
        self.assertNotIn("pear-passwords-sync.timer\"", self._read("install.sh"))

    def test_sync_accepts_the_flag(self):
        from icp.cli import app
        parser = app.build_parser() if hasattr(app, "build_parser") else None
        if parser is None:
            self.skipTest("no module-level parser factory to introspect")
        ns = parser.parse_args(["sync", "--no-prompt"])
        self.assertTrue(ns.no_prompt)


class UnlockTriggersSyncTest(unittest.TestCase):
    def test_a_successful_unlock_syncs(self):
        """Because the timer now skips while locked, the unlock has to be what syncs."""
        from icp.cli import appapi
        src = __import__("inspect").getsource(appapi.cmd_app_auth)
        self.assertIn("_sync_in_background()", src,
                      "nothing syncs on unlock, so a locked timer means no syncing at all")


class NoSelfAssertedAuthTest(unittest.TestCase):
    """1.3.1 shipped an AUTHORIZED command that opened the grace window with no check, so any
    process running as this user could take the key by asking for it. It must not come back."""

    def test_the_agent_has_no_command_that_asserts_prior_authentication(self):
        import inspect
        from icp.auth import agent
        src = inspect.getsource(agent)
        self.assertNotIn("AUTHORIZED", src,
                         "a caller can once again claim it already authenticated")
        self.assertFalse(hasattr(agent, "mark_authorized"),
                         "the client helper for that bypass is back")

    def test_the_idle_wipe_is_unconditional(self):
        """The gate is a convenience; residency time is the only control that bites, because
        same-uid code can read this process's memory through /proc regardless of any socket."""
        import inspect
        from icp.auth import agent
        src = inspect.getsource(agent._serve)
        self.assertNotIn("not gated and time.monotonic() >= expires", src,
                         "the idle wipe is skipped while gated, so the key is session-resident")
        self.assertIn("if key is not None and time.monotonic() >= expires:", src,
                      "the unconditional idle wipe is gone")


if __name__ == "__main__":
    unittest.main()


class KeyGateTest(unittest.TestCase):
    """Which protection the agent applies to the key it holds."""

    def test_env_forces_the_gate_either_way(self):
        from icp.auth import agent
        with mock.patch.dict(os.environ, {"ICP_KEY_GATE": "timeout"}):
            self.assertFalse(agent._gate_usable())
        with mock.patch.dict(os.environ, {"ICP_KEY_GATE": "polkit"}):
            self.assertTrue(agent._gate_usable())

    def test_auto_follows_whether_the_polkit_action_is_installed(self):
        from icp.auth import agent
        with mock.patch.dict(os.environ, {"ICP_KEY_GATE": "auto"}), \
             mock.patch("icp.ui.reauth.available", return_value=True):
            self.assertTrue(agent._gate_usable())
        with mock.patch.dict(os.environ, {"ICP_KEY_GATE": "auto"}), \
             mock.patch("icp.ui.reauth.available", return_value=False):
            self.assertFalse(agent._gate_usable())

    def test_authorize_is_bounded_and_does_not_fall_through_to_pkexec(self):
        """pkexec waits up to 90s more; the agent cannot hold its socket that long."""
        from icp.auth import agent
        with mock.patch("icp.ui.reauth.challenge_status", return_value="denied") as ch, \
             mock.patch("icp.ui.reauth.pkexec_challenge") as pk:
            self.assertEqual("denied", agent._authorize())
        pk.assert_not_called()
        self.assertEqual(agent.GATE_TIMEOUT, ch.call_args.kwargs["timeout"])
        self.assertLessEqual(agent.GATE_TIMEOUT, 30)

    def test_a_broken_gate_reports_error_rather_than_raising(self):
        from icp.auth import agent
        with mock.patch("icp.ui.reauth.challenge_status", side_effect=OSError("no bus")):
            self.assertEqual("error", agent._authorize())

    def test_a_broken_gate_degrades_to_the_timeout_rule_instead_of_locking_you_out(self):
        """A damaged polkit policy must cost residency time, never access to the vault."""
        import inspect
        from icp.auth import agent
        src = inspect.getsource(agent._serve)
        self.assertIn('verdict == "error" and now < expires', src,
                      "a broken gate now denies the key outright")
