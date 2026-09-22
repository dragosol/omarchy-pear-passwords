"""The app's launch lock: nothing identifying leaves the backend before authentication."""

import io
import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

from icp.cli import appapi


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "app-session.json")
        p = mock.patch.object(appapi, "_app_session_path", return_value=self.path)
        p.start(); self.addCleanup(p.stop)

    def write(self, pid, expires):
        with open(self.path, "w") as fh:
            json.dump({"pid": pid, "expires": expires}, fh)

    def test_no_session_file_is_locked(self):
        self.assertFalse(appapi._app_session_ok())

    def test_session_for_this_app_instance_is_open(self):
        self.write(os.getppid(), time.time() + 60)
        self.assertTrue(appapi._app_session_ok())

    def test_relaunch_asks_again(self):
        # A new app instance has a new PID, so an old session must not carry over.
        self.write(os.getppid() + 1, time.time() + 60)
        self.assertFalse(appapi._app_session_ok())

    def test_expired_session_is_locked(self):
        self.write(os.getppid(), time.time() - 1)
        self.assertFalse(appapi._app_session_ok())

    def test_corrupt_session_is_locked(self):
        with open(self.path, "w") as fh:
            fh.write("{not json")
        self.assertFalse(appapi._app_session_ok())


class LockedCommandTests(unittest.TestCase):
    """With no session, the backend must withhold - not hand data over to be blurred."""

    def setUp(self):
        p = mock.patch.object(appapi, "_app_session_ok", return_value=False)
        p.start(); self.addCleanup(p.stop)

    def run_cmd(self, fn, **kw):
        out = io.StringIO()
        with redirect_stdout(out):
            code = fn(mock.Mock(**kw))
        return code, json.loads(out.getvalue())

    def test_list_withholds_every_entry(self):
        code, d = self.run_cmd(appapi.cmd_app_list, all=False)
        self.assertTrue(d["locked"])
        self.assertEqual(d["entries"], [])
        self.assertNotIn("count", d)          # not even how many there are

    def test_every_data_command_refuses(self):
        for fn in (appapi.cmd_app_unlock, appapi.cmd_app_reveal, appapi.cmd_app_copy,
                   appapi.cmd_app_totp, appapi.cmd_app_history):
            with self.subTest(fn=fn.__name__):
                code, d = self.run_cmd(fn, id="x", field="username", seconds=0)
                self.assertEqual(code, 1)
                self.assertTrue(d.get("locked"))


if __name__ == "__main__":
    unittest.main()
