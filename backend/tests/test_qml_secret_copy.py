"""A secret leaves the window only through pear-clip (audit: Ctrl+C / context menu bypass).

The plain-text fields that hold a secret (notes, setup keys, new and typed passwords, the old
1.x passphrase, the Apple password and the verification code) supported Ctrl+C / Ctrl+X to
the regular clipboard and, on Qt 6.9 and later, a context menu with Copy and Cut. That put the
value on the clipboard with no one-paste or 30 s limit and into clipboard history.

Two checks:
- on the source: every secret field calls root.guardSecretKeys from Keys.onPressed and sets
  `ContextMenu.menu: null`, and guardSecretKeys swallows the Copy and Cut key sequences;
- at run time (qmltestrunner, offscreen): the exact guard text from shell.qml, applied to a
  TextArea, a TextField and a TextInput, really keeps the value off the clipboard, while an
  unguarded field still copies (so the test can tell).
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

import qmlscan

SHELL = qmlscan.read(os.path.join(qmlscan.APP, "shell.qml"))
CODE = qmlscan.strip_comments(SHELL)

SECRET_FIELDS = ("edArea", "edSetup", "crSetup", "crNotes", "newPw", "crPass", "oldPass",
                 "signinField", "codeField")
KEYS_LINE = "Keys.onPressed: (event) => root.guardSecretKeys(event)"
MENU_LINE = "ContextMenu.menu: null"
QMLTESTRUNNER = shutil.which("qmltestrunner") or (
    "/usr/lib/qt6/bin/qmltestrunner" if os.access("/usr/lib/qt6/bin/qmltestrunner", os.X_OK)
    else None)


def element_of(ident: str) -> str:
    m = re.search(rf"\bid: {ident}\n", CODE)
    if m is None:
        raise AssertionError(f"shell.qml has no element with id {ident}")
    start = CODE.rfind("{", 0, m.start())
    return qmlscan.element_body(CODE, start)


def guard_function() -> str:
    m = re.search(r"\bfunction guardSecretKeys\s*\(event\)\s*\{", CODE)
    if m is None:
        raise AssertionError("shell.qml has no function guardSecretKeys(event)")
    return "function guardSecretKeys(event) " + qmlscan.element_body(CODE, m.end() - 1)


class SourceTests(unittest.TestCase):
    def test_every_secret_field_has_the_guard(self):
        for ident in SECRET_FIELDS:
            body = element_of(ident)
            self.assertIn(KEYS_LINE, body, ident)
            self.assertIn(MENU_LINE, body, ident)

    def test_the_guard_swallows_copy_and_cut(self):
        fn = guard_function()
        self.assertIn("StandardKey.Copy", fn)
        self.assertIn("StandardKey.Cut", fn)
        self.assertIn("event.accepted = true", fn)

    def test_no_secret_field_copies_on_its_own(self):
        for ident in SECRET_FIELDS:
            self.assertNotRegex(element_of(ident), r"\.(copy|cut)\(\)", ident)


@unittest.skipUnless(QMLTESTRUNNER, "qmltestrunner (qt6-declarative) not installed")
class RuntimeTests(unittest.TestCase):
    """The guard text from shell.qml, run under Qt itself."""

    def qml(self, guarded: bool) -> str:
        guard = f"\n        {KEYS_LINE}\n        {MENU_LINE}" if guarded else ""
        return f"""import QtQuick
import QtQuick.Controls
import QtTest

Item {{
    id: root
    width: 400; height: 400
    {guard_function()}
    TextArea {{ id: area; y: 0; width: 300; height: 50; text: "secret-area"{guard} }}
    TextField {{ id: field; y: 60; width: 300; height: 40; text: "secret-field"{guard} }}
    TextInput {{ id: input; y: 110; width: 300; height: 30; text: "secret-input"{guard} }}
    TextField {{ id: sink; y: 160; width: 300; height: 40 }}
    TestCase {{
        name: "SecretCopy"; when: windowShown
        function leaked(src) {{
            sink.text = ""; sink.forceActiveFocus(); keySequence(StandardKey.Paste);
            sink.text = ""; sink.forceActiveFocus(); sink.text = "x"; sink.selectAll();
            keySequence(StandardKey.Cut);                       // clipboard = "x"
            src.forceActiveFocus(); src.selectAll();
            keySequence(StandardKey.Copy);
            keySequence(StandardKey.Cut);
            sink.text = ""; sink.forceActiveFocus(); keySequence(StandardKey.Paste);
            return sink.text.indexOf("secret") >= 0 || src.text === "";
        }}
        function test_fields() {{
            var out = [leaked(area), leaked(field), leaked(input)];
            console.log("LEAKED " + JSON.stringify(out));
            {"verify(!out[0] && !out[1] && !out[2], JSON.stringify(out));" if guarded
             else "verify(out[0] && out[1] && out[2], JSON.stringify(out));"}
            {"compare(area.ContextMenu.menu, null); compare(field.ContextMenu.menu, null);"
             if guarded else ""}
        }}
    }}
}}
"""

    def run_qml(self, guarded: bool) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "tst_secretcopy.qml")
            with open(path, "w") as f:
                f.write(self.qml(guarded))
            env = {"PATH": "/usr/bin", "QT_QPA_PLATFORM": "offscreen", "HOME": d,
                   "XDG_RUNTIME_DIR": d, "QT_QUICK_CONTROLS_STYLE": "Basic"}
            return subprocess.run([QMLTESTRUNNER, "-input", path], capture_output=True,
                                  text=True, timeout=120, env=env)

    def test_unguarded_fields_do_copy(self):
        # The control: without the guard Qt copies, so the guarded run below means something.
        r = self.run_qml(guarded=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_guarded_fields_never_reach_the_clipboard(self):
        r = self.run_qml(guarded=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
