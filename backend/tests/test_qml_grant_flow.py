"""The window's account-grant flow (app/shell.qml), checked on its source.

The window cannot be run here without a compositor, so these read the QML with comments
removed and pin the rules the reviews found broken:

- an unlock never starts a sign-in on its own (a second dialog nobody asked for);
- a reply for an account that is no longer selected, or whose grant ended, is dropped;
- a one-use grant keeps what its one request returned (the grant-expired event that request
  causes must not wipe it);
- a grant running out keeps the unsaved edit, out of sight, for the next approval;
- the fields that hold secrets in plain text ask the input method for nothing.
"""

import re
import unittest

import qmlscan

SHELL = qmlscan.read(qmlscan.os.path.join(qmlscan.APP, "shell.qml"))
CODE = qmlscan.strip_comments(SHELL)


def function_body(name: str) -> str:
    m = re.search(rf"\bfunction {re.escape(name)}\s*\([^)]*\)\s*\{{", CODE)
    if not m:
        raise AssertionError(f"shell.qml has no function {name}")
    return qmlscan.element_body(CODE, m.end() - 1)


def case_body(label: str) -> str:
    start = CODE.index(f'case "{label}":')
    end = CODE.index("return;", start)
    nxt = CODE.find("case ", start + 5)
    # the case runs to its last `return;` before the next case label
    while nxt != -1 and CODE.find("return;", end + 1) != -1 and CODE.find("return;", end + 1) < nxt:
        end = CODE.find("return;", end + 1)
    return CODE[start:end]


class NoUnsolicitedSigninTests(unittest.TestCase):
    def test_the_unlock_reply_never_starts_a_signin(self):
        # clipboard_ui-3: "signin" raises .manage; after the unlock dialog it was a second
        # dialog without a click.
        body = function_body("authenticate")
        self.assertNotIn("startSignin", body)
        self.assertNotRegex(body, r'send\(\s*"(signin|grant|create|delete|signout|reset)"')
        self.assertNotIn("firstRunShown", CODE)

    def test_hello_never_starts_a_signin(self):
        self.assertNotIn("startSignin", function_body("onHello"))


class StaleReplyTests(unittest.TestCase):
    def test_secret_replies_are_dropped_unless_their_grant_is_still_open(self):
        # clipboard_ui-4
        stillopen = function_body("stillOpen")
        self.assertIn("root.selectedId", stillopen)
        self.assertIn("root.grantId", stillopen)
        for fn, op in (("doReveal", "reveal"), ("loadNotes", "reveal"),
                       ("loadHistory", "history"), ("loadTotp", "totp")):
            body = function_body(fn)
            m = re.search(rf'send\(\s*"{op}"\s*,\s*\{{\s*id:\s*id\b.*?function\s*\(d\)\s*\{{\s*'
                          r'if \(!root\.stillOpen\(id\)\) return;', body, re.S)
            self.assertIsNotNone(m, f"{fn}: the reply is not checked against its grant first")
            self.assertRegex(body, r"const id = root\.selectedId;", fn)


class SingleUseGrantTests(unittest.TestCase):
    def test_grant_expired_of_a_single_use_grant_keeps_what_it_returned(self):
        # clipboard_ui-5: the request that spends a one-use grant is answered first, then its
        # grant-expired event arrives; that event must not wipe the answer.
        body = case_body("grant-expired")
        single = body[body.index("if (root.grantSingleUse)"):]
        single = single[:single.index("return;")]
        self.assertNotIn("endGrant", single)
        self.assertNotIn("forgetSecrets", single)
        self.assertIn('root.grantId = ""', single)


class GrantRunsOutTests(unittest.TestCase):
    def test_running_out_keeps_the_edit_for_the_next_approval(self):
        # clipboard_ui-6
        ranout = function_body("grantRanOut")
        for what in ("edArea.text", "edSetup.text", "newPw.text", "root.editDraft = d",
                     "root.endGrant()"):
            self.assertIn(what, ranout)
        self.assertLess(ranout.index("edArea.text"), ranout.index("root.endGrant()"),
                        "the edit must be kept before the grant's cleanup closes the editor")
        self.assertIn("root.grantRanOut()", case_body("grant-expired"))
        timer = CODE[CODE.index("root.grantLeft = Math.max(0, Math.ceil(root.grantExpires - now));"):]
        self.assertIn("root.grantRanOut()", timer[:400])
        opener = function_body("openEditor")
        self.assertIn("root.editDraft", opener)
        self.assertRegex(opener, r"edArea\.text = draft\.text")

    def test_the_draft_never_crosses_accounts_or_a_lock(self):
        for fn in ("select", "clearSelection", "lockApp"):
            self.assertIn("root.editDraft = null", function_body(fn), fn)
        self.assertIn("draft.id === root.selectedId", function_body("openEditor"))


class SecretFieldTests(unittest.TestCase):
    def test_plain_text_secret_fields_ask_the_input_method_for_nothing(self):
        # clipboard_ui-2 (defence in depth; pear-exec also disables the protocols)
        for ident in ("edArea", "edSetup", "crNotes", "crSetup", "newPw"):
            m = re.search(rf"\bid: {ident}\n", CODE)
            self.assertIsNotNone(m, ident)
            body = CODE[m.end():m.end() + 600]
            self.assertRegex(body, r"inputMethodHints: Qt\.ImhSensitiveData \| "
                                   r"Qt\.ImhNoPredictiveText", ident)


if __name__ == "__main__":
    unittest.main()
