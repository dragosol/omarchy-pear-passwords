"""docs/protocol.md and icp.daemon.protocol describe the same protocol.

The document is what the UI, the clients and a third-party extension author read; the module is
what the daemon and the clients import. Each check parses the document independently of the
module, so an op, event or error code added to one side only fails here.
"""

import os
import re
import unittest

from icp.daemon import paths, protocol

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOC = os.path.join(ROOT, "docs", "protocol.md")


def _section(text: str, heading: str) -> str:
    m = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not m:
        raise AssertionError(f"protocol.md has no section {heading!r}")
    return m.group(1)


def _table_rows(section: str) -> list[list[str]]:
    rows = []
    for line in section.splitlines():
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue
        rows.append([c.strip() for c in line.strip().strip("|").split("|")])
    return rows[1:]   # drop the header row


class ProtocolDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(DOC, encoding="utf-8") as f:
            cls.doc = f.read()

    def test_error_codes_match(self):
        rows = _table_rows(_section(self.doc, "12. Error codes"))
        documented = {r[0].strip("`") for r in rows}
        self.assertEqual(documented, set(protocol.ERRORS))
        # And a second, looser matcher over the whole document: every "error":"x" shown in
        # an example is a known code.
        shown = set(re.findall(r'"error":"([a-z-]+)"', self.doc))
        self.assertTrue(shown, "no error examples found")
        self.assertLessEqual(shown, set(protocol.ERRORS))

    def test_op_table_matches_roles(self):
        rows = _table_rows(_section(self.doc, "13. Op table"))
        doc_roles = {}
        doc_dialogs = {}
        for op, role, dialog, *_ in rows:
            op = op.strip("`")
            doc_roles[op] = role
            doc_dialogs[op] = dialog.strip("`")
        self.assertEqual(set(doc_roles), set(protocol.ALL_OPS))
        for role, ops in protocol.ROLE_OPS.items():
            for op in ops:
                self.assertEqual(doc_roles[op], role, op)
        self.assertEqual(doc_roles["hello"], "all")
        for op, dialog in doc_dialogs.items():
            if op in protocol.PROMPT_ACTION:
                self.assertEqual(paths.POLKIT_ACTION_PREFIX + dialog,
                                 protocol.PROMPT_ACTION[op], op)
            else:
                self.assertEqual(dialog, "–", f"{op} must not raise a dialog")

    def test_every_op_has_an_example_request(self):
        shown = set(re.findall(r'\{"op":"([a-z-]+)"', self.doc))
        self.assertEqual(shown, set(protocol.ALL_OPS))

    def test_events_match(self):
        shown = set(re.findall(r'\{"event":"([a-z-]+)"', self.doc))
        declared = set().union(*protocol.EVENTS.values())
        self.assertEqual(shown, declared)

    def test_no_lease_anywhere(self):
        # Owner decision: sync only while unlocked. No setting, no field, no code path.
        self.assertNotIn("sync_lease_h", protocol.DEFAULT_SETTINGS)
        settings = _section(self.doc, "3. Shared shapes")
        self.assertNotIn('"sync_lease_h"', settings.split("There is no")[0])
        self.assertFalse(any("lease" in k for k in protocol.SETTINGS_KEYS))


class ProtocolValueTests(unittest.TestCase):
    def test_owner_decided_defaults(self):
        self.assertEqual(protocol.GRANT_S_DEFAULT, 120)
        self.assertEqual(protocol.CLIP_TIMEOUT_S_DEFAULT, 30)
        self.assertEqual(protocol.IDLE_LOCK_S_DEFAULT, 0)
        self.assertEqual(protocol.TICKET_TTL_S, 10)
        self.assertEqual(protocol.DEFAULT_SETTINGS,
                         {"grant_s": 120, "idle_lock_s": 0, "clip_timeout_s": 30})
        lo, hi = protocol.CLIP_TIMEOUT_S_RANGE
        self.assertTrue(lo <= protocol.CLIP_TIMEOUT_S_DEFAULT <= hi)
        lo, hi = protocol.GRANT_S_RANGE
        self.assertTrue(lo <= protocol.GRANT_S_DEFAULT <= hi)
        self.assertIn(protocol.IDLE_LOCK_S_DEFAULT, protocol.IDLE_LOCK_S_CHOICES)

    def test_roles_and_prompts(self):
        self.assertEqual(set(protocol.ROLE_OPS), set(paths.ROLES))
        self.assertEqual(set(protocol.PROMPT_ACTION.values()), set(paths.ACTIONS))
        # The autofill role can raise only its own dialog, and the UI never raises it.
        for op, action in protocol.PROMPT_ACTION.items():
            is_autofill = op in protocol.ROLE_OPS["autofill"]
            self.assertEqual(action == paths.ACTION_AUTOFILL, is_autofill, op)
        # clip and migrate never raise a dialog: their authority is the ticket.
        for role in protocol.TICKET_ROLES:
            self.assertFalse(protocol.ROLE_OPS[role] & set(protocol.PROMPT_ACTION), role)
        self.assertLessEqual(set(protocol.PROMPT_BUCKET), set(paths.ROLES))

    def test_ops_are_unique_to_a_role(self):
        seen = {}
        for role, ops in protocol.ROLE_OPS.items():
            for op in ops:
                self.assertNotIn(op, seen, f"{op} in {role} and {seen.get(op)}")
                seen[op] = role
        self.assertNotIn("hello", seen)

    def test_field_sets(self):
        self.assertLessEqual(protocol.COPY_FIELDS_NEED_GRANT, protocol.COPY_FIELDS)
        self.assertEqual(protocol.COPY_FIELDS - protocol.COPY_FIELDS_NEED_GRANT,
                         {"username", "domain"})
        self.assertLessEqual(protocol.GRANT_OPS, protocol.ROLE_OPS["ui"])

    def test_limits(self):
        # One raw import chunk, base64-encoded inside its JSON line, stays under the cap.
        b64 = 4 * -(-protocol.IMPORT_CHUNK_MAX // 3)
        self.assertLess(b64 + 200, protocol.MAX_REQUEST_LINE)
        self.assertLess(protocol.MAX_REQUEST_LINE, protocol.MAX_REPLY_LINE)
        self.assertLessEqual(set(protocol.IMPORT_REQUIRED), set(protocol.IMPORT_FILES))

    def test_op_error(self):
        e = protocol.OpError("rate-limited", retry_after=12)
        self.assertEqual(e.reply(7), {"rid": 7, "error": "rate-limited", "retry_after": 12})
        with self.assertRaises(ValueError):
            protocol.OpError("no-such-code")


if __name__ == "__main__":
    unittest.main()
