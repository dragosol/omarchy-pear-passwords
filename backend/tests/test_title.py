"""Renaming an entry through Apple's metadata record."""

import plistlib
import unittest

from icp.keychain import metadata as meta, update as up


def blob(**inner):
    return {"v_Data": plistlib.dumps(inner, fmt=plistlib.FMT_BINARY), "acct": "me"}


class TitleReadTests(unittest.TestCase):
    def test_reads_the_bytes_form_apple_actually_writes(self):
        # The regression that hid every user-given name: the value is bytes, not str.
        self.assertEqual(meta.title({"title": b"Zebra Test Co"}), "Zebra Test Co")

    def test_reads_a_str_too(self):
        self.assertEqual(meta.title({"title": "Zebra Test Co"}), "Zebra Test Co")

    def test_missing_or_undecodable_is_empty(self):
        self.assertEqual(meta.title({}), "")
        self.assertEqual(meta.title({"title": b"\xff\xfe\x00bad"}), "")
        self.assertEqual(meta.title(None), "")


class TitleWriteTests(unittest.TestCase):
    def test_writes_the_name_as_bytes(self):
        out = up.set_title(blob(title=b"Old"), "New Name")
        inner = plistlib.loads(out["v_Data"])
        self.assertIsInstance(inner["title"], bytes)   # a str reads as nothing on Apple devices
        self.assertEqual(inner["title"], b"New Name")

    def test_empty_name_clears_it(self):
        out = up.set_title(blob(title=b"Old"), "   ")
        self.assertNotIn("title", plistlib.loads(out["v_Data"]))

    def test_password_history_survives_a_rename(self):
        # s_hi shares the blob; a rename must not quietly drop it.
        hist = [{"p": "secret", "id": "x"}]
        out = up.set_title(blob(title=b"Old", s_hi=hist, s_as=[]), "New")
        inner = plistlib.loads(out["v_Data"])
        self.assertEqual(inner["s_hi"], hist)
        self.assertEqual(inner["s_as"], [])

    def test_only_name_and_mdat_change(self):
        before = blob(title=b"Old")
        after = up.set_title(before, "New")
        self.assertEqual(set(up.diff_plists(before, after)), {"v_Data", "mdat"})

    def test_collapses_whitespace(self):
        out = up.set_title(blob(), "  Work   VPN ")
        self.assertEqual(plistlib.loads(out["v_Data"])["title"], b"Work VPN")

    def test_refuses_a_record_with_no_blob(self):
        with self.assertRaises(up.ItemUpdateError):
            up.set_title({"acct": "me"}, "New")


if __name__ == "__main__":
    unittest.main()
