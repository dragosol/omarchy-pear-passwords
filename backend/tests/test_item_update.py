"""Rewriting a single item record. No network: a fake record plus a known class key."""

import base64
import datetime
import os
import plistlib
import unittest

from icp.keychain import crypto as kc, update as up
from icp.transport import ckks


def make_record(plist, class_key, *, name="REC-UUID", parent="PARENT-UUID"):
    item_key = os.urandom(64)
    fields = {"encver": 2, "gen": 0, "parentkeyref": parent, "uploadver": "test 1.0",
              "server_wascurrent": 1,
              "wrappedkey": base64.b64encode(kc.siv_wrap(class_key, item_key)).decode()}
    rec = ckks.CloudKitRecord(record_name=name, type="item", fields=dict(fields))
    from icp.keychain.pipeline import authenticated_data_v2
    aad = authenticated_data_v2(name, rec.fields, encver=2, gen=0, parent_key_id=parent)
    rec.fields["data"] = kc.encrypt_item(item_key, plistlib.dumps(plist, fmt=plistlib.FMT_BINARY),
                                         aad, iv=os.urandom(16))
    return rec


class ItemUpdateTests(unittest.TestCase):
    def setUp(self):
        self.class_key = os.urandom(64)
        # mdat is present on every real record; set_password rewrites it rather than adding it.
        self.plist = {"acct": "someone", "v_Data": b"old-secret", "srvr": "example.com",
                      "port": 0, "tomb": 0, "musr": b"", "class": "inet",
                      "mdat": datetime.datetime(2020, 1, 1, 0, 0, 0)}
        self.rec = make_record(self.plist, self.class_key)

    def test_decrypts_what_was_written(self):
        self.assertEqual(up.decrypt_item_record(self.rec, self.class_key), self.plist)

    def test_set_password_changes_only_value_and_mdat(self):
        _, before, after = up.set_password(self.rec, self.class_key, "new-secret")
        self.assertEqual(up.diff_plists(before, after), {"v_Data": "changed", "mdat": "changed"})
        self.assertEqual(after["v_Data"], b"new-secret")

    def test_rewritten_record_decrypts_to_the_new_plist(self):
        fields, _, after = up.set_password(self.rec, self.class_key, "new-secret")
        rebuilt = ckks.CloudKitRecord(record_name=self.rec.record_name, type="item", fields=fields)
        self.assertEqual(up.decrypt_item_record(rebuilt, self.class_key), after)

    def test_a_write_mints_a_fresh_item_key(self):
        # Apple's client never reuses the item key; reusing it would leak that two ciphertexts
        # are versions of the same secret.
        fields, _, _ = up.set_password(self.rec, self.class_key, "new-secret")
        self.assertNotEqual(fields["wrappedkey"], self.rec.fields["wrappedkey"])

    def test_only_data_and_wrappedkey_go_out_changed(self):
        fields, _, _ = up.set_password(self.rec, self.class_key, "new-secret")
        changed = {k for k in set(fields) | set(self.rec.fields)
                   if fields.get(k) != self.rec.fields.get(k)}
        self.assertEqual(changed, {"data", "wrappedkey"})

    def test_unknown_plist_keys_are_carried_across(self):
        self.plist["someFutureKey"] = b"\x01\x02"
        rec = make_record(self.plist, self.class_key)
        _, _, after = up.set_password(rec, self.class_key, "x")
        self.assertEqual(after["someFutureKey"], b"\x01\x02")

    def test_refuses_a_record_with_no_password(self):
        rec = make_record({"acct": "x", "class": "inet"}, self.class_key)
        with self.assertRaises(up.ItemUpdateError):
            up.set_password(rec, self.class_key, "new")

    def test_pinned_key_and_iv_reproduce_bytes_exactly(self):
        # The property the live oracle relies on: deterministic given key, IV, AAD and padding.
        item_key = kc.siv_unwrap(self.class_key, base64.b64decode(self.rec.fields["wrappedkey"]))
        data = self.rec.fields["data"]
        again = up.encrypt_item_record(self.rec, self.class_key, self.plist, iv=data[:16],
                                       item_key=item_key, pad_to=len(data) - 32)
        self.assertEqual(again["data"], data)
        self.assertEqual(again["wrappedkey"], self.rec.fields["wrappedkey"])


if __name__ == "__main__":
    unittest.main()
