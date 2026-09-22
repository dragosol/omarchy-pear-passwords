"""New records and details edits must read back through the same path a sync uses."""
import os
import plistlib

from icp.keychain import metadata as md, update as up
from icp.transport.ckks import CloudKitRecord

CK = os.urandom(64)
PARENT = "PARENT-KEY-ID"
NAME = "0F3C2A1B-1111-4222-8333-944455556666"


def _roundtrip(plist):
    fields = up.new_item_fields(CK, PARENT, plist, record_name=NAME, uploadver="macOS 25.6.0 (25G72)")
    assert set(fields) == {"parentkeyref", "encver", "gen", "uploadver", "data", "wrappedkey"}
    return up.decrypt_item_record(CloudKitRecord(NAME, "item", fields), CK)


def test_new_password_record_matches_apples_shape():
    back = _roundtrip(up.new_password_plist("example.com", "alex", "s3cret-pw", now=1_700_000_000))
    assert back["agrp"] == "com.apple.cfnetwork" and back["v_Data"] == b"s3cret-pw"
    assert (back["class"], back["atyp"], back["ptcl"], back["pdmn"]) == ("inet", "form", "htps", "ak")
    assert back["labl"] == "example.com (alex)" and back["desc"] == "Web form password"


def test_new_metadata_record_carries_details():
    cfg = {"secret": b"12345678901234567890", "digits": 6, "period": 30, "algorithm": 0,
           "issuer": "Example"}
    back = _roundtrip(up.new_metadata_plist("example.com", "alex", title="My Example",
                                            notes="line one\nline two",
                                            sites=["https://login.example.com/x", "example.com"],
                                            totp=cfg))
    assert back["labl"] == "Password Manager Metadata: example.com (alex)"
    assert back["type"] == up.METADATA_TYPE
    meta = md.parse(back["v_Data"])
    assert md.title(meta) == "My Example"
    assert md.notes(meta) == "line one\nline two"
    assert md.sites(meta) == ["login.example.com"]           # primary site not repeated
    assert md.totp_config(meta)["secret"] == b"12345678901234567890"


def test_edit_details_changes_only_what_was_asked():
    base = up.new_metadata_plist("example.com", "alex", title="Keep me", notes="old")
    inner_before = plistlib.loads(base["v_Data"])
    inner_before["s_hi"] = [{"p": "hist"}]
    base["v_Data"] = plistlib.dumps(inner_before, fmt=plistlib.FMT_BINARY)

    out = up.edit_details(base, sites=["a.example.com", "A.example.com", "b.example.com/login"])
    meta = md.parse(out["v_Data"])
    assert md.sites(meta) == ["a.example.com", "b.example.com"]
    assert md.notes(meta) == "old" and md.title(meta) == "Keep me"
    assert meta["s_hi"] == [{"p": "hist"}]
    assert set(up.diff_plists(base, out)) == {"mdat", "v_Data"}

    cleared = md.parse(up.edit_details(out, notes="", totp=None)["v_Data"])
    assert "notes" not in cleared and "totp" not in cleared and md.title(cleared) == "Keep me"


def test_notes_stored_as_bytes_are_read():
    assert md.notes({"notes": "café".encode()}) == "café"


def test_new_wifi_record_matches_apples_shape():
    back = _roundtrip(up.new_wifi_plist("Example Home", "hunter2-wifi"))
    assert (back["class"], back["agrp"], back["svce"], back["pdmn"]) == ("genp", "apple", "AirPort", "ck")
    assert back["acct"] == back["labl"] == "Example Home" and back["v_Data"] == b"hunter2-wifi"
