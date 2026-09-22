"""create_entry / push_details against a fake zone: which records get written, and the guards."""
import os
import pytest

from icp.cli import push
from icp.keychain import metadata as md, update as up
from icp.transport import ckks
from icp.transport.ckks import CloudKitRecord

CK = os.urandom(64)
PARENT = "CLASS-KEY"


def _rec(name, plist):
    return CloudKitRecord(name, "item", up.new_item_fields(CK, PARENT, plist, record_name=name,
                                                          uploadver="test"))


class FakeTransport:
    def __init__(self):
        self.saves = []

    def save_record(self, req):
        self.saves.append(req)


class FakeClient:
    user_id = "_user"

    def __init__(self):
        self.transport = FakeTransport()


@pytest.fixture
def zone(monkeypatch):
    records = {"item": [
        _rec("A-PW", up.new_password_plist("has-meta.example", "alex", "pw1")),
        _rec("A-META", up.new_metadata_plist("has-meta.example", "alex", notes="n")),
        _rec("B-PW", up.new_password_plist("bare.example", "sam", "pw2")),
    ]}
    client = FakeClient()
    saved = []
    monkeypatch.setattr(push, "_open_zone", lambda anisette=None: (client, records, {PARENT: CK}))
    monkeypatch.setattr(push, "_resync", lambda anisette: None)
    monkeypatch.setattr(push, "_check_synced", lambda *a: None)
    monkeypatch.setattr(push, "_save", lambda c, rec, fields, create=False, zone="Passwords":
                        saved.append((rec.record_name, create, up.decrypt_item_record(
                            CloudKitRecord(rec.record_name, "item", fields), CK))))
    return saved


def test_details_edit_touches_only_the_metadata_record(zone):
    push.push_details("has-meta.example", "alex", sites=["www.has-meta.example"])
    assert [(n, c) for n, c, _ in zone] == [("A-META", False)]
    meta = md.parse(zone[0][2]["v_Data"])
    assert md.sites(meta) == ["www.has-meta.example"] and md.notes(meta) == "n"


def test_details_on_entry_without_metadata_creates_one(zone):
    cfg = {"secret": b"12345678901234567890", "digits": 6, "period": 30, "algorithm": 0}
    push.push_details("bare.example", "sam", totp=cfg)
    (name, created, plist), = zone
    assert created and name not in ("B-PW",)
    assert plist["agrp"] == up.AGRP_METADATA and plist["srvr"] == "bare.example"
    assert md.totp_config(md.parse(plist["v_Data"]))["secret"] == cfg["secret"]


def test_create_writes_password_and_metadata(zone):
    assert push.create_entry("https://new.example/login", "kim", "pw3", title="New") == 2
    kinds = [(c, p["agrp"], p["srvr"]) for _, c, p in zone]
    assert kinds == [(True, up.AGRP_PASSWORD, "new.example"), (True, up.AGRP_METADATA, "new.example")]
    assert zone[0][2]["v_Data"] == b"pw3"


def test_create_refuses_an_existing_account(zone):
    with pytest.raises(push.PushError, match="already exists"):
        push.create_entry("bare.example", "sam", "other")
    assert zone == []


def test_create_needs_site_and_password(zone):
    with pytest.raises(push.PushError):
        push.create_entry("", "kim", "pw")
    with pytest.raises(push.PushError):
        push.create_entry("new.example", "kim", "")
    assert zone == []
