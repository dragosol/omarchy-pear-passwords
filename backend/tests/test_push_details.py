"""create_entry / push_details / push_nickname / push_password / delete_entry against a fake
zone: which records get written, and the guards."""
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
        self.performed = []

    def save_record(self, req):
        self.saves.append(req)

    def _perform(self, url, op_type, field, body, *, bundle):
        self.performed.append((url, op_type, field, body))


class FakeClient:
    user_id = "_user"

    def __init__(self):
        self.transport = FakeTransport()


@pytest.fixture
def records():
    return {"item": [
        _rec("A-PW", up.new_password_plist("has-meta.example", "alex", "pw1")),
        _rec("A-META", up.new_metadata_plist("has-meta.example", "alex", notes="n")),
        _rec("B-PW", up.new_password_plist("bare.example", "sam", "pw2")),
    ]}


@pytest.fixture
def zone(monkeypatch, records):
    saved = []
    monkeypatch.setattr(push, "_save", lambda c, rec, fields, create=False, zone="Passwords":
                        saved.append((rec.record_name, create, up.decrypt_item_record(
                            CloudKitRecord(rec.record_name, "item", fields), CK))))
    z = push.Zone(FakeClient(), records, {PARENT: CK})
    z.saved = saved
    return z


def test_details_edit_touches_only_the_metadata_record(zone):
    push.push_details(zone, "has-meta.example", "alex", sites=["www.has-meta.example"])
    assert [(n, c) for n, c, _ in zone.saved] == [("A-META", False)]
    meta = md.parse(zone.saved[0][2]["v_Data"])
    assert md.sites(meta) == ["www.has-meta.example"] and md.notes(meta) == "n"


def test_details_on_entry_without_metadata_creates_one(zone):
    cfg = {"secret": b"12345678901234567890", "digits": 6, "period": 30, "algorithm": 0}
    push.push_details(zone, "bare.example", "sam", totp=cfg)
    (name, created, plist), = zone.saved
    assert created and name not in ("B-PW",)
    assert plist["agrp"] == up.AGRP_METADATA and plist["srvr"] == "bare.example"
    assert md.totp_config(md.parse(plist["v_Data"]))["secret"] == cfg["secret"]


def test_create_writes_password_and_metadata(zone):
    site = push.clean_site("https://new.example/login")
    assert push.create_entry(zone, site, "kim", "pw3", title="New") == 2
    kinds = [(c, p["agrp"], p["srvr"]) for _, c, p in zone.saved]
    assert kinds == [(True, up.AGRP_PASSWORD, "new.example"), (True, up.AGRP_METADATA, "new.example")]
    assert zone.saved[0][2]["v_Data"] == b"pw3"


def test_an_entry_without_a_site_gets_a_uuid_server_like_apples_own():
    site = push.clean_site("", title="Bank card PIN")
    assert len(site) == 36 and site.count("-") == 4
    with pytest.raises(push.PushError):
        push.clean_site("", title="   ")


def test_create_refuses_an_existing_account(zone):
    with pytest.raises(push.PushError, match="already exists"):
        push.create_entry(zone, "bare.example", "sam", "other")
    assert zone.saved == []


def test_create_needs_site_and_password(zone):
    with pytest.raises(push.PushError):
        push.create_entry(zone, "", "kim", "pw")
    with pytest.raises(push.PushError):
        push.create_entry(zone, "new.example", "kim", "")
    assert zone.saved == []


def test_password_change_moves_both_records(zone):
    assert push.push_password(zone, "has-meta.example", "alex", "new-pw") == 2
    names = [n for n, _, _ in zone.saved]
    assert names == ["A-PW", "A-META"]
    assert zone.saved[0][2]["v_Data"] == b"new-pw"
    hist = md.password_history(md.parse(zone.saved[1][2]["v_Data"]))
    assert hist and hist[0]["password"] == "new-pw"


def test_password_change_on_a_password_only_entry_writes_one_record(zone):
    assert push.push_password(zone, "bare.example", "sam", "x") == 1
    assert [n for n, _, _ in zone.saved] == ["B-PW"]


def test_nothing_is_written_for_an_account_that_is_not_there(zone):
    with pytest.raises(push.PushError):
        push.push_password(zone, "nowhere.example", "alex", "x")
    with pytest.raises(push.PushError):
        push.push_details(zone, "has-meta.example", "someone-else", notes="x")
    assert zone.saved == []


def test_rename_goes_to_the_metadata_record_or_reports_it_cannot(zone):
    assert push.push_nickname(zone, "bare.example", "sam", "Sam's") is False
    assert zone.saved == []
    assert push.push_nickname(zone, "has-meta.example", "alex", "Work") is True
    (name, created, plist), = zone.saved
    assert name == "A-META" and not created
    assert md.title(md.parse(plist["v_Data"])) == "Work"


def test_delete_sends_nothing_while_unverified(zone):
    with pytest.raises(push.DeleteUnavailable):
        push.delete_entry(zone, "has-meta.example", "alex")
    assert zone.client.transport.performed == [] and zone.saved == []


def test_delete_when_enabled_names_exactly_the_two_records(monkeypatch, zone):
    monkeypatch.setattr(push, "RECORD_DELETE_VERIFIED", True)
    assert push.delete_entry(zone, "has-meta.example", "alex") == 2
    bodies = [p[3] for p in zone.client.transport.performed]
    assert [b"A-META" in b for b in bodies] == [True, False]
    assert [b"A-PW" in b for b in bodies] == [False, True]
    assert all(b"Passwords" in b for b in bodies)


def test_refetch_reads_one_zone_and_decrypts_with_the_held_keys(monkeypatch, zone, records):
    asked = []
    monkeypatch.setattr(ckks, "record_zone_identifier", lambda name, uid: asked.append(name) or b"z")
    monkeypatch.setattr(ckks, "build_retrieve_changes_request", lambda zid, cont=None: b"req")
    monkeypatch.setattr(zone.client.transport, "fetch_records", lambda req: b"raw", raising=False)
    monkeypatch.setattr(ckks, "parse_retrieve_changes_response",
                        lambda raw: {"records": records["item"], "continuation_token": None,
                                     "status": 3})
    monkeypatch.setattr(push, "decrypt_items",
                        lambda its, keys: [up.decrypt_item_record(r, CK) for r in its])
    store = push.refetch(zone, "Passwords")
    assert asked == ["Passwords"]
    c = push.find(store, "has-meta.example", "alex")
    assert c.password == "pw1" and c.notes == "n"
    assert push.find(store, "has-meta.example", "nobody") is None
