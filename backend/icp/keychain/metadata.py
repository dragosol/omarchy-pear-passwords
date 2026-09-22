"""Apple "Password Manager Metadata" items.

These live in the keychain alongside real logins, keyed by the same (srvr, acct), but their
`v_Data` is a binary plist of *attributes* rather than a password: notes, a title, passkey
bookkeeping, TOTP configuration - and on some accounts, payment card fields.

Upstream fed them through the ordinary credential path, so a large fraction of a typical
vault ended up with `bplist00...` as its "password" and the browser extension would have typed
that into a login form. They are now recognised, parsed for the parts worth keeping, and never
offered as credentials in their own right.
"""

from __future__ import annotations

import plistlib

_MAGIC = b"bplist00"

# Payment card material also lives in these blobs. It is deliberately not surfaced: this tool
# fills login forms, and a card number is not something to put a copy of on a Linux box.
_CARD_KEYS = {"CardNumber", "CardSecurityCode", "ExpirationDate", "CardholderName",
              "displayableLastFour", "FPANHash", "PrimaryAccountIdentifier"}


def is_metadata(v_data) -> bool:
    return isinstance(v_data, (bytes, bytearray)) and bytes(v_data).startswith(_MAGIC)


def parse(v_data):
    """The attribute dict, or None if this is not a metadata blob we can read."""
    if not is_metadata(v_data):
        return None
    try:
        parsed = plistlib.loads(bytes(v_data))
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def has_card_data(meta) -> bool:
    return isinstance(meta, dict) and bool(_CARD_KEYS & set(meta))


def totp_config(meta):
    """{'secret','digits','period','algorithm','issuer'} or None.

    `secret` is handed on untouched - icp.totp works out raw-vs-base32 itself."""
    if not isinstance(meta, dict):
        return None
    t = meta.get("totp")
    if not isinstance(t, dict) or not t.get("secret"):
        return None
    return {
        "secret": t["secret"],
        "digits": int(t.get("digits") or 6),
        "period": int(t.get("period") or 30),
        "algorithm": int(t.get("algorithm") or 0),
        "issuer": str(t.get("issuer") or ""),
    }


def notes(meta) -> str:
    """The entry's notes. Apple stores them as UTF-8 *bytes* - reading only `str` here hid
    every note in the keychain, the same trap title() fell into."""
    if not isinstance(meta, dict):
        return ""
    v = meta.get("notes")
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", "replace")
    return v if isinstance(v, str) else ""


def sites(meta) -> list:
    """Extra websites this entry is offered on, from `s_as`: a list of {"s": "example.com"}.
    The entry's primary site is the record's own `srvr` and is not repeated here."""
    if not isinstance(meta, dict):
        return []
    out = []
    for item in meta.get("s_as") or []:
        s = item.get("s") if isinstance(item, dict) else None
        if isinstance(s, str) and s.strip() and s.strip() not in out:
            out.append(s.strip())
    return out


def title(meta) -> str:
    """The name a person gave this entry in Apple's Passwords app.

    Apple writes it as **bytes**, not a string - this used to test `isinstance(v, str)` and so
    returned "" for every entry that actually had one. It is the only field in the keychain
    that carries a user-chosen name: `labl` on the password record is generated
    (`domain (username)`) for 468 of 547 entries and is not editable from the Passwords UI.
    """
    if not isinstance(meta, dict):
        return ""
    v = meta.get("title")
    if isinstance(v, (bytes, bytearray)):
        try:
            return bytes(v).decode("utf-8").strip()
        except UnicodeDecodeError:
            return ""
    return v.strip() if isinstance(v, str) else ""


def password_history(meta) -> list:
    """Apple's own history from a metadata blob: `s_hi` entries of
    {d: date, id: uuid, p: password, t: tag}, normalised to {at, password} newest first.

    Ordering inside s_hi is not guaranteed, so sort by the date rather than trusting position.
    """
    if not isinstance(meta, dict):
        return []
    out = []
    for h in meta.get("s_hi") or []:
        if not isinstance(h, dict):
            continue
        pw = h.get("p")
        if pw is None:
            continue
        when = h.get("d")
        out.append({"at": when.timestamp() if hasattr(when, "timestamp") else 0.0,
                    "password": pw})
    return sorted(out, key=lambda e: e["at"], reverse=True)
