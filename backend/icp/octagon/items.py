"""From decrypted keychain credentials to the store's SyncItems.

The pipeline (keychain/pipeline.py) turns CKKS records into Credentials; this module turns
those into what UserStore.apply_sync takes: one SyncItem per entry, split into the metadata
tier 1 may release (Meta) and the secrets only a grant may open (Secrets).

Entry ids. An id is opaque to every client but has to be stable for the same keychain item
across syncs, and the same for a v1 entry imported by migration and that entry's next sync -
otherwise every migrated account would look deleted and re-added, and its nickname and local
history (both keyed by id) would be orphaned. The keychain identifies an account by its server
and account fields (srvr, acct), which is also what an edit matches records on, so the id is a
hash of exactly those two: `entry_id(domain, username)`. 1.x used the same pair joined with a
\\x1f, which the 2.0 id alphabet does not allow, so the importer maps 1.x keys through this
function too.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from ..vstore import Meta, Secrets, SyncItem

ID_PREFIX = "k1-"
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def entry_id(domain: str, username: str) -> str:
    """The stable id of the account (domain, username): "k1-" and 40 hex characters.

    The pair is hashed as a JSON array, not joined with a separator, so no choice of domain
    and username can collide with another pair that happens to contain the separator."""
    pair = json.dumps([str(domain), str(username)], ensure_ascii=False, separators=(",", ":"))
    h = hashlib.sha256(b"pear/v2/entry\x00" + pair.encode("utf-8"))
    return ID_PREFIX + h.hexdigest()[:40]


def v1_entry_key(domain: str, username: str) -> str:
    """How 1.x keyed nicknames and history: domain, unit separator, username."""
    return f"{domain}\x1f{username}"


def _iso(at) -> str:
    try:
        at = float(at or 0)
    except (TypeError, ValueError):
        return ""
    if at <= 0:
        return ""
    return datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _totp(cfg) -> tuple[bytes | None, dict]:
    """(raw seed, {digits, period, algorithm}) from a Credential's totp config. The seed is
    always bytes: Apple stores the decoded key, and a str is the base32 text a person pasted."""
    if not cfg or not cfg.get("secret"):
        return None, {}
    from .. import totp
    secret = cfg.get("secret")
    if cfg.get("secret_hex") and isinstance(secret, str):
        secret = bytes.fromhex(secret)
    params = {"digits": int(cfg.get("digits") or totp.DEFAULT_DIGITS),
              "period": int(cfg.get("period") or totp.DEFAULT_PERIOD),
              "algorithm": int(cfg.get("algorithm") or 0)}
    return totp.key_bytes(secret), params


def to_sync_item(c, nicknames: dict | None = None) -> SyncItem:
    """One Credential as a SyncItem. `nicknames` are the store's local names by entry id."""
    eid = entry_id(c.domain, c.username)
    seed, params = _totp(c.totp)
    history = [{"date": _iso(h.get("at")), "value": str(h.get("password"))}
               for h in (c.apple_history or ()) if h.get("password") is not None]
    meta = Meta(id=eid, title=str(c.title or ""), domain=str(c.domain or ""),
                sites=[str(s) for s in (c.sites or ())], username=str(c.username or ""),
                nickname=str((nicknames or {}).get(eid, "")), has_totp=seed is not None,
                has_notes=bool(c.notes), mdat=float(c.mdat or 0.0),
                history_count=len(history), apple_title=str(c.apple_title or ""),
                aliases=[str(a) for a in (c.aliases or ())])
    secrets = Secrets(password=str(c.password or ""), notes=str(c.notes or ""),
                      totp_secret=seed, apple_history=history, totp_params=params)
    return SyncItem(id=eid, meta=meta, secrets=secrets)


def to_sync_items(credentials, nicknames: dict | None = None) -> list[SyncItem]:
    """Every credential as a SyncItem, one per id. Two password items for the same account
    (it happens: a site saved twice, or over two protocols) collapse to the newest, which is
    also the one any Apple device fills."""
    by_id: dict[str, SyncItem] = {}
    for c in credentials:
        item = to_sync_item(c, nicknames)
        prev = by_id.get(item.id)
        if prev is None or item.meta.mdat > prev.meta.mdat:
            by_id[item.id] = item
    return list(by_id.values())
