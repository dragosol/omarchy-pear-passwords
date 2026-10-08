"""The credential list as 1.x code knew it (a CredentialStore), over the 2.0 per-user store.

In 1.x this module encrypted the whole vault - passwords included - into one file under a key
any process running as you could obtain, and deleted that file when it would not decrypt. In
2.0 the daemon's icp.vstore holds the data, and this is only a translation layer:

* `save_vault(store, creds)` turns a freshly decrypted keychain (CredentialStore) into
  SyncItems and hands them to `store.apply_sync`, which seals each password to PK_secret.
  Accounts no longer in `creds` are tombstoned. SK_secret is never unsealed.
* `load_vault(store)` gives the list back **without secrets**: every Credential has an empty
  password, notes and TOTP. Tier 1 releases metadata only; a password is one
  `store.open_entry(id)` call, made under a grant.

Nothing here deletes anything. An entry that will not open is reported by the store as damaged
and its file is kept.
"""

from __future__ import annotations

import dataclasses

from ..vstore import Meta, Secrets, SyncItem, UserStore
from ..vstore import legacy as _legacy
from ..vstore.ids import assign_ids, entry_id
from .host import Credential, CredentialStore


def credential_id(c: Credential) -> str:
    """The 2.0 id of a credential: the same one the 1.x import gave it."""
    return entry_id(c.domain, c.username)


def credential_parts(c: Credential) -> tuple[Meta, Secrets]:
    """(Meta, Secrets) for one credential, with the TOTP seed as raw bytes. The id is left
    empty; sync_items() assigns it for the whole batch."""
    return _legacy.credential_parts(c.storage_dict())


def sync_items(creds) -> list[SyncItem]:
    """SyncItems for every credential in `creds`, ids per vstore.ids.assign_ids (a repeated
    domain and username gets `.2`, `.3` in order)."""
    creds = list(creds.all() if isinstance(creds, CredentialStore) else creds)
    parts = [credential_parts(c) for c in creds]
    ids = assign_ids((m.domain, m.username) for m, _ in parts)
    return [SyncItem(id=i, meta=dataclasses.replace(m, id=i), secrets=s)
            for i, (m, s) in zip(ids, parts)]


def save_vault(store: UserStore, creds: CredentialStore) -> dict:
    """Make the store hold exactly `creds` (a full keychain read). Returns apply_sync's
    counts. Raises StoreLocked."""
    items = sync_items(creds)
    present = {it.id for it in items}
    gone = {m.id for m in store.list_meta()} - present
    return store.apply_sync(items, gone)


def load_vault(store: UserStore) -> CredentialStore:
    """Every live entry as a Credential with no secrets in it (password, notes and totp are
    empty). Raises StoreLocked."""
    return CredentialStore([
        Credential(domain=m.domain, username=m.username, password="", title=m.title,
                   mdat=m.mdat, totp=None, notes="", aliases=tuple(m.aliases),
                   apple_history=(), apple_title=m.apple_title, sites=tuple(m.sites))
        for m in store.list_meta()])
