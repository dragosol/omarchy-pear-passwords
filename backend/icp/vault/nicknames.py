"""User-chosen names for entries.

The keychain's own title is whatever the site called itself when the password was saved, which
is why the list is full of `account.bellmedia.ca` and bare UUIDs. A nickname overrides it.

Stored encrypted with the vault's key rather than in the clear: on its own a nickname is not a
secret, but a file listing "Work VPN", "Mum's bank", "old Gmail" against account identifiers is
a map of someone's life, and it would be the one unencrypted file in a directory where
everything else is sealed.

Local to this machine. Apple's own `labl` field is where a synced rename would have to go, and
that means a two-record push per rename - worth doing, deliberately not bundled in here.
"""

from __future__ import annotations

import json
import logging

import nacl.exceptions
import nacl.secret

from .. import paths
from ..auth.session import _master_key

logger = logging.getLogger(__name__)
MAX_LEN = 80


def load() -> dict:
    f = paths.nicknames_file()
    if not f.exists():
        return {}
    try:
        box = nacl.secret.SecretBox(_master_key())
        return json.loads(box.decrypt(f.read_bytes()).decode()).get("names", {})
    except (nacl.exceptions.CryptoError, ValueError) as e:
        logger.warning("cannot read nicknames (%s); starting fresh", e)
        return {}


def save(names: dict) -> None:
    box = nacl.secret.SecretBox(_master_key())
    f = paths.nicknames_file()
    f.write_bytes(box.encrypt(json.dumps({"names": names}).encode()))
    f.chmod(0o600)


def clean(value: str) -> str:
    """Collapse whitespace and cap the length. An empty result means 'use the real title'."""
    return " ".join((value or "").split())[:MAX_LEN]


def set_for(entry_id: str, value: str) -> dict:
    names = load()
    value = clean(value)
    if value:
        names[entry_id] = value
    else:
        names.pop(entry_id, None)
    save(names)
    return names
