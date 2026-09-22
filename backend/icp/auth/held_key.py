"""Persisted copy of the derived vault key.

Fingerprint is the presence check for the TUI. The passphrase only exists to
derive this key; once derived it is kept in a 0600 file so later launches do
not ask for it again.

Deliberately NOT in the Secret Service / login keyring. Secret Service has no
per-application ACL on Linux: once the collection is unlocked, any process
running as this user can ask D-Bus for the item. That is the same exposure the
0600 file already has, so a second copy bought no security and no convenience -
it only widened the surface. `load()` still reads a legacy keyring item once, to
migrate it into the file, and then deletes it.
"""

from __future__ import annotations

import logging
import os

from .. import paths
from . import lockbox

logger = logging.getLogger(__name__)

_ATTRS = {"application": "icp", "type": "lockbox-key"}
_LABEL = "iCloud Keychain vault key"


def _valid(raw: bytes | None) -> bytes | None:
    if not raw:
        return None
    key = bytes(raw)
    return key if lockbox.verify(key) else None


def _load_file() -> bytes | None:
    f = paths.vault_key_file()
    if not f.exists():
        return None
    try:
        return _valid(f.read_bytes())
    except OSError:
        return None


def _save_file(key: bytes) -> None:
    f = paths.vault_key_file()
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    os.chmod(f, 0o600)


def _load_keyring() -> bytes | None:
    try:
        import secretstorage
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked():
            return None
        for item in coll.search_items(_ATTRS):
            key = _valid(item.get_secret())
            if key is not None:
                return key
    except Exception as e:
        logger.warning("Secret Service unavailable for vault key (%s)", e)
    return None


def _purge_keyring() -> None:
    """Delete any Secret Service copy of the vault key. Safe when there is none."""
    try:
        import secretstorage
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked():
            return
        for item in coll.search_items(_ATTRS):
            item.delete()
    except Exception as e:
        logger.warning("could not remove the Secret Service vault key (%s)", e)


def load() -> bytes | None:
    if not lockbox.is_initialised():
        return None
    key = _load_file()
    if key is not None:
        return key
    key = _load_keyring()
    if key is not None:
        # Legacy copy from when the key was mirrored into Secret Service. Adopt it
        # into the 0600 file and remove it, so only one copy survives.
        _save_file(key)
        _purge_keyring()
        return key
    return None


def save(key: bytes) -> None:
    key = _valid(key)
    if key is None:
        return
    _save_file(key)


def clear() -> None:
    try:
        paths.vault_key_file().unlink(missing_ok=True)
    except OSError:
        pass
    try:
        import secretstorage
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked():
            return
        for item in coll.search_items(_ATTRS):
            item.delete()
    except Exception:
        pass
