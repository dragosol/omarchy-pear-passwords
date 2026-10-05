"""Removal of any persisted copy of the derived vault key.

This module used to keep the key in a 0600 file so later launches did not ask for the
passphrase again. That defeated the passphrase: the file sat in ~/.config/icp beside the
encrypted vault, so anyone who obtained a copy of that directory could decrypt everything
without knowing the passphrase. File permissions protect a live filesystem; they do not
travel with a copied directory, which is exactly the case a passphrase is for.

So the key is no longer written anywhere. While a passphrase is set, the only copy lives in
the agent's memory, behind a socket in $XDG_RUNTIME_DIR (0700, tmpfs, dropped after an idle
timeout and gone at logout). After a reboot the passphrase is asked for once more, which is
the cost of the guarantee.

What remains here is cleanup, so an existing install stops being exposed as soon as it is
updated: `purge()` deletes the old file and any legacy Secret Service item.
"""

from __future__ import annotations

import logging

from .. import paths

logger = logging.getLogger(__name__)

_ATTRS = {"application": "icp", "type": "lockbox-key"}


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
        logger.debug("could not remove the Secret Service vault key (%s)", e)


def purge() -> None:
    """Remove every stored copy of the derived vault key. Idempotent."""
    f = paths.vault_key_file()
    try:
        existed = f.exists()
        f.unlink(missing_ok=True)
        if existed:
            logger.warning("removed the stored vault key at %s; the passphrase is now the only "
                           "way in after a restart", f)
    except OSError as e:
        logger.warning("could not remove %s (%s)", f, e)
    _purge_keyring()


# Kept so an older caller cannot silently start writing a key again.
clear = purge
