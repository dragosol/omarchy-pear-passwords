"""Encrypted local cache of Hide My Email aliases (read by the native host). Same encryption as
`vault/store.py`; refreshed by `icp show`/`icp sync` so the host serves a snapshot, never live."""

from __future__ import annotations

import dataclasses
import json
import logging

import nacl.exceptions
import nacl.secret

from .. import paths
from ..auth.session import _master_key
from .client import HmeAlias


def save_aliases(aliases: list[HmeAlias]) -> None:
    box = nacl.secret.SecretBox(_master_key())
    blob = box.encrypt(json.dumps({"aliases": [dataclasses.asdict(a) for a in aliases]}).encode())
    f = paths.aliases_file()
    f.write_bytes(blob)
    f.chmod(0o600)


def load_aliases() -> list[HmeAlias]:
    f = paths.aliases_file()
    if not f.exists():
        return []
    box = nacl.secret.SecretBox(_master_key())
    try:
        data = json.loads(box.decrypt(f.read_bytes()).decode())
    except nacl.exceptions.CryptoError:
        logging.getLogger(__name__).warning("cannot decrypt %s with the current master key; "
                                            "discarding it - it will be refetched", f)
        f.unlink()
        return []
    return [HmeAlias(**a) for a in data.get("aliases", [])]
