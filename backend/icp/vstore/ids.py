"""Entry ids: opaque, filesystem-safe, and the same for the same account before and after the
migration.

1.x named an entry `"<domain>\\x1f<username>"` - the key its history journal and nicknames
were filed under. That cannot be a file name (`/`, control characters, any length), so 2.0
hashes it. The hash keeps one property that matters more than readability: the importer, which
only ever sees 1.x credentials, and the Apple pipeline, which sees keychain items, compute the
same id for the same (domain, username). If they did not, the first sync after a migration
would add all 554 entries again under new ids and tombstone the imported ones, taking every
nickname and every local history entry with them.

So the rule for every producer of a SyncItem is: `entry_id(domain, username)`, with
`assign_ids()` when one batch can hold the same pair twice.
"""

from __future__ import annotations

import hashlib
import re
from typing import Iterable

# What vstore.Meta promises callers ([A-Za-z0-9._:-], at most 128), minus a leading dot so an
# id can never be "." or ".." when it becomes entries/<id>.box or the directory history/<id>/.
_ID_RE = re.compile(r"^[A-Za-z0-9_:-][A-Za-z0-9._:-]{0,127}$")

PREFIX = "k"
HEX_CHARS = 40          # 160 bits of SHA-256: no accidental collision across one keychain


def entry_id(domain: str, username: str) -> str:
    """The id of the account (domain, username), byte-exact: no case folding, no `www.`
    stripping, because 1.x did none either and two such entries really are two entries."""
    key = f"{domain}\x1f{username}".encode("utf-8", "surrogatepass")
    return PREFIX + hashlib.sha256(key).hexdigest()[:HEX_CHARS]


def assign_ids(pairs: Iterable[tuple[str, str]]) -> list[str]:
    """Ids for a batch, in order. A repeated (domain, username) gets `.2`, `.3`... in the order
    it appears, so the first occurrence keeps the plain id that history and nicknames use."""
    seen: dict[str, int] = {}
    out = []
    for domain, username in pairs:
        base = entry_id(domain, username)
        n = seen.get(base, 0) + 1
        seen[base] = n
        out.append(base if n == 1 else f"{base}.{n}")
    return out


def valid_id(value) -> bool:
    return isinstance(value, str) and bool(_ID_RE.match(value))


def check_id(value) -> str:
    """Return `value` if it is a usable entry id, else raise ValueError (never a path)."""
    if not valid_id(value):
        raise ValueError("bad entry id")
    return value
