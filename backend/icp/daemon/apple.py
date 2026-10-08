"""The Apple pipeline as the daemon calls it. Owned by WP3; these signatures are frozen.

Every function is blocking (network-bound) and is run by WP1 in a worker thread under the
uid's store lock. Each takes a UserContext whose store is unlocked, reads and writes the
iCloud session only through ctx.store, and asks questions only through ctx.ui - so a
background call (ctx.frontend is None) that needs a person raises NeedsLogin.

This module must never import or name the daemon's authorization module (not even in a
comment), and a sync must never unseal SK_secret: tests grep, walk the AST and count unseals.

Errors: NeedsLogin (context), Cancelled (context), icp.auth.anisette.AnisetteError for an
unreachable anisette server, and icp.errors.AppleError subclasses for everything iCloud
refuses. WP1 maps them to the error codes in docs/protocol.md.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .context import UserContext


def sync(ctx: "UserContext") -> dict:
    """Refresh tokens non-interactively if needed, fetch and decrypt the keychain, and hand
    the items to ctx.store.apply_sync. Refreshes Hide My Email aliases best-effort. Records
    synced_at and clears needs_login on success. Returns apply_sync's counts plus
    {"synced_at": unix seconds}."""
    raise NotImplementedError


def login(ctx: "UserContext") -> None:
    """Full interactive sign-in (Apple ID, password, 2FA, escrow join), then a first sync.
    Requires ctx.frontend."""
    raise NotImplementedError


def relogin(ctx: "UserContext") -> None:
    """Re-authenticate an existing session after needs-login (password, 2FA), then sync.
    Requires ctx.frontend."""
    raise NotImplementedError


def push_set(ctx: "UserContext", id: str, fields: dict) -> None:
    """Push a change to one entry: any of password, notes, sites, nickname, totp
    ({"setup": key-or-otpauth} or {"remove": true}), as validated by the handler. Then sync
    that zone so meta reflects iCloud, and call ctx.store.set_secrets when secrets changed."""
    raise NotImplementedError


def create(ctx: "UserContext", fields: dict) -> str:
    """Create an entry from protocol.CREATE_FIELDS, sync its zone, and return the new id."""
    raise NotImplementedError


def delete(ctx: "UserContext", id: str) -> None:
    """Delete an entry in iCloud, then sync its zone so it is tombstoned locally."""
    raise NotImplementedError


def fetch_aliases(ctx: "UserContext") -> int:
    """Refresh Hide My Email aliases into ctx.store; returns how many there are."""
    raise NotImplementedError


def signout(ctx: "UserContext") -> None:
    """Forget the iCloud session: ctx.store.save_session({}). Entries stay readable locally;
    nothing syncs until the next signin."""
    raise NotImplementedError
