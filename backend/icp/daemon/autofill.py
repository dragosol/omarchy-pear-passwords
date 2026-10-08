"""Browser autofill, daemon side: the two ops an `autofill` connection may send.

Owned by WP6; WP1's dispatch table calls the two handlers for role "autofill" and nothing else
does. The browser extension is not part of this repository - anyone can write one against
docs/autofill-protocol.md - so the daemon trusts nothing the extension says except the origin,
and treats that only as being as trustworthy as the browser that reported it.

The rules these handlers implement (docs/protocol.md 'Autofill' is the normative text):

- A locked Pear reveals nothing. Unless the uid's tier-1 UI session is unlocked, both ops
  answer as if no account exists for any site: autofill-query returns {"state": "locked"} with
  no other field, autofill-fill raises OpError("locked"). Neither ever unseals a key, raises a
  dialog, or touches the store while locked.
- The autofill role never gets a tier-1 or tier-2 grant and never uses the UI's grants. Every
  fill raises its own `.autofill` polkit dialog against the autofill process's pidfd.
- Matching is by site, never by name: the origin host must be the entry's `domain` or one of
  its `sites`, or a subdomain/parent of one at a dot boundary, within the same registrable
  domain. Name-only and inferred-alias matches (`Meta.aliases`) are never used.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .protocol import Connection, OpError, SessionRegistry  # noqa: F401  (contract types)

if TYPE_CHECKING:
    from ..vstore import Meta


def parse_origin(origin: str) -> str:
    """Validate an origin string from the extension and return its host.

    Accepts exactly `https://<host>` or `https://<host>:<port>`: lowercase it, require an
    ASCII host (IDNs arrive punycoded from the browser) of dot-separated [a-z0-9-] labels with
    at least two labels, no userinfo, path, query, fragment, trailing dot or IP literal.
    Strips one leading "www.". Raises OpError("insecure-origin") for any other scheme and
    OpError("bad-origin") for everything else malformed. The port is ignored for matching."""
    raise NotImplementedError


def match_rank(host: str, meta: "Meta") -> int | None:
    """How well an entry matches a page host from parse_origin(), or None for no match.

    0: `host` equals the entry's domain or one of its sites (both www-stripped).
    1: one is a subdomain of the other at a dot boundary, and the shorter of the two is not a
       public suffix (it has at least two labels and is not in the module's frozen guard list
       of multi-label public suffixes such as co.uk or github.io).
    None otherwise - including name-only matches and `meta.aliases`, which are never used."""
    raise NotImplementedError


def account_label(meta: "Meta") -> str:
    """The text for polkit's $(account) and for the query result: "<title> — <username>",
    using the nickname when one is set, falling back to the domain when there is no title.
    Unsanitized; SessionRegistry.authorize() sanitizes details values itself."""
    raise NotImplementedError


async def handle_autofill_query(session_registry: SessionRegistry, conn: Connection,
                                req: dict) -> dict:
    """op "autofill-query" {origin}.

    Never prompts. When the uid's tier-1 session is not unlocked it returns only
    {"state": "locked"} (store locked or no UI connection) or {"state": "unavailable"} (store
    empty, tpm-missing, tpm-cleared or damaged): no count, no hint whether the site has
    accounts, and the origin is validated but not used. Unlocked: returns
        {"state": "unlocked", "host": <parsed host>,
         "accounts": [{"id", "username", "label", "match": "exact"|"related"}, ...]}
    ranked by match_rank, then newest mdat, then label; at most 20 accounts. Never includes a
    password, notes, a code or any other entry's data.

    Raises OpError("bad-origin" | "insecure-origin" | "bad-request")."""
    raise NotImplementedError


async def handle_autofill_fill(session_registry: SessionRegistry, conn: Connection,
                               req: dict) -> dict:
    """op "autofill-fill" {origin, id}.

    In order: parse the origin; require the uid's session unlocked (else OpError("locked"));
    look up `id` and require match_rank(host, meta) is not None (else OpError("no-match") -
    the same code for an unknown id, so ids cannot be probed); raise the `.autofill` dialog via
    session_registry.authorize(conn, ACTION_AUTOFILL, {"account": account_label(meta),
    "origin": host}); after approval, re-check the session is still unlocked and the entry
    still matches, then open the entry (a transient SK unseal via run_store) and return
        {"id", "username", "password"}
    Notifies the UI with {"event": "autofill", "id", "origin": host, "outcome"} where outcome
    is "filled", "dismissed", "denied" or "failed". Holds the secret only for the reply.

    Raises OpError for every refusal authorize() raises, plus locked, no-match, bad-origin,
    insecure-origin and bad-request."""
    raise NotImplementedError
