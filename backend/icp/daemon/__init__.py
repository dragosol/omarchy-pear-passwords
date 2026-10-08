"""pear-passwordsd: the key holder, running as the `pear-passwords` system user.

Layout and owners (docs/WORKPACKAGES.md has the full table):

  paths.py, protocol.py, context.py   frozen shared interfaces (foundation; change via v2-base)
  __main__.py, server.py, peer.py,    WP1: socket activation, framing, peer checks, polkit,
  polkit.py, sessions.py, grants.py,  per-uid state, grants, tickets, logind, the scheduler
  tickets.py, logind.py,              and every op handler except the two below
  scheduler.py, handlers.py,
  frontend.py
  apple.py                            WP3: the Apple pipeline, called with a UserContext
  autofill.py                         WP6: autofill-query and autofill-fill

This package must stay cheap to import: the clients import icp.daemon.protocol and
icp.daemon.paths for shared constants, so nothing here may pull in jeepney, asyncio servers or
the Apple code at import time.
"""

from .context import BackgroundFrontend, Cancelled, Frontend, NeedsLogin, UserContext

__all__ = ["BackgroundFrontend", "Cancelled", "Frontend", "NeedsLogin", "UserContext"]
