#!/usr/bin/env python3
"""Ask the session polkit agent (Omarchy's fingerprint overlay) to authenticate.

Run with the system interpreter, not the icp venv: this needs gi/Polkit.
ALWAYS_CHECK forces a prompt even when the session would otherwise count as
already authorized.

Exit codes are a contract with icp.ui.reauth, and the distinction matters:

  0  authorized
  1  a person said no - cancelled, dismissed, or failed to authenticate
  2  the gate itself broke - gi missing, polkitd unreachable, anything else

A 1 is an answer and must be respected. A 2 is a malfunction, and the caller falls back to
pkexec so a broken gate can't lock someone out of their own passwords. These used to share
exit 1: `import gi` sat outside the try, so a system Python upgrade that dropped gi crashed
the script with the same code as "denied".
"""

from __future__ import annotations

import os
import sys

ACTION_ID = "org.icp.unlock"

AUTHORIZED, DENIED, BROKEN = 0, 1, 2


def main() -> int:
    try:
        import gi

        gi.require_version("Polkit", "1.0")
        from gi.repository import Polkit

        authority = Polkit.Authority.get_sync()
        subject = Polkit.UnixProcess.new_for_owner(os.getpid(), 0, os.getuid())
        flags = (
            Polkit.CheckAuthorizationFlags.ALLOW_USER_INTERACTION
            | Polkit.CheckAuthorizationFlags.ALWAYS_CHECK
        )
        result = authority.check_authorization_sync(subject, ACTION_ID, None, flags, None)
    except Exception as e:  # noqa: BLE001 - every failure here is "the gate broke"
        print(f"polkit gate error: {type(e).__name__}: {e}", file=sys.stderr)
        return BROKEN
    return AUTHORIZED if result.get_is_authorized() else DENIED


if __name__ == "__main__":
    raise SystemExit(main())
