#!/usr/bin/env bash
# Removes what install.sh added. Your keychain data (~/.config/icp) and the sign-in helper's
# device identity are kept unless you pass --purge, because deleting them signs this computer
# out and Apple will ask for a verification code next time.
set -euo pipefail
[ "$(id -u)" -ne 0 ] || { echo "run this as your own user, not root" >&2; exit 1; }

data="$HOME/.local/share/pear-passwords"

systemctl --user disable --now pear-passwords-sync.timer pear-passwords-anisette.service 2>/dev/null || true
rm -f "$HOME/.config/systemd/user/pear-passwords-anisette.service" \
      "$HOME/.config/systemd/user/pear-passwords-sync.service" \
      "$HOME/.config/systemd/user/pear-passwords-sync.timer"
systemctl --user daemon-reload
rm -f "$HOME/.local/share/applications/pear-passwords.desktop"
rm -rf "$data"
echo "Pear Passwords removed."

if [ "${1:-}" = "--purge" ]; then
  read -r -p "Also delete your synced passwords and this computer's Apple sign-in? [y/N] " yn
  if [ "$yn" = "y" ] || [ "$yn" = "Y" ]; then
    rm -rf "$HOME/.config/icp"
    podman volume rm -f icp-anisette >/dev/null 2>&1 || true
    echo "Keychain data and device identity deleted."
  fi
else
  echo "Your keychain data in ~/.config/icp was kept. Run with --purge to delete it too."
fi
