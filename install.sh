#!/usr/bin/env bash
# Pear Passwords installer. User-level only: it never uses sudo and refuses to run as root.
#
# What it does, all under your home directory:
#   ~/.local/share/pear-passwords/venv   the backend (Python), installed from ./backend
#   ~/.local/share/pear-passwords/app    the app window (Quickshell), copied from ./app
#   ~/.local/share/applications/pear-passwords.desktop   the "Pear Passwords" launcher
#   ~/.config/systemd/user/pear-passwords-*              local sign-in helper + 2-hourly sync
# Your keychain data lives in ~/.config/icp and is never touched by this script.
#
# Re-run it after `omarchy plugin update` to pick up a new version.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
data="$HOME/.local/share/pear-passwords"
apps="$HOME/.local/share/applications"
units="$HOME/.config/systemd/user"
omarchy_shell="/usr/share/omarchy/shell"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "run this as your own user, not root - nothing here needs root"

for cmd in python3 podman quickshell systemctl; do
  command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' is required but not installed"
done
[ -d "$omarchy_shell/Ui" ] && [ -d "$omarchy_shell/Commons" ] \
  || die "Omarchy's shell components were not found in $omarchy_shell"
command -v wl-copy >/dev/null 2>&1 || warn "wl-clipboard is not installed: copying to the clipboard will not work"
command -v notify-send >/dev/null 2>&1 || warn "notify-send is not installed: sign-in reminders will not show"

mkdir -p "$data" "$apps" "$units"

say "Installing the backend into $data/venv"
[ -x "$data/venv/bin/python" ] || python3 -m venv "$data/venv"
"$data/venv/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade "$here/backend"

say "Installing the app into $data/app"
# Built beside the old copy and swapped in, so a failed copy never leaves a half-installed app.
rm -rf "$data/app.new"
cp -r "$here/app" "$data/app.new"
# The app draws with Omarchy's own components, so it follows your theme.
ln -s "$omarchy_shell/Ui" "$data/app.new/Ui"
ln -s "$omarchy_shell/Commons" "$data/app.new/Commons"
rm -rf "$data/app.old"
[ ! -d "$data/app" ] || mv "$data/app" "$data/app.old"
mv "$data/app.new" "$data/app"
rm -rf "$data/app.old"

say "Adding the Pear Passwords launcher"
cat > "$apps/pear-passwords.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Pear Passwords
Comment=Your iCloud Keychain passwords
Exec=quickshell -p $data/app
Icon=$data/app/icon.svg
Terminal=false
Categories=Utility;Security;
Keywords=password;passwords;keychain;icloud;login;credentials;2fa;pear;
DESKTOP
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$apps" || true

say "Installing the sign-in helper and the 2-hourly sync"
install -m 644 "$here/systemd/pear-passwords-anisette.service" \
               "$here/systemd/pear-passwords-sync.service" \
               "$here/systemd/pear-passwords-sync.timer" "$units/"
systemctl --user daemon-reload
systemctl --user enable --now pear-passwords-anisette.service
systemctl --user enable pear-passwords-sync.timer
systemctl --user start pear-passwords-sync.timer

cat <<DONE

Pear Passwords is installed. Open it from the launcher: search "Pear Passwords".
The first launch asks you to sign in with your Apple Account.

Optional, see README.md:
  * fingerprint unlock through Omarchy's overlay (one polkit file, needs sudo once)
  * a window rule so the app floats at its designed size
DONE
