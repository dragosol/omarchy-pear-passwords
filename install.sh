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
#
# --app-only installs just the window and its launcher, and nothing else: no virtualenv, no
# services, no podman. The plugin runs it that way on first load so that `omarchy plugin add`
# alone gives you something you can open, which then asks for the rest. Running it with no
# arguments is the full install and is unchanged.
set -euo pipefail

app_only=0
[ "${1:-}" = "--app-only" ] && app_only=1

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
data="$HOME/.local/share/pear-passwords"
apps="$HOME/.local/share/applications"
units="$HOME/.config/systemd/user"
omarchy_shell="/usr/share/omarchy/shell"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "run this as your own user, not root - nothing here needs root"

needed="python3 podman quickshell systemctl"
[ "$app_only" -eq 1 ] && needed="quickshell"
for cmd in $needed; do
  command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' is required but not installed"
done
[ -d "$omarchy_shell/Ui" ] && [ -d "$omarchy_shell/Commons" ] \
  || die "Omarchy's shell components were not found in $omarchy_shell"
command -v wl-copy >/dev/null 2>&1 || warn "wl-clipboard is not installed: copying to the clipboard will not work"
command -v notify-send >/dev/null 2>&1 || warn "notify-send is not installed: sign-in reminders will not show"

mkdir -p "$data" "$apps" "$units"

if [ "$app_only" -eq 0 ]; then
say "Installing the backend into $data/venv"
# Every package is pinned to an exact version and checked against a committed hash, so what
# installs is byte-for-byte what was reviewed:
#   backend/build-requirements.lock  the build toolchain (setuptools)
#   backend/requirements.lock        every runtime dependency, transitive ones included
# Wheels only (--only-binary): no dependency is ever built from source, so no build step can
# fetch tools of its own. The backend itself is then built with the locked setuptools and no
# network (--no-build-isolation --no-index). A fresh virtualenv each time means nothing left
# over from an earlier install survives into this one. (It is rebuilt in place: a virtualenv
# cannot be renamed, its scripts carry their own path.)
rm -rf "$data/venv"
python3 -m venv "$data/venv"
pip_install() { "$data/venv/bin/python" -m pip install --quiet --disable-pip-version-check --no-input "$@"; }
pip_install --require-hashes --only-binary :all: --no-deps -r "$here/backend/build-requirements.lock"
pip_install --require-hashes --only-binary :all: --no-deps -r "$here/backend/requirements.lock"
pip_install --no-deps --no-build-isolation --no-index "$here/backend"
"$data/venv/bin/python" -m pip check --disable-pip-version-check >/dev/null \
  || die "installed packages are inconsistent with the lock files"
fi

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
Comment=Your passwords on iCloud
Exec=$data/app/launch.sh
Icon=$data/app/icon.svg
Terminal=false
Categories=Utility;Security;
Keywords=password;passwords;icloud;login;credentials;2fa;pear;
DESKTOP
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$apps" || true

# Where this checkout is, so the window can offer to finish the install from inside itself.
printf '%s\n' "$here" > "$data/app/.source"

if [ "$app_only" -eq 1 ]; then
  echo "The Pear Passwords window is installed. Open it and it will set up the rest."
  exit 0
fi

say "Building the anisette server from pinned source"
# The sign-in helper is third-party code (Dadoum/anisette-v3-server). The published image on
# Docker Hub has no provenance labels and ships a binary built elsewhere, so it is built here
# instead, from the one upstream commit pinned in anisette/Containerfile. Takes a couple of
# minutes the first time; after that the image is reused. See docs/anisette-provenance.md.
anisette_rev="$(sed -n 's/^ARG ANISETTE_REV=\([0-9a-f]\{40\}\)$/\1/p' "$here/anisette/Containerfile")"
[ -n "$anisette_rev" ] || die "could not read the pinned anisette revision from anisette/Containerfile"
anisette_image="localhost/pear-passwords-anisette:$anisette_rev"
# A unit pointing at a tag nobody builds would fail at start with a bare "image not known".
grep -qF "$anisette_image" "$here/systemd/pear-passwords-anisette.service" \
  || die "systemd/pear-passwords-anisette.service does not run $anisette_image"
if [ "$(podman image inspect --format '{{index .Labels "org.opencontainers.image.revision"}}' \
        "$anisette_image" 2>/dev/null)" = "$anisette_rev" ]; then
  say "Already built at ${anisette_rev:0:12}, reusing it"
else
  "$here/anisette/build.sh" "$anisette_rev"
fi

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

Optional, see README.md: a dedicated unlock prompt instead of pkexec
(one polkit file, needs sudo once).
DONE
