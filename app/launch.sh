#!/bin/sh
# Opens Pear Passwords. The launcher entry runs this, not quickshell directly.
#
# The window is laid out for 960x640 and floats centred at full opacity. Hyprland decides
# that when a window maps, so the rules are registered here, just before it opens, through
# `hyprctl eval` - nothing is written to your Hyprland config, nothing needs a reload, and
# uninstalling leaves nothing behind. They are registered once per Hyprland session.
here="$(dirname "$(readlink -f "$0")")"

if [ -n "$HYPRLAND_INSTANCE_SIGNATURE" ] && command -v hyprctl >/dev/null 2>&1; then
  hyprctl eval '
if not _G.__pear_passwords_rules then
  local m = { class = [[^org\.quickshell$]], title = [[^Pear Passwords$]] }
  hl.window_rule({ match = m, tag = [[-default-opacity]] })
  hl.window_rule({ match = m, opacity = [[1 override 1 override]] })
  hl.window_rule({ match = m, float = true })
  hl.window_rule({ match = m, size = [[960 640]] })
  hl.window_rule({ match = m, center = true })
  _G.__pear_passwords_rules = true
end' >/dev/null 2>&1 || true
fi

exec quickshell -p "$here"
