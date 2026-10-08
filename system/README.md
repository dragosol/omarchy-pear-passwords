# system/

Everything the root install step puts outside `$HOME`. The values of every path and name are in
`paths.env` (shell) and `backend/icp/daemon/paths.py` (Python); a test keeps them equal.

| Path in this repo | Installed as | Owner |
|---|---|---|
| `paths.env` | read by the scripts below (not installed) | foundation |
| `units/pear-passwordsd.socket`, `units/pear-passwordsd.service` | `/etc/systemd/system/` | WP1 |
| `sysusers.d/pear-passwords.conf` | `/etc/sysusers.d/pear-passwords.conf` | WP1 |
| `tmpfiles.d/pear-passwords.conf` | `/etc/tmpfiles.d/pear-passwords.conf` | WP1 |
| `libexec/pear-passwordsd` | `$P/libexec/pear-passwordsd` (ABI check, then the daemon; exit 78 on a Python minor bump) | WP1 |
| `libexec/pear-autofill-host` | `$P/libexec/pear-autofill-host` (`exec $P/libexec/pear-exec autofill`, browser arguments dropped) | WP6 |
| `bin/pear-passwords-autofill` | `/usr/local/bin/pear-passwords-autofill` (opt-in `register` / `unregister`, runs as the user) | WP6 |
| `native-messaging/io.github.dragosol.pearpasswords.json.in` | not installed; the template `register` fills in | WP6 |
| `install-root.sh`, `uninstall-root.sh`, `lib/files.sh` | run from the stage; `uninstall-root.sh` also as `$P/libexec/uninstall-root` | WP5 |

The polkit policy is in `polkit/` (WP1) and is installed as
`/usr/share/polkit-1/actions/io.github.dragosol.pearpasswords.policy`. `pear-exec` is built from
`native/pear-exec.c` (WP4).

No browser native-messaging manifest is ever written by an installer. See
`docs/WORKPACKAGES.md` section 4.5.
