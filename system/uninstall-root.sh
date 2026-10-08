#!/bin/sh
# Pear Passwords 2: remove what the root step installed.
#
#   sudo /usr/local/lib/pear-passwords/libexec/uninstall-root
#   sudo /usr/local/lib/pear-passwords/libexec/uninstall-root --purge <uid>
#
# It runs from its own root-owned installed copy (paths.env and lib/files.sh are inlined into
# it), so there is nothing to stage and nothing a user could swap underneath it.
#
# - The socket and service are stopped and disabled only if their unit files are still the
#   ones Pear installed.
# - Only files whose contents still match the receipt are removed. Anything changed since is
#   listed and kept, and stays in the receipt, so a later install refuses to overwrite it.
# - The pear-passwords user and the pear-client group are removed only when no file outside
#   the receipt is still owned by them. Your vault in /var/lib/pear-passwords is owned by
#   pear-passwords, so without --purge both stay, and reinstalling picks your vault up again.
# - --purge <uid> first deletes /var/lib/pear-passwords/u<uid> (and the copies a "Start over"
#   set aside) after you type the word it asks for. That is your vault on this computer. It
#   cannot be undone; iCloud keeps your passwords, but local history and nicknames are gone.
#
# The user half (anisette helper, browser registrations) is uninstall.sh in the plugin folder;
# run it first.
set -eu

#--- stage-only begin
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$here/paths.env"
. "$here/lib/files.sh"
#--- stage-only end

pp_init_mode

purge_uid=
case ${1:-} in
  "") ;;
  --purge)
    [ $# -eq 2 ] || pp_die "usage: uninstall-root [--purge <uid>]"
    case $2 in ''|*[!0-9]*) pp_die "--purge takes a numeric uid, for example: --purge $(id -u "${SUDO_USER:-root}" 2>/dev/null || echo 1000)" ;; esac
    purge_uid=$2 ;;
  *) pp_die "usage: uninstall-root [--purge <uid>]" ;;
esac

mkdir -p "$(pp_d /var/lib)"
work=$(mktemp -d "$(pp_d /var/lib)/pear-passwords-uninstall.XXXXXX")
trap 'rm -rf "$work"' EXIT

if [ -n "$purge_uid" ]; then
  udir=$(pp_d "$STATE_DIR")/u$purge_uid
  cat <<WARN
This deletes $STATE_DIR/u$purge_uid: the Pear Passwords vault of uid $purge_uid on this
computer. It cannot be undone. Your passwords stay in iCloud, but this computer's sign-in,
local password history and nicknames are gone.
WARN
  printf 'Type "delete" to continue: '
  read -r answer || answer=
  [ "$answer" = delete ] || pp_die "nothing was deleted"
fi

pp_load_receipt "$work/receipt"
if ! pp_have_receipt; then
  echo "There is no Pear Passwords install receipt ($INSTALL_RECEIPT): nothing to remove."
  if [ -z "$purge_uid" ]; then
    exit 0
  fi
fi

# Stop the daemon first, so nothing writes while files go away. Only units Pear installed.
if pp_ours "$UNIT_DIR/$SOCKET_UNIT" && pp_ours "$UNIT_DIR/$SERVICE_UNIT"; then
  pp_sys systemctl disable --now "$SOCKET_UNIT" "$SERVICE_UNIT" || true
  if pp_ours "$UNIT_DIR/$SEAL_SOCKET_UNIT"; then
    pp_sys systemctl disable --now "$SEAL_SOCKET_UNIT" || true
  fi
elif pp_exists "$UNIT_DIR/$SOCKET_UNIT" || pp_exists "$UNIT_DIR/$SERVICE_UNIT"; then
  pp_warn "the Pear units were changed since they were installed; left enabled and in place"
fi

if [ -n "$purge_uid" ]; then
  # u<uid>, and u<uid>.<anything> (a migration's .tmp, a reset's set-aside copy). Never a
  # symlink, never followed: the directory is pear-passwords' own, under a root-owned parent.
  for d in "$udir" "$udir".*; do
    if [ -L "$d" ]; then
      pp_warn "kept $d: it is a symlink"
    elif [ -d "$d" ]; then
      rm -rf -- "$d"
      pp_say "Deleted ${d#"$PP_D"}"
    fi
  done
fi

: > "$work/kept"
# While a vault is still in /var/lib/pear-passwords this command stays installed (and in the
# receipt), so `--purge <uid>` keeps working after an uninstall that kept the vault.
sd=$(pp_d "$STATE_DIR")
vault_left=0
if [ -d "$sd" ] && [ -n "$(ls -A "$sd" 2>/dev/null)" ]; then
  vault_left=1
  awk -F "$PP_TAB" -v u="$UNINSTALL_ROOT" '$3 != u' "$PP_OLD" > "$work/remove"
  awk -F "$PP_TAB" -v u="$UNINSTALL_ROOT" '$3 == u' "$PP_OLD" > "$work/keep.self"
else
  cp "$PP_OLD" "$work/remove"
  : > "$work/keep.self"
fi
pp_remove_entries "$work/remove" "$work/kept" "$VENV"
cat "$work/keep.self" >> "$work/kept"

if [ -s "$work/kept" ]; then
  # What is left stays recorded, so a reinstall sees it as edited rather than as foreign.
  {
    cat "$work/kept"
    awk -F "$PP_TAB" '$1 == "d"' "$PP_OLD" | while IFS="$PP_TAB" read -r kind value path; do
      [ -d "$(pp_d "$path")" ] && printf 'd\t-\t%s\n' "$path"
    done
  } | LC_ALL=C sort -u > "$work/receipt.kept"
  pp_write_receipt "$work/receipt.kept"
  grep -vxF -f "$work/keep.self" "$work/kept" > "$work/edited" || true
  if [ -s "$work/edited" ]; then
    echo "Left in place, changed or replaced since Pear installed them:"
    cut -f3 "$work/edited" | sed 's/^/  /'
  fi
else
  rm -f -- "$(pp_d "$INSTALL_RECEIPT")"
  rmdir -- "$(pp_d "$INSTALL_STATE_DIR")" 2>/dev/null || true
fi
pp_sys systemctl daemon-reload || true

# The user and the groups, only if nothing of theirs is left anywhere.
leftover=
if [ "$vault_left" -eq 1 ]; then
  leftover="$STATE_DIR still holds a vault"
elif [ "$PP_TEST" -eq 0 ] && [ -n "$(pp_getent passwd "$SERVICE_USER")" ]; then
  echo "Checking for files still owned by $SERVICE_USER or $CLIENT_GROUP..."
  for root in /etc /usr /var /opt /srv /run /home /root; do
    [ -d "$root" ] || continue
    f=$(find "$root" -xdev \( -user "$SERVICE_USER" -o -group "$SERVICE_GROUP" \
          -o -group "$CLIENT_GROUP" \) ! -path "$STATE_DIR" -print -quit 2>/dev/null || true)
    if [ -n "$f" ]; then leftover="$f is still owned by it"; break; fi
  done
fi
if [ -n "$leftover" ]; then
  echo "Kept the $SERVICE_USER user and the $CLIENT_GROUP group: $leftover."
  if [ "$vault_left" -eq 1 ]; then
    echo "Reinstalling picks the vault up again. To delete it, and then everything else:"
    echo "  sudo $UNINSTALL_ROOT --purge <uid>     (your uid: id -u)"
  fi
else
  [ -d "$sd" ] && rmdir -- "$sd" 2>/dev/null || true
  if [ -n "$(pp_getent passwd "$SERVICE_USER")" ]; then
    pp_sys userdel "$SERVICE_USER" || pp_warn "userdel $SERVICE_USER failed"
  fi
  for g in "$SERVICE_GROUP" "$CLIENT_GROUP"; do
    if [ -n "$(pp_getent group "$g")" ]; then
      pp_sys groupdel "$g" || pp_warn "groupdel $g failed"
    fi
  done
fi

echo "Pear Passwords' system component is removed."
