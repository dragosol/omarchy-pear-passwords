#!/usr/bin/env bash
# Check the Apple libraries in the live anisette volume against the digests
# recorded in anisette/apple-libs.sha256.
#
# A mismatch is not automatically a compromise: Apple ships a new Apple Music
# APK and the next first-start fetch picks it up. It means the bytes being
# loaded are not the bytes that were reviewed, and someone should look.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VOL="${ANISETTE_VOLUME:-icp-anisette}"

libdir="$(podman volume inspect "$VOL" --format '{{.Mountpoint}}' 2>/dev/null)/lib" || {
    echo "anisette: no podman volume '$VOL'; nothing to check yet" >&2
    exit 1
}

status=0
while read -r want name; do
    [[ -z "${want:-}" || "$want" == \#* ]] && continue
    f="$libdir/$name"
    if [[ ! -f "$f" ]]; then
        echo "MISSING  $name (not downloaded yet)"
        status=1
        continue
    fi
    got="$(podman unshare sha256sum "$f" | cut -d' ' -f1)"
    if [[ "$got" == "$want" ]]; then
        echo "OK       $name"
    else
        echo "CHANGED  $name"
        echo "         recorded $want"
        echo "         on disk  $got"
        status=1
    fi
done < "$HERE/apple-libs.sha256"

exit "$status"
