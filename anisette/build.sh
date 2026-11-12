#!/usr/bin/env bash
# Build the anisette image: Pear's CoreADI loader against pinned apple-crates source.
#
# Usage: anisette/build.sh [apple-crates-commit-sha]
#
# With no argument it builds the revision pinned in Containerfile, which is the one
# systemd/pear-passwords-anisette.service runs. Takes a few minutes the first time: it compiles
# the loader and its crates for Windows. See docs/anisette-provenance.md.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The Containerfile holds the pinned revision; nothing here keeps a second copy of it that
# could drift.
REV="${1:-$(sed -n 's/^ARG APPLE_CRATES_REV=\([0-9a-f]\{40\}\)$/\1/p' "$HERE/Containerfile")}"
if [[ ! "$REV" =~ ^[0-9a-f]{40}$ ]]; then
    echo "anisette: refusing to build from '$REV': need a full 40-character commit SHA" >&2
    exit 1
fi

# Pear's own files (the loader, the gate, the digests) change the image without changing the
# apple-crates revision, so their hash is part of the tag and a label. install.sh computes the
# same value with recipe-id.sh.
RECIPE="$("$HERE/recipe-id.sh")"
IMAGE="localhost/pear-passwords-anisette:$REV-$RECIPE"

echo "anisette: building $IMAGE from apple-crates@$REV with recipe $RECIPE"
podman build --build-arg "APPLE_CRATES_REV=$REV" --build-arg "PEAR_RECIPE=$RECIPE" \
    -t "$IMAGE" -f "$HERE/Containerfile" "$HERE"

# The image has to be able to say what it was built from.
got="$(podman image inspect --format '{{index .Labels "io.github.dragosol.pear-passwords.apple-crates.revision"}}' "$IMAGE")"
got_recipe="$(podman image inspect --format '{{index .Labels "io.github.dragosol.pear-passwords.recipe"}}' "$IMAGE")"
if [[ "$got_recipe" != "$RECIPE" ]]; then
    echo "anisette: built image claims recipe '$got_recipe', expected '$RECIPE'" >&2
    exit 1
fi
if [[ "$got" != "$REV" ]]; then
    echo "anisette: built image claims apple-crates '$got', expected '$REV'" >&2
    exit 1
fi

echo
echo "anisette: built $IMAGE"
echo "  apple-crates: $got"
echo "  image id: $(podman image inspect --format '{{.Id}}' "$IMAGE")"
echo
echo "The image id is specific to this build: apt and the Rust toolchain's target are resolved"
echo "at build time, so two machines building the same commit do not get byte-identical images."
echo "The revision and recipe labels, not the id, are what is pinned."
