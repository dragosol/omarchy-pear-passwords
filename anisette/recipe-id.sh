#!/bin/sh
# Print the 12-hex-digit id of Pear's own build recipe for the anisette image: the sha256 of the
# sha256sum lines of every file in this directory that goes into it, in a fixed order. It is part
# of the image tag, so systemd/pear-passwords-anisette.service names it too (a test keeps them equal).
set -eu
cd "$(dirname "$0")"
sha256sum Containerfile entrypoint.sh fetch-coreadi.py coreadi.sha256 microsoft-root-ca-2011.pem \
    loader/Cargo.toml loader/Cargo.lock loader/src/main.rs | sha256sum | cut -c1-12
