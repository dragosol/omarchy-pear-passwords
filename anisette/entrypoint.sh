#!/bin/sh
# Gate Apple's CoreADI64.dll on the recorded digest, then start the loader under Wine.
#
# The DLL is fetched here, on first start, from the Microsoft Store (fetch-coreadi.py), and it
# only reaches the volume if the package and the DLL match coreadi.sha256. A DLL already in the
# volume is checked again on every start: an earlier start having written it is not evidence,
# since the volume outlives the image and is writable. A mismatch stops the server.
set -eu

DATA=/home/pear/data
DLLDIR="$DATA/coreadi"
DIGESTS=/opt/pear/coreadi.sha256

if [ "$(uname -m)" != "x86_64" ]; then
    echo "anisette: refusing to start on $(uname -m): CoreADI64.dll is an x86_64 Windows DLL" >&2
    exit 1
fi
[ "$#" -eq 0 ] || { echo "anisette: takes no arguments" >&2; exit 1; }

# Wine wants a private runtime directory; the container has no session to provide one.
export XDG_RUNTIME_DIR="$HOME/.run"
mkdir -p -m 0700 "$XDG_RUNTIME_DIR"

mkdir -p "$DLLDIR"
if [ ! -f "$DLLDIR/CoreADI64.dll" ]; then
    python3 -I /opt/pear/fetch-coreadi.py "$DLLDIR"
fi
want="$(sed -n 's/^\([0-9a-f]\{64\}\)  CoreADI64\.dll$/\1/p' "$DIGESTS")"
if [ "$(sha256sum "$DLLDIR/CoreADI64.dll" | cut -d' ' -f1)" != "$want" ]; then
    echo "anisette: REFUSING TO START" >&2
    echo "  $DLLDIR/CoreADI64.dll does not match anisette/coreadi.sha256." >&2
    echo "  docs/anisette-provenance.md says how to check it and fetch it again." >&2
    exit 1
fi

# The Wine prefix is the machine: CoreADI keeps its provisioning in it (ProgramData/Apple
# Computer/iTunes/adi) and derives the device id partly from it, so it lives in the volume and
# is made only once.
if [ ! -f "$WINEPREFIX/system.reg" ]; then
    echo "anisette: creating the Wine prefix"
    wine wineboot --init
    wineserver --wait
fi

# Inside the container the loader listens on all of the container's addresses; the unit
# publishes the port on the host's 127.0.0.1 only.
exec wine /opt/pear/pear-coreadi.exe --dll 'Z:\home\pear\data\coreadi\CoreADI64.dll' \
    --bind 0.0.0.0 --port 6969
