#!/bin/sh
# Swap the freshly built Windows binary for the SignPath-signed copy produced
# by the sign-windows job. Invoked by goreleaser as a per-binary build post
# hook, before archiving, so the exe inside the winget zip is signed; no-op
# for non-Windows binaries so the same hook can run for every platform.
#
# Requires:
#   SIGNED_WINDOWS_BINARY - path to the Authenticode-signed openrun.exe
#
# If SIGNED_WINDOWS_BINARY is not set (local/snapshot builds), signing is
# skipped.
set -eu

BINARY="$1"

case "$BINARY" in
*.exe) ;;
*) exit 0 ;;
esac

if [ -z "${SIGNED_WINDOWS_BINARY:-}" ]; then
    echo "SIGNED_WINDOWS_BINARY not set, skipping signing of $BINARY"
    exit 0
fi

if [ ! -f "$SIGNED_WINDOWS_BINARY" ]; then
    echo "SIGNED_WINDOWS_BINARY=$SIGNED_WINDOWS_BINARY not found" >&2
    exit 1
fi

cp "$SIGNED_WINDOWS_BINARY" "$BINARY"
echo "Replaced $BINARY with SignPath-signed binary"
