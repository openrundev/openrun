#!/bin/sh
# Authenticode-sign Windows binaries with osslsigncode. Invoked by goreleaser
# as a per-binary build post hook; no-op for non-Windows binaries so the same
# hook can run for every platform.
#
# Requires:
#   WINDOWS_CERT_PFX      - base64 encoded PKCS#12 (.pfx) code signing certificate
#   WINDOWS_CERT_PASSWORD - password for the pfx file
#
# If WINDOWS_CERT_PFX is not set (local/snapshot builds), signing is skipped.
set -eu

BINARY="$1"

case "$BINARY" in
*.exe) ;;
*) exit 0 ;;
esac

if [ -z "${WINDOWS_CERT_PFX:-}" ]; then
    echo "WINDOWS_CERT_PFX not set, skipping signing of $BINARY"
    exit 0
fi

if ! command -v osslsigncode >/dev/null 2>&1; then
    echo "osslsigncode not found, cannot sign $BINARY" >&2
    exit 1
fi

CERT_FILE=$(mktemp)
trap 'rm -f "$CERT_FILE" "$BINARY.signed"' EXIT
printf '%s' "$WINDOWS_CERT_PFX" | base64 -d >"$CERT_FILE"

osslsigncode sign \
    -pkcs12 "$CERT_FILE" \
    -pass "${WINDOWS_CERT_PASSWORD:-}" \
    -n "OpenRun" \
    -i "https://openrun.dev" \
    -h sha256 \
    -ts http://timestamp.digicert.com \
    -in "$BINARY" \
    -out "$BINARY.signed"

mv "$BINARY.signed" "$BINARY"
echo "Signed $BINARY"
