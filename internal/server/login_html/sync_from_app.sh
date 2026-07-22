#!/bin/bash
# Sync the form-login page assets from the login dev-harness app in the
# openrundev/apps repo (openrun/login). The app is a dev harness only: install
# it with `openrun app create --dev <apps-repo>/openrun/login /login_dev` on a
# dev server (with system.tailwindcss_command configured) so the tailwind
# watcher regenerates static/gen/css/style.css, verify the preview pages
# (/login_dev/, /system, /error, /expired), then run this script to copy the
# template and generated CSS here for embedding into the openrun binary.
#
# Usage: sync_from_app.sh [path-to-login-app]   (default: sibling checkout)
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
src="${1:-$dir/../../../../apps/openrun/login}"

if [[ ! -f "$src/index.go.html" || ! -f "$src/logout.go.html" || ! -s "$src/static/gen/css/style.css" || ! -f "$src/static/css/login_extra.css" ]]; then
    echo "Error: $src does not contain index.go.html, logout.go.html, static/css/login_extra.css and a non-empty static/gen/css/style.css"
    echo "Install the app in dev mode first so the tailwind CSS is generated"
    exit 1
fi

cp "$src/index.go.html" "$dir/login.go.html"
cp "$src/logout.go.html" "$dir/logout.go.html"
cp "$src/static/gen/css/style.css" "$dir/style.css"
cp "$src/static/css/login_extra.css" "$dir/login_extra.css"
echo "Synced login.go.html, logout.go.html, style.css and login_extra.css from $src"
