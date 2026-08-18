#!/bin/sh
# Regenerates the embedded fallback stylesheet for action apps
# (internal/app/action/astatic/style.css) from input.css, scanning the
# action templates and astatic JS for tailwind/daisyui classes.
#
# Requires the standalone tailwindcss v4 CLI (TAILWIND_CMD, default
# "tailwindcss" from PATH). The prebundled daisyui plugins are downloaded
# into ./cache/ on first run (same pinned URLs as the server defaults in
# internal/system/openrun.default.toml).
set -e
cd "$(dirname "$0")"

TAILWIND_CMD="${TAILWIND_CMD:-tailwindcss}"
DAISYUI_URL="${DAISYUI_URL:-https://github.com/saadeghi/daisyui/releases/download/v5.6.10/daisyui.js}"
DAISYUI_THEME_URL="${DAISYUI_THEME_URL:-https://github.com/saadeghi/daisyui/releases/download/v5.6.10/daisyui-theme.js}"

mkdir -p cache
[ -s cache/daisyui.js ] || curl -fsSL -o cache/daisyui.js "$DAISYUI_URL"
[ -s cache/daisyui-theme.js ] || curl -fsSL -o cache/daisyui-theme.js "$DAISYUI_THEME_URL"

"$TAILWIND_CMD" -i input.css -o ../astatic/style.css --minify
echo "Generated $(cd ../astatic && pwd)/style.css"
