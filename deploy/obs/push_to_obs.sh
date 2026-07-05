#!/bin/bash
# Push OpenRun packaging to the Open Build Service (build.opensuse.org).
# Prereq: osc credentials configured (run any osc command once interactively).
# Usage: ./push_to_obs.sh [obs-username]

set -e
cd "$(dirname "$0")"

OSC="${OSC:-$(dirname "$0")/../osc-venv/bin/osc}"
OBS_USER="${1:-$($OSC user 2>/dev/null | cut -d: -f1)}"
if [ -z "$OBS_USER" ]; then
    echo "Could not determine OBS username. Pass it as the first argument."
    exit 1
fi
HOME_PROJECT="home:$OBS_USER"
PROJECT="$HOME_PROJECT:openrun"

echo "==> Using OBS user '$OBS_USER', project '$PROJECT'"

sed -e "s/@HOME_PROJECT@/$HOME_PROJECT/" -e "s/@OBS_USER@/$OBS_USER/" prj-meta.xml > /tmp/prj-meta.xml
sed -e "s/@HOME_PROJECT@/$HOME_PROJECT/" pkg-meta.xml > /tmp/pkg-meta.xml

echo "==> Creating/updating project meta"
$OSC meta prj "$PROJECT" -F /tmp/prj-meta.xml

echo "==> Creating/updating package meta"
$OSC meta pkg "$PROJECT" openrun -F /tmp/pkg-meta.xml

echo "==> Checking out package"
rm -rf co && mkdir co && cd co
$OSC checkout "$PROJECT" openrun
cd "$PROJECT/openrun"

echo "==> Copying sources"
cp ../../../pkg/openrun-0.18.3.tar.gz \
   ../../../pkg/openrun.sysusers \
   ../../../pkg/openrun.spec \
   ../../../pkg/openrun.changes \
   ../../../pkg/openrun.dsc \
   ../../../pkg/debian.tar.gz .

$OSC addremove
echo "==> Committing (uploads ~107MB tarball, may take a while)"
$OSC commit -m "OpenRun 0.18.3: initial OBS packaging (vendored sources, rpm + deb)"

echo "==> Done. Build results:"
$OSC results
echo
echo "Watch builds:  $OSC results $PROJECT openrun"
echo "Build log:     $OSC buildlog $PROJECT openrun openSUSE_Tumbleweed x86_64"
echo "Web UI:        https://build.opensuse.org/package/show/$PROJECT/openrun"
