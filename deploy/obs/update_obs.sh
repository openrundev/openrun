#!/bin/bash
# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Update the OpenRun package on OBS (build.opensuse.org) for a new release.
# Run from a checkout of the release tag (CI after goreleaser, or locally).
#
# Usage: VERSION=0.18.4 deploy/obs/update_obs.sh
#   VERSION      release version without leading v (default: current exact tag)
#   OBS_PROJECT  target OBS project (default: home:ajayvk:openrun)
#   DRY_RUN=1    prepare everything and show the pending change, skip commit
#
# Requires: osc with credentials configured, go >= version in go.mod, git.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OBS_DIR="$REPO_ROOT/deploy/obs"
OSC=${OSC:-osc}
OBS_PROJECT=${OBS_PROJECT:-home:ajayvk:openrun}
VERSION=${VERSION:-$(git -C "$REPO_ROOT" describe --tags --exact-match 2>/dev/null | sed 's/^v//')}
if [ -z "$VERSION" ]; then
    echo "VERSION not set and HEAD is not on a release tag" >&2
    exit 1
fi
GIT_COMMIT=$(git -C "$REPO_ROOT" rev-parse --short HEAD)

# macOS bsdtar embeds AppleDouble metadata that GNU tar extracts as ._ files,
# which breaks dpkg-source on OBS. Strip all of it.
TARFLAGS=(--owner=0 --group=0)
if [ "$(uname)" = "Darwin" ]; then
    export COPYFILE_DISABLE=1
    TARFLAGS=(--no-xattrs --no-mac-metadata --uid 0 --gid 0)
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/openrun-$VERSION"

echo "==> Exporting source tree for v$VERSION ($GIT_COMMIT)"
mkdir -p "$SRC"
git -C "$REPO_ROOT" archive --format=tar HEAD | tar -x -C "$SRC"

echo "==> Embedding appspecs and list_apps (same prep as goreleaser)"
cd "$SRC"
git clone --single-branch --depth 1 https://github.com/openrundev/appspecs.git
rm -rf appspecs/.git internal/server/appspecs
mv appspecs internal/server
git clone --single-branch --depth 1 https://github.com/openrundev/apps.git
cp internal/server/list_apps/embed.go "$WORK/embed.go"
rm -rf internal/server/list_apps
mv apps/openrun/list_apps internal/server
mv "$WORK/embed.go" internal/server/list_apps/embed.go
rm -rf apps

# Distro toolchains lag behind Go patch releases; the minor version is what
# actually gates the language level, so drop the patch from the go directive.
echo "==> Relaxing go.mod patch version and vendoring modules"
sed -E 's/^go ([0-9]+\.[0-9]+)\.[0-9]+$/go \1/' go.mod > go.mod.new && mv go.mod.new go.mod
go mod vendor
CGO_ENABLED=0 GOTOOLCHAIN=local go build -mod=vendor -o /dev/null ./cmd/openrun

echo "==> Creating source tarball"
cd "$WORK"
tar "${TARFLAGS[@]}" -czf "openrun-$VERSION.tar.gz" "openrun-$VERSION"

echo "==> Checking out OBS package $OBS_PROJECT/openrun"
$OSC checkout "$OBS_PROJECT" openrun
cd "$WORK/$OBS_PROJECT/openrun"

# Preserve changelog history from the previous OBS revision, falling back to
# the files in the repo on first run.
tar -xzf debian.tar.gz -O debian/changelog > "$WORK/prev-deb-changelog" 2>/dev/null \
    || cp "$OBS_DIR/debian/changelog" "$WORK/prev-deb-changelog"
cp openrun.changes "$WORK/prev.changes" 2>/dev/null \
    || cp "$OBS_DIR/openrun.changes" "$WORK/prev.changes"

# openrun.service is intentionally not uploaded: the spec and debian/rules
# install deploy/init/openrun.service from the source tarball
rm -f ./*.tar.gz ./*.dsc openrun.spec openrun.service openrun.sysusers openrun.changes
cp "$WORK/openrun-$VERSION.tar.gz" .
cp "$OBS_DIR/openrun.sysusers" .

sed -e "s/^Version:.*/Version:        $VERSION/" \
    -e "s/^%global git_commit .*/%global git_commit $GIT_COMMIT/" \
    "$OBS_DIR/openrun.spec" > openrun.spec

{
    echo "-------------------------------------------------------------------"
    echo "$(date -u '+%a %b %e %H:%M:%S UTC %Y') - Ajay Kidave <contact@openrun.dev>"
    echo
    echo "- Update to version $VERSION (commit $GIT_COMMIT)"
    echo
    cat "$WORK/prev.changes"
} > openrun.changes

echo "==> Building debian.tar.gz"
cp -R "$OBS_DIR/debian" "$WORK/debian"
sed -e "s/^GIT_COMMIT :=.*/GIT_COMMIT := $GIT_COMMIT/" \
    -e "s/^VERSION :=.*/VERSION := $VERSION/" \
    "$OBS_DIR/debian/rules" > "$WORK/debian/rules"
chmod 755 "$WORK/debian/rules" "$WORK/debian/postinst"
{
    echo "openrun ($VERSION-1) unstable; urgency=medium"
    echo
    echo "  * Update to version $VERSION (commit $GIT_COMMIT)"
    echo
    echo " -- Ajay Kidave <contact@openrun.dev>  $(date -R -u)"
    echo
    cat "$WORK/prev-deb-changelog"
} > "$WORK/debian/changelog"
tar -C "$WORK" "${TARFLAGS[@]}" -czf debian.tar.gz debian

sed -e "s/^Version:.*/Version: $VERSION-1/" \
    -e "s/^DEBTRANSFORM-TAR:.*/DEBTRANSFORM-TAR: openrun-$VERSION.tar.gz/" \
    "$OBS_DIR/openrun.dsc" > openrun.dsc

$OSC addremove
if [ "${DRY_RUN:-}" = "1" ]; then
    echo "==> DRY_RUN=1, skipping commit. Pending change:"
    $OSC status
    exit 0
fi

echo "==> Committing to OBS"
$OSC commit -m "Update to version $VERSION (commit $GIT_COMMIT)"
$OSC results
echo "Web UI: https://build.opensuse.org/package/show/$OBS_PROJECT/openrun"
