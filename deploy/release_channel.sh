#!/usr/bin/env bash
# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Release channel checks shared by the release workflow and the Makefile.
#
# The server has two release channels that share the v tag namespace:
#   tip  vMAJOR.YYMM.PATCH   from main, PATCH is DD*10+V (see the Makefile)
#   pro  vMAJOR.MINOR.PATCH  from a pro-MAJOR.MINOR branch, MINOR is 0 to 999
# A Tip minor always has four digits and a Pro minor never does. The v0.x
# tags from before the channels existed count as Tip releases.
#
# internal/types/CHANNEL is the source of truth for the channel of a source
# tree, the tag shape is only used to validate it. A Pro branch differs from
# main in three files that main never changes: internal/types/CHANNEL (pro),
# deploy/PRO_BASE (where the branch was cut) and LICENSE.
#
# Usage: deploy/release_channel.sh <command> [args]
#   channel                 print the channel of this source tree
#   ci-env <tag>            validate a pushed release tag against HEAD and
#                           print KEY=value lines for the release workflow.
#                           OPENRUN_LATEST says if the tag is the highest
#                           version of its channel
#   goreleaser-config <out> write the goreleaser config for this channel to
#                           <out>, a path outside the working tree
#   pro-branch <X.Y>        cut the pro-X.Y branch from the current main
#                           commit and create its overlay commit (not pushed)
#   pro-next [<version>]    print the next Pro version for this pro-X.Y
#                           branch, or validate the one given. Tags nothing
#   pro-release [<version>] tag the next Pro version on this pro-X.Y branch
#                           and push the tag. RELEASE_NO_PUSH=1 skips the push
#
# Environment:
#   MAIN_REF   ref of the Tip branch, default origin/main

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

CHANNEL_FILE=internal/types/CHANNEL
PRO_BASE_FILE=deploy/PRO_BASE
PRO_LICENSE_FILE=deploy/pro/pro.txt
MAIN_REF=${MAIN_REF:-origin/main}
LICENSE_TIP="Apache-2.0"
LICENSE_PRO="LicenseRef-PolyForm-Free-Trial-1.0.0"

tip_re='^v([1-9][0-9]*)\.([0-9]{2})(0[1-9]|1[0-2])\.([1-9][0-9]{1,2})$'
legacy_re='^v0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
pro_re='^v([1-9][0-9]*)\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]*)$'
line_re='^([1-9][0-9]*)\.(0|[1-9][0-9]{0,2})$'

die() {
    echo "Error: $*" >&2
    exit 1
}

# is_tip_tag <tag>: a Tip release tag, the patch has to be a day of the
# month followed by the daily sequence digit
is_tip_tag() {
    [[ "$1" =~ $tip_re ]] || return 1
    local day=$((10#${BASH_REMATCH[4]} / 10))
    ((day >= 1 && day <= 31))
}

is_legacy_tag() {
    [[ "$1" =~ $legacy_re ]]
}

is_pro_tag() {
    [[ "$1" =~ $pro_re ]]
}

read_channel() {
    [[ -f "$CHANNEL_FILE" ]] || die "$CHANNEL_FILE is missing"
    local channel
    channel=$(tr -d '[:space:]' <"$CHANNEL_FILE")
    case "$channel" in
    tip | pro) echo "$channel" ;;
    *) die "$CHANNEL_FILE must hold tip or pro, found '$channel'" ;;
    esac
}

# pro_base <key>: print a value from deploy/PRO_BASE (line, tag or commit)
pro_base() {
    [[ -f "$PRO_BASE_FILE" ]] || die "$PRO_BASE_FILE is missing, a Pro branch records where it was cut from main there"
    local value
    value=$(sed -n "s/^$1=//p" "$PRO_BASE_FILE" | head -n 1 | tr -d '[:space:]')
    [[ -n "$value" ]] || die "$PRO_BASE_FILE has no $1= entry"
    echo "$value"
}

# sort_versions: sort v tags on stdin by version, ascending
sort_versions() {
    sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | sed 's/^/v/'
}

server_tags() {
    git tag -l 'v[0-9]*'
}

# tip_tags: every Tip release tag in version order, including the v0.x tags
tip_tags() {
    local tag
    server_tags | while read -r tag; do
        if is_tip_tag "$tag" || is_legacy_tag "$tag"; then
            echo "$tag"
        fi
    done | sort_versions
}

# pro_line_tags <X.Y>: the Pro release tags of one maintenance line, in version order
pro_line_tags() {
    local tag
    server_tags | while read -r tag; do
        if is_pro_tag "$tag" && [[ "${tag%.*}" == "v$1" ]]; then
            echo "$tag"
        fi
    done | sort_versions
}

# previous_in <tag>: from the version sorted tags on stdin, print the one just before <tag>
previous_in() {
    local tag prev=""
    while read -r tag; do
        if [[ "$tag" == "$1" ]]; then
            break
        fi
        prev="$tag"
    done
    echo "$prev"
}

# upstream_tip_tag <commit>: the highest Tip tag contained in <commit>
upstream_tip_tag() {
    local tag best=""
    while read -r tag; do
        if git merge-base --is-ancestor "$tag^{commit}" "$1" 2>/dev/null; then
            best="$tag"
        fi
    done < <(tip_tags)
    echo "$best"
}

require_ref() {
    git rev-parse -q --verify "$1^{commit}" >/dev/null || die "$2"
}

require_ancestor() {
    git merge-base --is-ancestor "$1^{commit}" "$2" || die "$3"
}

require_clean() {
    [[ -z "$(git status --porcelain)" ]] || die "the working tree has uncommitted changes, commit or stash them first"
}

# require_pro_tree <X.Y> <commit>: checks common to every Pro release, in CI
# and before tagging. The commit has to be a Pro tree of that line which is
# not part of main. Prints the base Tip tag
require_pro_tree() {
    local line="$1" commit="$2" base_line base_tag base_commit
    [[ "$(read_channel)" == "pro" ]] || die "$CHANNEL_FILE is not pro, Pro releases are made from a pro-X.Y branch"
    base_line=$(pro_base line)
    base_tag=$(pro_base tag)
    base_commit=$(pro_base commit)
    [[ "$base_line" == "$line" ]] || die "$PRO_BASE_FILE is for the $base_line line, not $line"
    is_tip_tag "$base_tag" || is_legacy_tag "$base_tag" || die "$PRO_BASE_FILE tag '$base_tag' is not a Tip release tag"
    require_ref "refs/tags/$base_tag" "$PRO_BASE_FILE tag $base_tag does not exist"
    require_ref "$base_commit" "$PRO_BASE_FILE commit $base_commit does not exist"
    require_ancestor "refs/tags/$base_tag" "$base_commit" "$PRO_BASE_FILE tag $base_tag is not contained in its commit $base_commit"
    require_ancestor "$base_commit" "$commit" "the release commit does not contain the branch base $base_commit from $PRO_BASE_FILE"
    require_ref "$MAIN_REF" "$MAIN_REF not found, it is needed to check that a Pro release is not on main"
    require_ancestor "$base_commit" "$MAIN_REF" "$PRO_BASE_FILE commit $base_commit is not on $MAIN_REF"
    if git merge-base --is-ancestor "$commit" "$MAIN_REF"; then
        die "the release commit is on $MAIN_REF, a Pro release must be on a commit that only a pro-$line branch has"
    fi
    echo "$base_tag"
}

# pro_previous_tag <tag> <base_tag> <commit>: the changelog baseline for a Pro
# release, the previous release of the same line or the branch base for the
# first one
pro_previous_tag() {
    local line previous
    line="${1#v}"
    line="${line%.*}"
    previous=$(pro_line_tags "$line" | previous_in "$1")
    if [[ -z "$previous" ]]; then
        previous="$2"
    fi
    require_ancestor "refs/tags/$previous" "$3" "the previous release $previous is not contained in the release commit"
    echo "$previous"
}

cmd_channel() {
    read_channel
}

cmd_ci_env() {
    local tag="${1:-}" channel head previous="" package license base_tag line highest other
    [[ -n "$tag" ]] || die "ci-env needs the release tag"
    channel=$(read_channel)
    head=$(git rev-parse HEAD)
    require_ref "refs/tags/$tag" "tag $tag does not exist"
    [[ "$(git rev-parse "refs/tags/$tag^{commit}")" == "$head" ]] || die "tag $tag does not point at the checked out commit"

    if [[ "$channel" == "tip" ]]; then
        is_tip_tag "$tag" || die "$tag is not a Tip version (vMAJOR.YYMM.PATCH) but $CHANNEL_FILE is tip"
        require_ref "$MAIN_REF" "$MAIN_REF not found, it is needed to check that a Tip release is on main"
        require_ancestor "$head" "$MAIN_REF" "the release commit is not on $MAIN_REF, Tip releases are made from main"
        previous=$(tip_tags | previous_in "$tag")
        if [[ -n "$previous" ]]; then
            require_ancestor "refs/tags/$previous" "$head" "the previous Tip release $previous is not contained in the release commit"
        fi
        package=openrun
        license=$LICENSE_TIP
        highest=$(tip_tags | tail -n 1)
    else
        is_pro_tag "$tag" || die "$tag is not a Pro version (vMAJOR.MINOR.PATCH, minor 0 to 999) but $CHANNEL_FILE is pro"
        line="${tag#v}"
        line="${line%.*}"
        base_tag=$(require_pro_tree "$line" "$head")
        require_ref "origin/pro-$line" "branch origin/pro-$line not found"
        require_ancestor "$head" "origin/pro-$line" "the release commit is not on the pro-$line branch"
        previous=$(pro_previous_tag "$tag" "$base_tag" "$head")
        package=openrun-pro
        license=$LICENSE_PRO
        highest=$(server_tags | while read -r other; do
            if is_pro_tag "$other"; then echo "$other"; fi
        done | sort_versions | tail -n 1)
    fi

    echo "OPENRUN_CHANNEL=$channel"
    echo "OPENRUN_PACKAGE=$package"
    echo "OPENRUN_LICENSE=$license"
    # false for a patch release of an older line, made after a higher version
    # of the channel was released. Package managers that hold one version per
    # package, like the Homebrew formula, are not updated by such a release
    if [[ "$highest" == "$tag" ]]; then
        echo "OPENRUN_LATEST=true"
    else
        echo "OPENRUN_LATEST=false"
    fi
    # Both tags are passed to goreleaser explicitly. Without the current tag
    # an SDK tag on the same commit can be picked, and without the previous
    # tag a Tip tag merged into a Pro branch can become the changelog baseline
    echo "GORELEASER_CURRENT_TAG=$tag"
    echo "GORELEASER_PREVIOUS_TAG=$previous"
}

# The nfpm conflicts and license fields are the channel specific values in
# .goreleaser.yaml that goreleaser does not template. They are on two marked
# lines holding the Tip values, and the config used for a release is a copy
# with those lines set for the channel. Everything else in the config follows
# internal/types/CHANNEL by itself
cmd_goreleaser_config() {
    local out="${1:-}" channel i tip_line pro_line
    # Fields that goreleaser does not template. Each is a marked line in
    # .goreleaser.yaml holding the Tip value, replaced for a Pro release
    local tip_lines=(
        "    license: $LICENSE_TIP # channel-license"
        "      - openrun-pro # channel-conflicts"
        "    package_identifier: OpenRunDev.OpenRun # channel-winget-id"
    )
    local pro_lines=(
        "    license: $LICENSE_PRO # channel-license"
        "      - openrun # channel-conflicts"
        "    package_identifier: OpenRunDev.OpenRunPro # channel-winget-id"
    )
    [[ -n "$out" ]] || die "goreleaser-config needs the output path"
    channel=$(read_channel)
    for tip_line in "${tip_lines[@]}"; do
        [[ "$(grep -c -x -F -e "$tip_line" .goreleaser.yaml)" == "1" ]] ||
            die ".goreleaser.yaml must have exactly one '$tip_line' line"
    done
    cp .goreleaser.yaml "$out"
    if [[ "$channel" == "tip" ]]; then
        return
    fi
    for i in "${!tip_lines[@]}"; do
        tip_line=${tip_lines[$i]}
        pro_line=${pro_lines[$i]}
        sed -e "s|^$tip_line\$|$pro_line|" "$out" >"$out.tmp"
        mv "$out.tmp" "$out"
        grep -q -x -F -e "$pro_line" "$out" || die "failed to set '$pro_line' in $out"
    done
}

cmd_pro_branch() {
    local line="${1:-}" branch base_commit base_tag
    [[ "$line" =~ $line_re ]] || die "pro-branch needs the maintenance line as MAJOR.MINOR with the minor from 0 to 999, e.g. 1.3"
    branch="pro-$line"
    require_clean
    [[ "$(git branch --show-current)" == "main" ]] || die "pro-branch must be run on main"
    [[ "$(read_channel)" == "tip" ]] || die "$CHANNEL_FILE is not tip on this branch"
    [[ -f "$PRO_LICENSE_FILE" ]] || die "$PRO_LICENSE_FILE is missing"
    git fetch --quiet --prune --tags origin
    [[ "$(git rev-parse HEAD)" == "$(git rev-parse "$MAIN_REF")" ]] || die "main is not synchronized with $MAIN_REF"
    if git rev-parse -q --verify "refs/heads/$branch" >/dev/null || git rev-parse -q --verify "refs/remotes/origin/$branch" >/dev/null; then
        die "branch $branch already exists"
    fi
    if [[ -n "$(pro_line_tags "$line")" ]]; then
        die "the $line line already has release tags"
    fi
    base_commit=$(git rev-parse HEAD)
    base_tag=$(upstream_tip_tag "$base_commit")
    [[ -n "$base_tag" ]] || die "no Tip release tag is contained in main"

    git switch -q -c "$branch"
    echo pro >"$CHANNEL_FILE"
    cat >"$PRO_BASE_FILE" <<EOF
line=$line
tag=$base_tag
commit=$base_commit
EOF
    cp "$PRO_LICENSE_FILE" LICENSE
    git add "$CHANNEL_FILE" "$PRO_BASE_FILE" LICENSE
    git commit -q -m "Pro $line branch overlay, based on $base_tag"
    echo "Created branch $branch from $base_tag (${base_commit:0:12}) with the Pro overlay commit, not pushed."
    echo "Publish it with: git push -u origin $branch"
}

# pro_next <version>: sets the globals used by pro-next and pro-release
pro_next() {
    local given="${1#v}" branch latest patch=0
    branch=$(git branch --show-current)
    [[ "$branch" == pro-* ]] || die "Pro releases are made from a pro-X.Y branch, this is '$branch'"
    pro_line="${branch#pro-}"
    [[ "$pro_line" =~ $line_re ]] || die "branch '$branch' is not named pro-MAJOR.MINOR"
    pro_commit=$(git rev-parse HEAD)
    pro_base_tag=$(require_pro_tree "$pro_line" "$pro_commit")
    latest=$(pro_line_tags "$pro_line" | tail -n 1)
    if [[ -n "$latest" ]]; then
        patch=$((10#${latest##*.} + 1))
    fi
    pro_version="$pro_line.$patch"
    if [[ -n "$given" && "$given" != "$pro_version" ]]; then
        die "version '$1' is not the next release of the $pro_line line, the next one is $pro_version"
    fi
    pro_previous=$(pro_previous_tag "v$pro_version" "$pro_base_tag" "$pro_commit")
}

cmd_pro_next() {
    pro_next "${1:-}"
    echo "v$pro_version"
}

cmd_pro_release() {
    local branch upstream
    require_clean
    branch=$(git branch --show-current)
    git fetch --quiet --prune --tags origin
    require_ref "origin/$branch" "branch $branch is not pushed to origin"
    [[ "$(git rev-parse HEAD)" == "$(git rev-parse "origin/$branch")" ]] || die "$branch is not synchronized with origin/$branch"
    pro_next "${1:-}"
    if git rev-parse -q --verify "refs/tags/v$pro_version" >/dev/null; then
        die "tag v$pro_version already exists"
    fi
    upstream=$(upstream_tip_tag "$pro_commit")
    # Base is where the branch was cut from main and never changes for a
    # line. Upstream is the newest Tip release merged into this release
    git tag -a "v$pro_version" -m "Release v$pro_version" \
        -m "Channel: pro" -m "Version: $pro_version" -m "Commit: $pro_commit" \
        -m "License: $LICENSE_PRO" -m "Base: $pro_base_tag" -m "Upstream: $upstream" \
        -m "Previous: $pro_previous"
    if [[ -n "${RELEASE_NO_PUSH:-}" ]]; then
        echo "Tagged Pro release v$pro_version (not pushed, RELEASE_NO_PUSH is set)"
        return
    fi
    git push origin "v$pro_version"
    echo "Tagged and pushed Pro release v$pro_version"
}

command="${1:-}"
shift || true
case "$command" in
channel) cmd_channel ;;
ci-env) cmd_ci_env "$@" ;;
goreleaser-config) cmd_goreleaser_config "$@" ;;
pro-branch) cmd_pro_branch "$@" ;;
pro-next) cmd_pro_next "$@" ;;
pro-release) cmd_pro_release "$@" ;;
*) die "usage: $0 channel | ci-env <tag> | goreleaser-config <out> | pro-branch <X.Y> | pro-next [<version>] | pro-release [<version>]" ;;
esac
