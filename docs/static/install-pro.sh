#!/bin/sh

# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0

# Installs an OpenRun Pro release. install.sh installs the Tip releases.
#
# Usage: install-pro.sh [<line> | <version>]
#   (no argument)   highest Pro release across all maintenance lines
#   1.3             latest patch release of the Pro 1.3 line
#   v1.3.2          that exact Pro release, the leading v is optional
#
# Pro versions are vMAJOR.MINOR.PATCH. Their release assets are named
# openrun-pro, the installed binary is openrun.

set -e

REPO_API=https://api.github.com/repos/openrundev/openrun

# latest_pro <line> <os> <arch>: print the tag of the highest Pro release, of
# one maintenance line if <line> is set. Pro releases are found by their
# openrun-pro asset for this platform and ordered by version, since the
# release dates of two maintenance lines interleave. Every page has to be
# read for that, so a failed request fails the lookup instead of ending it:
# the unread pages can hold the highest version
latest_pro() {
    page=1
    found=""
    complete=""
    while test $page -le 20; do
        if ! releases=$(curl -sS --fail "$REPO_API/releases?per_page=100&page=$page"); then
            echo "Error listing openrun releases (page $page), GitHub may be rate limiting this address" >&2
            return 1
        fi
        # the page after the last one is an empty list
        if ! echo "$releases" | grep -q '"tag_name"'; then
            complete=1
            break
        fi
        tags=$(echo "$releases" | grep -o "\"name\": *\"openrun-pro-v[0-9]*\.[0-9]*\.[0-9]*-$2-$3\.tar\.gz\"" |
            sed -e 's/.*openrun-pro-v//' -e "s/-$2-$3.*//")
        found="$found
$tags"
        page=$((page + 1))
    done
    if test -z "$complete"; then
        echo "Error listing openrun releases, more than 20 pages" >&2
        return 1
    fi
    if test -n "$1"; then
        found=$(echo "$found" | grep "^$1\.[0-9]*$" || true)
    fi
    latest=$(echo "$found" | grep . | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)
    if test -n "$latest"; then
        echo "v$latest"
    fi
}

main() {
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    if test $arch = "x86_64"; then
        arch="amd64"
    fi

    if test $arch = "aarch64"; then
        arch="arm64"
    fi

    requested=${1#v}
    if echo "$requested" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        version="v$requested"
    elif test -z "$requested" || echo "$requested" | grep -Eq '^[0-9]+\.[0-9]+$'; then
        if ! version=$(latest_pro "$requested" "$os" "$arch"); then
            echo "Unable to find the latest Pro release, see https://github.com/openrundev/openrun/releases"
            exit 1
        fi
        if test -z "$version"; then
            echo "No Pro release found for ${requested:+the $requested line on }${os}-${arch}, see https://github.com/openrundev/openrun/releases"
            exit 1
        fi
    else
        echo "Invalid version '$1', pass a Pro line like 1.3 or a version like v1.3.2"
        exit 1
    fi

    target="openrun-pro-${version}-${os}-${arch}"
    openrun_uri="https://github.com/openrundev/openrun/releases/download/$version/${target}.tar.gz"
    openrun_install="${OPENRUN_HOME:-$HOME/openrun}"
    if test -z "${OPENRUN_HOME:-}" && test -d "/var/lib/openrun"; then
       openrun_install="/var/lib/openrun"
    fi

    bin_dir="$openrun_install/bin"
    tmp_dir="$openrun_install/tmp"
    exe="$bin_dir/openrun"

    mkdir -p "$bin_dir"
    mkdir -p "$tmp_dir"

    curl -q --fail --location --progress-bar --output "$tmp_dir/openrun.tar.gz" "$openrun_uri" || (echo "Error downloading $openrun_uri"; exit 1)
    # extract to tmp dir so we don't open existing executable file for writing
    tar -C "$tmp_dir" -xzf "$tmp_dir/openrun.tar.gz"
    chmod +x "$tmp_dir/${target}/openrun"
    mv -f "$tmp_dir/${target}/openrun" "$exe"
    rm -f "$tmp_dir/openrun.tar.gz"

    if test ! -s $openrun_install/openrun.toml; then
        echo ""
        echo "********** Initializing \"admin\" user **********"
        $exe password > $openrun_install/openrun.toml
        echo "************ Save this password ***************"
    fi

    SHELL_NAME=`basename $SHELL`
    profile_file="$HOME/.profile"
    if [ "$SHELL_NAME" = "zsh" ]; then
        profile_file="$HOME/.zshrc"
    elif [ "$SHELL_NAME" = "bash" ]; then
        profile_file="$HOME/.bash_profile"
    fi

    export_cmd="export PATH=\"$bin_dir:\$PATH\""
    if ! grep -Fxq "$export_cmd" "$profile_file" 2>/dev/null; then
        echo "$export_cmd" >> "$profile_file"
    fi

    echo "\nStart new shell to get updated PATH with $bin_dir. Run \"openrun server start\" to start the server."
    echo "See https://openrun.dev/docs/quickstart for the quick start guide."
}

main "$1"
