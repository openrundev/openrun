#!/bin/sh

# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0

set -e

main() {
    LATEST_VERSION=$(curl -sS https://api.github.com/repos/openrundev/openrun/releases/latest | grep tag_name | cut -d '"' -f 4)
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    if test $arch = "x86_64"; then
        arch="amd64"
    fi

    if test $arch = "aarch64"; then
        arch="arm64"
    fi

    version=${1:-${LATEST_VERSION}}
    target="openrun-${version}-${os}-${arch}"
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
