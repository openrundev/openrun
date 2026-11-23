# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0

# Script to create the openrun user/group, install and then create the systemd service
#
# Usage: setup_systemd.sh [<version>]
#        setup_systemd.sh pro [<line> | <version>]
# With no argument the latest Tip release is installed, a version installs
# that Tip release. With pro as the first argument install-pro.sh is used:
# the highest Pro release, the latest release of a line like 1.3, or an
# exact Pro version

set -ex
INSTALLER=install.sh
if [ "${1:-}" = "pro" ]; then
  INSTALLER=install-pro.sh
  shift
fi
RELEASE="${1:-}"
case "$RELEASE" in
*[!A-Za-z0-9.]*)
  echo "Invalid release '$RELEASE'"
  exit 1
  ;;
esac
groupadd --system -f openrun

# Create user if it does not exist
if ! id -u openrun >/dev/null 2>&1; then
  useradd --system --gid openrun --create-home --home-dir /var/lib/openrun \
    --shell /usr/bin/bash --comment "OpenRun" openrun
fi

su -l openrun /bin/bash -c "export OPENRUN_HOME=/var/lib/openrun; curl -sSL https://openrun.dev/$INSTALLER | sh -s -- $RELEASE"
chmod +x /var/lib/openrun
ln -sf /var/lib/openrun/bin/openrun /usr/bin/openrun

mkdir -p /etc/systemd/system
curl -sSLo /etc/systemd/system/openrun.service https://raw.githubusercontent.com/openrundev/openrun/main/deploy/init/openrun.service

systemctl daemon-reload
systemctl enable --now openrun
systemctl status openrun
