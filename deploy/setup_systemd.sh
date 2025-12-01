# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0

# Script to create the openrun user/group, install and then create the systemd service

set -ex
groupadd --system -f openrun

# Create user if it does not exist
if ! id -u openrun >/dev/null 2>&1; then
  useradd --system --gid openrun --create-home --home-dir /var/lib/openrun \
    --shell /usr/bin/bash --comment "OpenRun" openrun
fi

su -l openrun /bin/bash -c "export OPENRUN_HOME=/var/lib/openrun; curl -sSL https://openrun.dev/install.sh | sh"
chmod +x /var/lib/openrun
ln -sf /var/lib/openrun/bin/openrun /usr/bin/openrun

mkdir -p /etc/systemd/system
curl -sSLo /etc/systemd/system/openrun.service https://raw.githubusercontent.com/openrundev/openrun/main/deploy/init/openrun.service

systemctl daemon-reload
systemctl enable --now openrun
systemctl status openrun
