---
title: "Installation"
weight: 100
summary: "How to install OpenRun and do initial setup"
---

## Install Release Build

OpenRun manages TLS cert using LetsEncrypt for prod environments. For dev environment, it is recommended to install [mkcert](https://github.com/FiloSottile/mkcert). OpenRun will automatically create local certs using mkcert if it is present. Install mkcert and run `mkcert -install` before starting OpenRun server.

For container based apps, Docker or Podman or Orbstack should be installed and running on the machine. OpenRun automatically detects the container manager to use.

OpenRun uses an `admin` user account as the default authentication for accessing apps. A random password is generated for this account during initial OpenRun server installation. Note down this password for accessing apps.

To install the latest release build on Linux, OSX or Windows with WSL, run the install script. Note down the password printed. Add the env variables as prompted and then start the service.

```shell
curl -sSL https://openrun.dev/install.sh | sh
```

Open a new terminal to get the updated environment values, then run:

```shell
openrun server start
```

To install apps declaratively, run

```
openrun apply --approve github.com/openrundev/openrun/examples/utils.star all
```

Open https://localhost:25223 to access the app listing UI.

See [start the service]({{< ref "#start-the-service" >}}) for details.

## Install On Linux (Native Packages)

Native packages (rpm/deb) are published for openSUSE Tumbleweed, Fedora and Debian through the [Open Build Service](https://build.opensuse.org/package/show/home:ajayvk:openrun/openrun). The package installs the `openrun` binary, creates an `openrun` service account with home directory `/var/lib/openrun`, generates the initial config with a random `admin` password (printed during install, note it down) and sets up the systemd service.

### openSUSE Tumbleweed

```shell
sudo zypper addrepo https://download.opensuse.org/repositories/home:/ajayvk:/openrun/openSUSE_Tumbleweed/home:ajayvk:openrun.repo
sudo zypper --gpg-auto-import-keys refresh
sudo zypper install openrun
```

### Fedora

```shell
sudo dnf config-manager addrepo --from-repofile=https://download.opensuse.org/repositories/home:/ajayvk:/openrun/Fedora_Rawhide/home:ajayvk:openrun.repo
sudo dnf install openrun
```

For dnf 4, use `sudo dnf config-manager --add-repo <repo url>` instead.

### Debian

```shell
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.opensuse.org/repositories/home:/ajayvk:/openrun/Debian_Unstable/Release.key | gpg --dearmor | sudo tee /etc/apt/keyrings/openrun.gpg > /dev/null
echo 'deb [signed-by=/etc/apt/keyrings/openrun.gpg] https://download.opensuse.org/repositories/home:/ajayvk:/openrun/Debian_Unstable/ /' | sudo tee /etc/apt/sources.list.d/openrun.list
sudo apt update && sudo apt install openrun
```

### Start the systemd service

```shell
sudo systemctl enable --now openrun
```

The server runs as the `openrun` user, using the config file at `/var/lib/openrun/openrun.toml`. Logs go to the journal (`journalctl -u openrun`) and `/var/lib/openrun/logs`. Open https://localhost:25223 to access the app listing UI, using `admin` and the password printed during package installation.

On systemd-based distros without a native package, the same setup (openrun user, `/var/lib/openrun` home, systemd service) can be done with the setup script:

```shell
curl -sSL https://raw.githubusercontent.com/openrundev/openrun/refs/heads/main/deploy/setup_systemd.sh | sudo sh
```

### Zero downtime restarts and updates

On Linux and macOS, the server can restart in place with no downtime and no dropped connections: a new server process takes over the listening sockets, re-reads the config and starts serving; the old process finishes its in-flight requests and websockets (up to `restart.drain_timeout_secs`, default 300) and exits. Use this to apply config file changes or to move to a new server version — for a version update, upgrade the openrun binary first (e.g. `apt upgrade openrun`), then restart in place. Any of the following triggers the restart:

```shell
sudo systemctl reload openrun   # systemd installs
openrun server restart          # any install, uses the management API
kill -HUP <server pid>
```

Apps are not affected: app containers keep running through the restart. In-place restart is not available on Windows or when the server runs inside a container (restart the container instead; on Kubernetes use `kubectl rollout restart`, app traffic is drained via the pod's termination grace period).

## Install On Windows

To install OpenRun using [winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/), run:

```powershell
winget install OpenRunDev.OpenRun
```

Open a new terminal so `openrun` is on the PATH, then run:

```powershell
openrun server start
```

On the first server start, OpenRun creates its config file under `$HOME\openrun` (or `$env:OPENRUN_HOME` if set) and generates an admin password. Note down the password printed.

Alternatively, install using the install script:

```powershell
powershell -Command "irm https://openrun.dev/install.ps1 | iex"
```

The app is installed under `$env:OPENRUN_HOME`, defaulting to `$HOME\openrun`. Note down the generated password for the admin user. Open a new terminal to get the updated environment values, then run:

```powershell
openrun server start
```

To run OpenRun as a Windows service, register `openrun server start` with the Windows Service Control Manager from an elevated shell:

```powershell
$OpenRunExe = Join-Path $env:OPENRUN_HOME 'bin\openrun.exe'
$OpenRunConfig = Join-Path $env:OPENRUN_HOME 'openrun.toml'
sc.exe create openrun start= auto DisplayName= "OpenRun" binPath= "`"$OpenRunExe`" --config-file `"$OpenRunConfig`" server start"
sc.exe description openrun "OpenRun application server https://openrun.dev/"
sc.exe failure openrun reset= 86400 actions= restart/5000/restart/30000//
sc.exe start openrun
```

The paths from `$env:OPENRUN_HOME` are expanded when the service is created; re-create the service if the install location changes. For winget installs, see [Winget Service Install](#winget-service-install) below. The service runs as LocalSystem by default; for a network facing server, consider a less privileged account using `sc.exe config openrun obj= <account>`.

When started this way, OpenRun reports service status to Windows and handles service stop, shutdown and pre-shutdown requests as graceful server shutdowns.

Open https://localhost:25223 to access the app listing UI.

### Winget Service Install

To run OpenRun as a Windows service on a machine where it was installed with winget, the recommended approach is a machine scoped install with the service registered against an explicit config file. From an elevated shell:

```powershell
winget install --scope machine OpenRunDev.OpenRun
```

Machine scope installs the binary under `Program Files\WinGet` instead of the installing user's profile, which is preferable for a service. Open a new elevated terminal so `openrun` is on the PATH, then create the config file with a generated admin password:

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\openrun | Out-Null
openrun password | Out-File -Encoding utf8 C:\ProgramData\openrun\openrun.toml
```

Note down the password printed. Then register and start the service:

```powershell
$OpenRunExe = (Get-Command openrun.exe).Source
$OpenRunConfig = 'C:\ProgramData\openrun\openrun.toml'
sc.exe create openrun start= auto DisplayName= "OpenRun" binPath= "`"$OpenRunExe`" --config-file `"$OpenRunConfig`" server start"
sc.exe description openrun "OpenRun application server https://openrun.dev/"
sc.exe failure openrun reset= 86400 actions= restart/5000/restart/30000//
sc.exe start openrun
```

Passing `--config-file` pins the server home directory to the config file's directory (`C:\ProgramData\openrun` here), keeping the service independent of any user profile. Without it, a service would resolve its home under the service account profile (for LocalSystem, `C:\Windows\System32\config\systemprofile`), and OpenRun refuses to auto-create a config there. To use the `openrun` CLI against this server from a regular shell, set the env variable at machine scope so the CLI resolves the same home:

```powershell
[Environment]::SetEnvironmentVariable('OPENRUN_HOME', 'C:\ProgramData\openrun', 'Machine')
```

For a default user scoped winget install, keep everything under the user profile instead: run `openrun server start` once interactively to create `$HOME\openrun\openrun.toml` (note down the generated admin password), stop it with Ctrl+C, then register the service with `$OpenRunConfig = Join-Path $HOME 'openrun\openrun.toml'` in the `sc.exe create` command above. No env variable is needed in this setup: the CLI defaults to the same `$HOME\openrun` home.

In both flows, `(Get-Command openrun.exe).Source` resolves to the winget links shim, which stays valid across `winget upgrade`; after an upgrade, run `sc.exe stop openrun` and `sc.exe start openrun` to switch to the new binary.

## Brew Install

To install using [brew](https://brew.sh/), run

```
brew tap openrundev/homebrew-openrun
brew install openrun
brew services start openrun
```

## Install from Source

The release binaries are available at [releases](https://github.com/openrundev/openrun/releases).

To install from source

- Ensure that a recent version of [Go](https://go.dev/doc/install) is available, version 1.21.0 or newer.
- Checkout the OpenRun repo.
- The below instructions assume you are using $HOME/clhome/openrun.toml as the config file and $HOME/clhome as the work directory location.

First add the below env variables to your shell .profile or .bash_profile:

```shell
export OPENRUN_HOME=$HOME/clhome
export PATH=$OPENRUN_HOME/bin/:$PATH
```

Source the update profile file, like `source ~/.bash_profile`. Build the OpenRun binary

```shell
# Ensure go is in the $PATH
mkdir -p $OPENRUN_HOME/bin
mkdir $HOME/openrun_source && cd $HOME/openrun_source
git clone -b main https://github.com/openrundev/openrun && cd openrun
go build -o $OPENRUN_HOME/bin/openrun ./cmd/openrun/
```

## Certs and Default password

OpenRun manages TLS cert using LetsEncrypt for prod environments. For dev environment, it is recommended to install [mkcert](https://github.com/FiloSottile/mkcert). OpenRun will automatically create local certs using mkcert if it is present. Install mkcert and run `mkcert -install` before starting OpenRun server. Installing OpenRun using brew will automatically install mkcert.

For container based apps, Docker or Podman or Orbstack should be installed and running on the machine. OpenRun automatically detects the container manager to use.

OpenRun uses an `admin` user account as the default authentication for accessing apps. A random password is generated for this account during initial OpenRun server installation. Note down this password for accessing apps if using `system` auth.

## Initial Configuration

To use the openrun service, you need an initial config file with the service password and a work directory. Create the openrun.toml file, and create a randomly generate password for the **admin** user account

```shell
openrun password > $OPENRUN_HOME/openrun.toml
```

This will print a random password on the screen, note that down as the password to use for accessing the applications.

## Start the service

To start the OpenRun server, run

```shell
openrun server start
```

The service logs will be going to $OPENRUN_HOME/logs. The service will be started on [https://localhost:25223](https://127.0.0.1:25223) by default.

## Load an App

To create an app, ensure that code is available locally and then run the OpenRun client

```shell
openrun app create --dev $HOME/openrun_source/openrun/examples/disk_usage /disk_usage
```

To audit and approve the app's security policies, run

```shell
openrun app approve /disk_usage
```

This will create an app at /disk_usage with the example disk_usage app. The disk_usage app allows the user to explore the subfolders which are consuming most disk space.

To access the app, go to [https://localhost:25223/disk_usage](https://localhost:25223/disk_usage). Use `admin` as the username and use the password previously generated.

The code for the disk usage app is in [GitHub](https://github.com/openrundev/openrun/tree/main/examples/disk_usage/app.star). app.star is the Starlark config and app.go.html is the html template. The other files are generated files and are created during app development.

## Install the Console App

The [management console]({{< ref "/console-tour" >}}) is a web UI for managing the OpenRun server: apps, syncs, service bindings, containers, audit logs, server configuration and the AI app builder. A live [demo](https://utils.demo.clace.io/console/) of the console is available. The console is itself an OpenRun app, installed from the [openrundev/console](https://github.com/openrundev/console) repo:

```shell
openrun app create --approve --auth system \
    --param enable_all_features=true --param enable_updates=true \
    github.com/openrundev/console /console
```

Open https://localhost:25223/console and log in as `admin`, using the password printed during the OpenRun installation.

Since the console performs management operations, it should always run with an auth type that requires login. Using `system` auth is recommended: it needs no additional setup, the `admin` account with the password printed during installation is used to login. `system` is the server's default auth type, the `--auth system` option makes the choice explicit. OAuth/OIDC/SAML based [authentication]({{< ref "configuration/authentication" >}}) can also be used. Do not use `none` auth for the console: management operations are blocked for anonymous users.

The console features are controlled through app params, set with `--param name=value` during create:

| Param                 | Default | Description                                                                             |
| --------------------- | ------- | --------------------------------------------------------------------------------------- |
| `enable_updates`      | `false` | Enable write operations (create/update/delete). Without this, the console is read-only. |
| `enable_container`    | `false` | Enable the containers area                                                              |
| `enable_config`       | `false` | Enable the server configuration area                                                    |
| `enable_builder`      | `false` | Enable the AI app builder area                                                          |
| `enable_all_features` | `false` | Enable all the areas above; write operations still need `enable_updates`                |

The default install (no params) is a read-only console covering apps, syncs, bindings, the overview and audit logs. A disabled area registers no routes and requests no plugin permissions.

Params can be changed after install. Enabling a new area adds plugin permissions, which require re-approval; the change is staged and goes live on promotion:

```shell
openrun param update --promote enable_builder true /console
```
