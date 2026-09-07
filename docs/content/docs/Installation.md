---
title: "Installation"
weight: 100
description: "Install OpenRun as a self-hosted web app platform on a Linux VPS, macOS, Windows or Kubernetes infrastructure."
summary: "Install OpenRun on a VPS, local machine, private server or Kubernetes cluster."
---

OpenRun can run as a self-hosted web app platform on a Linux VPS, private server, local workstation or Kubernetes cluster.

## Self-Hosted VPS Deployment

A single-node VPS installation uses Docker or Podman to run application containers and requires no external control plane. OpenRun provides a PaaS-style workflow with Git-based deployments, application routing, automatic TLS, authentication and scale-to-zero on infrastructure you control.

For a complete public VPS setup with DNS, TLS and OAuth, follow the [self-hosted web apps on a VPS guide]({{< ref "/docs/use-cases/personal" >}}).

## Install Release Build

OpenRun manages TLS cert using Let's Encrypt for prod environments. For dev environment, it is recommended to install [mkcert](https://github.com/FiloSottile/mkcert). OpenRun will automatically create local certs using mkcert if it is present. Install mkcert and run `mkcert -install` before starting OpenRun server.

For container based apps, Docker or Podman or OrbStack should be installed and running on the machine. OpenRun automatically detects the container manager to use.

OpenRun creates an `admin` account during installation or first server start. Save the generated password for the console and apps configured with `system` authentication. Apps use `none` authentication by default; see [default authentication]({{< ref "configuration/authentication/#default-authentication-type" >}}) to change this.

To install the latest release build on Linux, macOS or Windows with WSL, run the install script. Note down the password printed. Add the env variables as prompted and then start the service.

```shell
curl -sSL https://openrun.dev/install.sh | sh
```

Open a new terminal to get the updated environment values, then run:

```shell
openrun server start
```

To install apps declaratively, run

```
openrun apply --approve github.com/openrundev/openrun/examples/utils.star /utils/bookmarks
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

If no home or config path is configured and no existing installation is found, the first server start creates `$HOME\openrun\openrun.toml` and generates an admin password. Note down the password printed. When setting a custom `$env:OPENRUN_HOME`, create the directory and initialize the config with `openrun password > "$env:OPENRUN_HOME\openrun.toml"` before starting the server.

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
$BinPath = "`"$OpenRunExe`" --config-file `"$OpenRunConfig`" server start"
New-Service -Name openrun -DisplayName OpenRun -StartupType Automatic -BinaryPathName $BinPath -Description "OpenRun application server https://openrun.dev/"
sc.exe failure openrun reset= 86400 actions= restart/5000/restart/30000//
Start-Service openrun
```

For winget installs, see [Winget Service Install](#winget-service-install) below. The service runs as LocalSystem by default; for a network facing server, consider a less privileged account using `sc.exe config openrun obj= <account>`.

When started this way, OpenRun reports service status to Windows and handles service stop, shutdown and pre-shutdown requests as graceful server shutdowns.

Open https://localhost:25223 to access the app listing UI.

### Winget Service Install

To run OpenRun as a Windows service on a machine where it was installed with winget, the recommended approach is a machine scoped install with the service registered against an explicit config file. From an elevated shell:

```powershell
winget install --scope machine OpenRunDev.OpenRun
```

Machine scope installs the binary under `Program Files\WinGet` instead of the installing user's profile, which is preferable for a service. Open a new elevated terminal so `openrun` is on the PATH, then create the config file with a generated admin password:

```powershell
$OpenRunHome = Join-Path $env:ProgramData 'openrun'
New-Item -ItemType Directory -Force $OpenRunHome | Out-Null
openrun password | Out-File -Encoding utf8 (Join-Path $OpenRunHome 'openrun.toml')
```

Note down the password printed. Then register and start the service:

```powershell
$OpenRunExe = (Get-Command openrun.exe).Source
$OpenRunConfig = Join-Path $env:ProgramData 'openrun\openrun.toml'
$BinPath = "`"$OpenRunExe`" --config-file `"$OpenRunConfig`" server start"
New-Service -Name openrun -DisplayName OpenRun -StartupType Automatic -BinaryPathName $BinPath -Description "OpenRun application server https://openrun.dev/"
sc.exe failure openrun reset= 86400 actions= restart/5000/restart/30000//
Start-Service openrun
```

Passing `--config-file` pins the server home directory to the config file's directory (`%ProgramData%\openrun` here), keeping the service independent of any user profile. Without it, a service would resolve its home under the service account profile (for LocalSystem, `C:\Windows\System32\config\systemprofile`), and OpenRun refuses to auto-create a config there. The `openrun` CLI finds this server automatically: a winget binary is a links shim, so the CLI cannot locate the server home relative to the executable like it does for script installs; when `OPENRUN_HOME` is not set it checks `%ProgramData%\openrun\openrun.toml` and connects over the unix domain socket under that home. On OpenRun releases before this discovery was added, set the env variable at machine scope instead:

```powershell
[Environment]::SetEnvironmentVariable('OPENRUN_HOME', (Join-Path $env:ProgramData 'openrun'), 'Machine')
```

Env changes apply to shells opened after the change, not existing ones.

For a default user scoped winget install, keep everything under the user profile instead: run `openrun server start` once interactively to create `$HOME\openrun\openrun.toml` (note down the generated admin password), stop it with Ctrl+C, then register the service with `$OpenRunConfig = Join-Path $HOME 'openrun\openrun.toml'` in the `New-Service` command above. No env variable is needed in this setup: the CLI defaults to the same `$HOME\openrun` home.

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

- Install the Go toolchain required by the checked-out revision's [go.mod](https://github.com/openrundev/openrun/blob/main/go.mod). The current source requires Go 1.27.0 or newer.
- Check out the OpenRun repo.
- The below instructions assume you are using $HOME/clhome/openrun.toml as the config file and $HOME/clhome as the work directory location.

First add the below env variables to your shell .profile or .bash_profile:

```shell
export OPENRUN_HOME=$HOME/clhome
export PATH=$OPENRUN_HOME/bin/:$PATH
```

Source the updated profile file, for example `source ~/.bash_profile`, then build the OpenRun binary:

```shell
# Ensure go is in the $PATH
mkdir -p $OPENRUN_HOME/bin
mkdir $HOME/openrun_source && cd $HOME/openrun_source
git clone -b main https://github.com/openrundev/openrun && cd openrun
go build -o $OPENRUN_HOME/bin/openrun ./cmd/openrun/
```

## Certs and Default password

OpenRun manages TLS cert using Let's Encrypt for prod environments. For dev environment, it is recommended to install [mkcert](https://github.com/FiloSottile/mkcert). OpenRun will automatically create local certs using mkcert if it is present. Install mkcert and run `mkcert -install` before starting OpenRun server. Installing OpenRun using brew will automatically install mkcert.

For container based apps, Docker or Podman or OrbStack should be installed and running on the machine. OpenRun automatically detects the container manager to use.

Apps configured with `system` authentication use the `admin` account. Save the password generated during installation or first server start. New apps use `none` authentication unless the server default or app configuration selects another auth type.

## Initial Configuration

The install scripts and native packages initialize the config. When no home or config path is configured and no installation is found, the first server start initializes `$HOME/openrun/openrun.toml`.

For the source installation above, or any custom `OPENRUN_HOME`, initialize the config explicitly. Run the following once for a new installation, before adding other settings; it overwrites the destination file:

```shell
openrun password > "$OPENRUN_HOME/openrun.toml"
```

This prints a random admin password to the terminal and saves its hash in the config. Save the password for the console and apps using `system` authentication.

## Start the service

To start the OpenRun server, run

```shell
openrun server start
```

The service logs will be going to $OPENRUN_HOME/logs. The service will be started on [https://localhost:25223](https://localhost:25223) by default.

## Load an App

The disk-usage example uses `exec.in`, which is blocked by default. To run this example, enable it explicitly in `openrun.toml` and restart the server:

```toml {filename="openrun.toml"}
[permissions]
disallow = []
```

This removes the server-wide block; each command still needs app-level approval. See [default plugin permissions]({{< ref "configuration/security/#default-plugin-permissions" >}}). Then create the app with authentication:

```shell
openrun app create --dev --auth system "$HOME/openrun_source/openrun/examples/disk_usage" /disk_usage
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

The console requires an authenticated user for management operations. `--auth system` selects the admin account created during installation. OAuth/OIDC/SAML and builtin-user [authentication]({{< ref "configuration/authentication" >}}) can also be used with appropriate RBAC grants. Do not use `none` auth for the console: management operations are blocked for anonymous users.

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
openrun param update enable_builder true /console
```

After enabling a new area, review and approve the added plugin permissions with `openrun app approve --promote /console`. The AI builder also requires server-side [builder configuration]({{< ref "appbuilder" >}}); enabling the console area alone does not start it.
