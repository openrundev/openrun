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

On Windows, to install the OpenRun application, run

```shell
powershell -Command "iwr https://openrun.dev/install.ps1 -useb | iex"
```

The app is installed under `$HOME/clhome` by default. Note down the generated password for the admin user. Open a new terminal (to get the updated ENV values) and run

```shell
openrun server start
```

to start the OpenRun server.

To install apps declaratively, run

```
openrun apply --approve github.com/openrundev/openrun/examples/utils.star all
```

Open https://localhost:25223 to access the app listing UI.

To install a bookmark manager app using the CLI, run

```shell
openrun app create --approve github.com/openrundev/apps/utils/bookmarks /book
```

The bookmark manager app should be available at [https://localhost:25223/book](https://localhost:25223/book).

See [start the service]({{< ref "#start-the-service" >}}) for details.

## Brew Install

To install using [brew](https://brew.sh/), run

```
brew tap openrundev/homebrew-openrun
brew install openrun
brew services start openrun
```

## Install from Source

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
