<p align="center">
  <img src="https://openrun.dev/openrun.png" alt="OpenRun-logo" width="300" height="250"/>

  <p align="center">App deployment simplified. Open source alternative to Google Cloud Run and AWS App Runner. Easily deploy internal tools across a team.</p>
</p>

<p>
  <a href="https://github.com/openrundev/openrun/blob/main/LICENSE"><img src="https://img.shields.io/github/license/openrundev/openrun" alt="License"></a>
  <a href="https://github.com/openrundev/openrun/releases"><img src="https://img.shields.io/github/release/openrundev/openrun.svg?color=00C200" alt="Latest Release"></a>
  <a href="https://github.com/openrundev/openrun/actions"><img src="https://github.com/openrundev/openrun/workflows/CI/badge.svg" alt="Build Status"></a>
  <a href="https://app.codecov.io/github/openrundev/openrun"><img src="https://img.shields.io/codecov/c/github/openrundev/openrun" alt="Code Coverage"></a>
  <a href="https://goreportcard.com/report/github.com/openrundev/openrun"><img src="https://goreportcard.com/badge/github.com/openrundev/openrun" alt="Go Report Card"></a>
  <a href="https://github.com/avelino/awesome-go"><img src="https://awesome.re/mentioned-badge.svg" alt="Mentioned in Awesome Go"></a>
  <a href="https://landscape.cncf.io/?item=app-definition-and-development--application-definition-image-build--openrun"><img src="https://img.shields.io/badge/CNCF%20Landscape-0086FF" alt="Listed in CNCF landscape"></a>
  <a href="https://www.bestpractices.dev/projects/11301"><img src="https://www.bestpractices.dev/projects/11301/badge"></a>
</p>

### Menu

- [Overview](#overview)
- [Features](#features)
- [Roadmap](#roadmap)
- [Setup](#setup)
- [Documentation](#documentation)
- [Getting help](#getting-help)
- [Contributing](#contributing)

## Overview

OpenRun is an Apache-2.0 licensed open source alternative to Google Cloud Run and AWS App Runner. OpenRun makes it easy to declaratively deploy applications built in frameworks like Streamlit/Gradio/FastHTML/NiceGUI etc.

OpenRun provides **declarative** GitOps based app deployment, OAuth/OIDC/SAML access controls, TLS certs & secrets management. OpenRun is built for teams to easily deploy internal tools, with full RBAC support. OpenRun apps are deployed directly from the git repo, no build step required. OpenRun scales idles apps down to zero and supports atomic updates across multiple apps.

This repo hosts the source code for OpenRun. The source for the documentation site [openrun.dev](https://openrun.dev) is in the [docs](https://github.com/openrundev/docs) repo. App specifications, which are templates to create apps, are defined in the [appspecs](https://github.com/openrundev/appspecs) repo. Sample apps are in the [apps](https://github.com/openrundev/apps) repo.

<img alt="OpenRun intro gif" src="https://openrun.dev/intro_dark_small.gif"/>

## Features

OpenRun can be used to:

- Deploy [containerized applications](https://openrun.dev/docs/container/overview/), OpenRun will build and manage the container lifecycle
- Automatically generate a form based UI for backend [actions](https://openrun.dev/docs/actions/)
- Add OAuth/OIDC/SAML based [auth](https://openrun.dev/docs/configuration/authentication/) and [RBAC](https://openrun.dev/docs/configuration/rbac/) for app access

OpenRun supports the following for all apps:

- [Declarative](https://openrun.dev/docs/applications/overview/#declarative-app-management) app deployment
- Atomic updates (all or none) across [multiple apps](https://openrun.dev/docs/applications/overview/#glob-pattern)
- [Staging mode](https://openrun.dev/docs/applications/lifecycle/#staging-apps) for app updates, to verify whether code and config changes work on prod before making them live.
- [Preview app](https://openrun.dev/docs/applications/lifecycle/#preview-apps) creation support, for trying out code changes.
- Support for [github integration](https://openrun.dev/docs/configuration/security/#private-repository-access), apps being directly deployed from github code.
- OAuth/OIDC/SAML based [authentication](https://openrun.dev/docs/configuration/authentication/#oauth-authentication)
- Support for domain based and path based [routing](https://openrun.dev/docs/applications/routing/#request-routing) at the app level.
- Integration with [secrets managers](https://openrun.dev/docs/configuration/secrets/), to securely access secrets.

For containerized apps, OpenRun supports:

- Managing [image builds](https://openrun.dev/docs/quickstart/#containerized-applications), in dev and prod mode
- Passing [parameters](https://openrun.dev/docs/develop/#app-parameters) for the container
- Building apps from [spec](https://openrun.dev/docs/develop/#building-apps-from-spec), no code changes required in repo for [supported frameworks](https://github.com/openrundev/appspecs) (Flask, Streamlit and repos having a Dockerfile)
- Support for [pausing](https://openrun.dev/docs/container/config/) app containers which are idle

For building Hypermedia based apps, OpenRun supports:

- Automatic [error handling support](https://openrun.dev/docs/plugins/overview/#automatic-error-handling)
- Automatic creation of ECMAScript modules using [esbuild](https://esbuild.github.io/).
- Support for [TailwindCSS](https://tailwindcss.com/) and [DaisyUI](https://daisyui.com/) watcher integration.
- [Automatic SSL](https://openrun.dev/docs/configuration/networking/#enable-automatic-signed-certificate) certificate creation based on [certmagic](https://github.com/caddyserver/certmagic).
- Backend app code runs in a [security sandbox](https://openrun.dev/docs/applications/appsecurity/#security-model), with allowlist based permissions.
- [No build step](https://openrun.dev/docs/develop/#app-lifecycle), the development artifacts are ready for production use.
- Support for application data persistance using SQLite
- Virtual filesystem with [content hash based file names](https://openrun.dev/docs/develop/templates/#static-function) backed by SQLite database, enabling aggressive static content caching.
- Brotli compression for static artifacts, HTTP early hints support for performance.

## Roadmap

The feature roadmap for OpenRun is:

- Support for deployment to Kubernetes is planned.

## Setup

### Certs and Default password

OpenRun manages TLS cert using LetsEncrypt for prod environments. For dev environment, OpenRun uses [mkcert](https://github.com/FiloSottile/mkcert) for local certs. Installing OpenRun using brew will automatically install mkcert.

For container based apps, Docker or Podman or Orbstack should be installed and running on the machine. OpenRun automatically detects the container manager to use.

### Install OpenRun On OSX/Linux

To install on OSX/Linux, run

```shell
curl -sSL https://openrun.dev/install.sh | sh
```

Start a new terminal (to get the updated env) and run `openrun server start` to start the OpenRun service.

### Brew Install

To install using brew, run

```
brew tap openrundev/homebrew-openrun
brew install openrun
brew services start openrun
```

### Install On Windows

To install on Windows, run

```
powershell -Command "iwr https://openrun.dev/install.ps1 -useb | iex"
```

Start a new command window (to get the updated env) and run `openrun server start` to start the OpenRun service.

### Install Apps

Once OpenRun server is running, to install apps declaratively, open a new window and run

```
openrun apply --approve github.com/openrundev/openrun/examples/utils.star
```

To schedule a background sync, which automatically applies the latest app config, run

```
openrun sync schedule --approve --promote github.com/openrundev/openrun/examples/utils.star
```

To install apps using the CLI (imperative mode), run

```
openrun app create --approve github.com/openrundev/apps/system/list_files /files
openrun app create --approve github.com/openrundev/apps/system/disk_usage /disk_usage
openrun app create --approve github.com/openrundev/apps/utils/bookmarks /book
```

Open https://localhost:25223 to see the app listing. The disk usage app is available at https://localhost:25223/disk_usage (port 25222 for HTTP). The bookmark manager is available at https://localhost:25223/book, the list files app is available at https://localhost:25223/files.

See [installation]({{< ref "installation" >}}) for details. See [config options]({{< ref "configuration" >}}) for configuration options. To enable Let's Encrypt certificates, see [Automatic SSL]({{< ref "configuration/networking/#enable-automatic-signed-certificate" >}}).

The release binaries are also available at [releases](https://github.com/openrundev/openrun/releases). See [install from source]({{< ref "installation/#install-from-source" >}}) to build from source.

To install a containerized app, ensure either Docker or Podman is running and run

```
openrun app create --spec python-streamlit --branch master --approve github.com/streamlit/streamlit-example /streamlit
```

If the source repo has a `Dockerfile` or `Containerfile`, run

```
openrun app create --spec container --approve <source_path> /myapp
```

to install the app.

### Build from source

To install a release build, follow steps in the [installation docs](https://openrun.dev/docs/installation/#install-release-build).

To install from source:

- Ensure that a recent version of [Go](https://go.dev/doc/install) is available, version 1.21.0 or newer
- Checkout the OpenRun repo, cd to the checked out folder
- Build the openrun binary and place in desired location, like $HOME

```shell
# Ensure go is in the $PATH
mkdir $HOME/openrun_source && cd $HOME/openrun_source
git clone -b main https://github.com/openrundev/openrun && cd openrun
export OPENRUN_HOME=$HOME/clhome && mkdir -p $OPENRUN_HOME/config
go build -o $OPENRUN_HOME/openrun ./cmd/openrun/
```

### Initial Configuration For Source Install

To use the openrun service, you need an initial config file with the service password and a work directory. The below instructions assume you are using $HOME/clhome/openrun.toml as the config file and $HOME/clhome as the work directory location.

- Create the clhome directory
- Create the openrun.toml file, and create a randomly generate password for the **admin** user account

```shell
cd $OPENRUN_HOME
git clone -C config https://github.com/openrundev/appspecs
$OPENRUN_HOME/openrun password > $OPENRUN_HOME/openrun.toml
$OPENRUN_HOME/openrun server start
```

The service will be started on [https://localhost:25223](https://127.0.0.1:25223) by default (HTTP port 25222).

## Documentation

OpenRun docs are at https://openrun.dev/docs/. For doc bugs, raise a GitHub issue in the [docs](https://github.com/openrundev/docs) repo.

## Getting help

Please use [Github Discussions](https://github.com/openrundev/openrun/discussions) for discussing OpenRun related topics. Please use the bug tracker for bug reports and feature requests.

## Contributing

PRs welcome for bug fixes and enhancements. For application behavior related fixes, refer the [app unit test cases](https://github.com/openrundev/openrun/tree/main/internal/app/tests). Those test run as part of regular unit tests `go test ./...`. For API related changes, OpenRun uses the [commander-cli](https://github.com/commander-cli/commander) library for [automated CLI tests](https://github.com/openrundev/openrun/tree/main/tests). To run the CLI test, run `gmake test` from the openrun home directory.
