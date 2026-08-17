<p align="center">
  <img src="https://openrun.dev/openrun.png" alt="OpenRun-logo" width="300" height="250"/>

  <p align="center">Open-source, self-hosted GitOps platform for deploying web apps and internal tools to Docker or Kubernetes. Declarative deployments, SSO, RBAC, TLS, secrets, database service bindings, SQLite backups to S3, staged releases and scale-to-zero.</p>
</p>

<p>
  <a href="https://github.com/openrundev/openrun/blob/main/LICENSE"><img src="https://img.shields.io/github/license/openrundev/openrun" alt="License"></a>
  <a href="https://github.com/openrundev/openrun/releases"><img src="https://img.shields.io/github/release/openrundev/openrun.svg?color=00C200" alt="Latest Release"></a>
  <a href="https://github.com/openrundev/openrun/actions"><img src="https://github.com/openrundev/openrun/workflows/CI/badge.svg" alt="Build Status"></a>
  <a href="https://app.codecov.io/github/openrundev/openrun"><img src="https://img.shields.io/codecov/c/github/openrundev/openrun" alt="Code Coverage"></a>
  <!--a href="https://goreportcard.com/report/github.com/openrundev/openrun"><img src="https://goreportcard.com/badge/github.com/openrundev/openrun" alt="Go Report Card"></a-->
  <a href="https://landscape.cncf.io/?item=app-definition-and-development--application-definition-image-build--openrun"><img src="https://img.shields.io/badge/CNCF-0086FF" alt="Listed in CNCF landscape"></a>
  <a href="https://www.bestpractices.dev/projects/11301"><img src="https://www.bestpractices.dev/projects/11301/badge"></a>
  <a href="https://github.com/avelino/awesome-go"><img src="https://awesome.re/mentioned-badge.svg" alt="Mentioned in Awesome Go"></a>
  <img src="https://img.shields.io/github/downloads/openrundev/openrun/total.svg" alt="downloads"/>
</p>

### Menu

- [Overview](#overview)
- [Ways To Manage Apps](#ways-to-manage-apps)
- [FAQ](#faq)
- [Architecture Overview](#architecture-overview)
- [Database Service Bindings](#database-service-bindings)
- [SQLite Backups with Litestream](#sqlite-backups-with-litestream)
- [Features](#features)
- [Roadmap](#roadmap)
- [Setup](#setup)
- [Documentation](#documentation)
- [Getting help](#getting-help)
- [Contributing](#contributing)

## Overview

OpenRun is an Apache-2.0 licensed open source, self-hosted GitOps platform for deploying web apps and internal tools. Run the single binary on one server with Docker/Podman, or deploy apps onto a Kubernetes cluster with the same declarative config. OpenRun provides declarative GitOps based blue-green deployment, OAuth/OIDC/SAML access controls, RBAC, audit logs, TLS certs and secrets management. Apps are deployed directly from the git repo, no build server required. OpenRun scales idle apps down to zero and supports atomic updates across multiple apps.

Some of the unique features of OpenRun are:

- Create and manage apps declaratively, through GitOps
- Service bindings to provision isolated Postgres/MySQL/SQLite/Redis database accounts for apps, with more databases supported through binding providers
- Managed SQLite with continuous Litestream replication to S3 and automatic restore
- Easily upgrade from single-node to Kubernetes, with no config changes required
- Domain based or path based routing, with auto-TLS
- OAuth/OpenID/SAML/Cert based auth
- RBAC for admin operations and for app access
- Scales idle apps down to zero
- Staged deployment, for code and config changes
- Atomic (all or nothing) updates across apps
- Browser based [management console](https://openrun.dev/console-tour/) for apps, bindings, containers, audit events and server config

This repo hosts the source code for OpenRun. The source for the documentation site [openrun.dev](https://openrun.dev) is in the docs folder. App specifications, which are templates to create apps, are defined in the [appspecs](https://github.com/openrundev/appspecs) repo. Sample apps are in the [apps](https://github.com/openrundev/apps) repo.

<img alt="OpenRun intro gif" src="https://openrun.dev/intro_dark_small.gif"/>

## Ways To Manage Apps

OpenRun supports three ways of managing apps, which can be mixed freely:

- **Declarative, through GitOps**: All apps are defined in config files in Git. `openrun sync schedule` sets up a background sync which creates new apps and updates existing apps as the config and code change in Git. This is the recommended mode for teams; every change is version controlled and staged deployments and atomic updates apply across apps. See [declarative app management](https://openrun.dev/docs/applications/overview/#declarative-app-management).
- **Imperative, through the CLI**: `openrun app create`, `openrun app update` and related commands manage individual apps directly. Useful for trying things out and for scripting. See the [quick start](https://openrun.dev/docs/quickstart/).
- **Through the management console UI**: A browser based console for creating and managing apps, services, bindings and secrets, viewing containers and audit events, and updating server config. See the [console tour](https://openrun.dev/console-tour/) and the live [demo](https://utils.demo.clace.io/console/).

## FAQ

<details open>
  <summary><b>How does OpenRun compare to other deployment solutions like Coolify/Dokku/CapRover etc?</b></summary>

> The main differences are:
>
> - OpenRun is declarative. After initial OpenRun setup, all operations including creating new apps and updating config for existing apps can be done by updating a config file in Git. With most other solutions, app creation/update is done manually through CLI or UI; only app source code updates can be done through Git.
> - OpenRun can deploy apps on a single machine with Docker/Podman or it can deploy apps onto a Kubernetes cluster. Most other solutions do not support deployment to Kubernetes.
> - OpenRun is implemented as a web server, it does not depend on an external web server like Nginx/Traefik. This simplifies end-user usage and allows OpenRun to implement features like scale down to zero (for app containers) and OAuth/SAML/Cert based auth with RBAC.
> - OpenRun provides database service bindings, provisioning isolated database accounts per app, and managed SQLite with Litestream replication to S3.
> - OpenRun supports features like staged deployment and automatic dev env setup which are not available in other solutions.

</details>

<details>
  <summary><b>Why is declarative configuration useful?</b></summary>

> Imperative CLI or UI operations are easy to start with, but they make it difficult to track changes and rollback updates. With a declarative config, all changes are version controlled. It is easy to create a new environment, since everything is in Git. If multiple folks are making config changes in a team, declarative systems are easier to manage.
>
> Declarative configuration is what makes Kubernetes and Terraform useful. OpenRun brings declarative configuration to web app deployment. Instead of writing pages of YAML, each app is a couple of lines of config. For example, see [utils.star](https://github.com/openrundev/openrun/blob/main/examples/utils.star).

</details>

<details>
  <summary><b>What types of apps can be deployed with OpenRun?</b></summary>

> OpenRun can deploy any web app which runs in a single container. OpenRun supports [AppSpecs](https://openrun.dev/docs/container/overview/#app-specs) which allow zero-config deployment of frameworks like Streamlit/Gradio/FastHTML/NiceGUI/Shiny/Reflex based apps. For frameworks which have an AppSpec, no Dockerfile is required, no code changes are required in the app source code. For frameworks which do not have an AppSpec defined, a Dockerfile needs to be present in the app source repo.
>
> OpenRun does NOT support apps which require multiple containers using Docker Compose. External services are accessed through a service binding, which is a more flexible and operationally convenient approach to provisioning services.

</details>

<details>
  <summary><b>Does OpenRun support deployment of internal tools by teams?</b></summary>

> Yes, deployment of internal tools by teams is a target [use case](https://openrun.dev/docs/use-cases/team/). Features which are built for this use case include:
>
> - **Declarative Config**: Manage apps [declaratively](https://openrun.dev/docs/applications/overview/#declarative-app-management) in git, allowing teams to follow regular SDLC for config
> - **OAuth/OIDC/SAML with RBAC**: Manage who can access which app using [RBAC](https://openrun.dev/docs/configuration/rbac/)
> - **Service Bindings**: Configure a database once and safely provision it across apps, each app getting its own [isolated account](https://openrun.dev/docs/applications/servicebindings/)
> - **Audit Logs**: All operations and API calls are automatically logged in the [audit trail](https://openrun.dev/docs/applications/audit/)

</details>

<details>
  <summary><b>How is OpenRun deployed?</b></summary>

> OpenRun can be deployed on a single node easily (Linux, Windows or macOS), using a SQLite database for storing metadata. Docker/Podman is the only dependency.
>
> OpenRun can also be deployed on Kubernetes using a Helm chart. On Kubernetes, OpenRun replaces a build system like Jenkins, CD with ArgoCD and an IDP like BackStage. Apps deployed using OpenRun are deployed as Kubernetes services, with OpenRun running as the api server/request router.

</details>

## Architecture Overview

### Single-Node Architecture

On a single node, the OpenRun server manages app containers through Docker or Podman, with metadata stored in SQLite (or an external Postgres database).

<img alt="OpenRun single-node components" src="https://openrun.dev/d2/single-node.svg"/>

### Kubernetes Architecture

On Kubernetes, OpenRun runs as the api server and request router, creating Kubernetes services for apps and building images through kaniko.

<img alt="OpenRun Kubernetes deployment" src="https://openrun.dev/d2/k8s.svg"/>

## Database Service Bindings

[Service bindings](https://openrun.dev/docs/applications/servicebindings/) automatically provision isolated database access for apps. Teams configure a managed or self-hosted database once, with its backups, monitoring and capacity management, and safely share that installation across multiple apps. Apps never see the administrator credentials of any bound service.

- **Built-in service types**: PostgreSQL (schema and role per app), MySQL (database and user per app), SQLite (persistent volume per app), Redis and Valkey (server-enforced ACL user restricted to an app-specific key prefix).
- **Binding providers**: SQL Server, Oracle, MongoDB (including Atlas), Snowflake, ClickHouse and Databricks are supported through out-of-process providers, installed with `openrun provider install`. Provider-backed bindings use the same workflow as the built-in types.
- **Unique credentials**: Each binding gets a generated password and connection URL, injected into the app environment. Staging and prod apps get separate accounts.
- **Derived bindings**: Multiple apps can share a schema or database with distinct least-privilege credentials (read-only, scoped or full-access grants).
- **Health checks**: Service and binding health can be verified through the CLI and the console.

<img alt="Service binding layout: a service with admin credentials, base bindings creating isolated schemas and roles, and apps getting credentials through their environment" src="https://openrun.dev/d2/base_binding.svg"/>

## SQLite Backups with Litestream

OpenRun has built-in [Litestream](https://openrun.dev/docs/applications/litestream/) support for SQLite. App SQLite databases are continuously replicated to AWS S3 or S3-compatible object storage such as Cloudflare R2, MinIO and SeaweedFS, and are automatically restored before the app starts if the local volume is lost.

- **No app changes**: Apps do not package, configure or run Litestream themselves. OpenRun manages the replication and restore lifecycle on Docker, Podman and Kubernetes.
- **App data and server metadata**: Both the SQLite databases behind SQLite service bindings and OpenRun's own metadata and audit databases can be replicated.
- **Disaster recovery**: Replication is continuous (changes upload within about a second) and restore is automatic. After a complete node loss, start a new server with the same config file and apps, bindings, versions and audit history come back from object storage.

<img alt="Single-node deployment with Litestream replication of app data and server metadata to S3-compatible storage" src="https://openrun.dev/d2/single-node-litestream.svg"/>

## Features

OpenRun can be used to:

- Deploy [containerized applications](https://openrun.dev/docs/container/overview/), OpenRun will build and manage the container lifecycle
- Provision databases for apps through [service bindings](https://openrun.dev/docs/applications/servicebindings/)
- Run stateful SQLite apps with [Litestream replication to S3](https://openrun.dev/docs/applications/litestream/)
- Automatically generate a form based UI for backend [actions](https://openrun.dev/docs/actions/)
- Add OAuth/OIDC/SAML based [auth](https://openrun.dev/docs/configuration/authentication/) and [RBAC](https://openrun.dev/docs/configuration/rbac/) for app access

OpenRun supports the following:

- [Declarative](https://openrun.dev/docs/applications/overview/#declarative-app-management) app deployment
- Atomic updates (all or none) across [multiple apps](https://openrun.dev/docs/applications/overview/#glob-pattern)
- [Staging mode](https://openrun.dev/docs/applications/lifecycle/#staging-apps) for app updates, to verify whether code and config changes work on prod before making them live
- [Preview app](https://openrun.dev/docs/applications/lifecycle/#preview-apps) creation support, for trying out code changes
- Support for [github integration](https://openrun.dev/docs/configuration/security/#private-repository-access), apps being directly deployed from github code
- [Automatic SSL](https://openrun.dev/docs/configuration/networking/#enable-automatic-signed-certificate) certificate creation based on [certmagic](https://github.com/caddyserver/certmagic)
- OAuth/OIDC/SAML based [authentication](https://openrun.dev/docs/configuration/authentication/#oauth-authentication)
- Support for domain based and path based [routing](https://openrun.dev/docs/applications/routing/#request-routing) at the app level
- Integration with [secrets managers](https://openrun.dev/docs/configuration/secrets/), to securely access secrets
- Automatic [audit trail](https://openrun.dev/docs/applications/audit/) of operations and API calls, with support for custom app events
- [OpenTelemetry](https://openrun.dev/docs/configuration/telemetry/) export of request traces, container lifecycle activity and platform metrics
- Browser based [management console](https://openrun.dev/console-tour/) for apps, bindings, containers, audit events and server config
- Support for [pausing](https://openrun.dev/docs/container/config/) app containers which are idle, scaling down to zero

OpenRun also supports building [hypermedia based apps](https://openrun.dev/docs/app/routing/#html-route): lightweight backend-driven HTML apps with no build step, running in a [security sandbox](https://openrun.dev/docs/applications/appsecurity/#security-model) with allowlist based permissions.

## Roadmap

The feature roadmap for OpenRun is:

- Adding more app specs, to support additional frameworks out of the box.
- Adding more binding providers, to support additional databases and services.
- Support for app scaling on Kubernetes based on concurrent APIs. Scaling based on CPU/memory metrics is supported right now.

## Setup

### Certs and Default password

OpenRun manages TLS certs using LetsEncrypt for prod environments. For dev environments, OpenRun uses [mkcert](https://github.com/FiloSottile/mkcert) for local certs. Installing OpenRun using brew will automatically install mkcert.

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
winget install OpenRunDev.OpenRun
```

or use the install script:

```
powershell -Command "irm https://openrun.dev/install.ps1 | iex"
```

Start a new command window (to get the updated env) and run `openrun server start` to start the OpenRun service. On the first start, OpenRun generates an admin password and prints it; note it down.

### Kubernetes Install

See [kubernetes docs](https://openrun.dev/docs/container/kubernetes/) for details on installing on Kubernetes using Helm chart and Terraform based infra setup.

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

To install the [management console](https://openrun.dev/console-tour/) app, see [console install](https://openrun.dev/docs/installation/#install-the-console-app).

See [installation](https://openrun.dev/docs/installation/) for install info. See [config options](https://openrun.dev/docs/configuration/) for configuration options. To enable Let's Encrypt certificates, see [Automatic SSL](https://openrun.dev/docs/configuration/networking/#enable-automatic-signed-certificate).

The release binaries are also available at [releases](https://github.com/openrundev/openrun/releases). See [install from source](https://openrun.dev/docs/installation/#install-from-source) to build from source.

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

To use the openrun service, you need an initial config file with the service password and a work directory. The below instructions assume you are using $HOME/openrun/openrun.toml as the config file and $HOME/openrun as the work directory location.

- Create the clhome directory
- Create the openrun.toml file, and create a randomly generated password for the **admin** user account

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

Please use [Github Discussions](https://github.com/openrundev/openrun/discussions) for discussing OpenRun related topics. Please use the bug tracker for bug reports and feature requests. The [OpenRun Discord](https://discord.gg/t2P8pJFsd7) community is another option.

## Contributing

PRs welcome for bug fixes and enhancements. For application behavior related fixes, refer the [app unit test cases](https://github.com/openrundev/openrun/tree/main/internal/app/tests). Those tests run as part of regular unit tests `go test ./...`. For API related changes, OpenRun uses the [commander-cli](https://github.com/commander-cli/commander) library for [automated CLI tests](https://github.com/openrundev/openrun/tree/main/tests). To run the CLI tests, run `gmake test` from the openrun home directory.
