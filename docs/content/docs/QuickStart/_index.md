---
title: "Self-Hosted Web App Deployment Quick Start"
linkTitle: "Quick Start"
weight: 50
description: "Deploy web apps with an open-source, self-hosted PaaS alternative with GitOps, running on a VPS, single server or Kubernetes cluster."
summary: "Quick start for self-hosted web app deployment on a VPS, single server or Kubernetes."
---

OpenRun is an Apache-2.0 licensed, self-hosted platform for deploying web apps and internal tools. One binary runs the server on Linux, macOS or Windows. Apps run as containers on Docker or Podman on a single server, or as deployments on a Kubernetes cluster. App configuration is kept in a declaration file that is applied from the CLI or synced from Git. See how OpenRun [compares]({{< ref "compare" >}}) with self-hosted PaaS platforms, managed container services and DIY Kubernetes setups.

{{< theme-image light="/d2/quickstart_overview_light.svg" dark="/d2/quickstart_overview_dark.svg" alt="OpenRun overview: apps are managed through a declaration file in Git, the CLI or the console; the server routes user requests through TLS, login and RBAC to staging and production apps backed by containers or Starlark handlers" >}}

The quick start is split into three pages:

- This page: what OpenRun provides, installation and the first deployment.
- [Configuration]({{< ref "docs/quickstart/configuration" >}}): the config file, authentication, RBAC, domains and secrets.
- [Managing apps]({{< ref "docs/quickstart/managing-apps" >}}): the declaration file, staging and promotion, GitOps sync, and the same operations from the CLI and console.

## What OpenRun Provides

- **Declarative GitOps**. Apps and database bindings are declared in a Starlark file. `openrun apply` creates or updates them and a scheduled sync keeps a server matching a file in Git. See [declarative app management]({{< ref "docs/applications/overview/#declarative-app-management" >}}).
- **Staged deployments**. Every production app has a staging app. Config and code changes land on staging first and are promoted once verified. See [app lifecycle]({{< ref "docs/applications/lifecycle" >}}).
- **Containers without writing Dockerfiles**. App specs supply the container config for Streamlit, Gradio, FastAPI, Flask, FastHTML, Shiny, Go, Hono and other frameworks. A repo with its own Dockerfile uses the `container` spec. Idle containers are stopped and restarted on demand. See [containerized apps]({{< ref "docs/container/overview" >}}).
- **Authentication and RBAC**. Each app picks `none`, the system admin account, builtin users, OAuth, OIDC, SAML or client certificates. RBAC grants decide who can reach and manage each app. See [authentication]({{< ref "docs/configuration/authentication" >}}) and [RBAC]({{< ref "docs/configuration/rbac" >}}).
- **Database service bindings**. PostgreSQL, MySQL, SQLite and Redis bindings give each app its own schema, user or key prefix, with credentials passed through the app environment. See [service bindings]({{< ref "docs/applications/servicebindings" >}}).
- **Operations**. TLS certificates from Let's Encrypt or mkcert, secrets from Vault, AWS or the environment, an audit log of every operation, [MCP apps]({{< ref "docs/applications/mcp" >}}) and a web [management console]({{< ref "/console-tour" >}}).
- **Action and hypermedia apps**. Starlark backends with a generated form UI for operational tasks, or fully custom hypermedia UIs. See [action apps]({{< ref "docs/actions" >}}) and [hypermedia apps]({{< ref "docs/app" >}}).

## Onboarding

{{< theme-image light="/d2/quickstart_onboarding_light.svg" dark="/d2/quickstart_onboarding_dark.svg" alt="Six onboarding steps: install, start the server, declare apps, apply, open the app, keep the file in Git" >}}

{{% steps %}}

### Installation

On macOS or Linux, run

```shell
curl -sSL https://openrun.dev/install.sh | sh
```

With Homebrew:

```shell
brew tap openrundev/homebrew-openrun
brew install openrun
```

On Windows:

```shell
winget install OpenRunDev.OpenRun
```

Native Linux packages, Docker images and a source build are covered in [installation]({{< ref "docs/installation" >}}). For container based apps, Docker, Podman or OrbStack has to be running on the machine. For local HTTPS without certificate warnings, install [mkcert](https://github.com/FiloSottile/mkcert) and run `mkcert -install` before the first server start; the brew install does this for you.

### Start the server

Open a new terminal so the updated `PATH` is picked up, then run

```shell
openrun server start
```

The first start generates an admin password and prints it. Save it, the `admin` account is used by apps with `system` auth and by the console. Brew users run `brew services start openrun` instead and find the password in the service output. The server listens on [https://localhost:25223](https://localhost:25223) by default and keeps its config, metadata database and logs under `$OPENRUN_HOME`, which is `$HOME/openrun` for script installs.

### Declare apps

Create a file named `apps.ace` (any name works) with one `app` entry per app:

```python {filename="apps.ace"}
# A hypermedia app from the OpenRun apps repo
app("/utils/bookmarks", "github.com/openrundev/apps/utils/bookmarks")

# A Streamlit app in a container, built from the python-streamlit spec
app("/streamlit", "github.com/streamlit/streamlit-example",
    git_branch="master", spec="python-streamlit",
    container_opts={"cpus": "1", "memory": "512m"})
```

The first argument is the install path, optionally prefixed with a domain as `domain:path`. The second is the source: a Git URL or a directory on the server. `spec` selects the container configuration for sources without an `app.star` file. The full property list is in [app configuration]({{< ref "docs/applications/overview/#app-configuration" >}}).

### Apply

```shell
openrun apply --approve apps.ace
```

This creates a staging app and a production app for each entry and loads the app source into the metadata database. `--approve` accepts the permissions each app requests. Add `--dry-run` first to see what would change without changing anything. Container images are built on the first request to the app, not during apply.

```shell
openrun app list --internal
```

lists the production apps and their staging apps with their versions.

### Open the app

Open [https://localhost:25223/utils/bookmarks](https://localhost:25223/utils/bookmarks) and [https://localhost:25223/streamlit](https://localhost:25223/streamlit). The staging copies are at the same paths on `stage.localhost`. The first request to the Streamlit app builds and starts its container, so it takes a little longer.

New apps use `none` authentication unless configured otherwise. Add `auth="system"` to an entry to require the admin login, or set a server default as described in [configuration]({{< ref "docs/quickstart/configuration" >}}).

### Keep the file in Git

Commit `apps.ace` to a repository and schedule it:

```shell
openrun sync schedule --approve --promote github.com/myorg/platform/apps.ace
```

Every 15 minutes the server fetches the file, applies changes and, with `--promote`, promotes them to production. Code changes in the app repos are picked up the same way. Add `--prune` to delete apps the file no longer declares. See [automated sync]({{< ref "docs/applications/overview/#automated-sync" >}}).

{{% /steps %}}

## Other Ways to Manage Apps

The declaration file is the recommended way to manage apps, since the file in Git records what is deployed. The same operations are available imperatively.

**CLI**. `openrun app create` installs one app, `app reload` picks up new source, `app promote` moves staged changes to production:

```shell
openrun app create --approve github.com/openrundev/apps/utils/bookmarks /book
openrun app reload --promote /book
```

Apps created this way can be moved into a declaration file later with `openrun export`. See [exporting configuration]({{< ref "docs/applications/export" >}}).

**Console**. The [management console]({{< ref "/console-tour" >}}) is a web UI for apps, syncs, bindings, containers, audit logs and server config. It is itself an OpenRun app:

```shell
openrun app create --approve --auth system \
    --param enable_all_features=true --param enable_updates=true \
    github.com/openrundev/console /console
```

Open [https://localhost:25223/console](https://localhost:25223/console) and log in as `admin` with the password from the first server start. See [console install]({{< ref "docs/installation/#install-the-console-app" >}}) for the parameters and a live [demo](https://utils.demo.clace.io/console/).

Changes made from the CLI or console are kept on the next apply. The apply does a three way merge, only properties that changed in the declaration file are written. `--clobber` makes the file win over everything.

## App Types

- **Containerized apps**. The backend runs in a container and OpenRun proxies requests to it. Any language or framework works. Frameworks with an [app spec]({{< ref "docs/container/appspecs" >}}) need no Dockerfile.
- **Action apps**. The backend is a Starlark function. OpenRun generates a form and a report page, which suits running a command, calling an API or a scheduled job. See [action apps]({{< ref "docs/actions" >}}).
- **Hypermedia apps**. Starlark request handlers with Go templates and HTMX, optionally combined with containers and actions. See [hypermedia apps]({{< ref "docs/app" >}}).

All types get staged deployment, authentication, RBAC, secrets, service bindings and TLS from the server.

## Next Steps

{{< cards >}}
{{< card link="configuration" title="Configuration" subtitle="Config file, authentication types, RBAC, domains, TLS and secrets" icon="adjustments" >}}
{{< card link="managing-apps" title="Managing Apps" subtitle="Declaration file, staging and promotion, GitOps sync, CLI and console" icon="collection" >}}
{{< card link="../installation" title="Installation" subtitle="Native packages, systemd, Windows service, Docker and source builds" icon="download" >}}
{{< card link="../container/overview" title="Containerized Apps" subtitle="App specs, builds, Kubernetes and container config" icon="cube" >}}
{{< /cards >}}
