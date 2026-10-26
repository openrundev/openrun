---
title: "Managing Apps Quick Start"
linkTitle: "Managing Apps"
weight: 20
description: "Manage OpenRun apps declaratively from a Git repo with staged deployments and promotion, or imperatively from the CLI and the management console."
summary: "Declaration file, staging and promotion, GitOps sync, CLI and console."
---

Apps are managed in three ways. The declaration file is the primary one: it records what is deployed and can be synced from Git. The CLI and the console do the same operations imperatively, and all three can be mixed on one server.

## The Declaration File

A declaration file is a Starlark file with `app` and `binding` entries. This example deploys a Streamlit app and a containerized API that shares a PostgreSQL schema through a service binding:

```python {filename="apps.ace"}
# A base binding creates a schema and role on the postgres service
binding("/todo-data/base", "postgres")
# A derived binding shares that schema with a read-only role
binding("/todo-data/reader", "/todo-data/base", grants=["read:*"])

app("/todo", "github.com/myorg/todo", spec="container",
    auth="oidc_okta", bindings=["/todo-data/base"],
    params={"PORT": "8080"}, container_opts={"memory": "512m"})

app("/todo/reports", "github.com/myorg/todo-reports",
    git_branch="main", spec="python-streamlit",
    auth="oidc_okta", bindings=["/todo-data/reader"])
```

The properties used most are:

| Property | Purpose |
| --- | --- |
| path, source | Install address as `[domain:]path` and the Git URL or server directory for the code |
| `spec` | Container config for sources without an `app.star`, see [app specs]({{< ref "docs/container/appspecs" >}}) |
| `auth` | Auth type, see the [configuration quick start]({{< ref "docs/quickstart/configuration/#authentication" >}}) |
| `params` | Values passed to the app, as environment variables for containers |
| `bindings` | Service bindings whose credentials are injected into the app |
| `git_branch`, `git_commit`, `git_auth` | Which revision to deploy and which credential to fetch it with |
| `container_opts`, `container_vols`, `sidecars` | CPU and memory limits, volumes and sidecar containers |
| `dev` | Create the app in dev mode with live reload from a local checkout |

The full list, including jobs, deploy hooks and MCP settings, is in [app configuration]({{< ref "docs/applications/overview/#app-configuration" >}}). Starlark means loops, helper functions and shared variables work in the file; `openrun pretty-print` shows the evaluated result.

## Apply, Stage, Promote

{{< theme-image light="/d2/quickstart_lifecycle_light.svg" dark="/d2/quickstart_lifecycle_dark.svg" alt="Apply or scheduled sync loads the declaration and app source into the staging app, which is then promoted to the production app" >}}

Every production app has a staging app at the same path on the `stage` subdomain, for example `stage.example.com/todo` for `example.com/todo`. Apply writes to staging. Promotion copies staging to production, so production only ever runs a version that was already running on staging.

{{% steps %}}

### Check what would change

```shell
openrun apply --dry-run apps.ace
```

### Apply to staging

```shell
openrun apply --approve apps.ace
```

New apps get a staging and a production app at version 1. Existing apps get their staged version bumped. `openrun app list --internal` shows both, with a `*` next to `PROD` when staged changes are waiting.

### Verify on staging

Open the app on the stage subdomain. For containerized apps, `--verify` on the apply starts the new container and waits for it to become healthy before the change is recorded, and rolls back if it does not.

### Promote

```shell
openrun app promote all
```

or `openrun app promote "/todo*"` for a subset. `openrun apply --promote` applies and promotes in one step for the apps where that is acceptable. Promotion moves all staged changes of an app, not only the most recent one.

{{% /steps %}}

Apply does a three way merge: the previous declaration, the new declaration and the live config are compared, and only properties that changed in the file are written. A param added from the CLI or console survives the next apply. `--clobber` resets the app to exactly what the file says. The pair `openrun delete apps.ace` removes everything the file declares.

## GitOps Sync

Once the file is in a repository, a scheduled sync applies it on an interval:

```shell
openrun sync schedule --approve --promote --verify github.com/myorg/platform/apps.ace
openrun sync list
openrun sync run <sync_id>      # run it now
```

Each run fetches the file, applies changes, reloads apps whose source repos have new commits, verifies container apps and promotes. The default interval is 15 minutes, `--minutes` changes it. `--prune` deletes apps and bindings the sync created that are no longer declared, which makes the file the source of truth for those resources. Private repos use a `[git_auth.<name>]` entry, see [private repository access]({{< ref "docs/configuration/security/#private-repository-access" >}}).

To react to pushes instead of polling, [webhooks]({{< ref "docs/applications/webhooks" >}}) trigger reloads and promotions from CI or GitHub.

## The Same Operations From the CLI

Each declaration property has a CLI counterpart. Changes made this way are staged like declarative ones and promoted the same way.

| Task | Command |
| --- | --- |
| Create an app | `openrun app create --approve --spec container github.com/myorg/todo /todo` |
| Pick up new source | `openrun app reload /todo` |
| Promote | `openrun app promote /todo` |
| Change auth | `openrun app update auth oidc_okta /todo` |
| Change a param | `openrun param update PORT 9000 /todo` |
| Attach bindings | `openrun app update bindings /todo-data/base /todo` |
| List versions and roll back | `openrun version list /todo`, `openrun version revert /todo` |
| Delete | `openrun app delete /todo` |

Most commands accept a glob such as `"example.com:**"` or `all` to act on many apps. Anything created from the CLI can be written out as a declaration file with `openrun export --output apps.ace` and managed declaratively from then on. See [app overview]({{< ref "docs/applications/overview" >}}) and the [reference]({{< ref "docs/reference" >}}).

## The Same Operations From the Console

The [management console]({{< ref "/console-tour" >}}) creates apps from a form with a validate step that lists the permissions the app will request, shows staging and production versions per app, and manages syncs, bindings, containers and the audit log.

{{< theme-image light="/images/console/09-app-detail-light.png" dark="/images/console/09-app-detail-dark.png" alt="Console app detail page with production and staging versions, approved permissions and links to open the app" >}}

Install it with the command in the [quick start]({{< ref "docs/quickstart/#other-ways-to-manage-apps" >}}). Console changes go through the same staging and promotion, and are kept on the next apply unless the file changes the same property.

## Dev Mode

Add `--dev` to `apply` or `app create` to create apps in dev mode. Git sources are checked out under `$OPENRUN_HOME/app_src`, source changes are picked up without a reload, and there is no staging app. Dev mode is for building apps on a workstation; production servers use the staged flow. See [development apps]({{< ref "docs/applications/lifecycle/#development-apps" >}}).

## Containerized Applications

Container apps are declared like any other app. The `spec` picks a framework config, for example `python-streamlit`, `python-fasthtml`, `go` or `js-hono`, and OpenRun copies the Dockerfile and startup config from the spec into the app. A source repo with its own Dockerfile uses the `container` spec, with a `port` param when the Dockerfile has no `EXPOSE`:

```python {filename="apps.ace"}
app("/api", "github.com/myorg/api", spec="container", params={"port": "8000"})
```

The image is built and the container started on the first request, idle containers are stopped and restarted on demand, and params are passed as environment variables. On Kubernetes each app becomes a deployment. See [containerized apps]({{< ref "docs/container/overview" >}}), [app specs]({{< ref "docs/container/appspecs" >}}) and [Kubernetes]({{< ref "docs/container/kubernetes" >}}).

## Service Bindings

A service is a database the platform team configures once, with backups and access control in place. A binding creates an isolated schema and role, database and user, or key prefix on that service for one app, and the credentials reach the app as environment variables. Derived bindings share a base binding's schema with narrower grants, such as read-only access for a reporting app. Bindings are declared in the same file as the apps and are staged and promoted with them. See [service bindings]({{< ref "docs/applications/servicebindings" >}}).

## Next Steps

{{< cards >}}
{{< card link="../../applications/lifecycle" title="App Lifecycle" subtitle="Dev, staging, preview and production apps, reloads, promotion and versions" icon="selector" >}}
{{< card link="../../applications/export" title="Export Configuration" subtitle="Move CLI and console created apps into a declaration file" icon="document-duplicate" >}}
{{< card link="../../applications/jobs" title="Jobs and Deploy Hooks" subtitle="Scheduled tasks, manual jobs and deployment gates declared with the app" icon="clock" >}}
{{< card link="../../develop" title="Developing Apps" subtitle="Write action and hypermedia apps in Starlark" icon="code" >}}
{{< /cards >}}
