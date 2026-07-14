---
title: "Quick Start"
weight: 50
summary: "Quick Start guide on using OpenRun"
---

OpenRun is an Apache-2.0 licensed web app deployment platform for internal tools. OpenRun is distributed as a single binary and runs natively on Linux, macOS and Windows, using Docker/Podman on a single-node or working with Kubernetes for a distributed setup.

## Installation

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
powershell -Command "irm https://openrun.dev/install.ps1 | iex"
```

Start a new command window (to get the updated env) and run `openrun server start` to start the OpenRun service.

### Install Apps

Once OpenRun server is running, to install apps declaratively, open a new window and run

```
openrun apply --approve github.com/openrundev/openrun/examples/utils.star
```

#### Setup Dev Environment

To instead setup a dev environment for apps, run

```
openrun apply --dev --approve github.com/openrundev/openrun/examples/utils.star
```

This creates a local copy of the source code and sets up a live reload url for each app.

#### Setup GitOps Pipeline

To setup an automatic GitOps sync, run

```
openrun sync schedule --approve --promote \
    github.com/openrundev/openrun/examples/utils.star
```

This starts a background sync which automatically creates new apps and updates existing apps, reading latest app config and code from Git.

#### Install Apps using CLI

To install apps using the CLI, run

```
openrun app create --approve github.com/openrundev/apps/utils/bookmarks /book
```

Open https://localhost:25223 to see the app listing. The bookmark manager is available at https://localhost:25223/book.

## Application Types

OpenRun allows easy management of multiple apps on one OpenRun server installation. There are three main types of OpenRun apps:

- **Containerized Apps** - App backend (in any language/framework) runs in a container. OpenRun acts as an application server doing reverse proxying for the app APIs. This allows OpenRun to install and manage apps built in frameworks like Streamlit/Gradio/FastHTML/FastAPI/Flask etc. Frameworks which have a `appspec` defined for OpenRun can be used without any further manual configuration. AppSpecs define how the container should be built and started and also how the request routing should be done to the app. For other frameworks, a Dockerfile is required in the app sources.
- **Action apps** - App backend is defined in Starlark and an auto generated form UI and report is created by OpenRun. These apps can be use dto related Rundeck/Jenkins type of operational automation use cases.
- **Hypermedia apps** - The app is completely customizable, allowing combining containerized apps with actions and custom API handlers, building Hypermedia driven UIs.

For all apps, OpenRun provides blue-green staged deployment, OAuth access controls, secrets management, TLS cert management etc.

## Containerized Applications

OpenRun can run any app which run in a container. OpenRun works with Docker and Podman. Using an [app spec]({{< ref "app/overview/#building-apps-from-spec" >}}) allows you to use OpenRun without requiring any changes to your app. No container file is even required. For example, the command

```
openrun app create --spec python-streamlit --branch master --approve \
   github.com/streamlit/streamlit-example /streamlit
```

does the following:

- Checks out the `github.com/streamlit/streamlit-example`
- Copies any missing files from the `python-streamlit` app specification into the repo
- Load the app source and metadata into the OpenRun server metadata database (SQLite)

When the first API call is done to the app (lazy-loading), the OpenRun server will build the container image from the `Dockerfile` defined in the spec, start the container and set up the proxy for the app APIs.

Any env params which need to be passed to the app can be configured as [app params]({{< ref "app/overview/#app-parameters" >}}). Params are set during app creation using `app create --param port=9000` or after creation using `param update port 9000 /myapp`.

If the source repo has a `Containerfile` or `Dockerfile`, the `container` spec can be used. It is a generic spec which works with any language or framework. If the container file defines a port using the `EXPOSE` directive, then port is not required. Otherwise, specify a port, for example

```
openrun app create --spec container --approve \
   --param port=8000 github.com/myorg/myrepo /myapp
```

See [containerized apps]({{< ref "container/overview/" >}}) for details.

## Action Apps

For use cases where an existing CLI application or API needs to be exposed as a web app, actions provide an easy solution. First, define the parameters to be exposed in the form UI. Create a `params.star` file with the params. For example,

```python {filename="params.star"}
param("repo", description="The GitHub repository to look up", default="openrundev/openrun")
```

The app defines a run handler which calls the GitHub API for the specified repository, using the [http plugin]({{< ref "docs/plugins/overview" >}}), and returns the stats as text.

```python {filename="app.star"}
load ("http.in", "http")

def run(dry_run, args):
   repo = http.get("https://api.github.com/repos/" + args.repo).value.json()
   out = ["Stars: %d" % repo["stargazers_count"], "Forks: %d" % repo["forks_count"],
          "Open Issues: %d" % repo["open_issues_count"]]
   return ace.result("Repo info for " + args.repo, out)

app = ace.app("Repo Info",
   actions=[ace.action("Repo Info", "/", run, description="Show the GitHub stats for the specified repository")],
   permissions=[
     ace.permission("http.in", "get", ["regex:^https://api\\.github\\.com/.*"]),
   ],
)
```

When accessed, the app shows a form for the params, with the action output displayed below it. For example, a file listing action app looks like:

<picture  class="responsive-picture" style="display: block; margin-left: auto; margin-right: auto;">
  <source media="(prefers-color-scheme: dark)" srcset="/images/list_files_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="/images/list_files_light.png">
  <img alt="List files app" src="/images/list_files_light.png">
</picture>

## Managing Applications

Multiple applications can be installed on an OpenRun server. Each app has a unique path and can be managed separately. The app path is made up of domain_name:url_path. If no domain_name is specified during app creation, the app is created in the default domain. The default domain is looked up when no specific domain match is found. See [app routing]({{< ref "applications/routing/" >}}) for details about routing.

For local env, URL-based routing can be used or `*.localhost` domain can be used for domain-based paths. For production deployment, if wildcard DNS is set up, domain-based routing can be used without new DNS entries being required per app. Apps can be hosted on multiple unrelated domains on one OpenRun server.

## App Installation

To install apps, run `openrun app create --approve <source_url> <[domain:]app_path>`. For example,

```shell
openrun app create --approve github.com/openrundev/apps/system/disk_usage /disk_usage
```

This is installing the `system/disk_usage` app from the main branch of the `openrundev/apps` repo on GitHub. The app is installed for the default domain, to the `/disk_usage` path. Opening [https://127.0.0.1:25223/disk_usage](https://127.0.0.1:25223/disk_usage) will initialize the app and show the app home page.

{{<callout type="warning" >}}
The `/disk_usage/*` path is now reserved for APIs under this app. No new apps can be installed under the `/disk_usage/` path, but `/disk_usage2` is available. Similarly, installing an app under `/` path means no new apps can be installed for the default domain.
{{</callout>}}

If the app code is available on the OpenRun server node, the `app create` can be done directly with the local disk path:

```shell
openrun app create --approve ./diskapp /disk_usage_local
```

When developing an app, the source code for the app has to be present locally. To install an app in dev mode, add the `--dev` option.

```shell
openrun app create --dev --approve ./diskapp /disk_usage_dev
```

If an app is created in dev mode with git as the source path, the git repo is checked out automatically into `$OPENRUN_HOME/app_src` and the app is created from the local source.

In dev mode, source code changes are picked up immediately and the app is live reloaded. For non-dev (prod) apps, `app reload` has to be done to pick up changes, from local disk or from git.

```
openrun app reload --approve --promote "/disk_usage*"
```

For apps created from GitHub source, `app reload` will pick up the [latest changes]({{< ref "applications/lifecycle/#github-reload" >}}) from the branch specified during `app create` (default is `main`). For apps created from local disk sources, the reload loads from the folder originally used during the create. For non-dev apps, the source code is loaded into the SQLite metadata database managed by the OpenRun server. This allows for versioning, even when working with local sources.

## Service Bindings

Service bindings are an easy way to configure one database installation properly (with backups, fault tolerance, security etc) and then safely share that database across multiple apps. This is an alternate approach as against usual deployment tooling where each app is assumed to create its own database from scratch, which ignores the challenges with ensuring that the database is properly administered.

Service bindings are supported for Postgres and MySQL currently. See details in [service bindings]({{< ref "applications/servicebindings/" >}})

## Staged Deployments

For dev mode apps, there is just one app. For a prod mode app, creating the app creates a staging app and the actual production app. All config and code changes are applied on the [staging mode]({{< ref "applications/lifecycle/#staging-apps" >}}) app first, and then manually promoted using `app promote`. Promotion is automatic if `--promote` option is specified for the `app reload` (or any other command performing a metadata change).

The `app list` command lists all the apps for the specified [glob pattern]({{< ref "applications/overview/#glob-pattern" >}}). By default, it lists only the dev and prod apps. To list the staging apps also, add the `--internal` (or `-i`) option to `app list`. `all` is a shortcut for `*:**`, which means all apps in all domains. `all` is the default for `app list`. For example:

```shell
openrun app list --internal all
```

lists all the apps and internal apps for each app. `openrun app list "example.com:**"` lists the main apps for the example.com domain.

The staging app can be used to verify whether changes are working before the production app is updated. By default, the staging app uses a staging subdomain and the same path as the production app. So for an app at `https://example.com/`, the staging URL is `https://stage.example.com/`. For an app at `https://example.com/utils/app1`, the staging app URL is `https://stage.example.com/utils/app1`.

Use `openrun app create --stage-at path ...` to use the path based staging location, where `_cl_stage` is suffixed to the production path. Use `--stage-at <domain>` to put the staging app on a specific domain.

To promote changes from staging to prod, run:

```shell
openrun app promote all
```

or `openrun app promote "/disk_usage*"` to promote specific apps. Use the `--dry-run` option to verify commands before they are actually applied.

## App Listing

Use `openrun app list` to get list of installed app. By default, all apps are listed. Use a glob pattern like `example.com:**` to list specific apps. Pass the `--internal` or `-i` option to `list` to include the internal apps in the app listing. The pattern matches the main apps, and if the internal option is specified, the matched app's linked apps are also listed.

Use `openrun version list` to get list of versions for an app. `openrun version switch` allows switching between versions. The version command can be run separately on the staging app and prod app, like `openrun version list stage.example.com:/myapp` and `openrun version list example.com:/myapp`. The current version is indicated in the output.
