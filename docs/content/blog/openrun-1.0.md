---
title: "OpenRun v1.0 - declarative deploys for internal tools on Docker or Kubernetes"
description: "After over three years of development and with multiple customers in production, OpenRun has a 1.0 release."
summary: "OpenRun has a 1.0 release after three years of development."
date: 2026-11-14
authors:
  - Ajay Kidave
toc: false
sidebar:
  hide: true
---

## Background

After over three years of development, over 2000 commits, 170 releases and with multiple customers running OpenRun in production, I am happy to do the 1.0 release for OpenRun.

OpenRun is an [open source](https://github.com/openrundev/openrun) self-hosted GitOps platform for deploying web apps and internal tools declaratively. Deploy on a single node with Docker/Podman, or deploy apps onto a Kubernetes cluster. OpenRun adds the authentication, authorization and auditing features required by teams. Code based internal tools get the deployment and auth features which are usually available in low code platforms.

I started the [OpenRun project]({{< ref "/blog/intro" >}}) (called Clace initially) in April 2023 - feels like an eternity ago. I have been working on OpenRun as a part time project, doing consulting on the side.

## OpenRun Project Goals

OpenRun is built to make it easy for teams to [declaratively]({{< ref "/docs/applications/overview/#declarative-app-management" >}}) deploy internal tools. OpenRun also aims to make it easy to set up [OIDC/SAML based authentication]({{< ref "/docs/configuration/authentication" >}}), with [RBAC policies]({{< ref "/docs/configuration/rbac" >}}) to control which apps are available to which teams and roles.

{{< theme-image light="/d2/use_cases_static_light.svg" dark="/d2/use_cases_static_dark.svg" alt="Developers and admins deploy and configure OpenRun through git push, openrun apply, the console and the CLI; team members use the apps from the browser with SSO login and AI agents through MCP. OpenRun runs internal tools, ops tools, SQLite apps and personal apps" caption="OpenRun use cases" >}}

A sample OpenRun config looks like below. See [intro](/intro/#config) for a comparison with Kubernetes.

```python {filename="apps.star"}
# Resource limits (optional)
limits = {"cpus": "1", "memory": "512m"}

# A Streamlit app, served at /misc/streamlit_example
app(path="/misc/streamlit_example",
    source="github.com/streamlit/streamlit-example",
    git_branch="master", spec="python-streamlit", container_opts=limits)

# A FastHTML app, served at the fasthtml subdomain
# (fasthtml. means use this subdomain on the default domain)
app(path="fasthtml.:",
    source="github.com/AnswerDotAI/fasthtml/examples",
    spec="python-fasthtml",
    params={"APP_MODULE": "basic_ws:app"}, container_opts=limits)
```

To declaratively create these two apps, run `openrun apply apps.star`. Setting a default auth and RBAC policies in the server config means they apply to all apps.

## Product Walkthrough

This shows a recorded demo of a [sample workload](https://github.com/openrundev/demo). See [console tour]({{< ref "/console-tour" >}}) for a walkthrough of the optional console UI or take a look at the console [live demo](https://utils.demo.clace.io/console).

<div style="height: 20px;"></div>

{{< walkthrough fullscreen="true" caption="A recorded demo workload" >}}

## Technical Choices and How They Worked Out

- **Go**: OpenRun is implemented in [Go](https://go.dev/). The fast compile cycle and excellent runtime performance of Go make developing in Go fun. The difficulty of adding dynamic behavior was the one challenge in Go, especially compared to something like the dynamic class loading available in the JVM. Out of process loading using [go-plugin](https://github.com/hashicorp/go-plugin) was the solution used to get [dynamic loading behavior]({{< ref "/docs/plugins/external-plugins" >}}). There is an additional performance overhead of an RPC call but there are advantages in terms of ease of use and stability.
- **[Starlark](https://starlark-lang.org/)** as the [config language]({{< ref "/blog/starlark" >}}) for declaring apps and defining app handler functions. The familiarity of Python which Starlark provides makes it very easy to get started with for end users.
- **[Hypermedia](https://hypermedia.systems/)** (using [HTMX](https://htmx.org/)) based UI is used for the built-in [actions UI]({{< ref "/docs/actions/" >}}) and for the optional [Console app]({{< ref "/console-tour" >}}). Hypermedia apps work well for the types of apps being built with OpenRun. Fewer frontend dependencies, no separate frontend build pipeline and avoiding the NPM ecosystem have been some benefits of building Hypermedia based apps.
- **SQLite and Postgres**: For single node deployment, SQLite is used for metadata. For Kubernetes deployment, Postgres is used for metadata. No ORM is used. This was a bit more work to develop initially but allowed for complete control over the queries used for each database.
- **Declarative deployments**: Initially, the plan was to use the Kubernetes libraries for [three way merge](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/#how-apply-calculates-differences-and-merges-changes) (between new config, previous config and current state), but implementing it in OpenRun itself turned out to be simpler and easier to maintain. The [implementation](https://github.com/openrundev/openrun/blob/8b31bbe4c8685f4648f3ac9d1094702826a8c0e6/internal/server/apply.go#L1364) is custom built for what OpenRun needs, so it does not have the complexity of a general purpose library.
- **Sequencing**: OpenRun is built for teams to deploy internal tools. The three types of apps which are supported (in the order in which support was added in OpenRun) are:

  1. [Starlark apps]({{< ref "/docs/app/overview/" >}}), where the whole app is defined in Starlark.
  2. [Action apps]({{< ref "/docs/actions/" >}}) for operational tasks like runbooks, defined in Starlark.
  3. [Containerized apps]({{< ref "/docs/container/overview/" >}}), in any backend language, no Starlark required in app definition.

  In terms of user adoption, it would have been better to start with Containerized apps, since those work with existing user applications, without requiring any OpenRun specific development.

- **Starlark Apps**: OpenRun did go somewhat overboard with Starlark support, with features like allowing [database app development]({{< ref "/docs/plugins/store/" >}}) from Starlark. Containerized apps would have been better since they work with the complete language ecosystem. The Hypermedia support could have been limited to what is required for a [backend for frontend pattern](https://samnewman.io/patterns/architectural/bff/) (although hypermedia apps do not need much of a frontend). Internal apps like the [Console](https://github.com/openrundev/console) are using Starlark, so the work done to support this was useful.
- **Container Management**: Single node deployment with Docker/Podman and multi-node with Kubernetes are the two supported modes. A multi-node deployment, with each node having a Docker/Podman installation, was considered but not done since that would have introduced too many complexities in terms of container and volume management.

## What OpenRun Does Differently

There are many products which make deployments easier. OpenRun [differs]({{< ref "/compare/coolify-caprover-kamal/" >}}) in that it provides a declarative solution and is targeted at teams deploying internal tools.

- GitOps based declarative deployments, with a simple declarative spec custom designed for deploying internal tools. App creation, config updates and deletion can be done declaratively. Most other solutions allow updating existing apps through git commits, but creating new apps requires CLI/API calls or click-ops.
- [OIDC/SAML based auth]({{< ref "/docs/configuration/authentication" >}}) for controlling access to deployed apps, with support for [RBAC]({{< ref "/docs/configuration/rbac/" >}}).
- Runs like an [application server]({{< ref "/blog/appserver" >}}), allowing apps to be deployed easily with [domain and path based routing]({{< ref "/docs/applications/routing/" >}}).
- [Service bindings]({{< ref "/docs/applications/servicebindings/" >}}) which allow each app to get isolated database credentials while operations and backups are managed centrally.
- Single node deployment configuration can easily upgrade to a [Kubernetes based deployment]({{< ref "/docs/container/kubernetes/" >}}), with no changes required in app declarations.
- Setting up a development environment for apps, with [live reload]({{< ref "/docs/container/devreload" >}}), is a built-in feature (on macOS, Windows and Linux).

## Can't agents just deploy your code?

With recent improvements in AI, internal tools which would have required weeks of development work can now be built much faster using AI agents. Higher level abstractions for deploying internal tools securely are necessary now, since the [tools themselves are easier to build]({{< ref "/blog/code-first-internal-tools" >}}).

Agents are at a point where they can handle the deployment workflow themselves. Letting agents directly do production deployments might be fine for testing and personal workflows, but that approach is not suited for team environments. A declarative approach is better if you want to set up multiple deployment environments and restore an environment from scratch.

Agents are pretty good at writing the YAML boilerplate required for Kubernetes deployments. Internal tools generally require OIDC/SAML authentication, RBAC and [audit logs]({{< ref "/docs/applications/audit" >}}). [Kubernetes]({{< ref "/compare/diy-kubernetes" >}}) alone does not make enabling such access policies easy. OpenRun provides a higher level app deployment abstraction. This helps reduce the overhead of maintaining the deployment configuration. Using Kubernetes directly, multiple systems like CI builder, ArgoCD, auth proxy, Internal Developer Platform (IDP) etc. have to be configured to get the functionality OpenRun provides.

## What 1.0 Means

The core config format, CLI commands and API are stable and will maintain backward compatibility across the 1.x releases. The plan is to ensure that existing deployments should work without issues when doing upgrades across 1.x, as new features are added and issues fixed.

Date based versioning is being used for the 1.x [releases](https://github.com/openrundev/openrun/releases). All fixes go on the `main` branch and releases use the `1.YYMM.D[D]V` version format, where V is the version number on that day, zero-indexed. So v1.2611.130 means the first release on 13 Nov 2026.

## Licensing and Support

The OpenRun server and its built-in features, including SSO, RBAC, audit logs, and PostgreSQL/MySQL/Redis service bindings, are [Apache 2.0](https://github.com/openrundev/openrun/blob/main/LICENSE) licensed.

Service bindings for additional databases and data platforms (Snowflake, Databricks, SQL Server, Oracle, MongoDB, ClickHouse) are available as downloadable [service providers]({{< ref "/docs/applications/servicebindings/#binding-providers-sql-server-oracle-mongodb-snowflake-clickhouse" >}}). These are under the [PolyForm Free Trial License 1.0.0](https://polyformproject.org/licenses/free-trial/1.0.0), which allows limited duration evaluation use.

Paid support is planned for OpenRun and the commercial service providers. The paid plan will also include SemVer based long term support releases, with fixes backported from the `main` branch. All features and fixes will be available in releases from the `main` branch. A SOC 2 Type 2 report on the organization will be available to customers on the paid plan. Email [contact@openrun.dev](mailto:contact@openrun.dev) for support.

To try out OpenRun, check out the [Quick Start]({{< ref "/docs/quickstart" >}}), which works on macOS, Windows and Linux.
