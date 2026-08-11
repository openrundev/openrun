---
title: "OpenRun vs Coolify, CapRover, Kamal and Dokku"
weight: 100
date: 2026-08-10
description: "Compare OpenRun with self-hosted PaaS platforms like Coolify, CapRover, Kamal and Dokku: true GitOps, SSO for apps, RBAC, scale-to-zero, service bindings and Kubernetes support."
summary: "OpenRun compared with self-hosted PaaS platforms like Coolify, CapRover, Kamal and Dokku."
---

Coolify, CapRover, Kamal and Dokku are popular self-hosted alternatives to Heroku-style platforms. They let you deploy web apps to your own servers using Docker. OpenRun serves the same self-hosting need with a different design: apps are managed declaratively through Git, every app gets SSO and RBAC, idle apps scale to zero and the same config deploys to a VPS or to Kubernetes.

**Summary**: Choose OpenRun for internal tools and team web apps that need GitOps management, authentication, access control and audit logs. Choose Coolify, CapRover or Dokku when you want to self-host multi-container Docker Compose stacks or one-click packaged software. Choose Kamal when you want a deployent tool for a small number of apps whose servers you script directly.

## True GitOps vs Git-Triggered Code Deploys

The biggest difference is what Git controls.

With most self-hosted PaaS platforms, Git integration means a push to a repo triggers a rebuild and redeploy of that app's source code. Creating a new app, changing its domain, setting environment variables, adjusting resource limits or attaching a database are separate steps done through a web UI or CLI commands. Those changes are not version controlled and are hard to review or roll back.

OpenRun manages the full application lifecycle through Git. Apps are [declared in a config file]({{< ref "docs/applications/overview/#declarative-app-management" >}}) checked into a repo:

```python {filename="apps.star"}
limits = {"cpus": "1", "memory": "512m"}

app(path="/dashboard", source="github.com/myorg/sales-dashboard",
    spec="python-streamlit", container_opts=limits)
```

One command sets up the pipeline:

```sh
openrun sync schedule --approve --promote github.com/myorg/platform/apps.star
```

OpenRun polls the repo and applies changes: newly declared apps are created, config edits are applied to existing apps and code updates are deployed. Config changes go through pull request review like code. Updates across apps are atomic, and [staged (blue-green) deployment]({{< ref "docs/applications/lifecycle/#staging-apps" >}}) applies to config changes as well as code changes. This is the same reason teams use Terraform for infrastructure and Kubernetes manifests with ArgoCD for services: the desired state lives in Git.

## Feature Comparison

| Capability                                  | OpenRun                                                                                          | Coolify                                                                                      | CapRover                                                | Kamal                                              | Dokku                                    |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------- | ------------------------------------------------------- | -------------------------------------------------- | ---------------------------------------- |
| App creation and config through Git         | Yes, declarative config file covers all apps                                                     | Partial: UI-driven; for Compose-based deploys the Compose file in Git is the source of truth | No, UI/CLI-driven                                       | Partial, `deploy.yml` per app, imperative CLI runs | No, CLI-driven                           |
| Code deploys from Git                       | Yes                                                                                              | Yes                                                                                          | Yes                                                     | Yes (via registry)                                 | Yes (git push)                           |
| Management UI                               | Optional [web console]({{< ref "console-tour" >}}); CLI, UI and declarative GitOps all supported | Yes, primary interface                                                                       | Yes, primary interface                                  | No, CLI only                                       | No, CLI only (third-party UIs available) |
| SSO for deployed apps (OAuth/OIDC/SAML)     | Yes, for every app                                                                               | Console login only                                                                           | Console login only                                      | No                                                 | No (plugins for basic auth)              |
| RBAC per app                                | Yes, path/domain based grants                                                                    | Team roles for the console                                                                   | No                                                      | No                                                 | No                                       |
| Audit logs                                  | Yes, built in                                                                                    | Limited                                                                                      | No                                                      | No                                                 | No                                       |
| Scale idle apps to zero                     | Yes, automatic                                                                                   | No                                                                                           | No                                                      | No                                                 | No (manual ps:scale)                     |
| Reverse proxy                               | Built into OpenRun                                                                               | Traefik or Caddy                                                                             | Nginx                                                   | kamal-proxy                                        | Nginx (or others)                        |
| Automatic TLS                               | Yes                                                                                              | Yes                                                                                          | Yes                                                     | Yes                                                | Yes (plugin)                             |
| Kubernetes support                          | Yes, same config via Helm chart                                                                  | No                                                                                           | No (Docker Swarm for clustering)                        | No                                                 | Partial (k3s scheduler)                  |
| Staging environment with explicit promotion | Yes: each app gets a staging version, promoted after verification, for code and config           | No; rolling updates and PR preview deployments                                               | No; start-first zero-downtime deploys with rollback     | No; rolling deploys via kamal-proxy                | No; zero-downtime deploy checks          |
| Docker Compose stacks                       | No                                                                                               | Yes                                                                                          | Partial: limited Compose parser, used by one-click apps | Accessories                                        | No (plugins for services)                |
| Database provisioning                       | Service bindings to managed Postgres/MySQL, managed SQLite + Litestream                          | Deploys DB containers                                                                        | One-click DB containers                                 | Accessory containers                               | Plugin DB containers                     |
| Packaging                                   | Single binary                                                                                    | Docker containers                                                                            | Docker containers                                       | Ruby gem                                           | Shell based install                      |
| License                                     | Apache-2.0                                                                                       | Apache-2.0                                                                                   | Apache-2.0                                              | MIT                                                | MIT                                      |

Details for the OpenRun column: [authentication]({{< ref "docs/configuration/authentication/" >}}), [RBAC]({{< ref "docs/configuration/rbac/" >}}), [audit events]({{< ref "docs/applications/audit/" >}}), [scale-to-zero]({{< ref "docs/container/config/" >}}), [service bindings]({{< ref "docs/applications/servicebindings/" >}}), [Litestream]({{< ref "docs/applications/litestream/" >}}) and [Kubernetes]({{< ref "docs/container/kubernetes/" >}}).

Comparison last verified on August 10, 2026 against the [Coolify](https://coolify.io/docs/), [CapRover](https://caprover.com/docs/), [Kamal](https://kamal-deploy.org/docs/) and [Dokku](https://dokku.com/docs/) documentation, including the [Coolify Docker Compose](https://coolify.io/docs/knowledge-base/docker/compose), [Coolify rolling updates](https://coolify.io/docs/knowledge-base/rolling-updates), [Coolify preview deployments](https://coolify.io/docs/applications/ci-cd/github/preview-deploy), [CapRover Docker Compose](https://caprover.com/docs/docker-compose.html) and [CapRover zero-downtime deployments](https://caprover.com/docs/zero-downtime.html) pages.

## Where OpenRun Differs

### SSO and RBAC for Apps, Not Just the Console

Self-hosted PaaS platforms authenticate access to their own dashboard. The apps they deploy are on their own for authentication: each app implements login itself, or you put an OAuth proxy in front. OpenRun protects every deployed app with [OAuth, OpenID Connect, SAML or client certificates]({{< ref "docs/configuration/authentication/" >}}), configured once at the server level. [RBAC]({{< ref "docs/configuration/rbac/" >}}) then controls which users and IdP groups can access which apps, using path and domain patterns. For internal tools, this removes the need to build login into every app.

### Scale to Zero

OpenRun is itself the web server, with no separate Nginx or Traefik in front. Because OpenRun sees every request, it can stop idle app containers and lazily start them on the next request. Internal tools are idle most of the time, so a single server can host hundreds of apps with only the active ones consuming CPU and memory. Platforms that route through an external proxy keep every app container running.

### Service Bindings Instead of Database Containers

Coolify, CapRover and Dokku deploy databases as containers next to your app. That works for getting started, but each database container needs its own backups, monitoring and upgrades. OpenRun takes the approach used in larger organizations: databases are managed externally (a team-managed instance, RDS and so on) and [service bindings]({{< ref "docs/applications/servicebindings/" >}}) automatically provision an isolated PostgreSQL schema and role or MySQL database and user per app, injecting generated credentials into the app environment.

The advantage is that backups, monitoring, capacity planning and scaling are set up once for the shared service instead of once per database container, while each app still gets isolated credentials and its own schema or database. The [service bindings blog post]({{< ref "/blog/service-binding" >}}) describes the design. For lighter apps, OpenRun manages [SQLite with Litestream replication]({{< ref "docs/applications/litestream/" >}}) to S3-compatible storage.

### Easy Migration to Kubernetes

Coolify, CapRover, Kamal and Dokku are built around Docker on individual servers. If your apps outgrow a single machine, moving to Kubernetes usually means rebuilding the deployment setup with different tools (Dokku's k3s scheduler is a partial exception). OpenRun uses the same declarative app config on a single node with Docker or Podman and on a [Kubernetes cluster]({{< ref "docs/container/kubernetes/" >}}), where apps are deployed as Kubernetes services through the OpenRun Helm chart. Starting on a VPS does not lock you out of Kubernetes later.

## Where the Alternatives Are Better

OpenRun focuses on web apps and internal tools, and that focus comes with a real limitation: **OpenRun does not support Docker Compose stacks**. An OpenRun app is a single container; multi-container applications defined in a compose file cannot be deployed as-is. Apps that need a database use service bindings to an externally managed database instead of a bundled database container.

This means Coolify, CapRover or Dokku are better choices when you want to:

- Self-host packaged third-party software distributed as Docker Compose stacks (Supabase, Plausible, WordPress and similar one-click installs)
- Run an app together with its own dedicated database, cache and worker containers as one unit
- Manage databases and other services from the same dashboard as apps

Kamal is a good fit when a small team deploys a few production apps to servers they manage directly and wants a simple, scriptable deploy tool rather than a platform.

## Tool by Tool

### OpenRun vs Coolify

Coolify is a UI-first platform: servers, apps, databases and one-click services are managed through its dashboard, with Git integration for code deploys. For [Docker Compose deployments](https://coolify.io/docs/knowledge-base/docker/compose), Coolify treats the Compose file in the repo as the source of truth for that app's services, while platform-level concerns such as servers, domains and app creation stay in the UI. It is a strong choice for self-hosting packaged software and full stacks. OpenRun is Git-first for the whole platform: apps are declared in config files and the platform converges to what Git describes. OpenRun adds SSO, RBAC and audit logs for the deployed apps themselves, scales idle apps to zero and can deploy the same apps to Kubernetes, while Coolify supports Docker Compose stacks and one-click databases which OpenRun does not.

### OpenRun vs CapRover

CapRover deploys apps on Docker Swarm behind Nginx, managed through its web dashboard and `caprover` CLI, with one-click apps for common software. App creation and configuration are interactive; the `captain-definition` file covers the build, not the app's existence or settings. OpenRun replaces the dashboard-driven workflow with declarative Git management, adds per-app SSO and RBAC, stops idle apps and provides staged deployments for config changes. CapRover is better if you want its one-click app catalog and Swarm based clustering of the platform itself.

### OpenRun vs Kamal

Kamal, from 37signals, deploys containers to your servers over SSH with zero-downtime cutover through kamal-proxy. Its `deploy.yml` is a declarative description of one app's deployment, which is closer to GitOps than UI-driven platforms, but deploys are imperative `kamal deploy` runs and each app carries its own config and accessory definitions. Kamal is a deploy tool rather than a platform: there is no app catalog, no authentication for apps, no RBAC, no audit logs and no scale-to-zero. OpenRun is a running platform that continuously syncs many apps from Git and adds the access control layer internal tools need. Kamal is a better fit for a few customer-facing production apps managed by the team that owns the servers.

### OpenRun vs Dokku

Dokku pioneered the git push to deploy workflow on a single server, using buildpacks or Dockerfiles with Nginx routing and a large plugin ecosystem. App creation, domains, TLS and databases are managed through per-app `dokku` CLI commands on the server, so the platform state lives on the server rather than in Git. OpenRun moves that state into declarative config files, adds SSO, RBAC and auditing, scales idle apps to zero and supports Kubernetes. Dokku is better if you want buildpack based deploys and its plugin catalog of self-hosted services.

## Frequently Asked Questions

### Is OpenRun a Coolify alternative?

Yes, for web apps and internal tools. OpenRun covers the same self-hosted deployment need with declarative GitOps management, SSO and RBAC for apps, audit logs and scale-to-zero. It is not a Coolify alternative for deploying Docker Compose stacks or one-click packaged software.

### Can OpenRun deploy any web app?

OpenRun can deploy any web app that runs in a single container. [App specs]({{< ref "docs/container/appspecs/" >}}) provide zero-config deployment for frameworks like Streamlit, Gradio, FastAPI, FastHTML, NiceGUI, Shiny and Reflex. Other apps need a Dockerfile in the repo.

### Does OpenRun require Kubernetes?

No. OpenRun runs as a single binary on Linux, macOS or Windows, using Docker or Podman for app containers. Kubernetes is an option for distributed deployments, using the same app config.

### How do apps get a database without Docker Compose?

Through [service bindings]({{< ref "docs/applications/servicebindings/" >}}). You register a PostgreSQL or MySQL service once, and each app automatically gets isolated credentials (schema and role, or database and user) injected into its environment. SQLite apps get managed persistent storage with [Litestream replication]({{< ref "docs/applications/litestream/" >}}).

### Is OpenRun open source?

Yes, OpenRun is Apache-2.0 licensed. Source is at [github.com/openrundev/openrun](https://github.com/openrundev/openrun).
