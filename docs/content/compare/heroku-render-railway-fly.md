---
title: "Heroku Alternative: OpenRun vs Heroku, Render, Railway, Fly.io"
linkTitle: "vs Heroku, Render, Railway, Fly.io"
weight: 700
date: 2026-11-09
description: "Open-source, self-hosted alternative to Heroku, Render, Railway and Fly.io: deploy web apps from Git on your own servers with SSO, RBAC and scale-to-zero."
summary: "OpenRun compared with hosted PaaS platforms: Heroku, Render, Railway and Fly.io."
keywords:
  - self-hosted Heroku alternative
  - open source Heroku alternative
  - Render alternative
  - Railway alternative
  - Fly.io alternative
  - self-hosted PaaS
  - deploy internal tools
---

Heroku, Render, Railway and Fly.io are hosted platforms: you connect a repo or push an image, and the provider builds, runs and scales the app on its own infrastructure, billed per service. OpenRun gives a similar deployment experience on infrastructure you control. It is an open-source platform which runs on your own server or Kubernetes cluster, deploys apps from Git and adds single sign-on and access control for the apps it serves.

**Summary**: Choose OpenRun for internal tools and team web apps which should run on your own infrastructure, behind your own login, without a bill for each app. Choose a hosted platform for public, customer-facing services when you want the provider to run the servers and databases, need many instances or several regions, or have no one to operate a server.

## Hosted PaaS vs Self-Hosted

The hosted platforms and OpenRun make different tradeoffs.

- **Who runs the servers.** The hosted platforms operate everything. With OpenRun you operate a Linux, macOS or Windows machine with Docker or Podman, or a Kubernetes cluster.
- **What is billed.** The hosted platforms bill for each running service, by instance size or by CPU and memory used. OpenRun is free, and the cost is the server. Many small apps share that server, and idle apps are stopped.
- **Where the apps run.** Hosted apps run in the provider's network. Reaching an internal database from there needs a private link, peering or a VPN, which are features of the higher plans. OpenRun runs inside your network.
- **Who can open the app.** The hosted platforms serve apps on public URLs, and each app implements its own login. OpenRun can require login through your identity provider before a request reaches the app.

Apps are declared in a config file in Git:

```python {filename="apps.star"}
app(path="/orders", source="github.com/myorg/orders-admin", spec="python-asgi", auth="oidc_okta")
app(path="/reports", source="github.com/myorg/reports", spec="container", auth="oidc_okta")
app(path="docs.example.com:/", source="github.com/myorg/docs-site", spec="static")
```

One command sets up the pipeline:

```sh
openrun sync schedule --approve --promote github.com/myorg/platform/apps.star
```

OpenRun polls the repo, creates newly declared apps, applies config changes and deploys code updates. The `auth` property selects the login required for an app, here an OIDC provider configured in `openrun.toml` under the name `oidc_okta`. New apps use `none` authentication unless an auth type is set on the app or a [server default]({{< ref "docs/configuration/authentication/#default-authentication-type" >}}) is configured.

## Feature Comparison

| Capability                          | OpenRun                                                           | Heroku                                                                    | Render                                                                 | Railway                                                                   | Fly.io                                                               |
| ----------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Hosting                             | Self-hosted, on a server with Docker or Podman, or on Kubernetes  | Hosted service                                                            | Hosted service                                                         | Hosted service                                                            | Hosted service                                                       |
| License and price                   | Open source, Apache-2.0, free                                     | Paid per dyno: Eco plan $5 a month, Basic $7, Standard from $25; no free tier | Workspace plans plus per-instance pricing; free instances with limits | Usage based; plan fee includes equal usage: Free with $1 of usage a month, Hobby $5, Pro $20 | Pay as you go per Machine, from about $2 a month; no free tier       |
| Deploy from Git                     | Yes, any Git host, polled by OpenRun                              | `git push` to Heroku, or GitHub integration                               | GitHub, GitLab and Bitbucket                                           | GitHub                                                                    | `fly deploy` from the CLI; deploy on push through GitHub Actions     |
| Builds                              | Container image from an app spec or a Dockerfile                  | Buildpacks or Docker images                                               | Native runtimes or Dockerfile                                          | Railpack or Dockerfile                                                    | Dockerfile, image or buildpacks                                      |
| App creation and config through Git | Yes, one declarative file covers all apps                         | No, CLI and dashboard; Terraform provider                                 | Yes, Blueprints (`render.yaml`) synced from a repo                     | Infrastructure as code file, applied with the CLI or a GitHub Action      | Per-app `fly.toml`; apps are created with the CLI                    |
| Login for app users (OAuth/OIDC/SAML) | Yes, selected per app or as the server default                  | No, apps implement login                                                  | No, apps implement login                                               | No, apps implement login                                                  | No, apps implement login                                             |
| Access control per app              | Yes, RBAC grants by user and IdP group                            | No                                                                        | No                                                                     | No                                                                        | No                                                                   |
| SSO for the platform itself         | Yes                                                               | Heroku Enterprise                                                         | SAML on the Scale plan and above                                       | Enterprise                                                                | Google or GitHub                                                     |
| Audit logs                          | Yes, built in                                                     | Not confirmed from the documentation                                      | Pro plan and above                                                     | Yes, retention depends on the plan                                        | Not documented                                                       |
| Scale idle apps to zero             | Yes, for every app, after 180 seconds by default                  | Eco dynos sleep after 30 minutes; other dynos are always on               | Free instances stop after 15 minutes; paid instances do not            | Optional per service                                                      | Yes, autostop and autostart of Machines                              |
| Staging and promotion               | Yes, each app has a staging version, for code and config          | Pipelines with staging apps and promotion                                 | No; preview environments on the Pro plan and above                     | Environments, synced manually                                             | No, separate apps or organizations                                   |
| Preview apps for pull requests      | [Preview apps]({{< ref "docs/applications/lifecycle/#preview-apps" >}}) created from a commit | Review apps                                 | Yes                                                                    | Yes                                                                       | Through a GitHub Action                                              |
| Rollback                            | Yes, switch to an earlier version                                 | Yes, among recent releases                                                | Yes, among retained builds                                             | Yes, within the image retention period                                    | Redeploy an earlier image                                            |
| Databases                           | Service bindings to your PostgreSQL or MySQL; managed SQLite with Litestream | Heroku Postgres and Key-Value Store, managed                   | Managed Postgres and Key Value                                         | Database templates run as services                                        | Managed Postgres                                                     |
| Access to private networks          | Runs inside your network                                          | Private Spaces, for Teams and Enterprise                                  | Private link to AWS, Pro plan and above                                | Not documented                                                            | WireGuard peering                                                    |
| Custom domains with automatic TLS   | Yes                                                               | Yes                                                                       | Yes                                                                    | Yes                                                                       | Yes                                                                  |
| Horizontal scaling and autoscaling  | Replicas and autoscaling on Kubernetes; one container per app on a single server | Yes; autoscaling on Performance dynos and above           | Yes; autoscaling on the Pro plan and above                             | Replicas, including across regions                                        | Yes, across regions                                                  |

Details for the OpenRun column: [declarative app management]({{< ref "docs/applications/overview/#declarative-app-management" >}}), [app specs]({{< ref "docs/container/appspecs/" >}}), [authentication]({{< ref "docs/configuration/authentication/" >}}), [RBAC]({{< ref "docs/configuration/rbac/" >}}), [audit events]({{< ref "docs/applications/audit/" >}}), [scale-to-zero]({{< ref "docs/container/config/#idle-shutdown" >}}), [staging apps]({{< ref "docs/applications/lifecycle/#staging-apps" >}}), [service bindings]({{< ref "docs/applications/servicebindings/" >}}), [automatic TLS]({{< ref "docs/configuration/networking/#enable-automatic-signed-certificate" >}}) and [Kubernetes]({{< ref "docs/container/kubernetes/#resources-and-autoscaling" >}}).

Comparison last verified on November 9, 2026 against the [Heroku pricing page](https://www.heroku.com/pricing) and [Dev Center](https://devcenter.heroku.com/), including the [Eco dyno hours](https://devcenter.heroku.com/articles/eco-dyno-hours), [GitHub integration](https://devcenter.heroku.com/articles/github-integration), [pipelines](https://devcenter.heroku.com/articles/pipelines), [releases](https://devcenter.heroku.com/articles/releases) and [Private Spaces](https://devcenter.heroku.com/articles/private-spaces) articles; the [Render documentation](https://render.com/docs), including the [free instances](https://render.com/docs/free), [Blueprints](https://render.com/docs/infrastructure-as-code), [preview environments](https://render.com/docs/preview-environments), [features by plan](https://render.com/docs/platform-features-by-plan), [SAML SSO](https://render.com/docs/saml-sso) and [private link](https://render.com/docs/private-link) pages; the [Railway pricing page](https://railway.com/pricing) and [documentation](https://docs.railway.com/), including the [plans](https://docs.railway.com/pricing/plans), [serverless](https://docs.railway.com/deployments/serverless), [infrastructure as code](https://docs.railway.com/infrastructure-as-code), [environments](https://docs.railway.com/environments) and [audit logs](https://docs.railway.com/enterprise/audit-logs) pages; and the [Fly.io pricing page](https://fly.io/pricing/) and [documentation](https://docs.fly.io/), including the [autostop and autostart](https://docs.fly.io/launch/autostop-autostart), [configuration reference](https://docs.fly.io/reference/configuration), [continuous deployment](https://docs.fly.io/launch/continuous-deployment-with-github-actions), [rollback](https://docs.fly.io/blueprints/rollback-guide) and [SSO](https://docs.fly.io/security/sso) pages. Plans, prices and limits of the hosted services change often; check the linked pages for current values.

## Where OpenRun Differs

### Login and Access Control for Apps

On the hosted platforms, SSO is a feature for signing in to the platform dashboard. A deployed app gets a public URL, and any login in front of it is built into the app or added with a separate proxy. OpenRun can require [OAuth, OpenID Connect, SAML or client certificate]({{< ref "docs/configuration/authentication/" >}}) login for an app, selected per app or set as the default for all apps. [RBAC]({{< ref "docs/configuration/rbac/" >}}) limits each app to specific users and identity provider groups, and [audit events]({{< ref "docs/applications/audit/" >}}) record the operations performed. Internal tools need no login code of their own.

### One Server Instead of a Bill per App

Hosted platforms price each running service. An always-on Heroku Basic dyno is $7 a month, so twenty small internal apps cost $140 a month before databases, and the plans which stop idle apps for free are limited: Heroku Eco dynos are for personal apps, and Render free instances cannot be used for anything which needs a disk or more than one instance. OpenRun stops every idle app container [after three minutes]({{< ref "docs/container/config/#idle-shutdown" >}}) by default and starts it on the next request. Apps which are used a few times a day share one server, and adding another app does not add a charge.

### Apps Run Inside Your Network

Internal tools read from internal databases and APIs. From a hosted platform, that needs the database to be reachable from the provider: Private Spaces on Heroku, a private link on Render or WireGuard peering on Fly.io. OpenRun runs on your own server or cluster, next to the data, and can run fully behind a VPN with no public endpoint.

### Apps Are Created and Configured from Git

All four platforms deploy code from Git. Creating the app and configuring it is mostly done in a dashboard or CLI; Render Blueprints and Railway's infrastructure as code are the exceptions. OpenRun treats the [declarative config]({{< ref "docs/applications/overview/#declarative-app-management" >}}) as the source for every app: its path or domain, spec, authentication, params and container limits. Adding an app is a pull request, and config changes go through the same [staging and promotion]({{< ref "docs/applications/lifecycle/#staging-apps" >}}) as code changes.

### No Lock-In

OpenRun is Apache-2.0 licensed and runs on any server or Kubernetes cluster. Apps are standard containers with no platform specific code. The same config moves from a single VPS to a [Kubernetes cluster]({{< ref "docs/container/kubernetes/" >}}).

## Where the Hosted Platforms Are Better

- **No servers to operate.** The provider handles hardware, operating system updates, capacity and availability. With OpenRun those are your responsibility.
- **Managed databases.** Heroku, Render and Fly.io run PostgreSQL for you, with backups and failover. OpenRun does not run a database server; [service bindings]({{< ref "docs/applications/servicebindings/" >}}) connect apps to a PostgreSQL or MySQL instance you provide, and SQLite apps are replicated with [Litestream]({{< ref "docs/applications/litestream/" >}}).
- **Scale and regions.** The hosted platforms run many instances of a service and scale them with load. Fly.io and Railway place instances in several regions. OpenRun on a single server runs one container per app; scaling out needs Kubernetes.
- **Multi-service apps.** A hosted project can hold a web service, background workers, cron jobs and a database as separate services. An OpenRun app is a single container with optional [sidecar containers]({{< ref "docs/container/overview/#sidecar-containers" >}}) and [jobs]({{< ref "docs/applications/jobs/" >}}).
- **Build without a Dockerfile.** Buildpacks, native runtimes and Railpack detect and build most languages. OpenRun has [app specs]({{< ref "docs/container/appspecs/" >}}) for common frameworks, and other apps need a Dockerfile.
- **Support and compliance.** The hosted platforms sell support plans and uptime commitments and hold compliance certifications. OpenRun is a community supported open-source project.

## Tool by Tool

### OpenRun vs Heroku

Heroku introduced the `git push` deployment model. Apps run in dynos, are built with buildpacks, and use add-ons such as Heroku Postgres. Pipelines give a staging app, promotion to production and review apps for pull requests. There is no free tier: the Eco plan is $5 a month for a pool of dyno hours on personal apps, and always-on dynos start at $7 a month each. SSO applies to the Heroku dashboard and is part of Heroku Enterprise, and private networking needs Private Spaces. OpenRun is a self-hosted alternative for the internal apps where that pricing and public hosting do not fit: apps are declared in Git, share one server, stop when idle and sit behind the company login. Heroku is the better choice for customer-facing apps which need managed databases and the add-on marketplace.

### OpenRun vs Render

Render is the closest of the four to OpenRun in its Git workflow. A Blueprint (`render.yaml`) in a repo declares services, databases and environment groups, and Render syncs changes to it. It deploys from GitHub, GitLab and Bitbucket, and runs managed Postgres. Free web services stop after 15 minutes without traffic and take about a minute to start; paid instances are always on. Dashboard SAML SSO needs the Scale plan, and preview environments, autoscaling and private links need Pro. OpenRun differs in running on your own infrastructure, stopping every idle app and providing login and RBAC for the apps themselves.

### OpenRun vs Railway

Railway bills for the CPU and memory a service uses. The monthly plan fee includes the same amount of usage, $5 on Hobby and $20 on Pro, and only usage above that amount is charged in addition. Railway has a project canvas where services and databases are added from templates. It deploys from GitHub, builds with Railpack or a Dockerfile and supports environments and pull request environments. A service can opt in to sleeping when it has no traffic. Databases are templates which run as services in the project. OpenRun is an alternative when the apps should run on your own servers with authentication in front; Railway is quicker to start with when you have no server and want a database in the same project.

### OpenRun vs Fly.io

Fly.io runs apps as Machines, which are fast-starting virtual machines, in regions around the world. Apps are deployed with the `fly` CLI from a Dockerfile, with a `fly.toml` file per app, and Machines can stop when idle and start on the next request. Continuous deployment and review apps are set up with GitHub Actions, and rollback is done by deploying an earlier image. Fly.io has no free tier, and bills per second for running Machines. It is the better choice for latency-sensitive public apps which need to run close to users in several regions. OpenRun covers a different need: a catalog of internal apps on one server or cluster, managed from one config file, with SSO and RBAC.

## Frequently Asked Questions

### Is OpenRun a self-hosted Heroku alternative?

Yes, for web apps and internal tools. OpenRun deploys apps from Git, builds containers, routes requests, issues TLS certificates and rolls back versions, on your own server or Kubernetes cluster. It does not run managed databases or an add-on marketplace; apps connect to a database you provide through [service bindings]({{< ref "docs/applications/servicebindings/" >}}).

### Does OpenRun support git push deploys like Heroku?

OpenRun pulls instead of receiving a push. Code is pushed to your normal Git host, and OpenRun [polls the repo]({{< ref "docs/applications/overview/#automated-sync" >}}) and deploys the change. An [app webhook]({{< ref "docs/applications/webhooks/" >}}) lets CI or a GitHub push event trigger the reload without waiting for the next poll.

### Does OpenRun use buildpacks or a Procfile?

No. OpenRun builds a container image using an [app spec]({{< ref "docs/container/appspecs/" >}}) or the Dockerfile in the app repo. Specs cover Python WSGI and ASGI apps, Streamlit, Gradio, Go, Hono, Spring Boot and other frameworks with no Dockerfile. An app which runs on Heroku from a Dockerfile runs on OpenRun with the `container` spec.

### How do apps get a database on OpenRun?

Register a PostgreSQL or MySQL instance once as a service. Each app with a [service binding]({{< ref "docs/applications/servicebindings/" >}}) gets its own schema and role, or database and user, with the credentials set in its environment. SQLite apps get persistent storage with [Litestream replication]({{< ref "docs/applications/litestream/" >}}).

### Do apps go to sleep on OpenRun?

Idle app containers are stopped after 180 seconds without activity and are started again on the next request. The timeout can be [changed or turned off]({{< ref "docs/container/config/#idle-shutdown" >}}) for the server or for one app.

### What does OpenRun cost compared with a hosted PaaS?

OpenRun is free and open source. The cost is the server or cluster it runs on, and the time to operate it. There is no charge per app, per user or per request.

### Can OpenRun run public, customer-facing apps?

Yes. Apps can be served on public domains with automatic TLS certificates, with or without authentication. For services which need many instances, several regions or a managed database, a hosted platform or OpenRun on a Kubernetes cluster is a better fit than a single server.
