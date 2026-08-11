---
title: "OpenRun for Platform Teams"
weight: 200
description: "Give teams a standardized internal application platform with GitOps, RBAC, audit logs and scale-to-zero on Docker or Kubernetes, without building a custom platform from scratch."
summary: "Give teams a standardized internal application platform."
---

OpenRun gives platform teams a standardized internal application platform without building one from scratch. Instead of gluing together a build system, a CD tool, an ingress controller, an identity proxy and an internal developer portal, OpenRun provides one system with a single declarative config format for every app.

## A Golden Path That Is Actually Declarative

Most platforms end up with a mix of Git-driven code deploys and UI-driven or CLI-driven app management. OpenRun manages the full application lifecycle through Git. App creation, config changes, resource limits, database bindings, auth settings and promotions are all edits to a [declarative config file]({{< ref "docs/applications/overview/#declarative-app-management" >}}) in a repo your team reviews.

```python {filename="apps.star"}
limits = {"cpus": "1", "memory": "512m"}

# Engineering team apps
app("/engg/metrics", "github.com/myorg/metrics-dashboard",
    spec="python-streamlit", container_opts=limits)

# IT team apps
app("/it/onboarding", "github.com/myorg/onboarding-tool",
    spec="python-fasthtml", container_opts=limits)
```

One command sets up continuous deployment:

```sh
openrun sync schedule --approve --promote github.com/myorg/platform/apps.star
```

OpenRun [polls the repo]({{< ref "docs/applications/overview/#automated-sync" >}}), creates newly declared apps, applies config changes and deploys code updates. Updates across apps are atomic: all changes apply or none do. Staged (blue-green) deployment applies to config changes as well as code changes.

## Access Control Per Team

Every app is protected by the [OAuth, OIDC or SAML]({{< ref "docs/configuration/authentication/" >}}) provider configured at the server level. [RBAC]({{< ref "docs/configuration/rbac/" >}}) grants map IdP groups to app access, using path or domain patterns:

- Apps under `/engg/**` accessible to the engineering group
- Apps under `/it/**` accessible to the IT group
- Shared apps accessible to all logged-in users

RBAC config is dynamic and applies without a server restart. [Audit events]({{< ref "docs/applications/audit/" >}}) capture app operations and API activity automatically. See the [team use case guide]({{< ref "docs/use-cases/team/" >}}) for a complete walkthrough, including running behind a VPN.

## Density Through Scale-to-Zero

Internal tools are idle most of the time. OpenRun [stops idle app containers]({{< ref "docs/container/config/" >}}) and scales their resource usage down to zero, then lazily restarts them on the next request. A single modest server can host hundreds of internal apps, since only actively used apps consume resources.

## Databases as a Managed Service

[Service bindings]({{< ref "docs/applications/servicebindings/" >}}) let the platform team manage one PostgreSQL or MySQL instance while every app gets its own isolated schema and role or database and user, provisioned automatically at install time. Bindings give the platform team an easy way to manage databases: operational work like backups, monitoring, scaling, upgrades and capacity planning is done once on the shared service and covers every app bound to it, instead of being repeated for a database container per app. Apps get isolated credentials without the platform team being involved in each install. The [service bindings blog post]({{< ref "/blog/service-binding" >}}) covers the design in detail. For SQLite apps, [Litestream replication]({{< ref "docs/applications/litestream/" >}}) to S3-compatible storage provides continuous backup and automatic restore.

## Start on a Single Server, Move to Kubernetes

OpenRun runs as a single binary on a Linux server with Docker or Podman. The same declarative app config later deploys to a [Kubernetes cluster]({{< ref "docs/container/kubernetes/" >}}) using the OpenRun Helm chart, with apps running as Kubernetes services. Teams get an easy on-ramp: no Kubernetes knowledge required to declare an app, and no config rewrite when the platform moves to Kubernetes.

## Operations

- [OpenTelemetry]({{< ref "docs/configuration/telemetry/" >}}) export for requests, container lifecycle events, traces and metrics
- [Secrets management]({{< ref "docs/configuration/secrets/" >}}) through AWS Secrets Manager, HashiCorp Vault and other providers
- Automatic [TLS certificates]({{< ref "docs/configuration/networking/#enable-automatic-signed-certificate" >}}) with domain based and path based routing
- A browser-based [management console]({{< ref "console-tour" >}}) for apps, syncs, service bindings, containers, audit logs and server config

For a comparison with building a platform yourself, see [OpenRun vs DIY on Kubernetes]({{< ref "compare/diy-kubernetes" >}}).
