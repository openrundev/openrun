---
title: "OpenRun for Developers"
weight: 100
description: "Deploy web apps from Git without managing infrastructure. Zero-config deployment for Streamlit, Gradio, FastAPI, FastHTML and NiceGUI apps with GitOps, TLS and databases built in."
summary: "Deploy from Git without managing infrastructure."
---

OpenRun lets developers deploy web apps from Git without managing infrastructure. Declare an app in a few lines of config, push to Git and OpenRun handles the container build, routing, TLS, authentication and database access. No Dockerfile is required for common frameworks, no YAML files, no reverse proxy setup.

## Declare an App in a Few Lines

An OpenRun app is declared in a [declarative config file]({{< ref "docs/applications/overview/#declarative-app-management" >}}) checked into Git:

```python {filename="apps.star"}
app(path="/dashboard", source="github.com/myorg/sales-dashboard",
    spec="python-streamlit")
```

That is the complete build and deployment config. OpenRun checks out the source, builds the container image, starts the container and routes requests to the app. Config changes go through the same pull request review workflow as code changes.

## Zero-Config Framework Support

[App specs]({{< ref "docs/container/appspecs/" >}}) define how a container is built and started for a framework and how requests are routed to it. Frameworks with an app spec deploy with zero configuration: no Dockerfile, no code changes in the app source. Specs are available for Streamlit, Gradio, FastAPI, FastHTML, NiceGUI, Shiny, Reflex, Flask and other frameworks, across Python, Go, Node.js and more. For any other framework, add a Dockerfile to the repo and OpenRun builds and runs it.

## Databases Without Tickets

Apps usually need a database, and getting credentials is usually a ticket to another team. With [service bindings]({{< ref "docs/applications/servicebindings/" >}}), each app automatically gets an isolated PostgreSQL schema and role, a MySQL database and user, or a key-prefix scoped Redis account, created at install time — with SQL Server, Oracle, MongoDB, Snowflake and ClickHouse available through binding providers. The generated credentials are injected into the app environment. Your app reads the environment variables and connects as usual.

The database service itself is operated centrally, so backups, monitoring and scaling are set up once for the shared service by the team running it, not once per app; your app just gets working credentials. The [service bindings blog post]({{< ref "/blog/service-binding" >}}) explains how this works.

For lighter apps, OpenRun manages [SQLite with Litestream]({{< ref "docs/applications/litestream/" >}}): persistent volumes, continuous replication to S3-compatible storage and automatic restore after volume or node loss.

## Fast Development Loop

Run `openrun apply --dev` to set up a [dev environment]({{< ref "docs/container/devreload/" >}}) from the same config used in production. OpenRun creates a local copy of the source and sets up a live reload URL for each app: edit code, and the running container picks up the change without a rebuild.

Staged deployments give every app a [staging environment]({{< ref "docs/applications/lifecycle/#staging-apps" >}}) automatically. Verify a change at the staging URL, then promote it to production. Rollbacks revert to a previous version tracked by OpenRun.

## What You Do Not Manage

- **Reverse proxy**: OpenRun is itself the web server. There is no Nginx or Traefik to configure.
- **TLS certificates**: certs are [created and renewed automatically]({{< ref "docs/configuration/networking/#enable-automatic-signed-certificate" >}}) per domain.
- **Authentication**: apps are protected with the OAuth, OIDC or SAML config [set up once]({{< ref "docs/configuration/authentication/" >}}) at the server level.
- **Secrets**: apps read secrets from [AWS Secrets Manager, HashiCorp Vault or other providers]({{< ref "docs/configuration/secrets/" >}}) without embedding credentials in config.
- **Idle resources**: idle app containers are [stopped automatically]({{< ref "docs/container/config/" >}}) and restart lazily on the next request.

## Automate Scripts, Not Just Apps

[Actions]({{< ref "docs/actions/" >}}) turn a backend function into a web app with an auto-generated form UI and report view. Use actions to replace Jenkins or Rundeck style jobs and manual curl commands with access-controlled, audited web interfaces.

## Get Started

Install OpenRun and deploy your first app in a couple of minutes with the [quick start]({{< ref "docs/quickstart/" >}}). See the [app development docs]({{< ref "docs/develop/" >}}) for building custom apps. If you are currently deploying with Coolify, CapRover, Kamal or Dokku, see the [comparison]({{< ref "compare/coolify-caprover-kamal" >}}).
