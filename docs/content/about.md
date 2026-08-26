---
title: "About"
description: "What OpenRun is, why it was built and answers to common questions about GitOps, authentication, databases, scale-to-zero, Kubernetes and how OpenRun compares with alternatives."
summary: "About OpenRun"
---

## What is OpenRun?

OpenRun (previously called Clace) is an open-source, self-hosted GitOps platform for deploying web apps to Docker, Podman or Kubernetes, with a focus on deploying internal tools for teams. Apps are declared in a config file in Git; OpenRun builds the containers, routes requests and keeps the running platform in sync with what Git describes.

OpenRun provides declarative GitOps based blue-green deployment, OAuth/OIDC/SAML access controls for every app, automatic TLS certs, secrets management, RBAC and audit logs. Idle apps scale down to zero. The same declarative config works on a single server and on a Kubernetes cluster.

## Project Goals

The goal of this project is to make it easy for individuals and teams to develop and deploy web applications declaratively, with minimal operational overhead. Easy integrations to enable SSO/SAML based authentication and authorization controls, audit logs and integration with secrets managers are goals. Deploying on a single machine or deploying across a cluster on Kubernetes should use the same config.

Application deployments should support a true GitOps approach: not just code updates, but app creation and configuration managed through Git. It should be easy, for the original developer or a new one, to make application code changes and deploy - after six months or after six years.

## FAQ

### How does OpenRun compare to Coolify, CapRover, Kamal and Dokku?

The main differences are:

- OpenRun is declarative. All operations, including creating new apps and updating config for existing apps, are done by updating a config file in Git. With most other solutions, app creation and config changes go through a UI or CLI; only app source code updates flow through Git.
- OpenRun provides SSO (OAuth/OIDC/SAML) and RBAC for every deployed app, not just for the admin interface.
- OpenRun is implemented as a web server and does not depend on an external proxy like Nginx or Traefik. This allows OpenRun to scale idle app containers down to zero and to enforce auth on every request.
- OpenRun supports staged (blue-green) deployment for both code and config changes, and atomic updates across apps.
- OpenRun deploys apps to a single machine or onto Kubernetes with the same config.

The tradeoff: OpenRun does not deploy Docker Compose stacks; apps run in a single container (with optional [sidecar containers]({{< ref "docs/container/overview/#sidecar-containers" >}})) and connect to externally managed databases through service bindings. See the full [comparison with Coolify, CapRover, Kamal and Dokku]({{< ref "compare/coolify-caprover-kamal" >}}).

### How does OpenRun compare to Google Cloud Run and AWS App Runner?

Cloud Run is a managed serverless container platform with scale-to-zero, running on Google's infrastructure with per-request pricing. App Runner is AWS's equivalent, though it keeps at least one provisioned instance billed while running and was closed to new AWS customers in March 2026. OpenRun provides the same deployment model, containers that scale to zero and start on demand, on your own server, node or Kubernetes cluster. OpenRun's SSO and RBAC are configured once and cover every app, including SAML providers, and it runs fully behind a VPN. The managed platforms are better for public services needing large elastic scale. See the full [comparison with Cloud Run and App Runner]({{< ref "compare/cloud-run-app-runner" >}}).

### How does OpenRun compare to building my own platform on Kubernetes?

A typical DIY stack combines Jenkins or GitHub Actions for builds, ArgoCD or Flux for CD, an ingress controller with cert-manager, an OAuth proxy for auth, Knative for scale-to-zero and Backstage as a portal. OpenRun provides the web app deployment slice of that stack as one system, with a few lines of config per app instead of YAML across many tools. Compared to Knative, OpenRun needs no external build system, loads apps lazily and supports auth for apps. See the full [comparison with DIY on Kubernetes]({{< ref "compare/diy-kubernetes" >}}).

### What makes OpenRun "true GitOps"?

Most platforms call it GitOps when a git push triggers a rebuild of one app's source code. App creation, domains, env vars, resource limits and database access still happen through a UI or CLI, outside version control. With OpenRun, the [declarative config]({{< ref "docs/applications/overview/#declarative-app-management" >}}) in Git covers the full app lifecycle: a scheduled sync creates newly declared apps, applies config changes to existing apps and deploys code updates. Config changes get pull request review, history and rollback, exactly like code.

### Why is declarative configuration useful?

Imperative CLI or UI operations are easy to start with, but they make it difficult to track changes and roll back updates. With a declarative config, all changes are version controlled. It is easy to create a new environment, since everything is in Git. If multiple people are making config changes in a team, declarative systems are easier to manage.

Declarative configuration is what makes Kubernetes and Terraform useful. OpenRun brings declarative configuration to web app deployment. Instead of writing pages of YAML, each app is specified as a few lines of Starlark (python-like) config. For example, see [utils.star](https://github.com/openrundev/openrun/blob/main/examples/utils.star).

### What types of apps can be deployed with OpenRun?

OpenRun can deploy any web app which runs in a single container, with optional [sidecar containers]({{< ref "docs/container/overview/#sidecar-containers" >}}) for background workers and companion services. OpenRun supports [AppSpecs]({{< ref "docs/container/appspecs" >}}) which allow zero-config deployment of frameworks like Streamlit/Gradio/FastHTML/NiceGUI/Shiny/Reflex based apps. For frameworks which have an AppSpec, no Dockerfile is required and no code changes are required in the app source. For frameworks which do not have an AppSpec defined, a Dockerfile needs to be present in the app source repo.

OpenRun does NOT support apps which require multiple containers using Docker Compose. The target use case is internal tools talking to existing API endpoints and web apps where the database is externally managed. OpenRun support service bindings, which is a better abstraction for managing endpoints.

### Does OpenRun support deployment of internal tools by teams?

Yes, deployment of internal tools by teams is the primary [use case]({{< ref "docs/use-cases/team" >}}). Features built for this use case include:

- **Declarative Config**: Manage apps [declaratively]({{< ref "docs/applications/overview/#declarative-app-management" >}}) in Git, allowing teams to follow regular SDLC for config
- **OAuth/OIDC/SAML with RBAC**: Manage who can access which app using [RBAC]({{< ref "docs/configuration/rbac" >}})
- **Audit Logs**: All operations and API calls are automatically logged in the [audit trail]({{< ref "docs/applications/audit" >}})

If not used for internal tools, the auth and auditing features can be disabled, in which case OpenRun is suitable for deploying any web application.

### Is SSO only for the admin console, or for apps too?

For every app. Configure [OAuth, OpenID Connect, SAML or client certificate auth]({{< ref "docs/configuration/authentication" >}}) once at the server level and any app can require login, with no code changes in the app. Group information from the IdP feeds [RBAC]({{< ref "docs/configuration/rbac" >}}) grants that control which users can access which apps. Setting `auth_required = true` ensures no app can be served without authentication. Most deployment platforms authenticate only their own dashboard; with them, each deployed app must implement login itself.

### How do apps get access to a database?

Through [service bindings]({{< ref "docs/applications/servicebindings" >}}). A PostgreSQL or MySQL service is registered once with admin credentials. Each app that requests a binding automatically gets an isolated schema and role (Postgres) or database and user (MySQL), with generated credentials injected into the app environment. Operational work like backups, monitoring and capacity planning needs to be set up only once, for the shared service, instead of once per app database. The [service bindings blog post]({{< ref "/blog/service-binding" >}}) describes the design.

For lighter apps, OpenRun manages [SQLite with Litestream]({{< ref "docs/applications/litestream" >}}): persistent volumes, continuous replication to S3-compatible storage and automatic restore.

### How does scale-to-zero work?

OpenRun is itself the web server, so it sees every request. App containers are started lazily on the first request to the app, and [idle containers are stopped automatically]({{< ref "docs/container/config" >}}); on Kubernetes, the app deployment is scaled down to zero. The next request starts the container again. Since internal tools are idle most of the time, a single server can host hundreds of apps with only the active ones consuming CPU and memory.

### How is OpenRun deployed?

OpenRun can be deployed on a single node easily (Linux, Windows or macOS), using a SQLite database for storing metadata. Docker or Podman is the only dependency. OpenRun can also be deployed across multiple machines, using an external Postgres database for storing metadata.

OpenRun can also be deployed on Kubernetes using a Helm chart. On Kubernetes, OpenRun avoids the need to set up a build system like Jenkins, CD with ArgoCD and an IDP like Backstage. Apps deployed using OpenRun run as Kubernetes services, with OpenRun acting as the API server and request router.

### Can OpenRun run behind a VPN with no public Internet access?

Yes. OpenRun serves apps fully on private infrastructure, with no dependency on a public cloud service. The [team use case guide]({{< ref "docs/use-cases/team" >}}) walks through a setup behind a VPN, including OIDC/SAML auth, manually managed TLS certs and a GitOps sync from a private repo. Note that installs and container builds download packages from the Internet by default; fully air-gapped setups need local mirrors and registries.

### How do I move from a single server to Kubernetes?

The same declarative app config works on both. Start with OpenRun on a single server using Docker or Podman. When a distributed deployment is needed, install OpenRun on a [Kubernetes cluster]({{< ref "docs/container/kubernetes" >}}) with the Helm chart and point it at the same config repo. The apps, auth setup and GitOps pipeline carry over unchanged.

### Does OpenRun replace my CI/CD system?

For web app deployment, OpenRun covers the pipeline end to end: it builds app containers from source and continuously syncs apps from Git, so no separate Jenkins job or ArgoCD application is needed per app. Test suites and other CI checks still run in your existing CI system before changes merge; OpenRun takes over once changes land in the branch it syncs from.

### Is OpenRun free and open source?

Yes. OpenRun is Apache-2.0 licensed, developed at [github.com/openrundev/openrun](https://github.com/openrundev/openrun). There is no per-seat or per-app pricing; the only cost is the infrastructure it runs on.

## How is OpenRun implemented?

- OpenRun is a single binary web application server written in Go, with a set of built-in plugins that provide access to external endpoints. The server is statically configured using a TOML file.
- Applications are configured using [Starlark](https://github.com/google/starlark-go), a subset of Python. Starlark works well as a glue language and is used to configure the application backend logic.
- Multiple applications can be installed dynamically. An embedded SQLite database stores application metadata; an external Postgres database can be used instead for multi-node deployments.
- For applications using the container plugin, OpenRun builds and runs containers through the Docker or Podman CLI. On Kubernetes, OpenRun creates app resources using the server-side apply (SSA) APIs.
- Each app is identified by a unique path. Domain-based routing allows multiple domains to point to the same OpenRun instance, with path-based routing done independently for each domain.
- TLS certificates are created and renewed automatically for each domain.
- A sandboxing layer at the Starlark to Go boundary enforces security and access control policies. Go code is trusted, Starlark code is untrusted.
- For Starlark based apps, the application UI is built with Go HTML templates and [HTMX](https://htmx.org/) for interactivity. Go templates support [context aware templating](https://pkg.go.dev/html/template#hdr-Contexts), which prevents encoding related security issues, and they work well with the HTML fragments HTMX requires.
- No additional components like Python or Node.js need to be installed on the host machine. The standalone [tailwindcss-cli](https://tailwindcss.com/blog/standalone-cli) is supported for styling, and [esbuild](https://esbuild.github.io/) (through the esbuild Go library) is supported out of the box for importing ESM modules.

## Current Status

The current status is:

- Client and server in a single binary, for service management and configuration.
- Application development with Starlark based configuration.
- Container management with Docker, Podman or Kubernetes.
- Auto-idling of containers to reduce resource usage.
- Go HTML template loading and caching for request processing.
- HTTP plugin for calling REST endpoints and an exec plugin for running system commands.
- Built-in admin account for local development.
- Auto-sync (file system watcher) and auto-reload using SSE to speed up the application development cycle.
- Admin functionality over unix domain sockets for security.
- Application sandboxing checks so that only audited operations are allowed.
- Staged deployments and preview app creation.
- App data persistence to SQLite with managed tables.

## Who is behind this project?

The project was started by [Ajay Kidave](https://www.linkedin.com/in/ajayvk/). Ajay's background has been in database systems and enterprise integration tools. OpenRun was started to find ways to reduce the development and operational complexity in tooling for internal applications.

## How to stay in touch?

- Star the repo at [github.com/openrundev/openrun](https://github.com/openrundev/openrun)
- Email at [contact@openrun.dev](mailto:contact@openrun.dev)
- Follow on [Twitter](https://twitter.com/ajay_kidave)
- Subscribe to the blog [RSS feed](https://openrun.dev/blog/index.xml)
- Connect on [Discord](https://discord.gg/t2P8pJFsd7)
- #openrun channel in the [CNCF Slack](https://cloud-native.slack.com/)
- Schedule a [Meeting](https://calendar.app.google/wacEeZ9agtHHZTkMA)
