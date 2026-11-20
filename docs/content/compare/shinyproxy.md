---
title: "OpenRun vs ShinyProxy"
linkTitle: "vs ShinyProxy"
weight: 1000
date: 2026-11-19
description: "OpenRun vs ShinyProxy: a per-user container launcher for Shiny and other data science apps compared with a GitOps platform which builds, deploys and serves shared web apps with SSO and RBAC."
summary: "OpenRun compared with ShinyProxy, the open-source platform for deploying Shiny and other data science apps in per-user containers."
keywords:
  [
    "ShinyProxy alternative",
    "ShinyProxy vs OpenRun",
    "deploy Shiny apps",
    "deploy R Shiny app from Git",
    "self-host Streamlit",
    "open source data app hosting",
    "Shiny Server alternative",
  ]
---

ShinyProxy is an open-source server from Open Analytics for deploying data science apps. It started with R Shiny and now runs any web app packaged as a Docker image: Streamlit, Dash, Gradio, Jupyter, RStudio, VS Code and others. When a user opens an app, ShinyProxy starts a container for that user, proxies the session to it and stops the container when the user is done. Apps are listed in a YAML config file, and users log in through LDAP, OpenID Connect or SAML.

OpenRun is an open-source platform for deploying web apps and internal tools. An app is declared in Git with its source repo; OpenRun builds the container, serves it on a path or domain with TLS, applies SSO and RBAC, and stops it when idle. One app container is shared by all the app's users.

Both are Apache-2.0 licensed, self-hosted, put a login in front of unmodified apps and start containers on demand. The main difference is the container model: ShinyProxy runs **one container per user session** from an image you have already built, while OpenRun runs **one container per app** from source in Git, with staging, versioning and promotion around it.

**Summary**: Choose ShinyProxy when each user needs their own container: Shiny apps with heavy per-session computation, notebooks and IDEs such as Jupyter and RStudio, or apps which need per-user resources and mounts. Choose OpenRun for apps which serve many users from one process, when you want apps created and updated from Git without a separate image build pipeline, with staged rollouts, per-app RBAC and an audit trail.

## Feature Comparison

| Capability | OpenRun | ShinyProxy |
| --- | --- | --- |
| Container model | One container per app, shared by all users; replicas with an HPA on [Kubernetes]({{< ref "docs/container/kubernetes/" >}}) | One container per user and app instance by default; optional pre-initialized and shared containers with seats (since 3.1.0) |
| Supported apps | Any app which runs in a container; [specs]({{< ref "docs/container/appspecs/" >}}) for Streamlit, Gradio, Shiny for R and Python, NiceGUI, Reflex, FastHTML, Flask, WSGI/ASGI, Go, Spring Boot and others; Starlark apps and [actions]({{< ref "docs/actions/" >}}) | Any web app in a Docker image; documented demos for Shiny, Dash, Streamlit, Gradio, Flask, FastAPI, Quarto, Jupyter, Marimo, Voila, RStudio, VS Code, pgAdmin and others |
| R Shiny | The [`r-shiny` spec]({{< ref "docs/container/appspecs/#the-r-shiny-spec" >}}) builds and runs an app from its source, with no Dockerfile; all users share one R process | The original use case; you provide the image; one R process per user keeps a blocking computation from stalling other sessions |
| Notebooks and IDEs per user | Not a fit; one shared container per app | Yes, a private Jupyter, RStudio or VS Code container per user |
| Builds from source | Yes, [container builds]({{< ref "docs/container/build/" >}}) from the app repo, with no Dockerfile needed for bundled specs | No; you provide an image, built on the Docker host or pulled from a registry |
| App definition | [Declarative config]({{< ref "docs/applications/overview/#declarative-app-management" >}}) in Git, the CLI, or the console; stored in a metadata database | `proxy.specs` entries in `application.yml` |
| Adding or changing an app | Applied live; a [scheduled sync]({{< ref "docs/applications/overview/#automated-sync" >}}) picks up changes from Git | Config change and a ShinyProxy restart; the operator rolls out a new ShinyProxy instance on a config change with no downtime. A new image under the same tag is picked up without a restart when the pull policy is `Always` |
| Staging, versions and rollback | Each app has a [staging app]({{< ref "docs/applications/lifecycle/#staging-apps" >}}) with an explicit promote step, preview apps per commit, version history with revert | Not provided; an app is an image tag in the config |
| Backends | Docker or Podman on a single server, Kubernetes | Docker, Docker Swarm, Kubernetes, AWS ECS (Fargate); Podman support is experimental |
| Authentication | [OAuth, OIDC, SAML, client certs and builtin users]({{< ref "docs/configuration/authentication/" >}}), selectable per app; no LDAP | LDAP, OIDC, SAML, web service, custom header and simple (config file) users; one method per server |
| Access control | [RBAC]({{< ref "docs/configuration/rbac/" >}}): roles and grants by user and IdP group, for app access, custom app permissions and management operations | Per app `access-groups`, `access-users` and SpEL `access-expression`; `admin-groups` and `admin-users` for the admin page |
| User identity passed to the app | `X-Openrun-User`, email and permission HTTP headers on every request | `SHINYPROXY_USERNAME` and `SHINYPROXY_USERGROUPS` environment variables, plus the OIDC access token; `X-SP-UserId` and `X-SP-UserGroups` HTTP headers on every request by default |
| Per-user customization | No; the container config is the same for all users | SpEL expressions set image, env, volumes and resource limits per user or group; [app parameters](https://shinyproxy.io/documentation/app-parameters/) let users choose from predefined options at launch |
| Request routing | Path or domain per app, including custom domains | Paths under the ShinyProxy host (`/app/<id>`, `/app_direct/<id>`) |
| TLS | Built in, with [automatic certificates]({{< ref "docs/configuration/networking/#enable-automatic-signed-certificate" >}}) | Through a reverse proxy such as nginx; the operator on Docker deploys Caddy with Let's Encrypt; an ingress on Kubernetes |
| Idle shutdown | Yes, [automatic]({{< ref "docs/container/config/" >}}) when an app has had no new requests and under 1500 bytes of data transfer over the idle window (180 seconds by default, checked periodically), with a lazy start on the next request | Yes; the container stops on logout, session expiry, or 60 seconds after browser heartbeats stop; an open tab keeps it running. Pre-initialized pools keep a minimum number of seats running |
| User interface | Management console for apps, syncs, bindings, audit and config; apps are opened by URL | App launcher page listing the apps a user can access, with app details, restart, stop and multiple instances per user; admin page showing running apps |
| CLI and API | CLI and REST API for all management operations; [MCP]({{< ref "docs/applications/mcp/" >}}) access for AI agents | REST API for starting and stopping app instances; no CLI |
| Operations tasks | [Actions]({{< ref "docs/actions/" >}}) and [jobs]({{< ref "docs/applications/jobs/" >}}) | Not provided |
| Audit and usage tracking | [Audit events]({{< ref "docs/applications/audit/" >}}) for management operations and non-read app requests; access log with the user on every request; [OpenTelemetry]({{< ref "docs/configuration/telemetry/" >}}) traces and metrics | [Usage statistics](https://shinyproxy.io/documentation/usage-statistics/) for logins and app starts and stops, to InfluxDB, SQL databases, CSV or Prometheus through Micrometer; per-container app logs to disk or S3 |
| Secrets | [Secret providers]({{< ref "docs/configuration/secrets/" >}}): AWS Secrets Manager and SSM, HashiCorp Vault, Kubernetes secrets, an embedded store | Environment variables and placeholders in the config; Swarm secrets, Kubernetes secret references and ECS managed secrets per backend |
| Database access for apps | [Service bindings]({{< ref "docs/applications/servicebindings/" >}}) provision isolated credentials on Postgres, MySQL and Redis; managed SQLite with Litestream | Not provided |
| High availability | Multiple server replicas on Kubernetes with Postgres metadata; in-place zero-downtime restart on a single server | Multiple ShinyProxy replicas with Redis for sessions and running app state; app recovery after a restart |
| Runtime | Single Go binary; SQLite metadata by default | Java 21; JAR, deb, rpm or Docker image; Redis for HA and the operator |
| License and support | Apache-2.0, free | Apache-2.0, free; commercial support contracts and paid feature development from Open Analytics |

Comparison last verified on November 19, 2026 against ShinyProxy 3.2.5 and its documentation for [configuration](https://shinyproxy.io/documentation/configuration/), [deploying apps](https://shinyproxy.io/documentation/deploying-apps/), [the app lifecycle](https://shinyproxy.io/documentation/concepts/app-lifecycle/), [authentication and authorization](https://shinyproxy.io/documentation/concepts/authentication_and_authorization/), [security](https://shinyproxy.io/documentation/security/), [the UI](https://shinyproxy.io/documentation/ui/), [the API](https://shinyproxy.io/documentation/api/), [the operator](https://shinyproxy.io/documentation/shinyproxy-operator/features/), [demos](https://shinyproxy.io/documentation/demos/) and [support](https://shinyproxy.io/support/).

## Where OpenRun Differs

### From Source in Git, Not a Prebuilt Image

A ShinyProxy app is a reference to an image:

```yaml {filename="application.yml"}
proxy:
  specs:
    - id: sales
      display-name: Sales Dashboard
      container-image: registry.example.com/sales-dashboard:1.4.2
      port: 8501
      access-groups: [analysts]
```

ShinyProxy does not build the app; you provide the image, either built on the Docker host or pulled from a registry. Releasing a change means building a new image, updating the tag in the config and restarting ShinyProxy, or reusing the same tag with the `Always` pull policy. The ShinyProxy operator removes the downtime from the restart, by starting a new ShinyProxy instance and keeping the old one until its users disconnect.

An OpenRun app is a reference to source:

```python {filename="apps.star"}
app(path="/sales", source="github.com/myorg/sales-dashboard",
    spec="python-streamlit", auth="oidc_okta")
```

One command sets up the sync:

```sh
openrun sync schedule --approve --promote github.com/myorg/platform/apps.star
```

OpenRun fetches the source, builds the image and starts the container. A new entry in the file creates an app, an edited entry reconfigures it and new commits in the app repo are picked up on the next sync, with no server restart. The spec supplies the Containerfile, so a Streamlit, Gradio or Shiny repo needs no Dockerfile. A Shiny for R app uses `spec="r-shiny"`, which installs the R packages the source refers to, or restores an `renv.lock`. Docker and Podman installs can use local images; [Kubernetes installs need a registry]({{< ref "docs/container/kubernetes/#registry-config" >}}), configured once for the platform.

### Staging, Versions and Rollback

In ShinyProxy, the config holds the current image for each app. There is no built-in notion of a previous version or a staging copy. Testing a change before users see it takes a second ShinyProxy server or a separate app entry for the test image, and a rollback is a config change back to the previous tag.

Every OpenRun app has a [staging app]({{< ref "docs/applications/lifecycle/#staging-apps" >}}). Code and config changes land there first and reach production through a promote step, which the sync can perform automatically. [Preview apps]({{< ref "docs/applications/lifecycle/#preview-apps" >}}) run a specific commit for review. Each change creates a version, and `openrun version revert` switches an app back.

### One Container per App

ShinyProxy's per-user containers are its defining feature, covered [below](#where-shinyproxy-is-better). The cost is resource usage and startup time: fifty concurrent users of a dashboard are fifty containers, and each user waits for a container to start. Pre-initialized containers and container sharing reduce this, with [documented limitations](https://shinyproxy.io/documentation/configuration/#container-pre-initialization-and-sharing): no per-user settings other than HTTP headers, no app recovery, and a pool which stays running.

OpenRun runs one container per app. The first request after an idle period waits for the container to start; every other user is served by the running container. This suits frameworks which handle many sessions in one process, such as Streamlit, Gradio, Dash, FastAPI and Shiny for Python, and regular web apps and APIs. Shiny for R apps run the same way with the [`r-shiny` spec]({{< ref "docs/container/appspecs/#the-r-shiny-spec" >}}), which works well when sessions are light or slow work is done asynchronously. On Kubernetes, stateless apps can run several replicas with a HorizontalPodAutoscaler.

### Per-App Auth, RBAC and Audit

ShinyProxy has one authentication method for the whole server, and per-app access lists by user, group or SpEL expression in the config file.

OpenRun selects the [auth type]({{< ref "docs/configuration/authentication/" >}}) per app, so a server can host apps behind Okta, apps behind GitHub login, apps with client certificates and public apps together. [RBAC]({{< ref "docs/configuration/rbac/" >}}) grants cover app access by path or domain pattern, custom permissions which are passed to the app, and management operations such as who may create, update or promote apps. Grants can be changed at runtime. [Audit events]({{< ref "docs/applications/audit/" >}}) record management operations and non-read app requests.

### Routing, Domains and TLS

ShinyProxy apps live under paths on the ShinyProxy host, by default inside a page with the ShinyProxy navigation bar, and TLS is terminated in front of ShinyProxy: by a reverse proxy you set up, by the Caddy instance which the operator deploys on Docker (with Let's Encrypt certificates), or by an ingress on Kubernetes. With OpenRun, each app gets its own path or domain, and OpenRun terminates TLS with automatically issued certificates.

### Beyond Data Apps

ShinyProxy does one job, running containers for users. OpenRun also provides [service bindings]({{< ref "docs/applications/servicebindings/" >}}) for database credentials, [actions]({{< ref "docs/actions/" >}}) which turn a function into a form, a CLI command and an MCP tool, scheduled [jobs]({{< ref "docs/applications/jobs/" >}}) and secrets management.

## Where ShinyProxy Is Better

ShinyProxy is the right choice when:

- **Each user needs an isolated container**: a crash or a long computation in one user's session stays in that user's container. With container resource limits and enough host capacity, so does a CPU or memory spike. In OpenRun, all users of an app share its container.
- **You host R Shiny apps with heavy computation**: R is single-threaded, so a synchronous computation blocks every session in the same R process unless the app is written with async features such as promises or `ExtendedTask`. A container per user sidesteps this without app changes. OpenRun's [`r-shiny` spec]({{< ref "docs/container/appspecs/#the-r-shiny-spec" >}}) runs a Shiny for R app as one R process shared by all users.
- **You provide notebooks and IDEs**: Jupyter, RStudio, VS Code and similar tools are personal workspaces. ShinyProxy gives each user their own, with per-user volumes mounted through SpEL expressions. OpenRun has no per-user workspace model.
- **Users need per-user resources or launch options**: memory and CPU limits, images and environment can differ by user or group, users can choose from predefined [app parameters](https://shinyproxy.io/documentation/app-parameters/) at launch and run several instances of an app.
- **Your directory is LDAP or Active Directory, without an OIDC or SAML IdP**: ShinyProxy authenticates against LDAP directly. OpenRun needs an OIDC or SAML provider in front of the directory.
- **You run on Docker Swarm or AWS ECS**: OpenRun supports Docker, Podman and Kubernetes only.
- **You want an app launcher for end users**: ShinyProxy's landing page lists the apps each user may open, with templates for branding.
- **You already build images in CI**: if every app already has a pipeline which publishes a tested image, ShinyProxy consumes it directly. OpenRun can run prebuilt images through the `image` spec, but its staging and build features add less in that setup.
- **You want a support contract**: Open Analytics sells support and SLAs. OpenRun has community support only.
- **You want the longer track record**: ShinyProxy has been developed since 2016 and has a large installed base for Shiny hosting.

## Using Them Together

The two can run side by side behind the same identity provider. ShinyProxy hosts the per-user workloads: Shiny apps with heavy sessions, RStudio and Jupyter. OpenRun hosts the shared ones: Streamlit, Gradio and lighter Shiny dashboards, internal web apps, APIs and operational actions, deployed from Git.

## Frequently Asked Questions

### Is OpenRun an alternative to ShinyProxy?

For apps which can serve all their users from one container, yes: Streamlit, Gradio, Dash, Shiny for Python, light Shiny for R apps, Flask, FastAPI and similar apps. OpenRun adds building from source, GitOps, staging and per-app RBAC. For workloads which need one container per user, such as RStudio, Jupyter or computation-heavy R Shiny apps, ShinyProxy is the better fit.

### Can OpenRun run R Shiny apps?

Yes. The [`r-shiny` spec]({{< ref "docs/container/appspecs/#the-r-shiny-spec" >}}) builds and runs a Shiny for R app from its source, on a path or a domain, with no Dockerfile:

```sh
openrun app create --spec r-shiny --approve github.com/rstudio/shiny-examples/001-hello /hello
```

Packages are restored from an `renv.lock` if the repo has one; otherwise they are detected from the source and installed as binaries. All users share one R process, so this suits light apps and apps written with async computation; for heavy synchronous per-session computation, ShinyProxy's container per user works better.

### Does OpenRun start a container for each user like ShinyProxy?

No. OpenRun starts one container per app on the first request and all users share it. It is stopped after an idle period and started again on the next request. On Kubernetes, stateless apps can scale to several replicas, but replicas are not tied to users.

### Do I need to build Docker images for OpenRun?

No. OpenRun builds the image from the app's source repo, using the Containerfile from the app spec or one in the repo. ShinyProxy requires an image which you build yourself and make available on the host or in a registry. OpenRun can also run an existing image.

### Does adding an app require a restart?

Not in OpenRun; apps are created and updated live through the CLI, the console or a Git sync. In ShinyProxy, apps are defined in `application.yml` and a config change needs a restart. The ShinyProxy operator automates this by deploying a new ShinyProxy instance and retiring the old one once its users disconnect.

### How does the app know who the user is?

OpenRun sets `X-Openrun-User`, `X-Openrun-User-Email` and `X-Openrun-Perms` headers on each request proxied to the app. ShinyProxy sets the `SHINYPROXY_USERNAME` and `SHINYPROXY_USERGROUPS` environment variables when it starts the user's container, and by default also adds `X-SP-UserId` and `X-SP-UserGroups` headers to every request. With shared containers, only the headers apply.

### Do OpenRun and ShinyProxy scale apps to zero?

Both stop idle containers. ShinyProxy stops a user's container on logout or when browser heartbeats stop, so an open tab keeps it running. OpenRun stops an app's container when there have been no new requests and less than 1500 bytes of data transfer over the idle window, 180 seconds by default. The check runs once per window, so the stop comes some time after the app goes idle, and a WebSocket connection carrying only small keepalive traffic does not keep the container running. Both thresholds are configurable.

### What do they cost?

Both are free, Apache-2.0 licensed open source with no limit on apps or users. Open Analytics offers paid support for ShinyProxy.
