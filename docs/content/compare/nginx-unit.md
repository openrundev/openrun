---
title: "NGINX Unit Alternative: OpenRun vs NGINX Unit"
linkTitle: "vs NGINX Unit"
weight: 500
date: 2026-11-09
description: "NGINX Unit was archived in October 2025. OpenRun vs NGINX Unit: a maintained open-source app server with GitOps, automatic TLS, SSO and scale-to-zero."
summary: "OpenRun compared with NGINX Unit, the universal web app server which was archived in October 2025."
keywords:
  - NGINX Unit alternative
  - OpenRun vs NGINX Unit
  - NGINX Unit archived
  - NGINX Unit replacement
  - open source application server
  - multi-language app server
  - self-hosted app server
---

NGINX Unit is a multi-language web app server: one server process runs application code in several languages, serves static files and handles TLS and request routing, all configured at runtime through a JSON API. OpenRun is also a single server which runs apps in any language and handles routing and TLS, but it runs each app in a container and adds the deployment platform around it: GitOps, staged deployments, SSO, RBAC, audit logs and scale-to-zero.

**NGINX Unit is no longer maintained.** The [Unit repository](https://github.com/nginx/unit) was archived on October 8, 2025 and is read-only. The [Unit website](https://unit.nginx.org/) states that "NGINX Unit is archived and unmaintained", and the README notes that "security vulnerabilities may be unaddressed". The last release is 1.34.2, from February 26, 2025. Teams running Unit in production need to plan a migration. New projects should not be started on it.

**Summary**: Choose OpenRun if you are looking for an actively maintained, open-source NGINX Unit alternative for web apps and internal tools, and want deployments from Git, automatic TLS certificates, authentication and access control for apps, and idle apps which scale to zero. Unit runs apps as in-process language modules without containers, runs WebAssembly components and has more detailed request routing. Those benefits come with the risk of running unmaintained software on the request path.

## Two Kinds of App Server

Both projects reduce the number of components needed to serve a web app. They do it in different ways.

**NGINX Unit embeds the language runtime.** Unit loads a language module (PHP, Python, Ruby, Perl, Java) into its own application processes, or links into the app through a library (Go, Node.js). There is no separate Gunicorn, PHP-FPM or Puma between the web server and the code. The language versions which can be used are the ones for which a Unit module is installed on the host.

**OpenRun runs each app in a container.** OpenRun builds an image from the app source and runs it with Docker, Podman or Kubernetes. The app uses its own regular server (Uvicorn, Gunicorn, a Go binary, Spring Boot) inside the container, and OpenRun proxies requests to it. Any language, version or system dependency which works in a container works with OpenRun, and each app's dependencies are isolated from every other app. The [AppServer blog post]({{< ref "/blog/appserver" >}}) describes the reasoning behind this design.

The other difference is scope. Unit is a runtime component: getting code onto the server, building it, issuing certificates, authenticating users and rolling back a bad release are left to other tools. OpenRun includes those parts.

## Feature Comparison

| Capability                              | OpenRun                                                                                                              | NGINX Unit                                                                                 |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Project status                          | Actively developed                                                                                                   | Archived October 2025, unmaintained; last release 1.34.2 (February 2025)                   |
| How apps run                            | Containers on Docker, Podman or Kubernetes                                                                           | Language modules in Unit managed processes                                                 |
| Supported languages                     | Any language which runs in a container                                                                               | Go, Java, Node.js, Perl, PHP, Python, Ruby, WebAssembly components (WASI 0.2)              |
| Configuration                           | Declarative config file for all apps, CLI and optional [web console]({{< ref "console-tour" >}})                     | JSON over a REST control API on a Unix socket; no config files                             |
| Deploy from Git                         | Yes, apps are created, configured and updated from Git                                                               | No, code is placed on the server by other tools                                            |
| Builds                                  | Built in, image built from app source                                                                                | None, dependencies are installed on the host                                               |
| Config changes without restart          | Yes                                                                                                                  | Yes                                                                                        |
| Staging and promotion                   | Yes, each app has a staging version, promoted after verification                                                     | No                                                                                         |
| Version history and rollback            | Yes, app versions tracked in OpenRun metadata                                                                        | No                                                                                         |
| TLS certificates                        | Automatic issuance and renewal through ACME                                                                          | Certificate bundles uploaded through the API; issuance and renewal with Certbot            |
| Static file serving                     | Yes                                                                                                                  | Yes                                                                                        |
| Reverse proxy                           | Yes                                                                                                                  | Yes, to HTTP backends; weighted round-robin upstreams                                      |
| Request routing                         | Domain and path based routing to apps                                                                                | Match rules on host, URI, method, headers, cookies, query and source address; njs scripting |
| SSO for deployed apps (OAuth/OIDC/SAML) | Yes, for every app                                                                                                   | No                                                                                         |
| RBAC per app                            | Yes, path/domain based grants                                                                                        | No                                                                                         |
| Audit logs                              | Yes, built in                                                                                                        | No                                                                                         |
| Secrets management                      | Yes, Vault, AWS Secrets Manager/SSM, Kubernetes and an embedded store                                                | No, environment variables in the app config                                                |
| Scale idle apps to zero                 | Yes, idle containers are stopped and started on the next request                                                     | Idle app processes above a configured spare count are stopped                              |
| App isolation                           | Containers                                                                                                           | Separate processes; optional Linux namespaces, cgroups and rootfs                          |
| Observability                           | OpenTelemetry traces and metrics, Grafana dashboards                                                                 | JSON status API; initial OpenTelemetry support added in 1.34                               |
| Kubernetes support                      | Yes, same config via Helm chart                                                                                      | No, Docker images only                                                                     |
| Platforms                               | Linux, macOS, Windows                                                                                                | Linux, FreeBSD, macOS, Solaris                                                             |
| CLI                                     | Yes                                                                                                                  | `unitctl`, a technical preview not recommended for production                              |
| License                                 | Apache-2.0                                                                                                           | Apache-2.0                                                                                 |

Details for the OpenRun column: [declarative app management]({{< ref "docs/applications/overview/#declarative-app-management" >}}), [app specs]({{< ref "docs/container/appspecs/" >}}), [staging apps]({{< ref "docs/applications/lifecycle/#staging-apps" >}}), [automatic TLS]({{< ref "docs/configuration/networking/#enable-automatic-signed-certificate" >}}), [authentication]({{< ref "docs/configuration/authentication/" >}}), [RBAC]({{< ref "docs/configuration/rbac/" >}}), [audit events]({{< ref "docs/applications/audit/" >}}), [secrets]({{< ref "docs/configuration/secrets/" >}}), [scale-to-zero]({{< ref "docs/container/config/#idle-shutdown" >}}), [telemetry]({{< ref "docs/configuration/telemetry/" >}}) and [Kubernetes]({{< ref "docs/container/kubernetes/" >}}).

Comparison last verified on November 9, 2026 against the [NGINX Unit documentation](https://unit.nginx.org/), including the [key features](https://unit.nginx.org/keyfeatures/), [configuration](https://unit.nginx.org/configuration/), [control API](https://unit.nginx.org/controlapi/), [certificates](https://unit.nginx.org/certificates/), [status API](https://unit.nginx.org/statusapi/), [installation](https://unit.nginx.org/installation/) and [unitctl](https://unit.nginx.org/unitctl/) pages, and the [Unit GitHub repository](https://github.com/nginx/unit).

## Where OpenRun Differs

### Actively Maintained

A web app server parses untrusted HTTP requests and terminates TLS. Unit's own README says security vulnerabilities may go unaddressed now that the repository is archived, and its language modules will not be updated for new runtime versions. OpenRun is under active development, with regular releases and a [changelog](https://github.com/openrundev/openrun/blob/main/CHANGELOG.md).

### Deployment from Git, Not Just a Runtime

With Unit, the control API tells the server where the code already is. Copying the code to the server, installing its dependencies, keeping the JSON config in version control and re-applying it are done with scripts, Ansible or a CI pipeline.

OpenRun manages the full application lifecycle through Git. Apps are [declared in a config file]({{< ref "docs/applications/overview/#declarative-app-management" >}}) checked into a repo:

```python {filename="apps.star"}
app(path="/api", source="github.com/myorg/orders-api", spec="python-asgi")
app(path="/dashboard", source="github.com/myorg/sales-dashboard", spec="python-streamlit")
```

One command sets up the pipeline:

```sh
openrun sync schedule --approve --promote github.com/myorg/platform/apps.star
```

OpenRun polls the repo, creates newly declared apps, applies config changes and deploys code updates. Images are built from the app source, so nothing is installed on the host apart from OpenRun and a container runtime.

### Automatic TLS

Unit stores certificate bundles which are uploaded through its API and can select between them using SNI. Getting the certificate and renewing it is done separately, with the Unit docs pointing to Certbot. OpenRun [issues and renews certificates automatically]({{< ref "docs/configuration/networking/#enable-automatic-signed-certificate" >}}) through ACME for the domains apps are served on.

### SSO and RBAC for Every App

Unit has no authentication layer. Each app implements login itself, or an OAuth proxy is added in front. OpenRun protects every deployed app with [OAuth, OpenID Connect, SAML or client certificates]({{< ref "docs/configuration/authentication/" >}}), configured once at the server level. [RBAC]({{< ref "docs/configuration/rbac/" >}}) controls which users and IdP groups can access which apps, and [audit events]({{< ref "docs/applications/audit/" >}}) record who did what. For internal tools, this removes the need to build login into every app.

### Staged Deployments and Rollback

A Unit config update takes effect immediately, and Unit keeps no history of earlier configs or code. In OpenRun, each app has a [staging version]({{< ref "docs/applications/lifecycle/#staging-apps" >}}) which receives code and config changes first. Changes are promoted to production after verification, and earlier versions can be [switched back to]({{< ref "docs/applications/overview/#switching-versions" >}}).

### Scale to Zero Across Containers

Unit can stop idle app processes above a configured number of spare processes, which keeps the memory use of a multi-app server down. OpenRun does the same at the container level: an app which receives no requests has its [container stopped]({{< ref "docs/container/config/#idle-shutdown" >}}) and it is started again on the next request. A single server can host hundreds of internal tools with only the active ones using CPU and memory.

## Where NGINX Unit Is Better

Unit's design has advantages for some workloads:

- **No container runtime.** Unit runs apps as plain processes. OpenRun needs Docker, Podman or Kubernetes for apps other than static sites and proxied services.
- **Lower overhead per request.** Unit passes requests to app processes over shared memory, with no second HTTP server and no proxy hop. OpenRun proxies HTTP to the server inside the app container.
- **Detailed request routing.** Unit routes can match on headers, cookies, query arguments, method and source address, rewrite URIs, return responses directly and run njs scripts. OpenRun routes by domain and path to an app, and request-level logic belongs in the app.
- **Upstream load balancing.** Unit distributes requests across a group of upstream servers with weighted round-robin. OpenRun is not a general purpose load balancer.
- **WebAssembly.** Unit runs WebAssembly components directly. OpenRun has no WebAssembly runtime.
- **FreeBSD and Solaris.** Unit supports both. OpenRun supports Linux, macOS and Windows.

If you need a general purpose reverse proxy and load balancer rather than an app deployment platform, a maintained web server such as NGINX, Caddy or HAProxy is a closer replacement for those parts of Unit than OpenRun is.

## Moving from NGINX Unit to OpenRun

Most Unit concepts have a direct OpenRun equivalent:

| NGINX Unit                                    | OpenRun                                                                                                                         |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `listeners`                                   | Server level [HTTP and HTTPS ports]({{< ref "docs/configuration/networking/" >}}), shared by all apps                           |
| `applications` entry of type `python`         | App using the `python-wsgi` or `python-asgi` [app spec]({{< ref "docs/container/appspecs/#app-specs-listing" >}})               |
| `applications` entry of type `external` (Go)  | App using the `go` spec                                                                                                         |
| `applications` entry of type `java`           | App using the `java-spring-boot` spec, or the `container` spec with a Dockerfile                                                |
| Node.js, PHP, Ruby and Perl applications      | App using the `container` spec, with a Dockerfile in the app repo                                                               |
| `share` action for static files               | App using the `static` or `static_disk` [spec]({{< ref "docs/container/appspecs/#static-specs" >}})                             |
| `proxy` action                                | App using the `proxy` spec                                                                                                      |
| `routes` matching on host and URI             | The domain and path the app is installed at                                                                                     |
| `/certificates` uploads                       | [Automatic certificates]({{< ref "docs/configuration/networking/#enable-automatic-signed-certificate" >}}), or certificate files |
| `environment` in the app config               | App params and [secrets]({{< ref "docs/configuration/secrets/" >}})                                                             |
| `processes` with `spare` and `idle_timeout`   | [Idle shutdown]({{< ref "docs/container/config/#idle-shutdown" >}}) of the app container                                        |
| `isolation` with namespaces and cgroups       | Container isolation, with [resource limits]({{< ref "docs/container/overview/#container-options" >}}) per app                                     |

Apps which use the Unit specific integration, `unit-http` for Node.js or `unit.nginx.org/go` for Go, need to switch back to the standard `http` module or `net/http` listener. Python (WSGI/ASGI), Ruby (Rack), PHP and Java (Servlet) apps use standard interfaces and run unchanged behind a regular server inside the container.

To try it, [install OpenRun]({{< ref "docs/installation/" >}}) and follow the [quick start]({{< ref "docs/quickstart/" >}}).

## Frequently Asked Questions

### Is NGINX Unit still maintained?

No. The NGINX Unit GitHub repository was archived on October 8, 2025 and is read-only. The Unit website states that the project is archived and unmaintained and no longer receives new features, and the README notes that security vulnerabilities may be unaddressed. The last release was 1.34.2 on February 26, 2025. The code remains available under the Apache-2.0 license.

### What is a good alternative to NGINX Unit?

It depends on which part of Unit you use. For deploying and running web apps in multiple languages on your own servers, OpenRun is an open-source alternative which adds GitOps deployment, automatic TLS, SSO, RBAC and scale-to-zero. For reverse proxying, load balancing and static file serving alone, a web server such as NGINX or Caddy is the closer fit. For PHP specifically, PHP-FPM or FrankenPHP behind a web server replace the Unit PHP module.

### Is OpenRun a drop-in replacement for NGINX Unit?

No. Unit loads language modules into its own processes and is configured with JSON through a control API. OpenRun runs apps in containers and is configured with a declarative file. Apps written against standard interfaces such as WSGI, ASGI, Rack and Servlet move over without code changes; the Unit JSON config is replaced by a few lines of OpenRun app config.

### Does OpenRun require Docker?

OpenRun needs Docker, Podman or Kubernetes to run containerized apps. Static sites and proxied services are served by OpenRun directly, without a container. OpenRun itself is a single binary for Linux, macOS and Windows.

### Which languages does OpenRun support?

Any language which runs in a container. [App specs]({{< ref "docs/container/appspecs/" >}}) provide zero-config deployment for common frameworks, including Python WSGI and ASGI apps, Streamlit, Gradio, FastHTML, NiceGUI, Shiny, Reflex, Go, Hono and Spring Boot. Other apps need a Dockerfile in the repo.

### Does OpenRun support dynamic configuration like NGINX Unit?

Yes. Apps are created, updated and deleted while OpenRun is running, with no server restart. Changes can be made from the CLI, the web console or by editing the declarative config in Git, and they go through staging before being promoted to production.

### Is OpenRun open source?

Yes, OpenRun is Apache-2.0 licensed, the same license as NGINX Unit. Source is at [github.com/openrundev/openrun](https://github.com/openrundev/openrun).
