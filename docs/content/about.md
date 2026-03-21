---
title: "About"
summary: "About OpenRun"
---

### What is OpenRun?

OpenRun (previously called Clace) is a web app deployment platform, with a focus on deploying internal tools. OpenRun makes it easy to declaratively deploy containerized web apps. OpenRun can deploy apps on a single-node or onto a Kubernetes cluster.

OpenRun provides declarative GitOps based blue-green deployment, OAuth/OIDC/SAML access controls, TLS certs & secrets management. OpenRun has RBAC and auditing features for teams to securely deploy internal tools.

### Project Goals

The goal of this project is to make it easy for individuals and teams to develop and deploy web applications declaratively, with minimal operational overhead. Easy integrations to enable SSO/SAML based authentication and authorization controls, audit logs and integration with secrets manager for managing credentials are goals. Deploying on a single machine or deploying across on a cluster on Kubernetes should use the same config.

Application deployments should support a GitOps approach. It should be easy, for the original developer or a new one, to make application code changes and deploy - after six months or after six years.

### FAQ

<details open>
  <summary><b>How does OpenRun compare to other deployment solutions like Coolify/Dokku etc?</b></summary>

> The main differences are:
>
> - OpenRun is declarative. After initial OpenRun setup. Instead of using CLI commands or UI operations, all operations including creating new app and updating config for existing apps can be doing by updating a config file in Git. With most other solution, app creation/update is through CLI or UI. Only app source code update can be done through Git.
> - OpenRun is implemented as a web server, it does not depend on external web server like Nginx/Traefik. This simplifies end-user usage and allows OpenRun to implement features like scale down to zero (for app containers) and OAuth/SAML/Cert based auth with RBAC.
> - OpenRun implements features like staged deployment and automatic dev env setup which are not available in other solutions.
> - OpenRun supports deploying apps to a single machine or onto Kubernetes.

</details>

<details>
  <summary><b>Why is declarative configuration useful?</b></summary>

> Imperative CLI or UI operation are easy to start with, but they make it difficult to track changes and rollback updates. With a declarative config, all changes are version controlled. It is easy to create a new environment, since everything is in Git. If multiple folks are making config changes in a team, declarative systems are easier to manage.
>
> Declarative configuration is what makes Kubernetes and Terraform useful. OpenRun brings declarative configuration to web app deployment. Instead of writing pages of YAML, each app is specified as a few lines of Starlark (python-like) config. For example, see [utils.star](https://github.com/openrundev/openrun/blob/main/examples/utils.star).

</details>

<details>
  <summary><b>What types of apps can be deployed with OpenRun?</b></summary>

> OpenRun can deploy any web app which runs in a single container. OpenRun supports [AppSpecs](https://openrun.dev/docs/container/overview/#app-specs) which allow zero-config deployment of frameworks like Streamlit/Gradio/FastHTML/NiceGUI/Shiny/Reflex based apps. For frameworks which have a AppSpec, no Dockerfile is required, no code changes are required in the app source code. For frameworks which do not have an AppSpec defined, a Dockerfile needs to be present in the app source repo.
>
> OpenRun does NOT support apps which require multiple containers using Docker Compose. The target use case is internal tools talking to existing API endpoints and web apps where the database is externally managed.

</details>

<details>
  <summary><b>Does OpenRun support deployment of internal tools by teams?</b></summary>

> Yes, deployment of internal tools by teams is a target [use case](https://openrun.dev/docs/use-cases/team/). Features which are built for this use case include:
>
> - **Declarative Config**: Manage apps by [declaratively](https://openrun.dev/docs/applications/overview/#declarative-app-management) in git, allowing team to do follow regular SDLC for config
> - **OAuth/OIDC/SAML with RBAC**: Manage who can access which app using [RBAC](https://openrun.dev/docs/configuration/rbac/)
> - **Audit Logs**: All operations and API calls are automatically logged in [audit trail](https://openrun.dev/docs/applications/audit/)
>
> If not used for internal tools, the auth and auditing features can be disabled, in which case OpenRun is suitable for deploying any web application.

</details>

<details>
  <summary><b>How is OpenRun deployed?</b></summary>

> OpenRun can be deployed on a single node easily (Linux, Windows or OSX), using a SQLite database for storing metadata. Docker/Podman is the only dependency. OpenRun can be deployed across multiple machines, using an external Postgres database for storing metadata.
>
> OpenRun can also be deployed on Kubernetes using a Helm chart. On Kubernetes, OpenRun will avoid the need to setup a build system like Jenkins, CD with ArgoCD and an IDP like BackStage. Apps deployed using OpenRun are deployed as Kubernetes services, with OpenRun running as the api server/request router.

</details>

### How is OpenRun implemented?

- Single binary web application server (in golang), with a set of plugins built in (also in golang) which allow access to external endpoints. The server is statically configured using a TOML file.
- Applications are configured using [Starlark](https://github.com/google/starlark-go), which is a subset of Python. Python is an ideal glue language, Starlark is used to configure the application backend logic
- Multiple applications can be dynamically installed, an embedded SQLite database is used to store application metadata (Postgres support is in the roadmap).
- For applications using the container plugin, OpenRun works with Docker/Podman using CLI to build and run the containers. On Kubernetes, OpenRun uses the Kubernetes server side apply (SSA) APIs to create app resources.
- Path based routing, each app identified by a unique path. Also, domain based routing, which allows multiple domains to point to the same OpenRun instance, with path based routing being done independently for each domain.
- Automatic TLS certificate management for each domain to simplify deployments.
- A sandboxing layer is implemented at the Starlark(python) to Golang boundary, allowing the implementation of security and access control policies. Go code is trusted, Starlark code is untrusted.
- For Starlark based apps, the application UI is implemented using Go HTML templates, with [HTMX](https://htmx.org/) for interactivity. Go templates support [context aware templating](https://pkg.go.dev/html/template#hdr-Contexts) which prevents encoding related security issues. They also work well with the HTML fragments required for HTMX.
- No need to install any additional components like Python or NodeJS/NPM on the host machine. Integration with [tailwindcss-cli](https://tailwindcss.com/blog/standalone-cli) is supported. [esbuild](https://esbuild.github.io/) (using the esbuild go library) is supported out of the box for importing ESM modules.

### Current Status

The current status is:

- Client and server (in a single binary) for service management and configuration.
- Support for application development with Starlark based configuration.
- Container management support with Docker/Podman or Kubernetes.
- Auto-idling of containers to reduce resource usage
- Go HTML template loading and caching for request processing.
- HTTP plugin for communicating with REST endpoints.
- Exec plugin for running system commands.
- Built in admin account for local development.
- Auto-sync (file system watcher) and Auto-reload using SSE (automatic UI refresh) for speeding up the application development cycle.
- Admin functionality using unix domain sockets for security.
- Application sandboxing checks to ensure only audited operations are allowed.
- Staged deployment support, preview app creations support.
- App data persistence to sqlite with managed tables.

### Who is behind this project?

The project was started by [Ajay Kidave](https://www.linkedin.com/in/ajayvk/). Ajay's background has been in database systems and enterprise integration tools. OpenRun was started to find ways to reduce the development and operational complexity in tooling for internal applications.

### How to stay in touch?

- Star the repo at [github.com/openrundev/openrun](https://github.com/openrundev/openrun)
- Email at [contact@openrun.dev](mailto:contact@openrun.dev)
- Follow on [Twitter](https://twitter.com/ajay_kidave)
- Subscribe to the blog [RSS feed](https://openrun.dev/blog/index.xml)
- Connect on [Discord](https://discord.gg/t2P8pJFsd7)
- #openrun channel in the [CNCF Slack](https://cloud-native.slack.com/)
- Schedule a [Meeting](https://calendar.app.google/wacEeZ9agtHHZTkMA)
