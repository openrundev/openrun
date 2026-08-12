---
title: "Features"
description: "Explore OpenRun's self-hosted PaaS alternative features for VPS, single server and Kubernetes deployments, including GitOps, RBAC, SSO, SQLite replication and service bindings for PostgreSQL, MySQL, SQLite, Redis, SQL Server, Oracle, MongoDB, Snowflake and ClickHouse."
summary: "Self-hosted web app deployment with GitOps, RBAC, SSO, managed database access and SQLite replication."
keywords:
  [
    "PostgreSQL service binding",
    "MySQL service binding",
    "SQLite hosting",
    "Redis service binding",
    "SQL Server provisioning",
    "Oracle database binding",
    "MongoDB provisioning",
    "Snowflake provisioning",
    "ClickHouse provisioning",
    "GitOps deployment",
    "self-hosted PaaS features",
  ]
layout: hextra-home
---

{{< hextra/feature-grid >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="GitOps Workflow" link="/docs/quickstart/#lifecycle-with-git" subtitle="Manage blue-green deployments, versioned releases and preview environments through declarative Git workflows without maintaining separate deployment infrastructure."  icon="github" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Hypermedia web apps" link="/docs/app/routing/#html-route" subtitle="Build fast, lightweight hypermedia web apps with server-driven HTML, minimal JavaScript and substantially less frontend complexity."  icon="html5" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Secrets Management" link="/docs/configuration/secrets/" subtitle="Securely provide application secrets through AWS Secrets Manager, HashiCorp Vault and other configured secret providers."  icon="shield-exclamation" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Auto-Stop Idle Apps" link="/docs/container/config/" subtitle="Automatically stop idle application containers and scale their resource usage down to zero until the next incoming request."  icon="pause" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Database Service Bindings" link="/docs/applications/servicebindings" subtitle="Automatically provision isolated database accounts for PostgreSQL, MySQL, SQLite and Redis/Valkey (built in), plus SQL Server, Oracle, MongoDB, Snowflake and ClickHouse via installable binding providers."  icon="database" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Managed SQLite + Litestream" link="/docs/applications/litestream/" subtitle="Deploy SQLite apps with continuous Litestream replication to S3-compatible storage and automatic restore after volume or node loss."  icon="cloud-upload" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Autogen Actions" link="/docs/actions/" subtitle="Generate secure form-based interfaces for backend operations automatically, eliminating custom frontend development for routine administrative actions."  icon="binary-off" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Audit Events" link="/docs/applications/audit/" subtitle="Capture application operations and API activity automatically, with searchable audit events plus support for custom business events."  icon="view-list" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="OpenTelemetry" link="/docs/configuration/telemetry/" subtitle="Export detailed application requests, container lifecycle activity, distributed traces and platform metrics through OpenTelemetry-compatible OTLP endpoints."  icon="chart-bar" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Container management" link="/docs/container/overview/" subtitle="Build and deploy containerized applications automatically across Docker, Podman or Kubernetes using the same declarative configuration."  icon="docker" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Self-hosted PaaS alternative" link="/docs/use-cases/personal/" subtitle="Run web apps on your own VPS or Kubernetes cluster with GitOps and no proprietary cloud platform dependency." icon="server" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Cross-platform support" link="/docs/quickstart/#installation" subtitle="Run OpenRun consistently on Linux, Windows and macOS with Docker, Podman or Kubernetes as the container backend."  icon="globe-alt" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Auto TLS Certificates" link="/docs/configuration/networking/#enable-automatic-signed-certificate" subtitle="Generate and renew trusted TLS certificates automatically for applications served across multiple domains, subdomains and custom hostnames."  icon="shield-check" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Powerful access controls" link="/docs/configuration/authentication" subtitle="Protect applications with OAuth, OpenID Connect, SAML or client certificates, backed by flexible role-based access controls."  icon="globe-alt" icon="shield-check"  class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Domain-based and path-based routing" link="/docs/applications/routing/#request-routing" subtitle="Route applications by domain, subdomain or URL path while OpenRun manages ingress, proxying and deployment changes automatically."  icon="map" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Zero-config dev env setup" link="/docs/applications/overview/#apply-command" subtitle="Create reproducible local development environments automatically from application configuration, with minimal manual setup or infrastructure knowledge."  icon="check" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Blue-green Deployment" link="/docs/applications/lifecycle/#staging-apps" subtitle="Stage application code and configuration changes in an isolated environment before promoting the verified release into production."  icon="chevron-double-up" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Security Sandbox" link="/docs/applications/appsecurity/#security-model" subtitle="Run Starlark-based application code inside a permission-controlled security sandbox with explicit allowlists for sensitive platform operations."  icon="shield-check" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Management Console" link="/console-tour/" subtitle="Manage applications, deployments, service bindings, containers, audit events and server configuration through OpenRun’s browser-based administration console."  icon="desktop-computer" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Compare OpenRun" link="/compare/" subtitle="See how OpenRun compares with Coolify, CapRover, Kamal, Dokku, Google Cloud Run, AWS App Runner and DIY Kubernetes platforms."  icon="scale" class="openrun-feature-card openrun-feature-card-light" >}}

{{< /hextra/feature-grid >}}

<div style="height: 20px;"></div>

<iframe
  src="/intro.html?v=20260808-storage"
  style="width:100%; height:80vh; border:0;"
></iframe>
