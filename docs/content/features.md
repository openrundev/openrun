---
title: "Features"
summary: "OpenRun Features"
layout: hextra-home
---

<iframe
  src="/intro.html"
  style="width:100%; height:80vh; border:0;"
></iframe>

<div style="height: 20px;"></div>

{{< hextra/feature-grid >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="GitOps Workflow" link="/docs/quickstart/#lifecycle-with-git" subtitle="Blue-green (staged) deployments, versioning and preview environments with no infra to manage."  icon="github" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Hypermedia web apps" link="/docs/app/routing/#html-route" subtitle="Easily build fast and lightweight backend driven apps, with minimal frontend complexity."  icon="html5" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Secrets Management" link="/docs/configuration/secrets/" subtitle="Manage secrets with AWS Secrets Manager and Vault."  icon="shield-exclamation" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Auto-Pause Idle apps" link="/docs/container/config/" subtitle="Idle apps are paused, scale down to zero."  icon="pause" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Autogen Actions" link="/docs/actions/" subtitle="Auto-generated UI for backend actions, no UI to develop."  icon="binary-off" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Audit Events" link="/docs/applications/audit/" subtitle="Auto-audit logging for all events, plus custom events."  icon="view-list" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="OpenTelemetry" link="/docs/configuration/telemetry/" subtitle="Export traces and metrics for app requests, containers and database calls over OTLP HTTP."  icon="chart-bar" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Cross-language AppServer" link="/docs/quickstart/#containerized-applications" subtitle="Application Server which supports all languages."  icon="support" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Container management" link="/docs/container/overview/" subtitle="Automatically build and deploy containers, with Docker/Podman or Kubernetes."  icon="docker" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Cross-platform support" link="/docs/quickstart/#installation" subtitle="OpenRun runs on Linux, Windows and OSX, works with Docker/Podman or Kubernetes"  icon="globe-alt" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Auto TLS Certificates" link="/docs/configuration/networking/#enable-automatic-signed-certificate" subtitle="Automatically generate TLS certificates, for multiple domains"  icon="shield-check" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Powerful access controls" link="/docs/configuration/authentication" subtitle="OAuth/OpenID/SAML/Client-cert based auth, with full RBAC support"  icon="globe-alt" icon="shield-check"  class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Domain-based and path-based routing" link="/docs/applications/routing/#request-routing" subtitle="Install apps at a domain, subdomain or at path level"  icon="map" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Zero-config dev env setup" link="/docs/applications/overview/#apply-command" subtitle="Easily setup dev environment with zero config required"  icon="check" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Blue-green Deployment" link="/docs/applications/lifecycle/#staging-apps" subtitle="Staged deployment, for code changes and for config changes"  icon="chevron-double-up" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Security Sandbox" link="/docs/applications/appsecurity/#security-model" subtitle="Apps built in Starlark based micro-framework use sandboxing for security"  icon="shield-check" class="openrun-feature-card openrun-feature-card-light" >}}

{{< /hextra/feature-grid >}}
