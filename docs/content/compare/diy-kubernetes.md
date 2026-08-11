---
title: "OpenRun vs DIY on Kubernetes"
weight: 300
date: 2026-08-10
description: "Compare OpenRun with building your own Kubernetes platform from Jenkins, ArgoCD, Knative, ingress controllers and an internal developer portal. One system, no YAML, with SSO and RBAC built in."
summary: "OpenRun compared with building your own platform from Jenkins, ArgoCD, Knative and an IDP."
---

Teams that deploy web apps on Kubernetes usually assemble a platform from parts: a build system like Jenkins or GitHub Actions, a CD tool like ArgoCD or Flux, an ingress controller with cert-manager for TLS, an OAuth proxy for authentication, Knative for scale-to-zero and an internal developer portal like Backstage to tie it together. Each part works, but the glue between them becomes a platform engineering project of its own.

OpenRun provides the web app deployment slice of that stack as one system. OpenRun installs on your Kubernetes cluster through a Helm chart. After that, OpenRun deploys apps as Kubernetes services and handles builds, GitOps sync, routing, TLS, authentication, RBAC, audit logs and scale-to-zero from the same declarative config which is used for single node OpenRun installations.

**Summary**: Choose OpenRun on Kubernetes to give teams a simple way to deploy web apps and internal tools without writing YAML or learning Kubernetes. Build a DIY platform when you need full control over the stack, run non-web workloads and operators, or already have an established platform team maintaining these tools.

## The Stack Comparison

| Concern                 | DIY Kubernetes stack                                                 | OpenRun                                                                                                                                        |
| ----------------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Container builds        | Jenkins, GitHub Actions, Tekton                                      | Built in, from app source repo                                                                                                                 |
| Continuous deployment   | ArgoCD or Flux watching manifest repos                               | Built-in [Git sync]({{< ref "docs/applications/overview/#automated-sync" >}})                                                                  |
| App config              | Deployment + Service + Ingress YAML, Helm charts, Kustomize overlays | A few lines of [declarative config]({{< ref "docs/applications/overview/#declarative-app-management" >}}) per app                              |
| Routing and TLS         | Ingress controller + cert-manager                                    | Built in, domain and path based routing with [automatic TLS]({{< ref "docs/configuration/networking/#enable-automatic-signed-certificate" >}}) |
| End-user authentication | oauth2-proxy or service mesh policies per app                        | [OAuth/OIDC/SAML/client certs]({{< ref "docs/configuration/authentication/" >}}) for every app                                                 |
| Access control          | Combination of Kubernetes RBAC, proxy config and app code            | [RBAC]({{< ref "docs/configuration/rbac/" >}}) grants mapping IdP groups to apps                                                               |
| Scale to zero           | Knative serving                                                      | Built in, lazy start on first request                                                                                                          |
| App catalog / portal    | Backstage or similar IDP                                             | Optional [management console]({{< ref "console-tour" >}}) and app listing; CLI, UI and declarative GitOps all supported                        |
| Docker Compose support  | Not native; convert with Kompose or rewrite as manifests             | No, apps are single container                                                                                                                  |
| Audit                   | Assembled from component logs                                        | [Audit events]({{< ref "docs/applications/audit/" >}}) built in                                                                                |
| Database access per app | Manual secrets, operators                                            | [Service bindings]({{< ref "docs/applications/servicebindings/" >}}) provisioning isolated credentials                                         |
| Version history         | Git plus cluster state across tools                                  | App versions tracked in OpenRun metadata                                                                                                       |

## Where OpenRun Differs

### One System Instead of Glue

Every integration point in a DIY stack is configuration you own: the Jenkins job that pushes an image tag, the ArgoCD app-of-apps layout, the ingress annotations, the oauth2-proxy sidecars, the Backstage catalog files. OpenRun collapses those into one config format. An app declaration names a Git repo and a framework spec; OpenRun builds the container, creates the Kubernetes resources through server-side apply, routes requests, enforces auth and records audit events.

### No YAML, No Webserver DSLs

A minimal web app on a DIY stack needs a Deployment, a Service, an Ingress, TLS annotations and usually a Helm chart wrapping them. The equivalent OpenRun app is:

```python {filename="apps.star"}
app(path="/dashboard", source="github.com/myorg/sales-dashboard",
    spec="python-streamlit")
```

Config is Starlark, a subset of Python, so shared settings like resource limits are plain variables instead of templating layers. Developers declare apps without learning Kubernetes concepts, which makes OpenRun an easy on-ramp to Kubernetes for application teams while the platform team keeps the cluster.

### GitOps for the Whole App Lifecycle

ArgoCD and Flux sync Kubernetes manifests from Git, which is true GitOps, but someone still has to write and maintain those manifests, and app-level concerns like auth and staged rollout live elsewhere. With OpenRun, the declarative config in Git covers app creation, source location, config, resource limits and bindings. A scheduled sync converges the platform to the repo, with [staged (blue-green) deployments]({{< ref "docs/applications/lifecycle/#staging-apps" >}}) for both code and config changes and atomic updates across apps.

### Authentication and RBAC as Platform Features

In a DIY stack, keeping internal apps private means per-app proxy deployments or mesh policies, and mapping IdP groups to app access is custom work. OpenRun authenticates every app against your OAuth, OIDC or SAML provider and applies [RBAC]({{< ref "docs/configuration/rbac/" >}}) grants by path or domain pattern, with changes applied dynamically. Audit logging of app access and operations comes with the platform.

## OpenRun vs Knative

Knative is the closest single component to OpenRun's runtime model, providing scale-to-zero request-driven services on Kubernetes. The differences:

- **Config**: Knative services are still YAML resources with revisions and traffic specs. OpenRun apps are a few lines of Starlark, with no YAML.
- **Builds**: Knative does not build images; you need an external build system. OpenRun builds app containers from source.
- **Resource usage**: OpenRun loads apps lazily on the first request and keeps app version history in its metadata database rather than as cluster resources, so thousands of mostly idle apps create far fewer Kubernetes objects.
- **Auth**: Knative has no end-user authentication for apps. OpenRun provides SSO and RBAC for every app.

## Where DIY Is Better

A DIY platform is the right choice when:

- You run workloads beyond single-container web apps: microservice meshes, operators, batch jobs, StatefulSets. OpenRun targets web apps and internal tools; it does not replace general Kubernetes usage and does not deploy Docker Compose style multi-container apps.
- You need fine-grained control over ingress behavior, sidecars, network policies or a service mesh.
- You already operate ArgoCD, Jenkins and friends with a platform team, and the marginal cost of another app on that stack is low.

OpenRun can also run alongside a DIY stack: use it for the long tail of internal tools and dashboards while core product services stay on the existing pipeline.

## Migration Path: Start Small, Keep the Config

OpenRun does not require Kubernetes on day one. Teams often start with OpenRun on a single server with Docker or Podman, host their internal tools there and later deploy OpenRun onto a [Kubernetes cluster]({{< ref "docs/container/kubernetes/" >}}) with the same declarative app config. The apps, auth setup and GitOps pipeline carry over unchanged.

## Frequently Asked Questions

### Does OpenRun replace ArgoCD?

For web app deployment, yes: OpenRun's scheduled Git sync provides continuous deployment from declarative config, including app creation. For general Kubernetes manifest syncing across arbitrary workloads, ArgoCD remains the right tool.

### Does OpenRun work with an existing Kubernetes cluster?

Yes. OpenRun installs via a Helm chart and creates app resources using Kubernetes server-side apply. Apps are deployed as Kubernetes services with OpenRun acting as the API server and request router.

### Do developers need to know Kubernetes to use OpenRun?

No. Developers declare apps in a few lines of config naming a Git repo and framework spec. The platform team operates the cluster; app teams never touch YAML.

### How does OpenRun handle builds on Kubernetes?

OpenRun builds app container images from the source repo as part of app deployment, so no external CI system like Jenkins is required for app builds.
