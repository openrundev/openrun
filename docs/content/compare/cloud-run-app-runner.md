---
title: "OpenRun vs Google Cloud Run and AWS App Runner"
weight: 200
date: 2026-08-10
description: "Compare OpenRun with Google Cloud Run and AWS App Runner: self-hosted scale-to-zero containers with GitOps, SSO and RBAC on your own servers or Kubernetes cluster instead of per-request cloud pricing."
summary: "OpenRun compared with managed serverless container platforms from Google and AWS."
---

Google Cloud Run and AWS App Runner are managed serverless container platforms. You hand them a container image or a repo, and they run it with automatic scaling, HTTPS and usage-based pricing. Cloud Run scales services down to zero when idle. App Runner does not: its autoscaling retains at least one provisioned instance whose memory is billed, and reducing compute to zero requires [manually pausing](https://docs.aws.amazon.com/apprunner/latest/dg/manage-pause.html) the service, which makes it unavailable.

{{< callout type="info" >}}
AWS [stopped accepting new App Runner customers](https://docs.aws.amazon.com/general/latest/gr/maintenance_services.html) on March 31, 2026. Existing services continue to run; the comparison here applies to existing deployments and to teams evaluating a replacement.
{{< /callout >}}

OpenRun brings the serverless container deployment model to infrastructure you control. Apps run in containers, scale to zero when idle and start lazily on the first request, but they run on your own server, node or Kubernetes cluster. For internal tools, this changes the economics and simplifies keeping apps private.

**Summary**: Choose Cloud Run for public-facing services that need elastic scaling on a team committed to Google Cloud. Choose OpenRun for internal tools and team web apps, for deployments on a private network, for flat infrastructure cost and for avoiding vendor lock-in. Teams migrating off App Runner get a comparable developer experience with OpenRun on their own infrastructure.

## Feature Comparison

| Capability | OpenRun | Google Cloud Run | AWS App Runner |
| --- | --- | --- | --- |
| Availability | Open source, self-hosted | Generally available | Closed to new customers since March 31, 2026 |
| Hosting | Self-hosted: single server, node or your Kubernetes cluster | Google managed | AWS managed |
| Pricing | Free, open source; you pay for your infrastructure | Per vCPU-second, memory and requests | Per vCPU and memory; at least one instance's memory always billed while running |
| Scale to zero | Yes, idle containers stopped | Yes | No; manual pause makes the service unavailable |
| Scale out under load | Via Kubernetes deployment | Yes, automatic | Yes, automatic |
| End-user authentication for apps | Built in: OAuth, OIDC, SAML, client certs for every app | IAP can be enabled on a service; per-service setup, Google identities | No built-in end-user auth |
| RBAC for app access | Built in, per app path/domain grants | Via IAM and IAP policies | Via fronting infrastructure |
| App management through Git | Yes, declarative config, apps created and configured via Git sync | Partial: YAML service specs; continuous deployment via Cloud Build triggers | Partial: source-based deploys from a repo |
| Management interface | CLI, optional [web console]({{< ref "console-tour" >}}) and declarative GitOps | Cloud console, gcloud CLI | AWS console, AWS CLI |
| Docker Compose support | No (sidecar containers supported) | No (sidecar containers supported) | No |
| Staged deployment | Yes, staging app per app with promote step | Revisions with traffic splitting | Deployments replace the service |
| Run on a private network behind a VPN | Yes | No, runs in Google Cloud (private ingress available) | No |
| Custom domains with automatic TLS | Yes | Yes | Yes |
| Database provisioning for apps | Service bindings to Postgres/MySQL, managed SQLite + Litestream | Separate Cloud SQL setup | Separate RDS setup |
| Audit logs | Built in, app operations and API calls | Cloud Audit Logs | CloudTrail |
| Vendor lock-in | Low: Apache-2.0 open source, runs on any infrastructure; app declarations use OpenRun's Starlark config format | Google Cloud | AWS |

Comparison last verified on August 10, 2026 against the [Cloud Run documentation](https://cloud.google.com/run/docs), [Cloud Run IAP documentation](https://docs.cloud.google.com/run/docs/securing/identity-aware-proxy-cloud-run), [App Runner pricing](https://aws.amazon.com/apprunner/pricing/) and [App Runner pause behavior](https://docs.aws.amazon.com/apprunner/latest/dg/manage-pause.html).

## Where OpenRun Differs

### Self-Hosted Scale-to-Zero

The appeal of serverless containers is not paying for idle services. OpenRun delivers that property on hardware you already pay for: idle app containers are [stopped automatically]({{< ref "docs/container/config/" >}}) and restarted lazily on the next request. A single server can host hundreds of internal tools, with a flat monthly cost instead of per-request billing. OpenRun itself adds no per-request or per-service charges; the total cost is whatever your server or cluster costs, including any bandwidth charges from your provider.

### One Authentication Setup for All Apps

Internal tools must not be publicly accessible. Cloud Run supports enabling [Identity-Aware Proxy directly on a service](https://docs.cloud.google.com/run/docs/securing/identity-aware-proxy-cloud-run), which covers Google-managed identities on a per-service basis. App Runner has no built-in end-user authentication, so teams put a load balancer, Cognito or custom middleware in front. With OpenRun, [OAuth, OIDC, SAML or client certificate auth]({{< ref "docs/configuration/authentication/" >}}) is configured once at the server level and applies to every app, including SAML IdPs, with [RBAC]({{< ref "docs/configuration/rbac/" >}}) mapping IdP groups to app access across the whole catalog and [audit events]({{< ref "docs/applications/audit/" >}}) recording activity.

### True GitOps Management

Cloud Run and App Runner can build and deploy when code changes, but creating services and changing their settings is done through the cloud console, CLI commands or separate infrastructure-as-code tooling. With OpenRun, [apps are declared in a config file in Git]({{< ref "docs/applications/overview/#declarative-app-management" >}}); a scheduled sync creates new apps, applies config changes and deploys code updates. The whole platform state is reviewable in one repo, with staged deployments and atomic updates across apps.

### Data Stays on Your Infrastructure

Internal tools often touch sensitive business data. With OpenRun, app containers, the metadata database, audit logs and app data all live on servers your organization controls. OpenRun runs on a private network behind a VPN with no inbound Internet access, a setup described in the [team use case guide]({{< ref "docs/use-cases/team/" >}}). Note that installation and container builds download packages and images from the Internet by default; a fully air-gapped setup requires local mirrors and registries.

## Where Cloud Run Is Better

- **Elastic scale**: Cloud Run scales a hot service to many instances automatically. OpenRun on a single node is bound by that machine; scaling out means running OpenRun on [Kubernetes]({{< ref "docs/container/kubernetes/" >}}).
- **Zero infrastructure**: there is no server to patch or monitor. OpenRun requires a machine you operate, even if the operation is minimal (single binary, single SQLite metadata file).
- **Cloud integration**: tight IAM integration with other managed services (queues, databases, storage) in the same cloud.

For public, spiky, customer-facing workloads on a team already invested in GCP, Cloud Run is a good fit. For a catalog of internal tools, dashboards and automation apps, self-hosting with OpenRun is usually simpler and cheaper.

## Frequently Asked Questions

### Is OpenRun a self-hosted alternative to Google Cloud Run?

Yes. OpenRun provides the core Cloud Run experience, deploying containers that scale to zero and start on demand, on your own server, node or Kubernetes cluster, with GitOps management and built-in SSO and RBAC.

### Is OpenRun an alternative to AWS App Runner?

Yes, and since AWS closed App Runner to new customers on March 31, 2026, teams that wanted the App Runner model need an alternative. OpenRun provides source-to-running-container deployment with automatic HTTPS on infrastructure you control, and unlike App Runner it scales idle apps fully to zero.

### Can OpenRun scale out like Cloud Run?

On a single node, OpenRun scales apps down to zero but runs on one machine. For horizontal scale, deploy OpenRun on [Kubernetes]({{< ref "docs/container/kubernetes/" >}}), where apps run as Kubernetes services.

### How do cold starts work in OpenRun?

An idle app's container is stopped (on Kubernetes, the deployment is scaled to zero). The first request to the app starts the container and the request is served once the app is ready. Subsequent requests hit the running container. Idle timeout behavior is [configurable per app]({{< ref "docs/container/config/" >}}).

### What does OpenRun cost?

OpenRun is free, Apache-2.0 licensed open source. The only cost is the infrastructure it runs on, such as a single server for a typical internal tools setup.
