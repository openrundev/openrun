---
title: "Cloud Run vs AWS App Runner: AWS Equivalent, Pricing and Self-Hosted Alternative"
linkTitle: "vs Cloud Run, App Runner"
weight: 200
date: 2026-08-10
lastmod: 2026-11-10
description: "What is the AWS equivalent of Google Cloud Run? Compare Cloud Run, App Runner, ECS Express Mode, Fargate and Lambda on pricing and scale-to-zero, and see the self-hosted OpenRun alternative."
summary: "Cloud Run vs App Runner, the AWS equivalents of Cloud Run, pricing, and OpenRun as a self-hosted alternative."
---

Google Cloud Run and AWS App Runner are managed serverless container platforms. You hand them a container image or a repo, and they run it with automatic scaling, HTTPS and usage-based pricing. Cloud Run scales services down to zero when idle. App Runner does not: its autoscaling retains at least one provisioned instance whose memory is billed, and reducing compute to zero requires [manually pausing](https://docs.aws.amazon.com/apprunner/latest/dg/manage-pause.html) the service, which makes it unavailable.

**What is the AWS equivalent of Cloud Run?** App Runner was the closest AWS equivalent of Google Cloud Run, but it is now in maintenance mode and closed to new customers. AWS recommends [Amazon ECS Express Mode](https://docs.aws.amazon.com/apprunner/latest/dg/apprunner-availability-change.html) for new container web services. For request-driven scale-to-zero on AWS, AWS Lambda with container images is the closest match. See [AWS equivalents of Cloud Run](#what-is-the-aws-equivalent-of-google-cloud-run) below.

{{< callout type="info" >}}
AWS [announced on March 31, 2026](https://docs.aws.amazon.com/general/latest/gr/maintenance_services.html) that App Runner is in maintenance and [no longer open to new customers](https://docs.aws.amazon.com/apprunner/latest/dg/apprunner-availability-change.html). Existing customers can keep running and creating services, but no new features are planned. AWS points migrating customers to Amazon ECS Express Mode. The comparison here covers existing deployments and teams evaluating a replacement.
{{< /callout >}}

OpenRun brings the serverless container deployment model to infrastructure you control. Apps run in containers, scale to zero when idle and start lazily on the first request, but they run on your own server, node or Kubernetes cluster. For internal tools, this changes the economics and simplifies keeping apps private.

**Summary**: Choose Cloud Run for public-facing services that need elastic scaling on a team committed to Google Cloud. Choose OpenRun for internal tools and team web apps, for deployments on a private network, for flat infrastructure cost and for avoiding vendor lock-in. Teams migrating off App Runner get a comparable developer experience with OpenRun on their own infrastructure.

## Feature Comparison

| Capability | OpenRun | Google Cloud Run | AWS App Runner |
| --- | --- | --- | --- |
| Availability | Open source, self-hosted | Generally available | Maintenance mode, closed to new customers (announced March 31, 2026) |
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
| Database provisioning for apps | Service bindings to Postgres/MySQL/Redis, managed SQLite + Litestream | Separate Cloud SQL setup | Separate RDS setup |
| Audit logs | Built in, app operations and API calls | Cloud Audit Logs | CloudTrail |
| Vendor lock-in | Low: Apache-2.0 open source, runs on any infrastructure; app declarations use OpenRun's Starlark config format | Google Cloud | AWS |

Comparison last verified on November 10, 2026 against the [Cloud Run documentation](https://cloud.google.com/run/docs), [Cloud Run pricing](https://cloud.google.com/run/pricing), [Cloud Run IAP documentation](https://docs.cloud.google.com/run/docs/securing/identity-aware-proxy-cloud-run), [App Runner pricing](https://aws.amazon.com/apprunner/pricing/), [App Runner pause behavior](https://docs.aws.amazon.com/apprunner/latest/dg/manage-pause.html) and the [App Runner availability change](https://docs.aws.amazon.com/apprunner/latest/dg/apprunner-availability-change.html).

## What Is the AWS Equivalent of Google Cloud Run?

AWS has no single service that matches Cloud Run feature for feature. The options, from closest to furthest:

| AWS service | How it compares to Cloud Run | Scale to zero |
| --- | --- | --- |
| AWS App Runner | Closest match: deploy from an image or repo, HTTPS and autoscaling included. In maintenance mode and closed to new customers | No, one provisioned instance stays billed |
| Amazon ECS Express Mode | AWS's recommended App Runner replacement. Creates an ECS service on Fargate with a load balancer, HTTPS and autoscaling from a container image, with no extra charge beyond the underlying resources | No request-driven scale to zero |
| Amazon ECS on AWS Fargate | Serverless containers without managing servers, but you configure the load balancer, networking and scaling yourself | No request-driven scale to zero |
| AWS Lambda (container images) | Runs container images and scales to zero, billed per request and duration. Functions have a 15-minute execution limit and use the Lambda runtime interface instead of a plain HTTP server | Yes |
| AWS Elastic Beanstalk | The AWS equivalent of Google App Engine rather than Cloud Run: managed environments on EC2 instances | No |

If the goal is Cloud Run's model, containers that start on demand and cost nothing when idle, without committing to one cloud, OpenRun provides it on your own servers or Kubernetes cluster on any provider, including AWS EC2 or EKS.

## Cloud Run vs App Runner Pricing

| | Google Cloud Run | AWS App Runner | OpenRun |
| --- | --- | --- | --- |
| Compute | Per vCPU-second; with request-based billing, charged only while handling requests | $0.064 per vCPU-hour while active (US East) | No charge; you pay for your own server or cluster |
| Memory | Per GiB-second | $0.007 per GB-hour; the provisioned instance's memory is billed even while idle (US East) | No charge |
| Requests | Per million requests beyond the free tier | Not billed per request | No charge |
| Idle cost | Zero when scaled to zero | At least one instance's memory | Fixed cost of your infrastructure |
| Other fees | Build (Cloud Build) and networking charges | Monthly fee per app for automatic deployments, plus a build fee for source-based deploys | None |
| Free tier | Monthly free allowance of vCPU-seconds, GiB-seconds and 2 million requests | No App Runner free tier | Free, open source |

For a single always-busy service, the managed platforms are cost-effective. For a catalog of internal tools that are idle most of the day, per-service charges add up, and a single server running OpenRun usually costs less than a few always-on App Runner services. Check the [Cloud Run pricing](https://cloud.google.com/run/pricing) and [App Runner pricing](https://aws.amazon.com/apprunner/pricing/) pages for your region; rates differ by region and billing mode.

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

### What is the AWS equivalent of Google Cloud Run?

AWS App Runner was the closest equivalent, but it is closed to new customers. AWS recommends Amazon ECS Express Mode for new container web services. ECS on Fargate runs serverless containers with more manual setup, and AWS Lambda with container images is the AWS option that scales to zero per request. Google App Engine's AWS equivalent is Elastic Beanstalk.

### Is OpenRun an alternative to AWS App Runner?

Yes. Since AWS closed App Runner to new customers, teams that wanted the App Runner model need an alternative. OpenRun provides source-to-running-container deployment with automatic HTTPS on infrastructure you control, and unlike App Runner it scales idle apps fully to zero. Unlike ECS Express Mode, it also adds SSO, RBAC and GitOps management for every app.

### How much does AWS App Runner cost?

In US East, App Runner charges $0.064 per vCPU-hour and $0.007 per GB-hour while instances are active. While idle, it still bills the memory of at least one provisioned instance at $0.007 per GB-hour. Automatic deployments add a monthly fee per app, and source-based deploys add a build fee. App Runner has no free tier.

### Is Cloud Run cheaper than App Runner?

For services that are idle part of the day, usually yes. With request-based billing, Cloud Run charges only while handling requests and scales to zero, and it has a monthly free tier. App Runner keeps at least one instance's memory billed at all times.

### What is the difference between AWS App Runner and Lambda?

App Runner runs a long-lived web server container and keeps at least one instance provisioned. Lambda runs functions, including container images, per request, scales to zero and has a 15-minute execution limit. Web frameworks run on Lambda through an adapter, while App Runner and Cloud Run run them as-is.

### Can I run a SQLite app on Cloud Run?

Cloud Run's local filesystem is in memory and lost when an instance stops, and SQLite is not safe on network file systems, so persistent SQLite needs extra work on Cloud Run. OpenRun gives each SQLite app a persistent volume plus continuous [Litestream replication to S3]({{< ref "docs/applications/litestream" >}}) with automatic restore.

### Can OpenRun scale out like Cloud Run?

On a single node, OpenRun scales apps down to zero but runs on one machine. For horizontal scale, deploy OpenRun on [Kubernetes]({{< ref "docs/container/kubernetes/" >}}), where apps run as Kubernetes services.

### How do cold starts work in OpenRun?

An idle app's container is stopped (on Kubernetes, the deployment is scaled to zero). The first request to the app starts the container and the request is served once the app is ready. Subsequent requests hit the running container. Idle timeout behavior is [configurable per app]({{< ref "docs/container/config/" >}}).

### What does OpenRun cost?

OpenRun is free, Apache-2.0 licensed open source. The only cost is the infrastructure it runs on, such as a single server for a typical internal tools setup.
