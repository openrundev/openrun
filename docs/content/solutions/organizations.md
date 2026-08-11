---
title: "OpenRun for Organizations"
weight: 300
description: "Self-host authentication, authorization, auditing and deployment for internal web apps. Keep code and data on your own infrastructure with SSO, RBAC and audit logs built in."
summary: "Self-host authentication, authorization, auditing and deployment."
---

OpenRun lets organizations self-host authentication, authorization, auditing and deployment for their web apps. Application code, user data and access logs stay on infrastructure your organization controls: a single server, a node behind your VPN or your own Kubernetes cluster. There is no proprietary deployment service in the path, and the platform is Apache-2.0 licensed open source.

## SSO for Every App, Without the SSO Tax

Many tools charge enterprise pricing for SAML support, and most deployment platforms authenticate only their own admin console. OpenRun makes [OAuth, OpenID Connect, SAML and client certificate authentication]({{< ref "docs/configuration/authentication/" >}}) available to every deployed app, not just the management interface. Configure the identity provider once at the server level; every app gets login, session handling and group information with no code changes.

Setting `auth_required = true` at the server level ensures no app can be served without authentication, even if an app is declared with auth disabled.

## Authorization With RBAC

[Role-based access control]({{< ref "docs/configuration/rbac/" >}}) determines who can access and manage which apps. Grants map users and IdP groups to roles, targeted at apps by path or domain patterns. Typical setups give each department access to its own apps, shared apps to all employees and admin apps to operators only. RBAC config changes apply dynamically, without a server restart, and the config itself can be managed through Git like everything else.

## Auditing Built In

[Audit events]({{< ref "docs/applications/audit/" >}}) are captured automatically for app operations and API calls, with support for custom business events. Audit data is searchable and stays in your own database. Combined with declarative GitOps management, this gives a reviewable trail for both who changed the platform (Git history) and who used the apps (audit events).

## Deployment on Your Infrastructure

- Runs on a Linux, macOS or Windows server as a single binary, with Docker or Podman for app containers
- Runs fully behind a VPN with no inbound Internet access, as described in the [team use case]({{< ref "docs/use-cases/team/" >}})
- Scales to a [Kubernetes cluster]({{< ref "docs/container/kubernetes/" >}}) using the same declarative config
- Secrets come from [AWS Secrets Manager, HashiCorp Vault or other providers]({{< ref "docs/configuration/secrets/" >}}), not from plain-text config
- App data can use [service bindings]({{< ref "docs/applications/servicebindings/" >}}) to databases your teams already operate, or [SQLite with Litestream replication]({{< ref "docs/applications/litestream/" >}}) to S3-compatible storage you control

## Moving on from Low-Code Platforms

Enterprise low-code platforms like Retool bundle hosting, authentication and access control, which is a large part of why teams pay for them. The other part was UI building: hand-writing an internal tool used to take longer than assembling one in a low-code editor. AI code generation changes that. An AI assistant can generate a complete Streamlit, Gradio or Hypermedia based app from a prompt, and the result is regular code that any developer or AI tool can read, review and extend, instead of an app definition locked inside a proprietary editor.

What code-first apps were missing is the platform around them, and that is what OpenRun provides: SSO, RBAC, audit logs, TLS and GitOps deployment for every app. AI-generated apps live in Git like any other code, so the same pull request review and OpenRun sync pipeline deploys them, and future AI-assisted changes flow through the same path. The [management console]({{< ref "console-tour" >}}) also includes an AI app builder for generating and publishing apps directly.

The benefits of moving from Retool to this model:

- No per-seat pricing; costs do not grow with the number of builders or viewers
- Apps are portable code in your Git repos, not definitions tied to a vendor platform
- App code and business data stay on your infrastructure instead of a vendor cloud
- Any framework and any AI coding tool can be used, now and as tools change

## Cost Model

OpenRun is free and open source. The main cost is the infrastructure it runs on, and [scale-to-zero]({{< ref "docs/container/config/" >}}) keeps that small: idle apps consume no resources, so a single server can host a large catalog of internal tools. Compare this with per-request pricing on managed platforms in [OpenRun vs Google Cloud Run and AWS App Runner]({{< ref "compare/cloud-run-app-runner" >}}), or see [all comparisons]({{< ref "compare" >}}).
