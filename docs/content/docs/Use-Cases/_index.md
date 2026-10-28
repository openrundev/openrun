---
title: "Self-Hosted Web App and Internal Tool Use Cases"
linkTitle: "Use Cases"
weight: 250
description: "Guides for running OpenRun as a self-hosted web app platform: personal apps on a VPS, internal team tools, app RBAC, SQLite hosting and ops tools."
summary: "Self-hosted deployment guides for VPS installations, personal web apps, secure internal team platforms and ops tools for AI agents."
---

Complete guides for configuring OpenRun as a self-hosted web app platform on your own VPS, server or private infrastructure, and for replacing Jenkins or Rundeck jobs with GitOps-deployed ops tools. For how different roles use OpenRun, see [Who It's For]({{< ref "solutions" >}}); for how it compares with other platforms, see the [comparisons]({{< ref "compare" >}}).

{{< cards >}}
{{< card link="personal" title="Self-Hosted Web Apps on a VPS" subtitle="Deploy personal web apps on a Linux VPS with GitOps and automatic TLS" icon="sparkles">}}
{{< card link="team" title="Self-Hosted Internal Tools" subtitle="Deploy team applications with SSO, RBAC, auditing and private infrastructure controls" icon="shield-check">}}
{{< card link="apprbac" title="Self-Hosted RBAC for Web Apps" subtitle="Enable RBAC for apps, with custom permissions passed to apps through HTTP headers" icon="lock-closed">}}
{{< card link="sqliteapps" title="SQLite Web App Hosting" subtitle="Deploy SQLite apps with persistent volumes, staged updates and automatic S3 backups" icon="database_plain">}}
{{< card link="jenkins-rundeck-alternative" title="Jenkins and Rundeck Alternative for Ops Tools" subtitle="Ops tools as actions kept in git: a web form, a CLI command and an MCP tool for AI agents, with RBAC, confirmation and audit" icon="terminal">}}
{{< /cards >}}
