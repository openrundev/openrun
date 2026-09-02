---
title: "Configuration"
weight: 200
summary: "Configuration options for the OpenRun server and client."
---

Most configuration options specified in the following sections are for the OpenRun server. The OpenRun client CLI, which talks with the OpenRun server using unix domain sockets, uses a small subset of the config properties. If the OpenRun client runs on the same machine as the server, then the same config file can be used for both. See [Remote API and MCP]({{< ref "remoteaccess" >}}) for managing a remote server.

For complete configuration examples, see [use-cases]({{< ref "docs/use-cases/" >}}), which documents the complete setup for a few scenarios.

{{< cards >}}
{{< card link="overview" title="Overview" subtitle="Understand server configuration files, environment overrides, OPENRUN_HOME and deployment settings" icon="information-circle" >}}
{{< card link="networking" title="Ports and Certificates" subtitle="Configure ports, domains, automatic TLS certificates, authorities and application networking" icon="adjustments" >}}
{{< card link="security" title="Security" subtitle="Secure administrator accounts, API access, source repositories and sensitive server operations" icon="shield-check" >}}
{{< card link="remoteaccess" title="Remote API and MCP" subtitle="Enable remote CLI and MCP access with API keys, browser login, scoped credentials and audited operations" icon="globe-alt" >}}
{{< card link="authentication" title="App authentication" subtitle="Protect applications with administrator, OAuth, OpenID Connect, SAML and client-certificate authentication" icon="badge-check" >}}
{{< card link="rbac" title="RBAC" subtitle="Define resource-scoped role-based permissions for users, teams, applications, services and operations" icon="view-list" >}}
{{< card link="secrets" title="Secrets Management" subtitle="Manage secrets through AWS Secrets Manager, Vault, environment variables and properties files" icon="lock-closed" >}}
{{< card link="telemetry" title="Telemetry" subtitle="Export application, container, database and server telemetry through OpenTelemetry OTLP endpoints" icon="chart-bar" >}}
{{< /cards >}}
