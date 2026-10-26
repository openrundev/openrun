---
title: "Configuration Quick Start"
linkTitle: "Configuration"
weight: 10
description: "Set up the OpenRun config file, app authentication with system, builtin, OAuth, OIDC or SAML login, RBAC, domains, TLS and secrets."
summary: "Config file, authentication, RBAC, domains and secrets at a glance."
---

This page covers the settings most installations change in the first week: the server config file, how users log in to apps, who is allowed to reach them, the domains apps are served on, and where secrets come from. Each section links to the full reference.

## The Config File

The server reads `$OPENRUN_HOME/openrun.toml` at startup. Every setting has a default, listed in [openrun.default.toml](https://github.com/openrundev/openrun/blob/main/internal/system/openrun.default.toml), so the file only needs the values you change. A small production file looks like

```toml {filename="openrun.toml"}
[system]
default_domain = "apps.example.com"   # apps without a domain in their path are served here

[security]
app_default_auth_type = "system"      # auth for new apps that do not set one
auth_required = true                  # refuse requests to apps with auth "none"

[https]
port = 443
service_email = "ops@example.com"     # enables Let's Encrypt certificates for app domains
use_staging = false
```

After editing the file, run `openrun server restart`. On Linux and macOS this is a zero downtime in-place restart.

Settings that change often are kept in the **dynamic config**: RBAC groups, roles and grants, named entries such as auth providers and Git credentials, and individual settings that override the static file. Dynamic config is updated without a restart through `openrun server update-config`, the `openrun user` commands or the console, and is replicated to every server instance. See [config overview]({{< ref "docs/configuration/overview" >}}).

## Authentication

Each app has an auth type. The server checks the login first and then the RBAC grants before the request reaches the app.

{{< theme-image light="/d2/quickstart_auth_light.svg" dark="/d2/quickstart_auth_dark.svg" alt="Request flow: the browser request is authenticated according to the app's auth type, with a login redirect to the identity provider for OAuth, OIDC and SAML types, then authorized against the RBAC grants, then handed to the app" >}}

| Auth type | Who can log in | Setup |
| --- | --- | --- |
| `none` | Everyone. The default for new apps | Nothing |
| `system` | The `admin` account with the password printed at first start | Nothing |
| `builtin` | Users created with `openrun user add` | Add users, no restart needed |
| `github`, `google`, `oidc_<name>`, `saml_<name>` and other provider entries | Accounts at the identity provider | An `[auth.<name>]` or `[saml.<name>]` entry in the config and a callback URL registered at the provider |
| Client certificates | Holders of a certificate signed by your CA | A `[client_auth.<name>]` entry, see [mTLS]({{< ref "docs/configuration/authentication/#client-cert-authentication-mtls" >}}) |

Set the type per app in the declaration file with `auth="system"`, on the CLI with `app create --auth system` or `app update auth --promote system /myapp`, or in the console app form. `security.app_default_auth_type` sets the type for apps that do not choose one, and `security.auth_required = true` refuses requests to any app still on `none`, which is a useful guardrail on a shared server.

### Builtin users

For small teams, or for trying RBAC with several users, builtin users need no external provider:

```shell
openrun user add alice --groups dev        # a random password is printed
openrun user add bob --prompt --groups ops # prompt for the password
openrun user list
```

Apps with `auth="builtin"` show a login page in browsers and accept HTTP Basic auth from `curl` and API clients. See [builtin users]({{< ref "docs/configuration/authentication/#builtin-users" >}}).

### OAuth, OIDC and SAML

Add a provider entry to the config. The entry name is the provider, optionally followed by `_` and a qualifier, and doubles as the app auth type:

```toml {filename="openrun.toml"}
[auth.github_prod]
key = "<client id>"
secret = "<client secret>"

[auth.oidc_okta]
key = "<client id>"
secret = "<client secret>"
discovery_url = "https://YOURDOMAIN.okta.com/.well-known/openid-configuration"
scopes = ["openid", "profile", "email", "groups"]
```

Register the callback URL `https://<server>/_openrun/auth/<entry name>/callback` at the provider, restart the server and set `auth="github_prod"` or `auth="oidc_okta"` on the apps. With OIDC the user's groups come from the provider and can be used directly in RBAC grants. Google, Microsoft Entra, Okta, Auth0, GitLab, Bitbucket and generic OIDC and SAML providers are supported. See [OAuth]({{< ref "docs/configuration/authentication/#oauth-authentication" >}}), [OIDC]({{< ref "docs/configuration/authentication/#openid-connect-oidc" >}}) and [SAML]({{< ref "docs/configuration/authentication/#saml" >}}).

{{< callout type="info" >}}
The login page is served from a dedicated auth domain, `auth.<default_domain>` by default, so app code is never on the same origin as the credential form. For production, add a DNS record for that domain pointing at the server, or use a wildcard record that covers it. See [login page]({{< ref "docs/configuration/authentication/#login-page" >}}).
{{< /callout >}}

## Authorization With RBAC

Authentication says who the user is. RBAC says what they may do: reach an app, view its details, update it, approve permissions, manage users and so on. RBAC is always on. The default dynamic config contains one grant that gives every principal the `openrun-user` role, which is `app:access` and `app:read` on all apps, so by default anyone who passes an app's login can use it.

To restrict access, edit the `rbac` section of the dynamic config. This example lets the `finance` group reach one app and gives the `platform` group the builtin operator role on everything:

```json
{
  "rbac": {
    "groups": {
      "finance": ["oidc_okta:alice@example.com", "group:finance-analysts"],
      "platform": ["github_prod:bob"]
    },
    "grants": [
      {
        "users": ["group:finance"],
        "roles": ["openrun-user"],
        "targets": ["apps.example.com:/reports"]
      },
      {
        "users": ["group:platform"],
        "roles": ["openrun-operator"],
        "targets": ["all"]
      }
    ]
  }
}
```

Remove the default grant once your own grants are in place. Builtin roles cover the common cases: `openrun-user`, `openrun-developer`, `openrun-operator`, `openrun-monitor`, `openrun-builder` and `openrun-admin`. Grants can also be edited in the console. See [RBAC]({{< ref "docs/configuration/rbac" >}}) and the [team RBAC walkthrough]({{< ref "docs/use-cases/apprbac" >}}).

## Domains and TLS

Every app has a `domain:path` address. Entries without a domain use `system.default_domain`, which is `localhost` out of the box. With a wildcard DNS record such as `*.example.com` pointing at the server, apps can be placed on their own subdomains without further DNS changes, for example `app("reports.example.com:/", ...)`. Requests for unknown hostnames return 404. See [app routing]({{< ref "docs/applications/routing" >}}).

For local development, OpenRun creates certificates with mkcert for `localhost`, `*.localhost` and other local domains. For production, setting `https.service_email` turns on certmagic, which issues and renews Let's Encrypt certificates for every served domain. Test with `use_staging = true` first to stay within the Let's Encrypt rate limits. Running behind an existing reverse proxy is also supported. See [networking]({{< ref "docs/configuration/networking" >}}).

## Secrets

Secrets never need to be written into declaration files or app params. Configure a provider once and reference the secret by name:

```toml {filename="openrun.toml"}
[secret.vault_prod]
address = "https://vault.example.com"
token = "..."
```

```python {filename="apps.ace"}
app("/reports", "github.com/myorg/reports",
    params={"API_KEY": '{{secret_from "vault_prod" "reports/api_key"}}'})
```

HashiCorp Vault, AWS Secrets Manager, AWS Parameter Store, Kubernetes secrets, the server environment and a properties file are supported. Service bindings store database credentials in the secret store automatically. See [secrets]({{< ref "docs/configuration/secrets" >}}).

## Managing Config From the Console

The console edits the dynamic config with a form per section, staged versions and a history to roll back to. Auth providers, Git credentials, secrets providers and RBAC can all be managed there once the console is installed. See the [console tour]({{< ref "/console-tour/#operate" >}}).

## Next Steps

{{< cards >}}
{{< card link="../managing-apps" title="Managing Apps" subtitle="Declaration file, staging and promotion, GitOps sync, CLI and console" icon="collection" >}}
{{< card link="../../configuration/security" title="Security Settings" subtitle="Admin password, plugin permissions, host commands, CSRF, headers and private repos" icon="shield-check" >}}
{{< card link="../../configuration/remoteaccess" title="Remote Access" subtitle="Manage a server from another machine over the REST API or MCP" icon="globe" >}}
{{< /cards >}}
