---
title: "Internal Tools for Teams"
weight: 200
summary: "Deploying apps for use by teams across an enterprise"
---

## Scenario

This use-case documents the scenario where you want to:

- Set up an instance to host web apps for use by your team in an enterprise
- The instance is behind a VPN, there is no inbound access over the public Internet
- Uses OIDC (or SAML) to manage access to the various apps
- Set up an automated GitOps workflow for app updates and new app creation

For this use case, we will use a GitHub account for source control.

## Initial Setup

To get OpenRun running, the initial setup involves:

- Create a Linux machine, accessible by your team through the VPN on port 443.
- Create a DNS entry pointing to the machine's IP address, for example an `A` record for `apps.example.com`. A wildcard DNS entry `*.apps.example.com` will make it easier to install apps at the domain level.
- Create a [OIDC]({{< ref "docs/configuration/authentication/#openid-connect-oidc" >}}) app in the IdP console. Set up `groups` scope such that [group info]({{< ref "docs/configuration/rbac/#group-info" >}}) is available. Note the client ID and secret. The callback URL would be `https://apps.example.com/_openrun/auth/oidc/callback`. Note the client ID and secret.
- Create a GitHub Personal Access Token in [GitHub settings](https://github.com/settings/personal-access-tokens). Set the scope to the repositories you want to use for your apps. Note the token. SSH key based auth is an alternative.

## Installation

Assuming a systemd based Linux system, to install OpenRun and start the service, run

```sh
curl -sSL https://raw.githubusercontent.com/openrundev/openrun/refs/heads/main/deploy/setup_systemd.sh | sudo sh
```

This will create a user `openrun` and install the service under `/var/lib/openrun`.

To run [containerized apps]({{< ref "docs/container/overview/" >}}), ensure that Docker or Podman is installed and running on the machine. For Docker, the `openrun` user should be added to the docker group. As `openrun` user, run `docker ps` or `podman ps` to verify that the container manager is functional.

## Configuration

Change to the `openrun` account by running `sudo su -l openrun`. Edit the openrun [config]({{< ref "/docs/configuration/overview/" >}}) `/var/lib/openrun/openrun.toml`. Update it to have below contents (replace values which say `CHANGEME`):

```toml {filename="/var/lib/openrun/openrun.toml"}
[security]
admin_password_bcrypt = "$2a$10$L5dzoAEZFKmpdXbbbFddkurIP639w2.fl49737kmxxxxxxxx" # CHANGEME Retain orig value
callback_url = "https://apps.example.com" # CHANGEME: OAuth/OIDC/SAML callback URL prefix
app_default_auth_type = "rbac:oidc_okta" # Default auth for all apps, with rbac
default_git_auth = "githubpat" # Account used for all GitHub access

[system]
default_domain="apps.example.com" # CHANGEME: domain without protocol

[http]
host = "0.0.0.0"
port = 80
redirect_to_https = true

[https]
port = 443
# auto-TLS is not enabled since the node is not accessible over the public internet

[git_auth.githubpat]
user_id = "mygithubaccount" # CHANGEME
password = "github_pat_11A7FEN7Q0XPbzMWp2LxrF_emLLexxxxxxxxxxxx" # CHANGEME

[auth.oidc_okta]
key = "0oavknst5tcxxxxxx" # CHANGEME client ID
secret = "nBTsFRY9BUZ5aAQsbmHtbvkIAx_OnUyxoExxxxxxx" # CHANGEME client secret
discovery_url = "https://integrator-33xxxxx-admin.okta.com/.well-known/openid-configuration" # CHANGEME
scopes = ["openid", "profile", "email", "groups"]
```

This sets the default ports to 80 and 443, sets the apps to use OIDC for auth and sets the GitHub PAT. As the regular user (since `openrun` user might not have sudo access), run `sudo systemctl restart openrun` to pick up the config update. The `admin_password_bcrypt` is not used in this scenario, it can be kept at its original value or changed.

## TLS Certificates

OpenRun can automatically create [TLS certs]({{< ref "docs/configuration/networking/#enable-automatic-signed-certificate" >}}) when an app is created for a domain. That requires the node to be accessible over the public internet, since only the [TLS-ALPN](https://github.com/caddyserver/certmagic#tls-alpn-challenge) based cert is currently supported.

In this scenario, since the node is behind a VPN, TLS certs will have to be [managed manually]({{< ref "docs/configuration/networking/#tls-certificates" >}}). Create the cert files and place them in `/var/lib/openrun/config/certificates`. Files with the name `default.crt` and `default.key` are used as the default certificate file and key file for all domains. If a file is found with the name `example.com.pem` and `example.com.key`, that is used as the cert for the `example.com` domain.

## RBAC Config

At this point, all apps are authenticated by OIDC, but every logged-in user can access all apps. To restrict which user has access to which apps, [RBAC]({{< ref "docs/configuration/rbac/" >}}) can be used. RBAC uses the [dynamic config]({{< ref "docs/configuration/overview/#dynamic-config" >}}), which does not require restarting the OpenRun server. We will set up a RBAC schema where:

- Apps under /it will be available to the IT team
- Apps under /engg will be available to the engineering team
- Apps under /shared will be available to everyone
- All other apps will be available only to the admin.

To set the RBAC config, change to the `openrun` account by running `sudo su -l openrun`. Edit `/var/lib/openrun/config/dynamic_config.json` to have:

```json {filename="/var/lib/openrun/config/dynamic_config.json"}
{
  "version_id": "ver_33erDLffhaXjgibPb5GRb3anN0V",
  "rbac": {
    "enabled": true,
    "roles": {
      "viewer": ["list", "access"],
      "user": ["access"]
    },
    "grants": [
      {
        "description": "Admin has full access to all apps",
        "users": ["group:admin"],
        "roles": ["viewer"],
        "targets": ["*:**"]
      },
      {
        "description": "IT team has access to apps under /it",
        "users": ["group:it"],
        "roles": ["viewer"],
        "targets": ["/it/**"]
      },
      {
        "description": "Engineering team has access to apps under /engg",
        "users": ["group:engineering"],
        "roles": ["viewer"],
        "targets": ["/engg/**"]
      }
    ]
  }
}
```

Group info is not defined in the config, it will come from the IdP. To update the RBAC config, run

```sh
openrun server update-config /var/lib/openrun/config/dynamic_config.json
```

This will upload the RBAC config to the metadata server (and also update the file on disk). Use the current `version_id`, or use the `--force` option to overwrite. The server is now ready for installing apps.

## SAML instead of OIDC

If [SAML]({{< ref "docs/configuration/authentication/#saml" >}}) needs to be used instead of OIDC, much of the setup remains the same. Create the SAML app in the IdP. The Single sign-on URL should be set to `https://apps.example.com:25223/_openrun/sso/saml_okta_test/acs` and the Audience URI (SP Entity ID) should be set to `https://apps.example.com:25223/_openrun/sso/saml_okta_test/metadata`.

In the `openrun.toml`, instead of the `[auth.oidc_okta]` section, add a section like

```toml {filename="/var/lib/openrun/openrun.toml"}
[saml.okta_test]
metadata_url = "https://integrator-336XXXXX.okta.com/app/exkvzxe13XXXXX/sso/saml/metadata" # CHANGEME
```

and for `app_default_auth_type`, set the value to `rbac:saml_okta_test`. The IdP has to be configures to provide the group information under the `groups` attribute.

For both OIDC and SAML, in addition to the group info coming from the IdP, additional groups can be defined in the OpenRun RBAC config. The user names would have to be provided in the RBAC config, prefixed with the provider name, like `oidc_okta:user1@example.com` or `saml_okta_test:user1@example.com`.

## App Installation

OpenRun supports installing apps using the imperative [CLI interface]({{< ref "docs/applications/overview/#app-management" >}}) or using the [declarative]({{< ref "docs/applications/overview/#declarative-app-management" >}}) config files. We will use the declarative approach here.

In one of the GitHub repos which is accessible using the PAT created above, create a app config file like

```python {filename="apps.star"}
# Admin apps
app("/admin/disk_usage", "github.com/openrundev/apps/system/disk_usage")
app("/admin/memory_usage", "github.com/openrundev/apps/system/memory_usage")
app("/admin/audit", "github.com/openrundev/apps/openrun/audit_viewer")

# IT apps
app("/it/bookmarks", "github.com/openrundev/apps/utils/bookmarks")
app("/it/contacts", "github.com/openrundev/apps/utils/contacts")

# Engineering apps
# Install container based apps (python and go)
limits = {"cpus": "2", "memory": "512m"} # Set limits (optional)
app("/engg/streamlit_example", "github.com/streamlit/streamlit-example", git_branch="master",
    spec="python-streamlit", container_opts=limits)

# shared apps, use auth=oidc_okta instead of default rbac:oidc_okta, so accessible to all logged in users
app("/shared/dictionary", "github.com/openrundev/apps/misc/dictionary", auth="oidc_okta")
```

If this file is checked into the main branch in the `myorg/myrepo` repo, then running a command like

```sh
openrun sync schedule --minutes 1 --approve --promote github.com/myorg/myrepo/apps.star
```

will set up a [sync]({{< ref "docs/applications/overview/#automated-sync" >}}) which checks every minute for new updates to the file. Apps in /shared have `auth="oidc"`, instead of the default `auth="rbac:oidc_okta"`, so anyone can access the app after OIDC login. If `auth="none"` is used, then no auth is required to access the app.

Any new apps declared will be automatically created. Any code changes in the repos referenced or config changes in the apps will also automatically be applied on the existing apps. No further manual updates are required on the machine. All updates can be done by just checking in changes into the declarative config - **Full GitOps CI/CD, in one command.**
