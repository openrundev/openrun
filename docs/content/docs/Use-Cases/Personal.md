---
title: "Family and Friends"
weight: 100
summary: "Deploying apps for personal use and for sharing with family and friends"
---

## Scenario

This use-case documents the scenario where you want to:

- Set up an instance on the public internet to host web apps for use by yourself and for family and friends
- Use an OAuth provider like Google for login
- Set up an automated GitOps workflow for app updates and new app creation

For this use case, we will use a Google OAuth account for authentication and a GitHub account for source control.

## Initial Setup

To get OpenRun running, the initial setup involves:

- Create a Linux machine, publicly accessible on port 443.
- Create a DNS entry pointing to the machine's IP address, for example an `A` record for `apps.example.com`. A wildcard DNS entry `*.apps.example.com` will make it easier to install apps at the domain level.
- Create a Google OAuth by visiting [Google Console](https://console.cloud.google.com/auth/clients). The callback URL would be `https://apps.example.com/_openrun/auth/google/callback`. Note the client ID and secret.
- Create a GitHub Personal Access Token in [GitHub settings](https://github.com/settings/personal-access-tokens). Set the scope to the repositories you want to use for your apps. Note the token.

## Installation

Assuming a systemd-based Linux system, to install OpenRun and start the service, run

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
app_default_auth_type = "rbac:google" # Default auth for all apps, with rbac
default_git_auth = "githubpat" # Account used for all github access

[system]
default_domain="apps.example.com" # CHANGEME: domain without protocol

[http]
host = "0.0.0.0"
port = 80
redirect_to_https = true

[https]
port = 443
service_email = "contact@example.com" # CHANGEME: email address for registering with Let's Encrypt. Set a value to enable automatic certs
use_staging = false # whether to use Let's Encrypt staging server

[git_auth.githubpat]
user_id = "mygithubaccount" # CHANGEME
password = "github_pat_11A7FEN7Q0XPbzMWp2LxrF_emLLexxxxxxxxxxxx" # CHANGEME

[auth.google]
key = "37019xxxxx-u8e2lltb1tmxxxxxx.apps.googleusercontent.com" # CHANGEME
secret = "GOCSPX-ybUAedirQiexxxxxxxxxx" # CHANGEME
```

This sets the default ports to 80 and 443, sets the apps to use Google for auth and sets the GitHub PAT. Automatic TLS cert creation is also enabled. As the regular user (since `openrun` user might not have sudo access), run `sudo systemctl restart openrun` to pick up the config update. The `admin_password_bcrypt` is not used in this scenario, it can be kept at its original value or changed.

## RBAC Config

At this point, all apps are authenticated by the Google OAuth account, but anyone with a Google account can access the apps. To restrict which user has access to what apps, [RBAC]({{< ref "docs/configuration/rbac/" >}}) can be used. RBAC uses the [dynamic config]({{< ref "docs/configuration/overview/#dynamic-config" >}}), which does not require restarting the OpenRun server. We will set up a RBAC schema where:

- Apps under /family will be shared with family members
- Apps under /shared will be shared with family members and friends
- All other apps will be available only to the admin.

To set the RBAC config, change to the `openrun` account by running `sudo su -l openrun`. Edit `/var/lib/openrun/config/dynamic_config.json` to have:

```json {filename="/var/lib/openrun/config/dynamic_config.json"}
{
  "version_id": "ver_33erDLffhaXjgibPb5GRb3anN0V",
  "rbac": {
    "enabled": true,
    "groups": {
      "admin": ["me@example.com"],
      "family": ["family1@example.com", "family2@example.com"],
      "friends": ["group:family", "friend1@example.com", "friend2@example.com"]
    },
    "roles": {
      "viewer": ["list", "access"],
      "user": ["access"]
    },
    "grants": [
      {
        "description": "Admin has full access to all apps",
        "users": ["group:admin"],
        "roles": ["viewer"],
        "targets": ["all"]
      },
      {
        "description": "Family has access to apps under /family",
        "users": ["group:family"],
        "roles": ["viewer"],
        "targets": ["/family/**"]
      },
      {
        "description": "Family and friends have access to apps under /shared",
        "users": ["group:friends"],
        "roles": ["user"],
        "targets": ["/shared/**"]
      }
    ]
  }
}
```

To update the RBAC config, run

```sh
openrun server update-config /var/lib/openrun/config/dynamic_config.json
```

This will upload the RBAC config to the metadata server (and also update the file on disk). Use the current `version_id`, or use the `--force` option to overwrite. The server is now ready for installing apps.

## App Installation

OpenRun supports installing apps using the imperative [CLI interface]({{< ref "docs/applications/overview/#app-management" >}}) or using the [declarative]({{< ref "docs/applications/overview/#declarative-app-management" >}}) config files. We will use the declarative approach here.

In one of the GitHub repos which is accessible using the PAT created above, create a app config file like

```python {filename="apps.star"}
# Admin apps
app("/admin/disk_usage", "github.com/openrundev/apps/system/disk_usage")
app("/admin/memory_usage", "github.com/openrundev/apps/system/memory_usage")
app("/admin/audit", "github.com/openrundev/apps/openrun/audit_viewer")

# Family apps
app("/family/bookmarks", "github.com/openrundev/apps/utils/bookmarks")
app("/family/contacts", "github.com/openrundev/apps/utils/contacts")

# Friends apps
app("/friends/dictionary", "github.com/openrundev/apps/misc/dictionary")
# Install container based apps (python and go)
limits = {"cpus": "2", "memory": "512m"} # Set limits (optional)
app("/friends/streamlit_example", "github.com/streamlit/streamlit-example", git_branch="master",
    spec="python-streamlit", container_opts=limits)
```

If this file is checked into the main branch in the `myuser/myrepo` repo, then running a command like

```sh
openrun sync schedule --minutes 1 --approve --promote github.com/myuser/myrepo/apps.star
```

will set up a [sync]({{< ref "docs/applications/overview/#automated-sync" >}}) which checks every minute for new updates to the file. If an app is created with `auth="google"`, instead of the default `auth="rbac:google"`, then anyone can access the app after Google login. If `auth="none"` is used, then no auth is required to access the app.

Any new apps declared will be automatically created. Any code changes in the repos referenced or config changes in the apps will also automatically be applied on the existing apps. No further manual updates are required on the machine. All updates can be done by just checking in changes into the declarative config - **Full GitOps CI/CD, in one command.**
