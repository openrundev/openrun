---
title: "Security"
weight: 300
summary: "OpenRun Security related configuration"
---

The default configuration for the OpenRun server is:

- Application management (admin APIs) are accessible over unix domain sockets only (not accessible remotely). Since UDS enforces file permissions checks, no additional authentication is needed for admin APIs.
- Admin user account is used to access applications, default `auth` for apps is `system`
- The admin user password bcrypt hash has to be added to the server config file, or a random password is generated every time the server is restarted
- Applications can be changed to not require any authentication, `auth` can be `none` or use OAuth2 based auth.
- There is no user management support in OpenRun currently. The system account is present by default (which can be disabled) or OAuth based auth can be used.

## Admin Account Password

When the OpenRun server is started, it looks for the entry

```toml {filename="openrun.toml"}
[security]
admin_password_bcrypt = "" # the password bcrypt value
```

in the config file. If the value is undefined or empty, then a random password is generated and is used as the admin password for that server session. The password being used is displayed on the stdout of the server startup. This will change on every restart.

To configure a value for the admin user password, use the `password` helper command:

```bash
openrun password
```

to generate a random password. This will print out the password and its bcrypt value to the screen. Save the password in your password manager and add the bcrypt hash to your config file.

To use a particular value for the admin password, run:

```bash
openrun password --prompt
```

This will prompt for the password and print out the bcrypt hash to add to the config file.

## Admin API Access

By default, the OpenRun client uses Unix domain sockets to connect to the OpenRun server. Admin API calls to manage applications are disabled over HTTP/HTTPS by default. Unix sockets work when the client is on the same machine as the server, the client does not need to pass any credentials to connect over unix sockets.

To enable remote API calls, where the client is on a different machine from the server, the server needs to be changed to add the following:

```toml {filename="openrun.toml"}
[security]
unsafe_admin_over_tcp = true
```

If running the OpenRun client from a remote machine, the config options required for the client are:

```toml {filename="openrun.toml"}
server_uri = "https://<SERVER_HOST>:25223"
admin_user = "admin"

[client]
admin_password = "" # Change to actual password
skip_cert_check = false # Change to true if using self-signed certs
```

All other server related config entries are ignored by the OpenRun client. Note that to connect to an OpenRun server over HTTP remotely, the server needs to be bound to the all interface (0.0.0.0), see [networking]({{< ref "networking" >}}).

If server_uri is set to the HTTPS endpoint and the OpenRun server is running with a self-signed certificate, set `skip_cert_check = true` in config to disable the TLS certificate check.

## Application Security

See [appsecurity]({{< ref "appsecurity" >}}) for details about the application level sandboxing and [authentication]({{< ref "authentication" >}}) for details about adding OAuth/OIDC/SAML/cert-based auth for apps.

## Default Plugin Permissions

OpenRun can allow plugin calls at the server level so apps do not need an explicitly approved permission entry in app metadata. The default server permissions are:

```toml {filename="openrun.toml"}
[[permissions.allow]]
plugin = "proxy.in"
method = "config"
arguments = ["<CONTAINER_URL>"]

[[permissions.allow]]
plugin = "container.in"
method = "config"
arguments = ["regex:.*"]
secrets = [] # no secrets allowed by default
```

`permissions.allow` adds globally approved plugin calls for all apps. If a permission entry includes `secrets`, that list controls which secrets the globally approved plugin call can resolve. An empty `secrets` list means the global approval does not grant access to any secret values. `permissions.full_access` list grants the listed apps access to all plugin calls without requiring app-level approvals.

The default OpenRun server config already includes two implicit approvals used by containerized apps:

- `proxy.config(container.URL, ...)`
- `container.config(...)`

Because of these defaults, a standard containerized app does not need explicit `ace.permission(...)` entries just to call `proxy.config(container.URL)` and `container.config(...)`. The default `container.config(...)` approval does not allow secrets. If a containerized app passes secrets through params, build args or generated secret volumes, the app must declare and receive approval for a `container.config` permission with the required `secrets=[...]` allowlist, or the server config must be intentionally changed to allow those secrets globally.

For example, to restore blanket server-level secret access for containerized apps:

```toml {filename="openrun.toml"}
[[permissions.allow]]
plugin = "container.in"
method = "config"
arguments = ["regex:.*"]
secrets = [["regex:.*"]]
```

Container bind-mount sources are constrained separately from Starlark plugin permissions. Relative bind sources must stay inside the app source directory. Absolute bind sources must be inside the app source directory, the app runtime directory, or a directory listed in `security.allowed_mounts`:

```toml {filename="openrun.toml"}
[security]
allowed_mounts = ["$OPENRUN_HOME/mounts", "/srv/openrun/shared"]
```

`security.allowed_mounts` entries are expanded with environment variables before validation.

## CSRF Protection

CSRF protection is automatically enabled for OpenRun internal APIs and for API calls to apps. This uses the [CrossOriginProtection](https://pkg.go.dev/net/http#CrossOriginProtection) middleware. Use `app_config.security.disable_csrf_protection = true` in `openrun.toml` to disable globally for all apps. CSRF protection can be disabled individually for apps by running `openrun app update conf --promote 'security.disable_csrf_protection=true' /myapp`

## CORS

CORS headers are disabled by default for apps. Containerized apps are normally accessed through OpenRun, which performs authentication before proxying the request to the app. With the default config, OpenRun does not add `Access-Control-Allow-Origin` and does not answer CORS preflight requests before they reach the app.

To allow browser requests from a specific frontend origin, set an app-level CORS origin:

```bash
openrun app update conf --promote 'cors.allow_origin="https://frontend.example.com"' /myapp
```

To reflect the request origin as the allowed origin, use:

```bash
openrun app update conf --promote 'cors.allow_origin="origin"' /myapp
```

For credentialed browser CORS requests, enable credentials explicitly:

```bash
openrun app update conf --promote 'cors.allow_credentials="true"' /myapp
```

Avoid enabling credentials with `cors.allow_origin="*"`. Browsers reject wildcard origins for credentialed CORS, and it can expose authenticated app endpoints too broadly.

## Trusted Proxies and Client IP Headers

By default, OpenRun does not trust `X-Forwarded-For` or `X-Real-IP` headers supplied by the client. The client IP exposed to apps in `req.RemoteIP` is taken from the direct peer connection unless the peer is explicitly configured as a trusted proxy.

To allow a reverse proxy or load balancer to supply the client IP, set `security.trusted_proxies` to a list of IP addresses or CIDR ranges:

```toml {filename="openrun.toml"}
[security]
trusted_proxies = ["127.0.0.1", "10.0.0.0/8", "192.168.0.0/16"]
```

Behavior:

- If the direct peer is not in `trusted_proxies`, OpenRun ignores `X-Forwarded-For` and `X-Real-IP`.
- If the direct peer is trusted, OpenRun uses the rightmost non-trusted address from the `X-Forwarded-For` chain as the client IP.
- If `X-Forwarded-For` is not present and the direct peer is trusted, OpenRun falls back to `X-Real-IP`.
- When OpenRun proxies requests to an upstream service, it strips inbound forwarding headers and rebuilds a clean set based on the resolved client IP.

This setting should include only infrastructure that is allowed to rewrite client IP headers, such as your ingress proxy or load balancer.

## Private Repository Access

OpenRun can read public GitHub/GitLab repositories automatically. If the repository is private, to be able to access the repo, the [ssh key](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account) or [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) needs to be specified. Same for GitLab.

### SSH Keys

For SSH key, in the `openrun.toml` config file, create an entry like:

```toml {filename="openrun.toml"}
[git_auth.mykey]
key_file_path = "/Users/myuser/.ssh/id_rsa"
password = "mypassphrase"
```

`mykey` is the git auth key name, `key_file_path` points to the location of a private key file for a user with access to the repository and `password` is the passphrase if any for the file.

{{<callout type="info" >}}
Use `ssh-keygen -l -f ~/.ssh/id_rsa.pub` (on public key) to check if the fingerprint matches the SHA256 fingerprint shown at https://github.com/settings/keys. To verify the passphrase, use `ssh-keygen -y -f ~/.ssh/id_rsa` (on the private key) and type in the passphrase to check if the passphrase is correct.
{{</callout>}}

### Personal Access Token

For personal access token, set

```toml {filename="openrun.toml"}
[git_auth.mypat]
user_id = "myid"
password = "github_pat_11A7FXXXXXXX"
```

The `user_id` needs to be set to an non-empty value like the github id even though it is ignored for the auth.

When running `app create`, add `--git-auth mykey` or `--git-auth mypat` option. The private key specified will be used for accessing the repository. `app reload` command will automatically use the same key as specified during the create. To set the default git key to use, add in config:

```toml {filename="openrun.toml"}
[security]
default_git_auth = "mykey"
```

This git key is used for `apply` and `sync` also. To change the git auth key for an app, run:

```bash
openrun app update git-auth --promote newkey /myapp
```

## GitLab Groups and Subgroups

GitLab Cloud and on-prem supports [group and sub-groups](https://docs.gitlab.com/user/group/). By default in OpenRun, a git path like `gitlab.com/myuser/a/b/c` is assumed to be referencing `myuser` user or org, repo `a` and folder `b/c`. If using groups in GitLab, this might be incorrect. Two forward slashes `//` are required to indicate the end of the repo name. If `b` is the repo name, the above path would have to be referenced as `gitlab.com/myuser/a/b//c`. In that case, repo will be `a/b` and folder will be `c`.

If no folder is present, that is if `c` is the repo, then the path should be specified as `gitlab.com/myuser/a/b/c//`. Without the `//` delimiter, the repo name is assumed to immediately follow the user name.
