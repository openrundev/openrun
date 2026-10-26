---
title: "Security"
weight: 300
summary: "OpenRun Security related configuration"
---

The default configuration for the OpenRun server is:

- Application management (admin APIs) are accessible over unix domain sockets only (not accessible remotely). Since UDS enforces file permissions checks, no additional authentication is needed for admin APIs.
- Apps use `none` authentication by default. Set `--auth system` to require the admin account, or select another configured authentication provider.
- Installers and first-start setup save a generated admin password hash in the config file. If an existing config omits the hash, the server generates a temporary password on each restart.
- [Builtin users]({{< ref "authentication/#builtin-users" >}}), OAuth/OIDC, SAML and client certificate authentication are supported. Builtin users can be managed through `openrun user` without restarting the server.
- RBAC is enforced for app access and management operations. The default grant allows every principal, including `anonymous`, to access and list apps; additional management permissions require grants or resource ownership.

## Admin Account Password

When the OpenRun server is started, it looks for the entry

```toml {filename="openrun.toml"}
[security]
admin_password_bcrypt = "" # the password bcrypt value
```

in the config file. If the value is undefined or empty in an existing config, a random password is generated for that server session and printed during startup. This temporary password changes on every restart. Normal installation and first-start setup persist the hash, so the generated password remains valid across restarts.

The admin username is `admin` by default. It can be changed with the top-level `admin_user` key in `openrun.toml`.

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

By default, the OpenRun client uses Unix domain sockets to connect to the OpenRun server. Admin API calls to manage applications are disabled over HTTP/HTTPS by default. Unix sockets work when the client is on the same machine as the server, the client does not need to pass any credentials to connect over unix sockets. The socket is created at `server_uri` (default `$OPENRUN_HOME/run/openrun.sock`) with file mode `0700`, so only the OS user running the server (and root) can connect. Only local CLI requests over the unix domain socket are treated as transport-trusted and skip the RBAC checks; remote requests are always attributed to their credential's user.

To manage the server from another machine (the remote CLI) or connect an AI client over MCP, enable the remote API surfaces. See [Remote API and MCP]({{< ref "remoteaccess" >}}) for the setup walkthrough, API keys, `openrun login`, defaults and security best practices.

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

[[permissions.allow]]
plugin = "http.in"
method = "regex:.*"
arguments = ["regex:^<CONTAINER_URL>"] # only calls to the app's own container are auto-allowed
secrets = []
```

`permissions.allow` adds globally approved plugin calls for all apps. `method` is an exact method name or a `regex:` pattern (the `http.in` default covers every method of the plugin that way). `arguments` are exact values or `regex:` patterns matched against the positional arguments of the call, position by position; a call that passes a restricted argument by keyword is not approved by an entry with argument patterns. If a permission entry includes `secrets`, that list controls which secrets the globally approved plugin call can resolve. An empty `secrets` list means the global approval does not grant access to any secret values.

Argument patterns are checked twice when an argument carries a `{{secret ...}}` template: on the raw text before the call is approved, and again on the resolved value the plugin receives. The resolved value must match the patterns of the permission that approved the call and must not match a `permissions.disallow` entry, so a template cannot assemble a value the raw text did not show.

The `http.in` default only auto-allows outbound HTTP calls to the app's own container (`<CONTAINER_URL>...`), so a Starlark frontend can call its own backend without an approval. The pattern is anchored with `^` because the argument matcher is unanchored — without it an app could embed `<CONTAINER_URL>` inside an external URL to bypass the restriction. Calls to any other host fall back to requiring an approved `http.in` permission. The `params` values are merged into the url's query, so the url the request goes out with is checked the same way as the `url` argument (against the disallow list and the app's approved `http.in` permissions). When a response redirects, each redirect target is checked the same way before it is followed, so a permitted host cannot redirect the request to one that is not; when the call resolved secrets (in `ace.eval` or param template values), the permission approving the redirect target must also grant those secrets, since custom headers and a 307/308 body are forwarded to the target. To allow all outbound HTTP (which opens an SSRF surface, since these calls originate from the server's network position and can reach internal or metadata endpoints), use `arguments = ["regex:.*"]`; to allow specific hosts, list them, e.g. `arguments = ["regex:^https://api\\.example\\.com/.*"]`.

`permissions.disallow` blocks matching plugin calls for **every app**, even when the app's approved permissions (or the `permissions.allow` list) would permit them. Entries match with the same options as `allow`: an empty `method` matches every method of the plugin (a `regex:` method matches by pattern), and `arguments` (exact or `regex:`) narrow the block to matching calls. An entry with argument patterns also blocks a call that passes keyword arguments in place of the positional arguments the patterns cover, since the patterns cannot see keyword values. For example, to stop every app from revealing secret values through the admin plugin:

```toml {filename="openrun.toml"}
[[permissions.disallow]]
plugin = "openrun_admin.in"
method = "secret_reveal"
```

### Host commands (exec plugin)

The `exec.in` plugin runs commands on the server host, as the server user. Besides the per-app approval of each command, the server keeps an allowlist of the executables any app may run, `security.allowed_exec_commands`, and of the environment variables an app may pass them, `security.allowed_exec_env`. Both are empty by default, so no host command runs until the operator lists it.

{{<callout type="error" >}}
**Every entry in these lists is a grant of code execution on the host, as the server user, to each app approved for `exec.in`.** The allowlist bounds which program starts, not what the program does: the app chooses the arguments, and a program that runs other programs hands the app everything those can do. There is no safe way to allowlist a shell, an interpreter, or a general-purpose tool, and the lists do not substitute for trusting the apps and everyone who can change their code. Before adding an entry, assume the apps will use it in every way the program allows. For workloads that are not trusted to that degree, run the command inside the app's container with `container.in` instead, which the host lists do not govern. Adding the openrun binary to the allow list can allow app code to do admin operations against the openrun server, so it is not recommended.
{{</callout>}}

```toml {filename="openrun.toml"}
[security]
allowed_exec_commands = [
  "du",                      # bare name, looked up on the server PATH
  "/usr/local/bin/ffmpeg",   # absolute path
  "/opt/tools/*",            # glob: * does not cross a slash, ** does
  "!/opt/tools/*sh",         # exclusion, applied after the allow entries
]
```

Both layers apply: the server list says which executables the host permits at all, and the app's approved `exec.in` permission says which of them that app may call, with which arguments. An app approved for `exec.in run` without argument restrictions is still bounded by the server list, but its arguments are then entirely up to the app's code. `"*"` allows every executable, restoring the behavior of a server with no allowlist.

Commands are matched on the file that would actually run, not on the string the app passes: a bare name is resolved on the server's `PATH`, a relative path against the call's `cwd`, and symlinks are followed before matching. An exact entry (a bare name or an absolute path) matches when the requested command is the same file **and** has the same name as the entry, so a symlink or a relative path cannot stand in for another program, and one command of a multi-call binary cannot stand in for another: on Alpine (the base of the official container image) `ls`, `sh` and nearly every other command are the single `busybox` file, and on recent Ubuntu the coreutils are one `uutils` file, so matching the file alone would make an entry of `ls` admit `sh` or `env`. Globs match the resolved path under any name, and the literal directory prefix of a glob is itself resolved, so `/bin/*` also covers `/usr/bin` on Linux distributions where `/bin` is a symlink. A `!` exclusion is broader than an allow entry: it matches by file or by name, so excluding one name of a multi-call binary excludes the file, and with it every command it provides. Environment variables in entries are expanded. Globs must be absolute. The OpenRun binary itself is always refused, whatever the list says: an app that needs management operations uses the `openrun_admin.in` plugin, which is subject to authentication and RBAC.

When choosing entries, avoid:

- **Shells and interpreters** (`sh`, `bash`, `python`, `perl`, `node`, `awk`): they run whatever the app passes.
- **Programs that start other programs**: `env`, `xargs`, `find` (`-exec`), `tar` (`--to-command`), `git` (`-c core.sshCommand=...`, hooks), `make`, `nohup`, `timeout`, `nice`, `watch`, `sudo`, `su`. Many utilities have such an option; check before listing one.
- **Globs over system directories** (`/bin/*`, `/usr/bin/*`): they contain all of the above, and on a multi-call system the glob covers every name of the binary, so `/bin/*` admits the shell whether or not `!/bin/*sh` is listed, since `busybox sh` is also a shell. A glob is for a directory the operator populates with specific tools, such as `/opt/tools/*`.
- **Programs that read or write arbitrary paths** when the arguments are not restricted: `cat`, `cp`, `tee`, `dd` and `curl` reach the server's configuration, database and secrets as the server user.

List the specific programs an app needs, by name or absolute path, and restrict the call in the app's `exec.in` approval: `ace.permission("exec.in", "run", ["du"])` pins the command, and a second `regex:` entry can constrain the text of the arguments list. The exec plugin is additionally a privileged system plugin: like `openrun_admin` and `build`, it requires an authenticated (non-anonymous) caller unless `security.unsafe_allow_system_plugins_anon` is set. A malformed entry is rejected at startup and on dynamic config updates.

The environment an app passes to a host command (the `env` argument of `exec.run`) is bounded by `security.allowed_exec_env`, a list of variable names:

```toml {filename="openrun.toml"}
[security]
allowed_exec_env = [
  "TZ",          # a name
  "MYAPP_*",     # a pattern: * ? and [...] on the name
  "!MYAPP_AUTH", # an exclusion, applied after the allow entries
]
```

The list is empty by default: a call that passes any variable is refused, while a call that passes none runs with an empty environment (the server's own environment is never inherited). `"*"` allows every name. Names are compared case-insensitively on Windows, where the child sees `Path` as `PATH`, and exactly elsewhere. The environment is the usual way to make an allowed program run other code even when the file that runs is the right one: the dynamic loader honors `LD_PRELOAD` and `LD_LIBRARY_PATH` (`DYLD_*` on macOS) for every dynamically linked program, `bash` imports function definitions from `BASH_FUNC_*` variables and runs `BASH_ENV` and `ENV` files, `git` runs the programs in `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF` and `GIT_CONFIG_*`, `PERL5OPT` and `PYTHONSTARTUP` load code into interpreters, and `PATH` decides which helpers a script finds. Never list these, and prefer the variables the program is documented to read over `"*"`.

The default OpenRun server config already includes two implicit approvals used by containerized apps:

- `proxy.config(container.URL, ...)`
- `container.config(...)`

Because of these defaults, a standard containerized app does not need explicit `ace.permission(...)` entries just to call `proxy.config(container.URL)` and `container.config(...)`. The default `container.config(...)` approval does not allow secrets. If a containerized app passes secrets through params, build args or generated secret volumes, the app must declare and receive approval for a `container.config` permission with the required `secrets=[...]` allowlist, or the server config must be intentionally changed to allow those secrets globally.

The server config entry and the app's own permission work at two levels. The server entry approves the plugin call, so an app whose `container.config` permission declares `secrets=[...]` still deploys without approval. The secrets themselves are granted by the app's approved permissions (plus any secrets on the server entry): until the app is approved, the declared secrets do not resolve and the container fails to start with an error saying so. `openrun app create` and `openrun app reload` print a warning when the app declares secret access it does not have, and `openrun app approve <path>` (or `--approve` on create/reload) records the declared secrets as approved. `openrun param update` warns in the same way when the new value references a secret the app cannot resolve, or when it declares the access (the `secrets` param of the built-in specs).

For the built-in container specs, secret access is opt-in: their `container.config` permission uses the `secrets` param as its allowlist, which defaults to none, so an app passing no secrets needs no approval. Setting it declares the access, e.g. `--param secrets='[["DB_PASSWORD"]]'` (or `[["regex:.*"]]` for all secrets), after which the app must be approved.

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

Related allowlists in the `[security]` section: `allowed_container_args` (raw Docker/Podman flags apps may set, see [Container Config]({{< ref "docs/container/overview" >}})), `allowed_sidecar_images` (foreign images sidecars may use, empty allows any) and `allowed_job_images` (foreign images [jobs]({{< ref "docs/applications/jobs" >}}) may use, default `["*"]`).

## Development-only Flags

The `unsafe_*` settings turn off a safety boundary and are meant for development and test setups only. They are static config: none of them can be set through the dynamic config API.

- `security.unsafe_disable_rbac`: turns off all [RBAC]({{< ref "rbac" >}}) enforcement. Setting it also disables the remote API surfaces.
- `security.unsafe_allow_system_plugins_anon`: lets anonymous callers use the privileged system plugins, see [System Plugin Access](#system-plugin-access).
- `security.unsafe_enable_testurl_rbac`: enables the `_cl_perm=<perm>` and `_cl_role=<role>` URL path directives (for example `/myapp/_cl_perm=appread/page`) on dev mode apps with `none` auth, to simulate RBAC permissions and roles while developing an app which uses [custom permissions]({{< ref "rbac/#custom-permissions" >}}).
- `security.unsafe_agent_without_sandbox`: runs [app builder]({{< ref "docs/appbuilder" >}}) agents on the host instead of in a container sandbox.
- `bindings.unsafe_allow_http`: allows plain `http` source urls for `openrun provider install`.

## System Plugin Access

The privileged system plugins — `openrun_admin` (app lifecycle, config, RBAC, secrets, containers, ...) and `build` (the AI app builder) — perform server-side management operations. They are used by the management console app. By default, these plugins require an authenticated (non-anonymous) caller regardless of RBAC status, so a console app accidentally served with `none` auth cannot be driven by anonymous users to create/delete apps, edit config, or run the builder. The read-only `openrun` plugin is never gated.

To let anonymous callers use these plugins (for example, a development console running with `none` auth), set:

```toml {filename="openrun.toml"}
[security]
unsafe_allow_system_plugins_anon = true
```

This is an unsafe, development-only escape hatch. In production, serve the console with an auth type that requires login and leave this off.

## Disk Paths Over The Remote API

An app source, apply file or sync path which is not a git url is a path on the server's disk, read as the server user. Over the [remote management surfaces]({{< ref "remoteaccess" >}}) (the REST API, the MCP endpoint and the console's in-process `openrun_admin` calls) that would let any caller with `app:create` or `app:apply` fetch any file the server can read, by creating an app from it. So by default, disk paths are accepted over the unix domain socket only: `openrun app create ./myapp /myapp`, `openrun apply ./apps.star`, `openrun sync schedule ./apps.star` and `openrun apply --pretty-print` work on the server itself, while the same commands over a remote client (or the console) are refused with an error saying so. Remote callers deploy from git urls. Dev mode apps and `static_from_disk` apps need a disk source, so remotely they can only be created from a git url (dev mode) or on the server.

Only naming a new path is gated. Reloading, promoting or running a sync of an app or sync entry whose disk path was recorded by a caller on the server stays possible from anywhere: the path was chosen by someone with the server's file access. A sync entry created remotely keeps that standing for its scheduled runs, so a git hosted apply file it syncs cannot declare disk sources either.

Directories listed in `security.remote_disk_read_paths` are exempt: paths under them are accepted from any caller. The default is the server's own publish and checkout area, `$OPENRUN_HOME/app_src`, where the [app builder]({{< ref "appbuilder" >}}) publishes apps in local mode and dev mode apps created from a git url are checked out. So a console user can create an app from `$OPENRUN_HOME/app_src/myapp` or re-apply `$OPENRUN_HOME/app_src/apps.star`, while the rest of the disk stays off limits. Entries are expanded with environment variables, symlinks are resolved before the check, and the list is static config only (a `config:update` holder cannot widen it). Set it to `[]` to exempt nothing:

```toml {filename="openrun.toml"}
[security]
remote_disk_read_paths = []
```

To lift the restriction entirely, for example on a trusted single-user host:

```toml {filename="openrun.toml"}
[security]
unsafe_enable_remote_disk_read = true
```

Like every `unsafe_` setting this is static config only, not settable through the dynamic config API.

## CSRF Protection

CSRF protection is automatically enabled for OpenRun internal APIs and for API calls to apps. This uses the [CrossOriginProtection](https://pkg.go.dev/net/http#CrossOriginProtection) middleware. Use `app_config.security.disable_csrf_protection = true` in `openrun.toml` to disable globally for all apps. CSRF protection can be disabled individually for apps by running `openrun app update conf --promote 'security.disable_csrf_protection=true' /myapp`

## Security Response Headers

OpenRun adds security related HTTP response headers to app responses based on the `security.headers_level` app config. The level is a value from 0 to 10; only 0, 2, 5 and 10 are implemented, other values round down. The default is 2.

- **0**: no headers are added.
- **2** (default): `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN` and `Referrer-Policy: strict-origin-when-cross-origin`.
- **5**: level 2 plus `X-Frame-Options: DENY`, `Strict-Transport-Security`, `Cross-Origin-Opener-Policy: same-origin` and `X-Permitted-Cross-Domain-Policies: none`.
- **10**: level 5 plus a restrictive `Content-Security-Policy: default-src 'self'`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy` and `Permissions-Policy`. This can break apps which use inline scripts or external resources, so it is opt-in.

Each header is only added when the response does not already carry that header, so an app (including a proxied containerized app) can override any of them by setting its own value. The exceptions are `X-Frame-Options` at level 5+ and `Strict-Transport-Security` at level 10, which are forced. Apps that need to be embedded in cross-origin iframes should either set their own `X-Frame-Options`/`Content-Security-Policy` headers or lower the level:

```bash
openrun app update conf --promote 'security.headers_level=0' /myapp
```

The default for all apps can be changed with `app_config.security.headers_level` in `openrun.toml`.

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

Instead of a file path, the key contents can be provided inline with `private_key`. The value supports `{{secret ...}}` references, so the key can live in a secrets manager or the [embedded secrets store]({{< ref "secrets" >}}) instead of on disk:

```toml {filename="openrun.toml"}
[git_auth.mykey]
private_key = '{{secret_from "db" "gitauth_key1"}}'
password = '{{secret_from "db" "gitauth_pass1"}}'
```

When both are set, `private_key` takes precedence. In the management console, the git auth form's private key field can store a picked key file into the embedded secrets store with one click.

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

The `user_id` needs to be set to a non-empty value like the github id even though it is ignored for the auth.

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
