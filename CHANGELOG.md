# Changelog

Changes to OpenRun will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Builtin users are now accounts in their own `builtin_users` table instead of `[builtin_auth.*]` config entries. `openrun user update` gains `--disable`/`--enable` (a disabled user cannot log in, and its sessions, API keys and scheduled job authority stop) and `--unlock`; `openrun user show <name>` and the `user_get` API/MCP tool report a user's groups, state, creation and last login. After ten consecutive wrong passwords an account is locked for 15 minutes. A password change, disable or delete signs the user out of existing browser sessions immediately, and deleting a user revokes their API keys and OAuth tokens.
- New RBAC permissions `user:read`, `user:create`, `user:update`, `user:delete` and `user:manage` govern builtin user management (previously `config:update`/`config:read`). `openrun-operator` includes `user:manage`, `openrun-monitor` includes `user:read`. The write permissions are never matched by API key scope globs, like `config:update`.

### Changed

- Passwords of builtin users are hashed on the server with argon2id (bcrypt hashes from earlier versions are verified and upgraded in place on the next login); the `openrun user` commands send the password as entered, the `/_openrun/user` API field `password` and the MCP `user_add` tool field `password` (was `password_hash`) take the plaintext. The server enforces a password policy (8 to 128 characters, not equal to the username) and a username syntax (letters, digits and `. _ @ + -`; `admin`, `anonymous` and the `openrun-` prefix are reserved).
- Grants that managed users through `config:update` need `user:manage` (or the individual `user:*` permissions) now.
- The `[builtin_auth.*]` section of `openrun.toml` is deprecated: its entries are imported as users at startup when no user of that name exists, an existing user is never changed from the file, and the section will be removed in a later release. A dynamic config document (`openrun server update-config`) carrying `entries.builtin_auth` is rejected. `openrun user list` no longer reports a static/dynamic source.
- The store plugin records the user of the request in the `_created_by` and `_updated_by` fields of an entry (`anonymous` when the request has no authenticated user); earlier versions always stored `admin`.
- `print()` output from `app.star` during app load and audit, and the tailwindcss watcher messages of dev apps, go to the server log instead of the server's stdout.

### Removed

- The default builtin users `test1`/`test1` and `test2`/`test2`, which v0.20.0 to v0.20.5 created on every install, are no longer created. On upgrade they are removed unless their password or groups were changed; a changed `test1` or `test2` is kept as an ordinary user. Create the users you need with `openrun user add`.

### Fixed

- Template globs (`routing.base_templates` and the template locations) of apps served from disk now also match files supplied by the app spec, as the other file reads already did.
- The http plugin sends a multipart form body with a `Content-Length` header instead of chunked transfer encoding, like the other body types.
- SAML: a configured `sp_key_file`/`sp_cert_file` now also serves as the decryption key (an `EncryptedAssertion` from the IdP failed with "no decryption certs available") and signs the response to an IdP-initiated logout. A signed `AuthnRequest` over the HTTP-Redirect binding signs the query string (`SigAlg`/`Signature`) instead of embedding an XML signature the binding does not allow. Logout to an IdP single logout endpoint no longer panics without an SP keypair (the request is sent unsigned), and over the HTTP-Redirect binding the LogoutRequest signs the query string rather than embedding an XML signature. The SP metadata endpoint works without an SP keypair, lists the single logout endpoint, and is valid for seven days rather than 24 nanoseconds.

### Security

- The browser pages of the OAuth authorization server (the login/chooser page, the federated login return and the consent page used by the remote CLI and MCP clients) are served only on the auth callback domain (`security.auth_callback_domain`, default `auth.<system.default_domain>`), where no app is ever served, and the AS metadata names that endpoint.
- The return URL of a federated OAuth login is built from the configuration, no longer from the request `Host` header, and the OAuth callback, the SAML ACS and the login form submit send their single-use completion token only to a host the server serves.
- A pending federated OAuth authorize request is bound to the browser that started it (a cookie on the auth callback domain) and, once the consent page is shown, to the identity it was shown to. A continue link or a consent post from another browser or user is refused; the record id and consent nonce alone mint nothing.
- The OAuth and SAML login completion endpoints (`/_openrun/auth/<provider>/redirect`, `/_openrun/sso/<provider>/redirect`) no longer delete the browser session when a check fails: they are GET requests any site can navigate to, so a crafted link could log the user out. The single-use login state is consumed atomically and the pre-login nonce is dropped from the session once logged in.
- An IdP-initiated SAML LogoutRequest clears the local session only when it names the session's user and was issued within the last ten minutes, so a captured request cannot be replayed to log other users out.
- A Google login now honours the `verified_email` claim of the userinfo document. An identity row pre-provisioned by an API key takes the IdP subject on the first login; a login with a different real subject never replaces the recorded one.
- `security.admin_password_bcrypt` and `security.callback_url` changed through the dynamic config now take effect without a restart: the admin basic auth drops its cached credential when the hash changes, and the OAuth/SAML providers are rebuilt with the new callback URL. A wrong admin username takes as long to reject as a wrong password.
- OAuth token refresh applies the same liveness check as the API endpoints: a disabled or deleted builtin user cannot refresh tokens.
- SAML IdP metadata is read with a size bound and its SSO/SLO endpoints must be http(s) URLs; a configured `groups_attr` is authoritative and no longer falls back to other attributes when the user has no values in it. The client metadata SSRF guard also blocks 0.0.0.0/8 and NAT64 (64:ff9b::/96) addresses that embed a private IPv4.
- Builtin user password hashes are no longer stored in the dynamic config document and its history snapshots. On upgrade the users move to the `builtin_users` table (DB version 33) and the `builtin_auth` entries are scrubbed from the stored config history. Replacing the dynamic config (`openrun server update-config --force`) or restoring an old version can no longer delete or resurrect users.

## [v0.20.5] - 2026-10-21

### Security

- The webhook tokens of an app (`settings.webhook_tokens`, the credentials of the reload and promote webhook endpoints, which run without further authorization) were returned by the app get and list APIs to every caller with `app:read_detail`, while the token list API requires `app:token_read`; the built-in `openrun-monitor` role and the default read-only MCP scope have the former without the latter. The tokens are now returned only to a caller holding `app:token_read` on the app.
- `fs.serve_tmp_file` files at the default visibility (`fs.USER`) were served to any user of the app: the download handler compared the visibility with a value the plugin never stored. The file is now served to the registering user only, unless registered with `fs.APP`; the visibility value is validated. A file was also served through the download route of any app on the server, since the file store is shared; it is now served by the app that registered it only.
- `http.in` calls could reach a url the approved argument patterns and the disallow list never saw. The `params` values are merged into the url's query after the checks ran on the `url` argument, so a call could add or replace query values (`http.get("https://api.example.com/items?mode=safe", params={"mode": "admin"})`) past a pattern that constrained them; the url the request goes out with is now checked the same way a redirect target is.
- Plugin permission checks could be bypassed by an approved app (GHSA-qgqh-4fgp-rf5c). `permissions.disallow` argument patterns were matched against positional arguments only, so a call passing the restricted argument by keyword (`http.get(url = ...)`) skipped every deny rule with argument patterns; an entry with argument patterns now blocks a call that passes keyword arguments in place of the positional arguments it covers. Argument patterns were also matched against the raw argument text, and `{{secret ...}}` templates were resolved afterwards, so a template (a `secret` call in a branch that never runs is enough to make a string a template, and needs no secret grant) could assemble a value the checks never saw, for example a cloud metadata address a deny rule blocks. The disallow list and the argument patterns of the permission that approved the call are now checked again on the resolved values.
- The `http.in` plugin followed redirects without re-checking the target, so a permitted host could redirect the request, with the app's custom headers, to a host the disallow list or the approved patterns exclude. Each redirect target is now checked as if the app had called the plugin with it, under the method of the redirected request (a 303 after a post is checked as a get), and a redirect is refused when the check fails.
- The `method` of a `permissions.allow` or `permissions.disallow` entry accepts a `regex:` pattern. The default `http.in` entry, which auto-allows calls to the app's own container, used `method = "regex:.*"` but methods were compared as plain strings, so the entry never matched and the documented behavior did not exist. The `http.in` `<CONTAINER_URL>` placeholder is also validated after it is replaced by the container address: the url must stay on the container's scheme and host, so a suffix such as `<CONTAINER_URL>@other-host/` can no longer redirect an auto-allowed container call to another host.
- Plugin arguments are no longer template evaluated when they are plain strings. Every string argument (including list elements and dict values) of an approved plugin call used to be run through the `{{secret ...}}` template engine, with no way to tell a string the app wrote from one taken out of a request. Any user of an app that passed request text to a plugin (a query param into an http call, a form field into a command) could submit `{{secret "NAME"}}` for a secret the call was approved for and read it back from whatever the plugin returned or sent. Now only template values are evaluated, at any depth in list, tuple and dict arguments: an app level param value containing `{{` (the `params.star` default or the `--param` value, both static) is such a value automatically, so apps passing `param.NAME` to a plugin keep working unchanged; a template built in app code is wrapped explicitly with `ace.eval("...")`, which is a no-op on a value which is already a template. Plain strings, request data and the values a caller supplies for an action or job run pass through literally. A template value supports `+` with strings (the strings stay literal) and `str()` gives the reference text; other string operations are type errors. Apps which put a `{{secret ...}}` literal directly in a plugin argument must wrap it in `ace.eval`. Container env and build args are unchanged.

### Fixed

- The console now lists apps under a replacement sync as soon as its first run claims them ([#115](https://github.com/openrundev/openrun/issues/115)). The claim added for #111 wrote the new sync id to the database only, so the in-memory app list used by the console (and the sync detail page's app list) kept the deleted entry's id until a server reload, and the apps showed as unmanaged. Claimed apps are now cleared from the caches on commit like reloaded apps, on every server of a cluster.

## [v0.20.4] - 2026-10-20

### Security

- OAuth/OIDC and SAML logins no longer complete with the state token the login started with (GHSA-rw93-hw9g-vc3m, session fixation). That token is visible to whoever started the login, and the final app-domain step checked only that browser's nonce cookie, so an attacker could start a login, hand the identity provider link to a victim and, once the victim had signed in, finish the login themselves with a session as the victim. The provider callback and the SAML ACS now consume the pre-login state and redirect with a fresh single-use token that expires after a minute, as form login already did.
- The `exec.in` plugin is governed by a server allowlist of host executables, `security.allowed_exec_commands`, in place of the plugin-wide `permissions.disallow` entry in the default config. The list is empty by default (no host command runs); entries are bare names looked up on the server `PATH`, absolute paths, absolute globs (`/bin/*`, `/opt/tools/**`) and `!` exclusions, with `"*"` allowing every executable. Commands are matched on the file that would run, after `PATH` and symlink resolution, so a renamed symlink or a relative path cannot stand in for another program, and the command executes by that resolved path. An exact entry also requires the requested command to have the entry's name, so on a system where many commands are one multi-call binary (busybox on Alpine, the base of the official image; uutils coreutils on recent Ubuntu) listing `ls` does not admit `sh` or `env` (GHSA-2qf8-7646-rxgx). An exclusion matches by file or by name. A per-app `exec.in` approval alone no longer grants a command the server does not list. The OpenRun binary itself is always refused. The list is dynamic config; a dynamic update applies to already-loaded apps on their next call, and a malformed entry is rejected. Servers that cleared the disallow list to enable exec must now list the commands their apps run.
- The environment an app passes to a host command through `exec.run` is bounded by a new server allowlist of variable names, `security.allowed_exec_env` (GHSA-2qf8-7646-rxgx). Variables such as `LD_PRELOAD`, `BASH_FUNC_*` and `GIT_SSH_COMMAND` make an allowed program run other code, so an unfiltered environment let an app approved for one harmless command run anything. The list is empty by default: a call passing an unlisted variable is refused, a call passing no `env` runs with an empty environment as before. Entries are names, patterns (`MYAPP_*`), `"*"` for any, and `!` exclusions. Dynamic config, validated like the command list. The security documentation now says that each entry in these lists grants code execution to the approved apps and which programs and variables to avoid.
- Paths on the server's disk (an app source directory, an apply or sync file, `apply --pretty-print` input) are accepted over the unix domain socket only. The REST and MCP management APIs and the console's `openrun_admin` plugin calls refuse them with an error. Apps and sync entries whose disk path was recorded by a caller on the server still reload, promote and run from anywhere. Paths under `security.remote_disk_read_paths` (static config, default `["$OPENRUN_HOME/app_src"]`: the app builder's local publish area and the dev mode git checkout area) stay accepted from any caller, so builder-published apps can be created from and re-applied through the console. `security.unsafe_enable_remote_disk_read = true` (static config) restores the previous behavior. An empty app source is rejected instead of resolving to the server's working directory, and the folder part of a git url cannot contain `..` components (it is joined onto the checkout directory).

### Added

- A `group:` member of an RBAC group definition can name a group from the user's sign-in (OIDC/SAML groups, builtin user groups) instead of another config group ([#112](https://github.com/openrundev/openrun/issues/112)): `"reporting-users": ["group:finance-analysts", "group:sales-ops"]` matches a user whose login groups include either, checked on each request, and is inherited through nested groups. The name has the same meaning as in a grant's `users` list: the config group of that name if one is defined, and the sign-in group of that name. Previously a `group:` member naming no config group was rejected when the config loaded.

### Changed

- Destructive MCP tools (an action declared `destructive=True`, the destructive management tools) are no longer run at once for a client which cannot confirm them (an older protocol, no form elicitation, a script calling the endpoint directly): the call is refused with a tool error. `[api.mcp] destructive_confirm` sets the mode: `require` (the new default), `ask` (the previous behavior: capable clients are asked, the others run the call at once) or `skip` (never ask). The mode is overridable per app with the `action.destructive_confirm` app config setting, and an API key created with `openrun apikey create --confirm skip` runs destructive tools without the prompt where the mode is `ask`, for headless automation. The audit event of a destructive call records how it was confirmed (`confirm=accepted`, `declined`, `refused`, `unsupported`, `skipped`, `skipped_by_key`). `skip_destructive_confirm = true` is kept as the same as `destructive_confirm = "skip"`. Metadata database version 32 adds the key options column.
- A refused destructive MCP call says what the request declared (protocol version, elicitation capability), and the `openrun_status` tool of `/_openrun/app_mcp` reports the `destructive_confirm` mode and whether the connection can confirm (`can_confirm`); the endpoint instructions state the rule.
- The `Hints` column of `openrun action list` and the `Hints:` line of `openrun action show` spell the hints out: `readonly`, `destructive`, `idempotent`, `open_world` (were `ro`, `idem`, `open`).

## [v0.20.3] - 2026-10-14

### Fixed

- A sync that was deleted and scheduled again now claims the apps it finds up to date on its first run, so the console lists them under the new entry ([#111](https://github.com/openrundev/openrun/issues/111)). Previously an app recorded the sync that last reloaded or updated it only, so after a replacement every unchanged app kept the deleted entry's id and showed as unmanaged until its repo got a new commit or its declaration changed. The id is written once per app, when it differs; imperative reloads still leave it alone.
- `apply` and scheduled syncs now save a declaration-only change (a param, container option, spec, auth or other `app()` setting) to an app whose git repo has no new commit ([#109](https://github.com/openrundev/openrun/issues/109)). With `--reload=matched` (the default) or `--reload=updated`, the up-to-date check skipped the code reload and the merged declaration was dropped with it, so the app was reported as both updated and skipped and every later sync run found the same difference.

### Added

- Docker/Podman: old images and containers of prod and stage apps are now cleaned up as new versions are deployed ([#108](https://github.com/openrundev/openrun/issues/108)). The superseded version's containers are removed (not just stopped) when a deploy commits, and the new `container.retain_previous_images` app config setting (default `1`) controls how many older versions keep their image for a quick `version switch`/`version revert`; the images of the current version of each app copy and of versions newer than the current one are always kept, `-1` keeps every image. Switching to a version whose image was removed rebuilds it from the stored source. Each app version now records the image it was deployed with (`image_name` in the version metadata); images of versions deployed before this release are not tracked and are removed on the first deploy unless a container still uses them.

## [v0.20.2] - 2026-10-13

### Fixed

- Litestream replication to Google Cloud Storage through its S3-compatible endpoint (`storage.googleapis.com` with an HMAC key) failed with `SignatureDoesNotMatch`, because the AWS SDK signed the `Accept-Encoding` header that GCS rewrites in transit ([#107](https://github.com/openrundev/openrun/issues/107)). Litestream is updated to v0.5.17, which leaves the header out of the signature for `googleapis.com` endpoints, and the replica listing client used by `openrun replication status` and by app deploys (restores of replicated SQLite bindings) applies the same rule and the same S3-compatible checksum settings as Litestream. Added the `sign_accept_encoding` litestream config key (default `true`) for other S3-compatible services with the same problem; it is passed through to the app replication sidecar and restore URLs. `truncate_page_n = 0` keeps disabling the blocking TRUNCATE checkpoint: Litestream 0.5.16+ treats 0 as its default threshold, so OpenRun now passes the disabling value (-1) to the embedded library and the sidecar config.

### Changed

- Secret access for containerized apps is now reported at every step instead of failing silently on the first request ([#105](https://github.com/openrundev/openrun/issues/105)). The default server config allows the `container.config` call without secrets, so an app declaring `secrets=[...]` on that permission deploys without approval but cannot resolve them until approved. `app create`, `app reload` and `apply` now print a warning (on stderr) when an app declares secret access that is neither approved nor allowed by the server config; `param update` and `app update container_args` warn when the new value references a secret the app cannot resolve, or when the update declares the access (the `secrets` param); and the container start error says which permission to declare and that `openrun app approve <path>` grants it. `app approve` (and `--approve`) reports the permissions it records as approved, including server-covered ones, instead of "No approval required". The audit result gains `changed`, `approved`, `ungranted_secrets` and `main_app_path`; the staged update responses gain `warnings`. The built-in container specs default their `secrets` param to empty, so a new app passing no secrets requests none; set `--param secrets='[["name"]]'` to declare the access. Existing apps are unaffected: the approval rules are unchanged.

### Added

- Access log (`logs/access.log`) entries now include `request_id`, `user_id` and `app_id`. The request id matches the audit events for the request, and the user and app ids are empty for unauthenticated and non-app requests ([#106](https://github.com/openrundev/openrun/issues/106)).

## [v0.20.1] - 2026-10-13

### Added

- Added the global CLI flag `--server-uri <uri>` (or the `OPENRUN_SERVER_URI` env variable): the server uri to connect to, a unix socket path or `https://host[:port]`. When set it takes precedence over `server_uri` in the config file, so one client config can be used against multiple servers (`openrun --server-uri https://staging.example.com:25223 app list`).

## [v0.20.0] - 2026-09-28

This release adds support for running Actions through CLI and MCP (in addition to the web UI interface). See https://openrun.dev/docs/actions/#mcp-tools
Support is added for running Actions asynchronously. Async actions run without being tied to the client session, run history is maintained for async actions https://openrun.dev/docs/actions/#async-actions

### Security

- Updated `gosaml2` to v0.12.0 and `goxmldsig` to v1.6.1 to reject unsigned logout responses, bound XML parsing complexity, and reject malformed encrypted assertions without panicking. Delayed logout responses no longer clear a newer login session.

### Added

- Added the `actions.star` and `action_params.star` convention files: an app built from a spec (or any app) declares actions in `actions.star` (`actions = [ace.action(...)]`, optionally `permissions = [ace.permission(...)]`) without copying the spec's `app.star`, and `action_params.star` declares the params the actions present. When `action_params.star` exists, only its params are shown on the action UI, REST API, CLI and MCP tool schema and passed in `args`; they are app params otherwise (`--param`, `openrun param update`, the `param` module, the container environment). A required action param no longer needs a value at create time.
- Added async actions: `ace.action(..., is_async=True, timeout="2h")` runs the handler in the background as the submitting user and records the run (its args, status, the first and last 10MB of a streamed command's output or up to 100MB of result values) in the metadata database, the last 100 runs per app instance. The action page gets a run card, a run page with live output and a runs list with cancel and run again; the REST API answers `202` with the run id and serves `/api/runs`; the CLI adds `--wait` and `--follow` to `action run` (both report the run id on stderr as soon as the run starts) and the `action runs`, `action output` and `action cancel` commands; the MCP tools of the app return the run id (or wait with `wait_seconds`) and gain `get_run`, `list_runs` and `cancel_run`; the management API and MCP surface gain `list_action_runs`, `get_action_run`, `action_run_output` and `cancel_action_run`. The limits and the timeout are `[app_config]` `action.*` settings, overridable per app. A run keeps executing on the app version it started with through a reload; a run whose node stops is marked `lost`.
- Added the `openrun action` commands (`list`, `show`, `run`, `validate`, `suggest`, `openapi`) to list and run app actions from the CLI, locally or through a remote CLI. Args are passed as `name=value` (or `--json`, with `name=@file` for file uploads), results are written as a table, text or JSON (`--format json|jsonl|csv`), streamed commands write their output as produced and the CLI exits with the command's exit code (2 for param validation errors), and `--output` saves the files of download and image results (fetched as the calling user).
- Added side-effect hints to `ace.action`: `read_only`, `destructive`, `idempotent` and `open_world` (each `True`/`False`, none by default). They become the tool annotations of the action's MCP tool, are shown by `openrun action list` (a `Hints` column) and `openrun action show`, and returned as `hints` by `list_actions` and `get_action`. An action declared `destructive=True` shows a Destructive badge on its page, and its MCP tool (and the management `run_action` tool for it) asks capable clients (protocol 2026-07-28 with elicitation) to confirm before running: the first call validates the arguments and returns the confirmation prompt, the retry with an accepted answer runs the action; `[api.mcp] skip_destructive_confirm` turns it off. Actions without hints are unchanged.
- Added `--mcp=actions` (`"source": "actions"` in the mcp document): the app's actions are served as MCP tools at `<app>/mcp`, beside the form UI. One tool per action with the params as the input schema, `dry_run` to validate, a `<tool>_suggest` tool for suggest handlers, results as structured content plus a markdown table for the model, param errors as correctable tool errors, streamed commands reported with their output and exit status, the files of image and download results returned inline. The tools listed are the ones the user's permits allow.
- Added the `list_actions`, `get_action`, `run_action`, `suggest_action` and `action_file` operations to the management REST API and MCP surface. A credential limited by scopes needs `app:access` to use them.
- MCP apps: `openrun app create --mcp` (also `--mcp=/upstream-path`, `--mcp='{...}'`, `app update mcp`, and `mcp=` in apply files) marks a deployed app as an MCP server whose endpoint OpenRun protects with OAuth 2.1. OpenRun serves the protected resource metadata, issues tokens bound to the app after a login and consent using the app's `auth`, enforces RBAC `app:access` and optional app-declared scopes with per-tool requirements, strips the token and forwards the identity headers (plus `X-Openrun-Scopes` / `X-Openrun-Client-Id`). API keys can be bound to an app with `openrun apikey create --resource app:<path>`. MCP apps get a JSON-RPC health probe (TCP probes on Kubernetes) and stage/preview apps accept MCP POSTs.
- The OAuth authorization server accepts Client ID Metadata Documents (https client ids), with `api.cimd_allowed_domains`, `api.cimd_denied_domains` and `api.cimd_allow_private_hosts`; dynamic client registration remains as the fallback. Pending authorization codes are stored in the metadata database so multi-node deployments work.

### Fixed

- The page the browser shows after an `openrun login` flow is now styled like the server's login page (stylesheets and fonts loaded from the server just signed in to) and names the server.
- CLI error reporting for management API calls goes through one path for every command. A call that gets no response names the configured server instead of Go's internal request text: a unix socket that is not there says the server may not be running and how to start it, a remote server that cannot be reached says so, and a certificate the client does not trust points at `client.skip_cert_check`. A remote call rejected with 401 reports why instead of a bare `Unauthorized`: no credential found for the server (with the `openrun login --server <url>` and `OPENRUN_API_KEY` ways to provide one), or the credential sent was rejected (expired or revoked login or api key). Other error responses report the server's message as before.

## [v0.19.4] - 2026-09-08

### Added

- Added API support for actions

## [v0.19.3] - 2026-09-01

### Added

- Automatic HTTPS certificates can now be obtained from any ACME compatible CA instead of only Let's Encrypt: `https.acme_ca_url` sets the CA's ACME directory URL (enables certmagic even without `service_email`, for private CAs like step-ca), `https.acme_ca_cert` points to a root CA PEM to trust for the CA endpoint, and `https.acme_eab_key_id`/`https.acme_eab_mac_key` configure External Account Binding for CAs that require it (e.g. ZeroSSL).
- Added `https.enable_http_challenge`: answers ACME HTTP-01 challenges on the HTTP port (before the HTTPS redirect and auth), in addition to the always-on TLS-ALPN challenge. Works with Let's Encrypt and custom ACME CAs; the HTTP listener must be reachable by the CA, on port 80 for public CAs.

## [v0.19.2] - 2026-08-25

### Added

- Added sidecar containers for container apps: background workers running the app image with a different command, or companion services from another image (e.g. memcached). Sidecars start in order and are ready before the app container; on Kubernetes they are native sidecars in the app pod (reachable on `localhost`), on docker/podman peer containers on a per app network.
- `app delete` now removes the app's runtime assets: its containers and sidecars, generated images, named volumes and per app network on docker/podman, and its workloads, service and volume claims on Kubernetes. Foreign sidecar images and remote registry images are not removed.
- Added `--prune` to `sync schedule`: each sync run deletes the apps and bindings the sync itself created that are no longer present in the apply file. Resources created imperatively and later adopted by the sync are never pruned. Pruning runs in the same transaction as the apply, so a blocked delete fails and rolls back the run.
- Added the `openrun delete <filePath> [<appPathGlob>]` command, the counterpart of `apply` for removal: the apps and bindings declared in the file that match the glob are deleted (declared resources that do not exist are skipped and reported). All deletes run in one transaction; a blocked delete rolls the whole command back.

### Fixed

- Added the existing `provider:read` and `provider:manage` checks to the RBAC permission catalog. `provider:manage` now implies `provider:read`, and the built-in operator/monitor roles include the corresponding provider permission.

## [v0.19.0] - 2026-08-20

### Added

- Added support for dynamically loaded plugins using same go-plugin mechanism as used for bindings
- Added the `static_root_cache_control` app config property: sets the `Cache-Control` header value for files served from an app's `static_root` directory (favicons and other stable-named root files). Default is empty, no header. The built-in list_apps app sets `public, max-age=3600`.

## [v0.18.18] - 2026-08-12

### Added

- Added `openrun_admin.secret_reveal`: returns the clear text value of a secret reference (typically an app param holding `{{secret_from ...}}`), so an HTML app can pass an API key into a served page explicitly while the value lives only in the secret store, never in the app source or git history.
- Serving app files directly from the local disk source directory is now driven by the `static_from_disk` app config property instead of being hardcoded to the `static_disk` spec name.
- The `ace.app` settings dict now supports an `app_config` section which sets app config properties from `app.star`, e.g. `settings={"app_config": {"fs": {"retain_versions": 3}}}`.
- The `redis`/`valkey` service binding is now compiled into the server as a built-in binding type; it no longer needs `openrun provider install redis`. Each base binding gets a dedicated ACL user restricted to a unique key prefix (and matching pub/sub channel prefix); derived bindings share the base prefix with grant-controlled patterns. Requires Redis 7+ or Valkey, standalone mode.
- Added `openrun server stop --wait`: waits for the server process to fully exit instead of returning as soon as shutdown starts (the final litestream sync runs as the process exits, so scripts that move or restore data directories after a stop need this). Over the unix domain socket the server's pid (now returned by the stop API) is polled; over http(s) the listener port is polled as a best effort signal. Also added `openrun server status` (prints `ok` when the server connection works) and `openrun server version` (reports the server's build version and commit).

### Fixed

- The `openrun` CLI now discovers a machine scoped Windows service install: when `OPENRUN_HOME` is not set and no config is found relative to the executable (a winget binary is a links shim, so executable-relative discovery finds nothing), it checks `%ProgramData%\openrun\openrun.toml` and connects to the server's unix domain socket under that home, like `/var/lib/openrun` on Linux. Previously the CLI fell back to `$HOME\openrun` and failed to find the service's socket unless `OPENRUN_HOME` was set machine-wide.

## [v0.18.15] - 2026-07-29

### Added

- Added the `sqlite` service binding type: an app bound to a sqlite service gets a persistent volume (Docker/Podman named volume or Kubernetes PVC, `ReadWriteOnce` with single replica and `Recreate` strategy) holding its SQLite database files, surfaced through the `SQLITE_URL`/`SQLITE_DB_PATH`/`SQLITE_DIR` env variables. The mount directory defaults to `/data` and is configurable per binding with the `path` binding config key. An app can have one sqlite binding and a binding can be attached to one app (single-writer database); derived bindings and grants are not supported.
- Added Litestream-based continuous replication to S3-compatible storage, configured as named `[litestream.<name>]` server config entries. `metadata.litestream_config` replicates the server's own metadata and audit databases (embedded Litestream, restore-on-startup rebuilds a lost node from the replica); a sqlite service's `litestream_config` config replicates its apps' databases via a per-app replication container (Docker/Podman) or restore init containers plus a native sidecar in the app pod (Kubernetes 1.29+). Every `*.db` file in the binding directory is replicated, missing databases are restored from the replica before the app starts, and prod/staged environments replicate to separate locations (a linked staging service can use its own litestream config).
- Auto bindings can now carry binding config through the `--bind` source reference, e.g. `--bind "sqlite;path=/mydata"`; the comma separated params become the auto binding's config, for any service type. Slice CLI flag values are no longer split on commas (pass multiple values by repeating the flag).
- Zero downtime in-place restarts (Linux/macOS): `openrun server restart` (or `SIGHUP`, or `POST /_openrun/restart`) re-execs the server binary and hands the HTTP/HTTPS/unix-socket listeners to the new process.
- Added login page for system and builtin auth type and generic logout page
- Add support for Windows binary signing with signpath.io

### Fixed

- Fix WAL cleanup for SQLite based metadata

## [v0.18.7] - 2026-07-20

### Added

- Added out-of-process binding providers: new binding types (mongodb, redis/valkey, sqlserver, oracle) are built as standalone executables in the [openrundev/bindings](https://github.com/openrundev/bindings) repo and invoked by the server over gRPC using hashicorp/go-plugin, so adding a binding type no longer grows the openrun binary or its dependency tree. Providers are installed with the new `openrun provider install/uninstall/list` commands (`/_openrun/provider` APIs, gated by the new `provider:read` / `provider:manage` RBAC permissions); the install is recorded in the metadata database with pinned sha256 checksums, so it survives restarts and propagates to all server replicas — each replica materializes the verified binaries into the `bindings.cache_dir` local cache at startup, before serving traffic, making installs work on Kubernetes multi-replica deployments.
- Added the OCI image distribution path for binding providers: each provider release also publishes a minimal `FROM scratch` image (`ghcr.io/openrundev/openrun-binding-<name>`), and the Helm chart's `bindings.images` values render one init container per provider which copies the binary (via the provider binary's new `export` subcommand) into a shared volume. The server registers pre-placed provider executables from the new `bindings.preinstalled_dir` config at startup, with no downloads and no database registration — integrity comes from the image digests, and the sha256 computed at discovery is verified on every provider launch. The new `bindings.disable_install` config (chart value `bindings.disableInstall`) rejects the imperative `openrun provider install/uninstall` API/CLI, for deployments where providers are managed only declaratively.
- Add agent builder support using ACP integration
- Added the `builtin` app auth type: username/password authentication (HTTP Basic) against `[builtin_auth.<username>]` config entries, each with a bcrypt `password` hash and a `groups` list used for RBAC `group:` matching (user id is `builtin:<username>` in grants). Users can be defined statically in `openrun.toml` or managed dynamically with the new `openrun user add/update/delete/list` commands (`/_openrun/user` APIs), which take effect immediately without a server restart and shadow static entries of the same name. Useful for small deployments and for testing RBAC policies with multiple users and groups without setting up OAuth/SAML.
- Added the global CLI flag `--as <provider>:<username>` (e.g. `openrun --as builtin:user1 app list`): the management API call runs as the given user with RBAC enforcement (permission checks, list filtering, the owner rule, audit attribution) instead of as the trusted administrator. Supported over the unix domain socket only and requires RBAC to be enabled; for `builtin:` users the entry must exist and its groups feed `group:` grant matching, other provider ids (e.g. `github:user`) are taken literally with no groups so grants for SSO identities can be tested without creating them. Useful for testing RBAC policies from the CLI without going through an app.
- The `stop_server` management API now enforces the `server:stop` RBAC permission (reachable only through `--as`; the trusted admin CLI is unaffected).
- Service and binding RBAC permissions are now scoped by grant targets, like app permissions. Grant `targets` accept `service:<glob>` entries matched against service ids (`<type>/<name>`, e.g. `service:postgres/*`) and `binding:<glob>` entries matched against binding paths (e.g. `binding:/apps/team1/**`); `all` matches every app, service and binding. New permissions: `service:bind` (provision binding accounts on a service, required to create base/auto bindings from it), `binding:use` (attach a binding to an app or derive a new binding from it), `binding:reveal` (read back binding account credentials with `binding show-account`; like `secret:reveal` it always needs an explicit grant — it is never implied by `binding:manage` and binding owners do not hold it by default, opt owners in via `owner_permissions.binding`), and the `service:manage` / `binding:manage` composites. Attaching bindings at app create/update/apply time now enforces `binding:use` / `service:bind` for newly added bindings, sync background runs enforce them against the frozen creator snapshot, and service/binding list operations (including export) return only the entries the user can read. The creator of a service or binding holds the owner permissions on it (default `service:manage` / `binding:manage`, configurable via `owner_permissions`).

### Changed

- `service:*` and `binding:*` permissions are no longer global. A grant that should confer them must include `service:`/`binding:` target entries (or use the `all` target); grants whose targets only name app paths no longer confer any service or binding permissions. Sync entries created before this change froze grants without typed targets — recreate RBAC-snapshotted syncs whose apply files manage bindings.
- The app-level binding source whitelist is removed in favor of the scoped RBAC checks: the `--bind-perm` flag, `openrun app update bind-perm`, the `bind_perm` apply file argument, the `permissions.binding_source_perms` server config and the runtime container-start source check are gone, and approval no longer covers binding sources. Binding access authority is now checked when the binding is attached (RBAC `binding:use`/`service:bind`); with RBAC disabled, management operations are admin-only as usual.

### Fixed

- App version history now records the user who created each version (create, update, reload, apply, promote). Previously every `app_versions` row was attributed to `admin` regardless of the caller, so version listings misattributed changes made by RBAC/SSO/builtin users. Trusted CLI/UDS calls (no user identity) keep the `admin` attribution.
- RBAC `regex:` user patterns (in `grant.users` and group members) now must match the entire user ID instead of any substring. Patterns already anchored with `^...$` behave the same as before.
- Grant target globs are now validated when the RBAC config is updated. A malformed target previously caused authorization checks that evaluated the grant to error at request time.

## [v0.18.6] - 2026-07-13

### Added

- Added an embedded secrets store: the `db` secret provider encrypts values with AES-256-GCM and saves them in the metadata database. The master key is auto generated into `$OPENRUN_HOME/config/secret.key` or can be a `{{secret_from ...}}` reference resolved through another provider (for Kubernetes, mount it from a native Secret). Secrets are managed with the `openrun secret create/list/show/delete/rekey` commands, the `/_openrun/secret` management APIs and the `openrun_admin` plugin (`create_secret`, `get_secret`, `list_secrets`, `delete_secret`, `rekey_secrets`); `create` generates a unique name from a prefix and prints the `{{secret_from "db" "<name>"}}` reference to use. New `secret:create`, `secret:read`, `secret:delete` and `secret:reveal` RBAC permissions gate the APIs.
- The management console can now store values as secrets with one click: value fields in app params, service and binding config, config entry forms (OAuth client id/secret, git auth) and the system config key/value tables have a lock button which encrypts the value (or a picked file's content, for example an SSH private key) into the embedded secrets store and replaces the field with the generated `{{secret ...}}` reference.
- Added the `git_auth` setting `private_key` for providing the SSH private key contents inline (supports `{{secret ...}}` references), as an alternative to `key_file_path`.
- Added the app code setting `container.separate_stage_prod_images` for specs that need distinct staging and production container images.
- With structured templates, a route's `full` template (and template names passed to `ace.response`) can now name a `{{define}}` block from the base templates instead of a template file, so fragment-only endpoints need no dedicated template file.
- Added the `static_disk` app spec for serving static files directly from a local source directory without storing the static file contents in the metadata database.
- Container management operations are now gated by RBAC. New `container:read` permission covers listing containers, getting container details, logs and Kubernetes stats/status; new `container:manage` permission covers starting and stopping managed containers (and implies `container:read`). These operations previously had no RBAC check.
- Added the `audit:read` RBAC permission, which grants read access to the audit log across all apps. It gates the `list_audit_events` and `list_operations` plugin APIs, which previously had no RBAC check.

### Fixed

- The `delete_apps` plugin API now rejects an empty path glob instead of matching every app: a caller omitting the path argument could previously delete all apps (the HTTP route already validated this, plugin calls did not).
- Scheduled sync runs now record a synthesized request id on their audit events, attributed to the user who created the sync. These events previously had no request id since no HTTP request is behind a scheduled run, so they could not be traced; now all events of one run share an id and the audit trace shows everything the run did.

### Changed

- App responses now include baseline security headers by default: the new `security.headers_level` app config defaults to 2, which adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN` and `Referrer-Policy: strict-origin-when-cross-origin` when the app did not set its own value. Apps embedded in cross-origin iframes need `security.headers_level = 0` (settable per app with `openrun app update conf`) or an app-provided `X-Frame-Options`/CSP header, which takes precedence. Levels 5 and 10 opt into stricter sets (HSTS, CSP).
- The proxy write-access check for staging and preview apps (`stage_enable_write_access` / `preview_enable_write_access`) now treats every method other than GET, HEAD and OPTIONS as a write, so PATCH and custom verbs fail closed; denied requests now return 403 instead of 500.
- New production apps now create their linked staging app on a staging subdomain by default, for example `stage.example.com:/app`, instead of suffixing `_cl_stage` to the production path. Use `system.stage_at`, `system.default_stage_domain`, `openrun app create --stage-at`, or declarative `stage_at` to choose path-based staging or a specific staging domain for new apps.
- Containerized staging and production apps now share the same generated image name by default when the build inputs match, avoiding a second image build during production promotion. Specs can opt out with `settings={"container": {"separate_stage_prod_images": True}}`.
- Kubernetes deploys now watch Deployment rollout status instead of relying only on repeated polling, reducing API overhead and returning sooner when Kubernetes reports readiness or rollout failure. The watch path uses the same `container.deploy_health_attempts` budget, and the best-effort EndpointSlice convergence check now skips immediately when the Kubernetes API or RBAC policy does not allow listing EndpointSlices.
- Docker/Podman container names and image tags are much shorter: the version suffix is now the first 16 chars of the content hash (matching Kubernetes workload names) instead of a base32 encoding of the full hash, for example `clc-app_prd_<id>-e96c79f753cfafff` instead of a 143-character name. Containers running under the old names are stopped by the stale-container sweeper after upgrade and the app is recreated under the new name on its next request; images built under old tags are not reused.

## [v0.18.2] - 2026-06-28

### Added

- Added the app internal `/_openrun_app/verify_file/{file_name}` API to verify that an app-relative source file exists and return its size.

## [v0.17.8] - 2026-06-03

### Fixed

- Fixed service stop error when running as windows service

## [v0.17.7] - 2026-06-02

### Security

- Fixed an open redirect issue reported by @Fushuling https://github.com/openrundev/openrun/security/advisories/GHSA-h5g6-xmh4-hc37

## [v0.17.6] - 2026-06-01

### Added

- Added Windows Service Control Manager support for `openrun server start`, allowing OpenRun to run as a native Windows service registered with `sc.exe`.

## [v0.17.5] - 2026-05-28

### Changed

- Proxied responses now rewrite the `Location` header so upstream redirects don't leak the internal backend authority. Absolute Locations pointing at the proxy target are converted to path-only URLs, and path-absolute Locations get any stripped prefix (`strip_app` / `strip_path`) restored so the client's next request lands on the same public route. Cross-host Locations (OAuth/SSO and similar) pass through unchanged.

## [v0.17.4] - 2026-05-21

### Added

- Added forward auth support for apps using auth modifiers such as `system+forward_policy`, with named `[forward.<name>]` configs, trusted forwarded/OpenRun identity headers and configurable copied response headers.

## [v0.17.3] - 2026-05-18

### Changed

- Fix #95: Pull image and update apps which use image spec when app reload is done.

### Added

- Added background cleanup for stale Docker/Podman containers started by OpenRun. The cleanup stops running OpenRun-labeled containers that are no longer referenced by an active app, and its interval is configurable with `system.stale_container_cleanup_interval_mins`.

- Fix #94: Added `X-Openrun-User-Id` and `X-Openrun-User-Email` headers for proxied apps, and exposed the same OIDC subject/email values on the Starlark request as `UserSubject` and `UserEmail`.

## [v0.17.1] - 2026-04-27

### Changed

- Action request bodies are now capped by default at `33554432` bytes. The limit can be configured globally with `app_config.action.max_request_body_bytes` or overridden per app with `openrun app update conf --promote 'action.max_request_body_bytes=<bytes>' /myapp`.
- `http.in` requests now inherit the current request context, support an optional `timeout` argument with a default of `300` seconds, and automatically close unread response bodies through deferred plugin cleanup when `body()` or `json()` are not called.
- Fix #91: Store session info in metadata KV store to avoid cookie size limits
- Fix #85: `openrun app create --cvol` and `openrun app update cvol` now reject container volume values that start with `--`, making missing volume arguments fail clearly instead of consuming the next option as the volume name.

## [v0.17.0] - 2026-04-22

### Added

- Added `security.trusted_proxies` server config to control which reverse proxies or load balancers are allowed to supply forwarded client IP headers.
- Added `system.fallback_unknown_domains` server config to optionally preserve legacy routing of unknown hostnames to the default domain.
- Added `system.builder_auth_token` server config for delegated container builds, using a shared bearer token between the main OpenRun install and builder node(s).
- Added `security.allowed_mounts` server config to allow administrators to approve host directories that apps may use as container bind-mount sources.

### Changed

- `req.RemoteIP` now ignores `X-Forwarded-For` and `X-Real-IP` unless the direct peer is listed in `security.trusted_proxies`.
- Reverse proxied requests now strip inbound forwarding headers and rebuild a clean `X-Forwarded-*` / `X-Real-IP` set before sending the request upstream.
- Requests for unknown `Host` values no longer route to the default domain unless `system.fallback_unknown_domains` is explicitly enabled.
- Delegated builds now require a valid bearer token on `/_openrun/delegate_build`. Builder nodes should run with `builder.mode = "delegate_server"` and no longer require `security.admin_over_tcp = true` for delegated-build ingress. Existing delegated-build setups must set the same `system.builder_auth_token` value on the main install and every builder node before upgrading.
- CORS is disabled by default for apps. The default `app_config.cors.allow_origin` is now empty and `app_config.cors.allow_credentials` is now `"false"`. Apps that need browser cross-origin access must opt in with an app config override such as `cors.allow_origin="https://frontend.example.com"` or `cors.allow_origin="origin"`.
- The default server-level `container.config(...)` permission no longer allows access to all secrets. Containerized apps that pass secrets through params, build args or generated secret volumes now need an explicitly approved `container.config` permission with the required `secrets=[...]` allowlist, unless the server config is intentionally changed to allow those secrets globally.
- Container runtime options now only pass raw Docker/Podman flags from app metadata when the flag is explicitly listed in `security.allowed_container_args`. Built-in `cpus` and `memory` options continue to be parsed by OpenRun and do not require this raw flag allowlist.
- Container bind-mount sources are now restricted to the app source directory, the app runtime directory, or directories listed in `security.allowed_mounts`. Relative bind sources must stay inside the app source tree.

## [v0.16.26] - 2026-04-06

### Added

- Added `UserId`, `CustomPerms`, and `AppRBACEnabled` to the request object available in Starlark handlers and HTML templates.

## [v0.16.24] - 2026-04-03

### Added

- Added `system.list_apps_title` and `system.show_hosted_with` server config options to customize the built-in app listing page title and whether it shows the `Hosted with OpenRun` text.

- Add the `security.auth_required` server config option. When enabled, apps configured with `auth="none"` are denied at request time with `401 Authentication required`, providing a server-wide guardrail against unauthenticated app access.

## [v0.16.22] - 2026-03-25

### Added

- Added automatic app version cleanup with a default retention of 5 older versions per app, configurable globally with `app_config.fs.retain_versions` and per app with `openrun app update conf --promote fs.retain_versions=<count> /myapp`.

## [0.16.21] - 2026-03-19

### Added

- Support for default permissions in server config. Containerized apps do not require explicit approval.

## [0.16.19] - 2026-02-13

### Added

- Postgres database support for store plugin

### Changed

- Changed python appspecs to use uv for managing dependencies

## [0.16.17] - 2026-02-04

### Changed

- Updated appspecs to not use heredocs since Kaniko does not support it

## [0.16.16] - 2026-02-04

### Added

- Lots of changes for Kubernetes support.

## [0.15.14] - 2025-10-31

### Added

- Added `openrun_admin` plugin with apis to manage `sync` jobs, for use by manage_sync app

### Changed

- Changed app authentication setting and git auth setting to be stored in app metadata instead of in app settings. This allows those properties to be updated through declarative config. The property is moved over as part of a migration. Also, `app update-metadata` CLI command is renamed to `app update`.
- Changed `app update-settings` CLI command to `app settings`.

## [0.15.13] - 2025-10-28

### Added

- Added AWS Systems Manager (SSM) based secrets provider

## [0.15.12] - 2025-10-27

### Changed

- HTTP early hints is disabled by default since that seems to cause issues with HTTP/2 proxies

## [0.15.11] - 2025-10-27

### Added

- Added `/_openrun/health` health check endpoint

## [0.15.10] - 2025-10-26

### Added

- Support for passing `X-Openrun-Rbac-Enabled` header to the proxied downstream service. Value is true if RBAC is enabled for app, false otherwise.
- Added update_time field to listapps output, app listing will display that info

## [0.15.9] - 2025-10-22

### Added

- Regex support in user value for RBAC. Regex can be used in grant.users and group values, Regex has to be prefixed with `regex:`
- Support for passing `X-Openrun-User` header to the proxied downstream service. Value is the user making the request.
- Support for passing `X-Openrun-Perms` header to the proxied downstream service. Value is comma separated list of all custom perms granted for the user on that app. `custom:` prefix is trimmed from the passed values.

### Fixed

- Fixed an issue where the source path was not set to `$OPENRUN_HOME/app_src` when running `apply` in `dev` mode.

## [0.15.8] - 2025-10-14

### Added

- Enable CSRF protection for internal APIs and for apps. App level CSRF protection is enabled by default.
  Use `security.disable_csrf_protection = true` to disable. Disable in app metadata by running
  `openrun app update conf --promote 'security.disable_csrf_protection=true' /myapp`
