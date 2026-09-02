---
title: "Remote API and MCP"
weight: 350
summary: "Enable remote CLI access and the MCP endpoint, create API keys, and apply security best practices"
---

## Overview

By default, the OpenRun server is managed over a unix domain socket: the CLI on the same machine connects with no credentials, protected by file system permissions. Two optional remote surfaces extend management beyond the local machine:

- **`rest`** — the management REST API over TCP, used by the OpenRun CLI running on another machine.
- **`mcp`** — a [Model Context Protocol](https://modelcontextprotocol.io/) endpoint at `https://<host>:<https_port>/_openrun/mcp`, which lets AI clients like Claude Code operate OpenRun: list and create apps, promote, manage services and bindings, run syncs and more.

Both surfaces are **off by default** (`[api.rest] enable` / `[api.mcp] enable`). When enabled, they are served **only over HTTPS** (or through a TLS-terminating proxy listed in `security.trusted_proxies`) — a plaintext request gets a plain 404, never a redirect. Every remote call authenticates with a bearer credential (an API key, or an OAuth token from a browser login) and runs as that credential's user identity with [RBAC]({{< ref "rbac" >}}) enforced. RBAC is always on: the default grant gives every authenticated principal read access to apps, and the `admin` account has full authority, so a fresh install needs no RBAC setup before enabling remote access.

## Server Setup

Add to the server config and restart:

```toml {filename="openrun.toml"}
[api.rest]
enable = true
auth = ["admin"]   # login mechanisms for openrun login: "admin" (default), "builtin",
                   # or an [auth.*]/[saml.*] name. At least one is required

[api.mcp]
enable = true
auth = ["admin"]   # login mechanisms for MCP OAuth clients
```

API keys work on any enabled surface whatever its login mechanisms. The [console]({{< ref "/console-tour" >}}) manages these settings on its API Access page.

The server refuses to start with a surface enabled unless the transport prerequisites are met:

- An HTTPS listener (on by default, port 25223) or `security.trusted_proxies` for a TLS-terminating proxy.
- A canonical https origin in `api.external_url`, defaulting to `security.callback_url` when that is set. This value backs the OAuth metadata and token bindings — treat it as stable; changing it invalidates outstanding tokens.

```toml {filename="openrun.toml"}
[security]
callback_url = "https://openrun.example.com:25223"
```

For real deployments, configure [automatic TLS certificates]({{< ref "networking" >}}); the default self-signed certificate works for the OpenRun CLI (with `skip_cert_check`) but most MCP clients reject it.

The `[api]` section is also part of the [dynamic config]({{< ref "overview/#dynamic-config" >}}), so the surfaces can be enabled and reconfigured at runtime without a restart (the same transport prerequisites are validated on update).

## Connect the Remote CLI

On the remote machine, point the client at the server:

```toml {filename="client openrun.toml"}
server_uri = "https://openrun.example.com:25223"

[client]
skip_cert_check = false  # true only for self-signed certs
```

Then either log in interactively:

```sh
openrun login             # opens the browser, authenticates against [api.rest] auth,
                          # stores short-lived tokens in the OS keychain
openrun app list
openrun logout            # revokes the session server side
```

or use an API key (for CI and headless use):

```sh
# on the server (or as any user holding apikey:manage:self):
openrun apikey create --desc "ci deploy"

# on the remote machine:
export OPENRUN_API_KEY=orun_pat_...   # or set client.api_key in the config file
openrun app list
```

`openrun login` tokens rotate automatically (access tokens live 1 hour, refreshed transparently) and the whole grant expires after `api.grant_max_ttl` (90 days), after which a fresh login is required. API keys expire after 90 days by default; `--expires` changes that and `--expires=never` is required for a non-expiring key.

## Connect an MCP Client

The MCP endpoint is `https://<external_url host>/_openrun/mcp`. There are two ways to authenticate:

**OAuth (browser login)** — for clients that support MCP OAuth, like Claude Code, add the server and the client discovers the OpenRun authorization server, registers itself, and opens a browser login (against the mechanisms in `[api.mcp] auth`). The consent page defaults MCP sessions to **read-only** scopes; choosing broader scopes at consent is an explicit act.

```sh
claude mcp add --transport http openrun https://openrun.example.com:25223/_openrun/mcp
```

**API key** — mint an MCP-bound key and pass it as a bearer header:

```sh
openrun apikey create --resource mcp --desc "claude on laptop"
claude mcp add --transport http openrun https://openrun.example.com:25223/_openrun/mcp \
  --header "Authorization: Bearer orun_pat_..."
```

An MCP-only key with no explicit `--scopes` defaults to **`*:read`** — the AI client can inspect everything its user can read, but cannot change anything. Mint a write-capable key deliberately with `--scopes "*"`. A key bound to `mcp` is rejected at the REST surface and vice versa (`--resource all` for a key valid on both).

Destructive tools (delete, promote, version switch, ...) support `dry_run`, and for clients that support elicitation the server runs a dry-run preview and asks for confirmation before applying the change. `[api.mcp] skip_destructive_confirm = true` disables the confirmation flow for headless automation.

## API Keys

```sh
openrun apikey create [--user builtin:alice] [--expires 30d|never] \
    [--scopes "app:*,sync:read"] [--resource rest|mcp|all] [--desc "text"]
openrun apikey list [--all]     # --all (every user's keys) requires admin
openrun apikey delete <id>
```

- The key value is shown **once** at creation and stored only as a hash.
- `--user` defaults to the caller. Creating a key for another user requires `admin` and is prominently audited.
- **Scopes are a ceiling, not a grant**: the key can never do more than its user's RBAC grants allow, and scopes only narrow that further. A `*` scope deliberately does **not** cover `secret:reveal`, `binding:reveal`, `app:approve`, `config:update` or `admin` — those must be named literally in `--scopes`, so a key carrying reveal- or admin-class authority is visible as such.
- A key created by a remote (credential-authenticated) caller can only be as powerful as the creating credential: scopes and resources must be subsets, and the new key cannot outlive its parent.
- Expired and revoked credentials are pruned automatically 30 days after they die.

## What MCP Can Do

The MCP tool set mirrors the management API: apps (list/create/delete/approve/reload/promote/preview/versions), sync, services, bindings, secrets metadata, config read, API key self-management and more. RBAC decides per identity what actually succeeds, and every call is audited with the invoker type and credential id.

Dangerous operations are **disabled for MCP by default** and are not even registered as tools:

| Operation | Why |
|---|---|
| `stop_server`, `restart_server` | server lifecycle |
| `secret_reveal`, `secret_rekey` | reading back / re-encrypting secret values |
| `binding_show_account` | revealing service account credentials |
| `provider_install`, `provider_uninstall` | installs binaries the server executes |
| `user_add`, `user_delete` | builtin user management |
| `config_update` | can grant every other permission |
| `create_apikey_other`, `delete_apikey_other` | credentials for other users |

Operations can be opted back in, or additionally disabled, per surface:

```toml {filename="openrun.toml"}
[api.mcp]
enable_apis  = []                # opt default-disabled operations back in (logged at startup)
disable_apis = ["secret_create"] # turn additional operations off
skip_destructive_confirm = false

[api.rest]                       # the same overrides for the remote REST surface
disable_apis = []
```

Note on secrets: `secret_create` **is** enabled for MCP by default, which means secret values typed into an AI client transit that client and the model's context by design. Disable it (as above) if secret writes must never pass through an AI client. Reading values back stays disabled unless explicitly enabled.

## Defaults Summary

| Setting | Default |
|---|---|
| `api.rest enable`, `api.mcp enable` | `false` — no remote surface |
| `api.rest auth`, `api.mcp auth` | `["admin"]` — the admin account is the only login mechanism |
| Transport | HTTPS only (or `security.trusted_proxies`); plaintext is a 404 |
| RBAC | Always on; default grant gives every principal `app:access` + `app:read` |
| API key expiry (`api.pat_default_ttl`) | 90 days; `--expires=never` must be explicit |
| API key resource (`--resource`) | `rest` |
| MCP-only key scopes | `*:read` (read-only) unless `--scopes` given |
| OAuth access token (`api.access_token_ttl`) | 1 hour |
| OAuth refresh token (`api.refresh_token_ttl`) | 30 days per rotation |
| Absolute login lifetime (`api.grant_max_ttl`) | 90 days, then log in again |
| MCP consent scope preset | read-only |
| MCP dangerous operations | disabled (table above) |
| Destructive tool confirmation | on, for clients supporting elicitation |
| Credential cleanup | expired/revoked keys pruned after 30 days |

## Security Best Practices

- **One identity per person, one key per client.** Create keys with `--user builtin:<name>` (or the SSO principal) and a `--desc` naming where it lives. Audit events record the acting user and the credential id, so shared keys destroy attribution.
- **Prefer `openrun login` for humans.** It stores rotating short-lived tokens in the OS keychain and is revoked with one `openrun logout`. Reserve long-lived API keys for automation.
- **Keep AI clients read-only until proven.** The MCP defaults (read-only key scopes, read-only consent preset, destructive confirmation, disabled dangerous ops) are the intended starting point; widen deliberately, one capability at a time.
- **Name dangerous scopes explicitly.** Since `*` never matches `secret:reveal`, `binding:reveal`, `app:approve`, `config:update` or `admin`, any credential carrying that authority shows it in `openrun apikey list` — review for keys with literal dangerous scopes.
- **Bind keys to one surface.** The `rest`/`mcp` resource binding stops a key leaked from an MCP client config being replayed against the REST API and vice versa; avoid `--resource all`.
- **Let keys expire.** Keep the 90 day default, rotate CI keys, and audit `openrun apikey list --all` for stale `never` keys. Deleting a key takes effect immediately.
- **Use real certificates.** `skip_cert_check` and self-signed certs are for trials; [automatic TLS]({{< ref "networking" >}}) makes real certificates easy. Only list actual TLS-terminating proxies in `security.trusted_proxies`, and bind the plaintext listener to a private address in that setup.
- **Watch the audit log.** Every remote call carries `invoker=rest` or `invoker=mcp` plus `cred=<id>` in the audit detail, and calls refused by the per-surface operation policy are audited too — "what has MCP done (or tried)" is a single filter.
- **Keep `unsafe_*` flags off in production.** `security.unsafe_disable_rbac` and friends are dev-only; they cannot be set through the dynamic config API, and disabling RBAC also disables the remote surfaces.
- **Narrow the default grant if apps should not be reachable by every authenticated user.** Replace the default `*` grant with group-scoped grants in the [RBAC config]({{< ref "rbac" >}}).

## Config Reference

```toml {filename="openrun.toml"}
[api]
external_url = ""                # canonical https origin; defaults to security.callback_url
access_token_ttl = "1h"          # OAuth access token lifetime
refresh_token_ttl = "720h"       # OAuth refresh token lifetime per rotation (30d)
grant_max_ttl = "2160h"          # absolute OAuth grant lifetime (90d)
federated_identity_ttl = "720h"  # provider group snapshot max age
pat_default_ttl = "2160h"        # default API key expiry (90d)

[api.mcp]                        # the MCP endpoint
enable = false
auth = ["admin"]                 # login mechanisms: "admin", "builtin", [auth.*]/[saml.*] names (never empty)
enable_apis = []                 # default-disabled operations opted back in
disable_apis = []                # additional operations turned off
skip_destructive_confirm = false

[api.rest]                       # the management REST API over TCP (remote CLI)
enable = false
auth = ["admin"]                 # login mechanisms for openrun login (never empty)
enable_apis = []
disable_apis = []
```
