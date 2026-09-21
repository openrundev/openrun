---
title: "MCP Apps"
weight: 360
summary: "Deploy an MCP server as an app and let MCP clients connect with OAuth, using the app's login and RBAC"
---

## Overview

An app deployed through OpenRun can be an [MCP](https://modelcontextprotocol.io) server: a container image speaking Streamable HTTP, a `proxy` app in front of a remote MCP endpoint, or any app that serves MCP on a path. Marking the app with `--mcp` makes OpenRun handle the MCP authorization flow for it:

- OpenRun serves the OAuth protected-resource metadata for the app and acts as the OAuth 2.1 authorization server (the same one that protects the [Remote API and MCP]({{< ref "docs/configuration/remoteaccess" >}}) surfaces).
- Users log in with the app's configured `auth` (the admin account, builtin users, an `[auth.*]` OAuth/OIDC provider such as GitHub or Google, or a `[saml.*]` provider) and approve the client on a consent page. Federated logins refresh the user's group snapshot used by RBAC. Access requires the same `app:access` grant the app's web UI requires when RBAC is on.
- The MCP endpoint accepts only OpenRun-issued bearer tokens bound to that app. Cookies, basic auth and login redirects do not apply there.
- The token is stripped before the request reaches the app. The app receives the usual `X-Openrun-User`, `X-Openrun-User-Id`, `X-Openrun-User-Email` and `X-Openrun-Perms` headers plus `X-Openrun-Scopes` (the granted scopes) and `X-Openrun-Client-Id` (the OAuth client holding the token, or `apikey`).

The app itself implements no authentication. Any MCP server that speaks Streamable HTTP without its own auth works unchanged.

## Deploying an MCP app

Three forms of `--mcp` cover the common layouts. The public MCP URL is always the app URL for the first two.

```sh
# The image serves MCP at / : the whole app is the endpoint
openrun app create --spec image --param image=ghcr.io/example/orders-mcp:1.2 --param port=8080 \
    --auth builtin --mcp /orders

# The image serves MCP at /mcp : the whole app is still the endpoint, OpenRun
# rewrites the app root to /mcp when proxying (note the = syntax)
openrun app create --spec image --param image=ghcr.io/example/orders-mcp:1.2 --param port=8080 \
    --auth builtin --mcp=/mcp /orders

# A mixed app: a web UI at / with normal login, MCP under /mcp, with scopes
openrun app create --auth builtin \
    --mcp='{"path":"/mcp","scopes":["orders:read","orders:write"],"default_scope":"orders:read","tools":{"cancel_order":"orders:write"}}' \
    ./src /shop
```

`--mcp=@file` reads the JSON document from a local file (the CLI expands it; the API only accepts the document itself). `openrun app update mcp <value> <glob>` changes it later (`-` clears it); updates are staged and promoted like other metadata. In apply files the `app()` entry takes `mcp=True`, `mcp="/mcp"` or `mcp={...}`.

The JSON document fields:

| field | meaning |
|---|---|
| `path` | The MCP region within the app, default `/` (whole app). With `/mcp`, only that subtree is the MCP endpoint and the rest of the app keeps its human login |
| `container_path` | The path the upstream serves MCP at when it differs from `path`. Only with `path` `/`; the app root is rewritten to it |
| `scopes` | The app's own scope names, offered at consent and advertised to clients. Omit for unscoped tokens |
| `default_scope` | Advertised in the 401 challenge and granted when the client asks for nothing. Must be in `scopes` |
| `tools` | Tool name to required scope. A `tools/call` for a listed tool needs that scope on the token; unlisted tools need none |
| `allowed_origins` | Browser origins (`scheme://host[:port]`) admitted on the endpoint. Requests with any other `Origin` are refused; native clients send none |

An MCP app needs the OAuth issuer origin configured: `api.external_url`, or `security.callback_url` which it defaults to.

The health check for an MCP app without an explicit `health` path in `container.config` sends an MCP JSON-RPC request to the endpoint instead of a `GET`, since an MCP endpoint does not answer `GET` with 200. On Kubernetes the pod readiness and startup probes are TCP probes on the container port (a native probe cannot send a body), and OpenRun additionally sends its JSON-RPC probe to the new version through a temporary per-version Service before traffic is switched to it; a version that does not answer as an MCP server is removed and the deploy fails, as with any failed health check.

## Connecting a client

Add the app URL to the client. The client discovers the metadata, opens the OpenRun login page in a browser, and receives a token bound to the app:

```sh
claude mcp add --transport http orders https://apps.example.com/orders
```

For clients that cannot run a browser flow (CI agents, server-side tools), mint an API key bound to the app and configure it as a static bearer header:

```sh
openrun apikey create --resource app:/orders                       # unscoped: RBAC alone governs
openrun apikey create --resource app:/orders --scopes orders:read  # limited to the app's scopes
openrun apikey create --resource app:apps.example.com:/orders      # app on a specific domain
```

An app-bound key is valid for exactly that app. Staging and preview apps are separate resources: a token for the production app does not work at the staging URL and vice versa. Use `app:<stage domain>:<path>` for a staging key.

## Scopes and tool policy

Scopes are the app's own vocabulary, not the OpenRun RBAC permissions. At consent the requested scopes are intersected with the app's declared list, unknown scopes are dropped, and the user may narrow the grant. When a listed tool is called with a token lacking its scope, OpenRun answers `403` with a `WWW-Authenticate: Bearer error="insufficient_scope", scope="..."` challenge so the client can re-consent for the missing scope. The operation is read from the JSON-RPC body (requests over 1 MiB, non-JSON or malformed bodies are refused); the `Mcp-Method` and `Mcp-Name` headers that current clients send must agree with the body or the request is rejected.

RBAC decides who may reach the app at all: with RBAC on, the user needs `app:access` on the app (checked at consent and on every call). Scopes only narrow what a specific token may do.

## Transport notes

- The endpoint is served over HTTPS, or behind a trusted TLS-terminating proxy listed in `security.trusted_proxies`. Plaintext requests get a 404, except on `localhost` for local development.
- Browser-based MCP clients need their origin in `allowed_origins`; CORS preflight requests from an allowed origin are passed to the app without a token so the app's CORS handler can answer them.
- Legacy MCP clients that use sessions (`Mcp-Session-Id`, GET streams) pass through unchanged. On Kubernetes with several replicas such clients need a stateless-mode server; OpenRun does not pin sessions to pods.
- Every MCP call is recorded in the app's HTTP audit log with the JSON-RPC method (`mcp_tools/call`) and the tool name.
