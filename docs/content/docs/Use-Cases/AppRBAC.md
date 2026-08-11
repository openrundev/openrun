---
title: "Self-Hosted RBAC for Web Apps"
weight: 300
description: "Enable open-source, self-hosted role-based access control for web apps: platform-level RBAC grants, custom permissions and HTTP headers that let apps implement their own app-specific RBAC."
summary: "Enable RBAC for applications, define custom permissions and pass user roles to apps through HTTP headers."
---

OpenRun provides self-hosted, open-source role-based access control (RBAC) for every deployed web app. RBAC works at two levels:

- **Platform level**: OpenRun checks whether a user is allowed to reach an app at all, using grants defined in the RBAC config. No app code is involved.
- **App level**: OpenRun passes the user identity and the user's custom permissions to the app through HTTP headers on every request. The app uses these to implement its own app-specific RBAC, such as read-only versus editor roles inside the app.

This guide walks through enabling RBAC, defining custom permissions and reading the permission headers in application code. See the [RBAC reference]({{< ref "docs/configuration/rbac/" >}}) for the full config format.

## Scenario

This use case covers the scenario where you want to:

- Require login for a set of internal apps, with access controlled per team
- Give some users read-only access and others write access inside an app
- Keep all authorization rules in one place, managed like the rest of the platform config
- Avoid implementing login, session handling and role storage in each app

Authentication comes from the [OAuth, OIDC or SAML provider]({{< ref "docs/configuration/authentication/" >}}) configured at the server level. RBAC then decides what each authenticated user can do.

## Enabling RBAC

RBAC is part of the [dynamic config]({{< ref "docs/configuration/overview/#dynamic-config" >}}), so enabling or changing it does not require a server restart. A minimal config with app access rules:

```json {filename="dynamic_config.json"}
{
  "version_id": "ver_33erDLffhaXjgibPb5GRb3anN0V",
  "rbac": {
    "enabled": true,
    "roles": {
      "user": ["app:access"]
    },
    "grants": [
      {
        "description": "Engineering can use apps under /engg",
        "users": ["group:engineering"],
        "roles": ["user"],
        "targets": ["/engg/**"]
      }
    ]
  }
}
```

Apply it with:

```sh
openrun server update-config dynamic_config.json
```

The RBAC config can also be managed through the [Console management UI]({{< ref "/console-tour#role-based-access-control" >}}): the configuration page has an RBAC section for editing groups, roles and grants, and changes take effect immediately without a server restart.

When RBAC is enabled, it applies to every app: a user needs an `app:access` grant to reach an app, in addition to passing the app's authentication. Group membership can come from the IdP (OIDC/SAML [group info]({{< ref "docs/configuration/rbac/#group-info" >}})) or be defined statically in the config. The `admin` user always has access.

## Custom Permissions

Permissions like `app:access` and `app:read` are OpenRun-defined: they control what OpenRun itself allows. Custom permissions use the `custom:` prefix and are different: OpenRun ignores them and passes them through to the app. They are how app-specific roles are modeled.

Define roles that carry custom permissions and grant them like any other role:

```json {filename="dynamic_config.json"}
{
  "version_id": "ver_33erDLffhaXjgibPb5GRb3anN0V",
  "rbac": {
    "enabled": true,
    "roles": {
      "viewer": ["app:access", "custom:reports_read"],
      "editor": ["role:viewer", "custom:reports_write"]
    },
    "grants": [
      {
        "description": "Engineering can view reports",
        "users": ["group:engineering"],
        "roles": ["viewer"],
        "targets": ["/engg/reports"]
      },
      {
        "description": "Team leads can edit reports",
        "users": ["group:engg-leads"],
        "roles": ["editor"],
        "targets": ["/engg/reports"]
      }
    ]
  }
}
```

Custom permissions are scoped like the other `app:*` permissions: a grant confers them only on the apps matched by its `targets`. The same user can hold `custom:reports_write` on one app and only `custom:reports_read` on another.

## Permission Headers Passed to Apps

For apps where requests are proxied through OpenRun (like containerized apps), OpenRun sets these headers on every request it forwards to the app:

| Header | Content |
| --- | --- |
| `X-Openrun-User` | The user making the request, prefixed with the provider name, like `oidc_okta:jane@example.com`. `anonymous` for anonymous requests, `admin` for admin requests |
| `X-Openrun-User-Id` | The provider user ID claim when available; for OIDC providers this is the `sub` claim |
| `X-Openrun-User-Email` | The provider email claim, when available |
| `X-Openrun-Perms` | Comma-separated list of the custom permissions this user holds on this app, without the `custom:` prefix, like `reports_read,reports_write` |
| `X-Openrun-Rbac-Enabled` | Whether RBAC is enabled for the app, `true` or `false` |

OpenRun strips any `X-Openrun-*` headers from the incoming request before setting its own values, so clients cannot inject identity or permissions. The app container should only be reachable through OpenRun (the default for OpenRun-managed containers); do not separately publish the app's port on the network.

## Implementing App-Specific RBAC

The app reads the headers and enforces its own rules. No login flow, session handling or role storage is needed in the app; every request arrives with the user and their permissions. For example, in a FastAPI app:

```python {filename="main.py"}
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

def require_perm(request: Request, perm: str):
    if request.headers.get("x-openrun-rbac-enabled") != "true":
        return  # RBAC not enabled, apply app defaults
    perms = request.headers.get("x-openrun-perms", "").split(",")
    if perm not in perms:
        raise HTTPException(status_code=403, detail=f"needs {perm} permission")

@app.get("/api/reports")
def list_reports(request: Request):
    require_perm(request, "reports_read")
    return load_reports()

@app.post("/api/reports")
def create_report(request: Request):
    require_perm(request, "reports_write")
    user = request.headers.get("x-openrun-user")
    return save_report(created_by=user)
```

The same pattern works in any language or framework: read `X-Openrun-Perms` for authorization decisions and `X-Openrun-User` for attribution, audit records or per-user data. In a Streamlit app, use `st.context.headers` to read the same values and hide or show UI elements based on the permission list.

Since the permission names are opaque to OpenRun, apps define whatever vocabulary fits: `reports_read`/`reports_write`, `approve`, `tenant_admin` and so on. Changing who holds a permission is a config change in the RBAC grants, applied without touching the app or restarting the server.

## Custom Permissions in Actions and Plugins

For [Action apps]({{< ref "docs/actions/" >}}), the permission check is declarative. Setting `permit=["reports_write"]` on an action definition makes that action visible and runnable only for users holding one of the listed custom permissions. If no permits are set, or RBAC is not enabled for the app, all actions are available to authenticated users.

For Starlark apps, plugin calls can be gated the same way with `ace.permission(..., permit=["reports_write"])`: when RBAC is enabled, the call is allowed only if the user holds one of the listed custom permissions.

## Testing Without an Identity Provider

To try RBAC policies without setting up OAuth or SAML, use [builtin users]({{< ref "docs/configuration/authentication/#builtin-users" >}}):

```sh
openrun user add alice --groups engineering
openrun app update --auth builtin /engg/reports
curl -u alice:password https://localhost:25223/engg/reports/api/reports
```

The user id in grants is `builtin:alice`, and the groups on the user entry are matched by `group:` references like SSO groups. To test management API grants, run CLI commands as another user with `openrun --as builtin:alice app list`. See [Testing RBAC with Builtin Users]({{< ref "docs/configuration/rbac/#testing-rbac-with-builtin-users" >}}) for details.

## Frequently Asked Questions

### Is OpenRun's RBAC open source?

Yes. RBAC is part of the Apache-2.0 licensed OpenRun platform, fully self-hosted with no external authorization service.

### Do apps need code changes for platform-level RBAC?

No. Controlling which users can reach which apps is done entirely with grants in the RBAC config. App code changes are only needed for app-specific rules, using the permission headers.

### How do apps know the user's roles?

OpenRun passes the user identity and the user's custom permissions for that app in the `X-Openrun-User` and `X-Openrun-Perms` HTTP headers on every proxied request. The app checks the permission list to enforce its own rules.

### Can the headers be spoofed?

OpenRun removes any `X-Openrun-*` headers from incoming requests before setting its own values. As long as the app container is only reachable through OpenRun, apps can trust the headers.

### Does this work with Okta, Entra or other identity providers?

Yes. Authentication uses the configured OAuth, OIDC or SAML provider, and IdP groups can be referenced directly in grants. See [Group Info]({{< ref "docs/configuration/rbac/#group-info" >}}).
