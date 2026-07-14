---
title: "Role Based Access Control"
weight: 500
summary: "Controlling access to applications using RBAC"
---

## RBAC Overview

Role based access controls (RBAC) allows fine-grained control on which users are allowed to view, access and update apps. RBAC is supported using [OAuth]({{< ref "/docs/configuration/authentication/#oauth-authentication" >}}) based auth (like GitHub, GitLab etc). When using OAuth, users have to be explicitly added to groups in the OpenRun RBAC config. RBAC is also supported for [OpenID Connect]({{< ref "/docs/configuration/authentication/#openid-connect-oidc" >}}) and [SAML]({{< ref "/docs/configuration/authentication/#saml" >}}), like Okta and Microsoft Entra etc. With OIDC, the group information can be detected automatically through the user profile information or it can be explicitly configured in the OpenRun config.

## Authentication versus Authorization

RBAC is used for multiple authorization checks, like `list` (view app info), `access` (access the app) and various update related actions. When RBAC is enabled at the system level, by default RBAC is used for the list and update actions. App access is controlled by the authentication check alone. For example, if app is using `google` for auth, any user who can login to the google account can access the app. If app access also needs to be controlled using RBAC, then the app auth needs to be changed to `rbac:google`. With that change, only users having `access` grant on the app can access the app.

## RBAC Configuration

The RBAC configuration is managed through [dynamic config]({{< ref "docs/configuration/overview/#dynamic-config" >}}). The structure of the RBAC config is

```json
{
  "version_id": "ver_32wLWdqboA08eCRDO1KEznxBxka",
  "rbac": {
    "enabled": true,
    "groups": {
      "group1": ["github_local:abc", "oidc_oktatest:def@example.com"],
      "group2": ["group:group1", "oidc_oktatest:xyz@example.com"]
    },
    "roles": {
      "accessor": ["access"],
      "viewer": ["list"],
      "fullaccess": ["role:accessor", "list"]
    },
    "grants": [
      {
        "description": "view on all apps",
        "users": ["group:group1", "github_local:xyz"],
        "roles": ["viewer"],
        "targets": ["all"]
      },
      {
        "description": "access on one app",
        "users": ["group:mygroup"],
        "roles": ["fullaccess"],
        "targets": ["example.com:/myapp"]
      }
    ]
  }
}
```

If `enabled` is `false` (default), RBAC is not used. `groups` is a map of group name to group members. Members are user ids, prefixed with the auth provider name. Group composition is supported, for example group2 includes all group1 users. `roles` is a map of role name to permissions. Roles also can be composed, for example role `fullaccess` gets all permissions of role `accessor`.

## Built-in Roles

In addition to any roles you define, OpenRun ships a set of built-in roles that are always available. Their names all use the reserved `openrun-` prefix — user-defined role names may not start with `openrun-`. They can be referenced directly in grants, or composed into your own roles with the `role:` prefix (for example `"team-lead": ["role:openrun-developer", "approve"]`). Because a role mixes app-scoped and global permissions, grant these with `targets: ["all"]` for their global permissions to take effect (see [Permission Scope](#permission-scope)).

| Role | Purpose | Highlights |
|------|---------|------------|
| `openrun-admin` | Unrestricted super-user; bypasses every check | the `admin` permission |
| `openrun-operator` | Runs the platform | full app lifecycle, `approve`, sync, services, bindings, container management, config, secrets (incl. reveal), audit, server stop, builder |
| `openrun-developer` | Builds and deploys apps | `app:manage`, services/bindings, `container:read`, `sync:run`/`read`, `secret:create`/`read`, audit — no `approve`, config, secret reveal, server stop, or builder |
| `openrun-builder` | A developer who also uses the AI app builder | everything in `openrun-developer` plus `builder:*` |
| `openrun-user` | Baseline authenticated user | `access` and `read` |
| `openrun-monitor` | Read-only observability | read access across apps, audit, containers, sync, services, bindings, config, and secret metadata (no reveal, no writes) |

Users have no permissions by default. Grants have to be added for each permission. A grant has a:

- `description` which is a note about the grant
- `users` which is list of users or groups
- `roles` which is list of roles granted
- `targets` which is the [glob path]({{< ref "/docs/applications/overview/#glob-pattern" >}}) list of apps to which the grant applies.

The group name referenced in a grant can be a group which is seen at runtime in the user profile. This works for [OIDC]({{< ref "/docs/configuration/authentication/#openid-connect-oidc" >}}) based auth, like Okta.

## Permission Scope

Most permissions are **app-scoped**: `access`, `read`, `create`, `update`, `reload`, `apply`, `delete`, `promote`, `preview` and `app:manage` (the composite of all app permissions except `approve`) apply to the apps matched by the grant's `targets`. The rest are **global** (`sync:*`, `service:*`, `binding:*`, `container:*`, `config:*`, `secret:*`, `builder:*`, `audit:read`, `server:stop`, `approve`, `admin`); a global permission only takes effect when the grant's `targets` cover all apps (`all` or `*:**`). `admin` is the super-user permission that bypasses every check.

`approve` is a global, operator-only permission that authorizes approving an app's plugin permissions (which run server-side code, so it is not scoped per app). It is never implied by `app:manage` or by a permission glob — it has to be granted by its literal name (or held via the `admin` super-user permission, e.g. the `openrun-admin` role). Setting the `--approve` flag on a create/reload/apply, or calling approve directly, requires this permission. (`approve` was previously named `app:approve`; the old name is still accepted in config and normalized to `approve`.)

## Group Info

To get the group info dynamically as part of the user login (instead of statically defining in the config file), the requirements are:

- OpenID Connect-based auth or SAML is used
- For OpenID, the appropriate scope is requested, like `groups`
- The Identity Provider is configured to return the groups info in the user profile, with the `groups` key. For example, see [Okta forum](https://devforum.okta.com/t/userinfo-not-returning-groups/31907/1) about configuring Okta with OIDC.
- The group name as returned in the user profile is used in the grant

## Regex User Name

In the `groups.<group_name>` property and in `grant.users`, the username can be specified as a regex. If the value starts with `regex:` prefix, the subsequent value is considered as a regex. For example, `regex:google:^.*@example.com$` matches any user ID with google provider.

## Custom Permissions

Permissions like `access`, `list`, `update` etc are OpenRun-defined permissions. They control what actions can be performed by the user in OpenRun. In addition to these, custom permissions are supported. Custom permissions are defined in the config with the `custom:` prefix. These permissions are ignored by OpenRun. They are passed to the app. For apps where requests are proxied through OpenRun (like containerized apps), these permissions are available in the HTTP headers

- `X-Openrun-User`: This is the user performing the request. The user ID is prefixed with the provider name (like `google:test@example.com`). The username is `anonymous` for anonymous requests and `admin` for admin requests.
- `X-Openrun-User-Id`: The provider user ID claim, when available. For OIDC providers this is the `sub` claim.
- `X-Openrun-User-Email`: The provider email claim, when available.
- `X-Openrun-Perms`: The list of custom permissions available to this user on this app. The list is comma-separated, without the `custom:` prefix, like `appread,appdelete`.
- `X-Openrun-Rbac-Enabled`: Whether RBAC is enabled for the app, `true` or `false`

For [Action apps]({{< ref "Actions" >}}), custom perms can be used to limit which user can perform what operations. In the action definition, adding `permit=['appread']` means that the action will be available only to users who have any one of the custom permissions specified in the list. The default action should be available to everyone, other actions can be controlled using custom permissions. If no permits are set or if RBAC is not enabled for the app, then all actions are available to authenticated users.

Plugin calls can use the same custom permissions with `ace.permission(..., permit=['appread'])`. When RBAC is enabled for the app, the call is allowed only if the user has at least one listed custom permission. If the permit list is empty or RBAC is not enabled, plugin permissions behave normally.

## Notes

- The auth provider name has to be prefixed with `rbac:` for the RBAC rules to apply for app `access` permission.
- Updates using the CLI client are done as the `admin` system user. There are no RBAC restrictions on the `admin`.
- For apps with no authentication (using `none` auth), the user ID to use in RBAC is `anonymous`, without the auth type prefix.
