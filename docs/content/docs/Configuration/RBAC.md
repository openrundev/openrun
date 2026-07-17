---
title: "Role Based Access Control"
weight: 500
summary: "Controlling access to applications using RBAC"
---

## RBAC Overview

Role based access controls (RBAC) allows fine-grained control on which users are allowed to view, access and update apps. RBAC is supported using [OAuth]({{< ref "/docs/configuration/authentication/#oauth-authentication" >}}) based auth (like GitHub, GitLab etc). When using OAuth, users have to be explicitly added to groups in the OpenRun RBAC config. RBAC is also supported for [OpenID Connect]({{< ref "/docs/configuration/authentication/#openid-connect-oidc" >}}) and [SAML]({{< ref "/docs/configuration/authentication/#saml" >}}), like Okta and Microsoft Entra etc. With OIDC, the group information can be detected automatically through the user profile information or it can be explicitly configured in the OpenRun config.

## Authentication versus Authorization

RBAC is used for multiple authorization checks, like `app:read` (view app info), `app:access` (access the app) and various update related actions. When RBAC is enabled at the system level, it applies to **every app**: a user needs an `app:access` grant to reach an app, in addition to passing the app's authentication. For example, if an app uses `google` for auth, a user who can log into the Google account still needs an `app:access` grant on the app to reach it. The `admin` user, and any user holding the `admin` permission, always have access.

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

In addition to any roles you define, OpenRun ships a set of built-in roles that are always available. Their names all use the reserved `openrun-` prefix — user-defined role names may not start with `openrun-`. They can be referenced directly in grants, or composed into your own roles with the `role:` prefix (for example `"team-lead": ["role:openrun-developer", "app:approve"]`). A role mixes scoped (`app:*`) and global permissions: the scoped ones apply to the grant's `targets`, the global ones apply regardless of the targets (see [Permission Scope](#permission-scope)).

| Role | Purpose | Highlights |
|------|---------|------------|
| `openrun-admin` | Unrestricted super-user; bypasses every check | the `admin` permission |
| `openrun-operator` | Runs the platform | full app lifecycle, `app:approve`, sync, services, bindings, container management, config, secrets (no reveal), audit, server stop, builder |
| `openrun-developer` | Builds and deploys apps | `app:manage`, services/bindings (no delete), `container:read`, `sync:run`/`read`, `secret:create`/`read`, `config:basic_read` (for the create/update forms) — no `app:approve`, full config, audit, secret delete/reveal, server stop, or builder |
| `openrun-builder` | A developer who also uses the AI app builder | everything in `openrun-developer` plus `builder:*` |
| `openrun-user` | Baseline authenticated user | `access` and `read` |
| `openrun-monitor` | Read-only observability | read access across apps, audit, containers, sync, services, bindings, config, and secret metadata (no reveal, no writes) |

`secret:reveal` (reading back stored secret values) and `binding:reveal` (reading back binding account credentials with `binding show-account`) are not included in any built-in role other than `openrun-admin` (whose `admin` permission bypasses every check). Users who need to read these values back must be granted `secret:reveal` / `binding:reveal` explicitly.

Users have no permissions by default. Grants have to be added for each permission. A grant has a:

- `description` which is a note about the grant
- `users` which is list of users or groups
- `roles` which is list of roles granted
- `targets` which is the list of targets the grant's scoped permissions apply to. A plain entry is an app [glob path]({{< ref "/docs/applications/overview/#glob-pattern" >}}) (`domain:path` format) matching apps. A `service:<glob>` entry matches service ids in the `<type>/<name>` form, without a leading slash: `service:postgres/*` matches `postgres/main`, `service:**` matches all services. A `binding:<glob>` entry matches binding paths: `binding:/apps/team1/**`. The `all` keyword (or `*:**`) matches every app, service and binding.

The group name referenced in a grant can be a group which is seen at runtime in the user profile. This works for [OIDC]({{< ref "/docs/configuration/authentication/#openid-connect-oidc" >}}) based auth, like Okta.

## Permission Scope

The `app:*` permissions are **scoped**: `app:access`, `app:read`, `app:create`, `app:update`, `app:reload`, `app:apply`, `app:delete`, `app:promote`, `app:preview`, `app:approve`, `app:manage` (the composite of all app permissions except `app:approve`) apply only to the apps matched by the grant's app path `targets`. Custom (`custom:`) app-level permissions are scoped the same way.

The `service:*` and `binding:*` permissions are scoped too, against the grant's `service:<glob>` and `binding:<glob>` target entries: `service:create`, `service:update`, `service:delete`, `service:read`, `service:bind` (provision binding accounts on the service, needed to create base/auto bindings from it) and the `service:manage` composite apply to the services matched by the grant's `service:` targets; `binding:create`, `binding:update`, `binding:delete`, `binding:read`, `binding:run_command`, `binding:use` (attach the binding to an app, or derive a new binding from it), `binding:reveal` (read back the binding account credentials) and the `binding:manage` composite apply to the bindings matched by the grant's `binding:` targets. Like `app:approve`, `binding:reveal` is never implied by `binding:manage`: it needs an explicit grant, and binding owners do not hold it by default (add it to `owner_permissions.binding` to opt owners in). A grant whose targets only name app paths confers no service or binding permissions; use `service:**` / `binding:/**` entries (or `all`) to grant them broadly. Attaching a binding to an app requires `binding:use` on the binding (or `service:bind` on the service for auto bindings created from a service source), in addition to the app permission for the app update itself. Service and binding list operations return only the entries the user can read.

Every other permission is **global** (`builder:*`, `sync:*`, `container:*`, `config:*`, `secret:*`, `audit:read`, `server:stop`, `admin`): a grant confers a global permission **regardless of its `targets`**. `admin` is the super-user permission that bypasses every check.

The creator of a service or binding holds the configured owner permissions on it (default `service:manage` / `binding:manage`) without needing a grant, like app and sync owners. Override with `owner_permissions.service` / `owner_permissions.binding`.

The `builder:*` permissions are global because a builder session is not bound to an app path until it publishes. The app a session publishes, edits or removes is enforced separately with the app permissions on that path: publishing to a new path needs `app:create`, republishing an existing app needs `app:update`, and unpublishing needs `app:delete` (local mode publishes also run through the declarative apply, which enforces `app:apply`, `app:promote` and `app:approve` before any file is staged). The preview dev app a session creates under the configured `preview_path` is authorized by `builder:create` itself — no app permission is needed for the preview mount — and is owned by the session creator, so the owner rule covers viewing the preview and deleting it with the session.

`app:approve` is the operator-only permission that authorizes approving an app's plugin permissions (which run server-side code). It is scoped like the other `app:*` permissions — a grant confers it only on the apps matched by its `targets` — but it always needs an explicit grant: it is never implied by `app:manage`, never matched by a permission glob and never granted through ownership; it has to be granted by its literal name (or held via the `admin` super-user permission, e.g. the `openrun-admin` role). Setting the `--approve` flag on a create/reload/apply, or calling approve directly, requires this permission on every matched app. Creating a sync entry with `approve` set requires `app:approve` granted with target `all`, since the entry's glob can match apps created later.

## Sync Jobs and Background Runs

A [sync entry]({{< ref "/docs/applications/overview" >}}) runs declarative applies in the background, without an authenticated user. When a sync is created through an RBAC enforced request, the creator's authorization is frozen on the entry: the grants matching the creator (with group membership, including SSO provided groups, resolved at create time and role permissions flattened) are stored in the sync metadata. Every scheduled run is then authorized against that snapshot — each apply, reload and promote the run performs needs the corresponding permission (`app:apply`, `app:promote`, `app:approve`) on that app in the frozen grants, and a denied action fails the run (counting toward the sync failure backoff and eventual disable).

Notes on the snapshot behavior:

- The snapshot is frozen at create time. Later edits to roles, groups or grants do not change what an existing sync may do — delete and recreate the sync to pick up new grants.
- Syncs created via the CLI (`admin` over the unix socket) or with RBAC disabled store no snapshot and run unrestricted, as before.
- Disabling RBAC disables snapshot enforcement too; re-enabling it restores enforcement for entries that have a snapshot.
- A sync created by a user holding the `admin` permission runs unrestricted (the snapshot just records the admin status).
- Manual `sync run` calls are authorized against the caller's own current grants, not the stored snapshot.
- The creator of a sync entry keeps the `sync:run`, `sync:delete` and `sync:read` owner permissions on it.

## Group Info

To get the group info dynamically as part of the user login (instead of statically defining in the config file), the requirements are:

- OpenID Connect-based auth or SAML is used
- For OpenID, the appropriate scope is requested, like `groups`
- The Identity Provider is configured to return the groups info in the user profile, with the `groups` key. For example, see [Okta forum](https://devforum.okta.com/t/userinfo-not-returning-groups/31907/1) about configuring Okta with OIDC.
- The group name as returned in the user profile is used in the grant

## Testing RBAC with Builtin Users

To try out RBAC policies with multiple users and groups without setting up an OAuth/SAML provider, use the [builtin auth type]({{< ref "Authentication#builtin-users" >}}). Create users with groups using `openrun user add alice --groups dev,qa` (no server restart needed), point an app at it with `--auth builtin`, and exercise grants with `curl -u alice:password`. The user id in grants is `builtin:alice`; the groups on the user entry are matched by `group:` references like SSO groups.

### Testing management API grants with --as

To test the management API side of a policy (app/service/binding/secret operations, list filtering, the owner rule), run CLI commands as another user with the global `--as` flag:

```shell
openrun --as builtin:alice app list
openrun --as builtin:alice service create --config url=... postgres/teamdb
```

The call is authorized against the named user's current grants instead of running as the trusted `admin`, and audit events record that user. `--as` requires RBAC to be enabled and works only over the unix domain socket (the caller is already the administrator; impersonation only ever narrows authority, no password is needed). For `builtin:` users the entry must exist and its groups feed `group:` matching; any other `<provider>:<username>` id (like `github:user1`) is taken literally with no groups, so grants for SSO identities can be tested without creating the users.

## Regex User Name

In the `groups.<group_name>` property and in `grant.users`, the username can be specified as a regex. If the value starts with `regex:` prefix, the subsequent value is considered as a regex. The pattern must match the entire user ID (it is evaluated fully anchored, as if wrapped in `\A(?:...)\z`), so a partial match does not grant access: `regex:google:.*@example\.com` matches any user ID with the google provider and an example.com email, and does not match `google:user@example.com.attacker.io`.

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

- When RBAC is enabled, it applies to every app: users need an `app:access` grant to reach an app. (The `rbac:` auth prefix is still accepted for backward compatibility but no longer has any special effect.)
- Updates using the CLI client are done as the `admin` system user. There are no RBAC restrictions on the `admin`.
- For apps with no authentication (using `none` auth), the user ID to use in RBAC is `anonymous`, without the auth type prefix.
