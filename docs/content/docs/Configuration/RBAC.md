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

Users have no permissions by default. Grants have to be added for each permission. A grant has a:

- `description` which is a note about the grant
- `users` which is list of users or groups
- `roles` which is list of roles granted
- `targets` which is the [glob path]({{< ref "/docs/applications/overview/#glob-pattern" >}}) list of apps to which the grant applies.

The group name referenced in a grant can be a group which is seen at runtime in the user profile. This works for [OIDC]({{< ref "/docs/configuration/authentication/#openid-connect-oidc" >}}) based auth, like Okta.

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
- `X-Openrun-Perms`: The list of custom permissions available to this user on this app. The list is comma-separated, without the `custom:` prefix, like `appread,appdelete`.
- `X-Openrun-Rbac-Enabled`: Whether RBAC is enabled for the app, `true` or `false`

For [Action apps]({{< ref "Actions" >}}), custom perms can be used to limit which user can perform what operations. In the action definition, adding `permit=['appread']` means that the action will be available only to users who have any one of the custom permissions specified in the list. The default action should be available to everyone, other actions can be controlled using custom permissions. If no permits are set or if RBAC is not enabled for the app, then all actions are available to authenticated users.

## Notes

- The auth provider name has to be prefixed with `rbac:` for the RBAC rules to apply for app `access` permission.
- Updates using the CLI client are done as the `admin` system user. There are no RBAC restrictions on the `admin`.
- For apps with no authentication (using `none` auth), the user ID to use in RBAC is `anonymous`, without the auth type prefix.
