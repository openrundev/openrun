---
title: "App Authentication"
weight: 400
summary: "Details about authentication mechanisms for app access, including OAuth based auth"
---

Each app has an auth type which decides who can reach it. This page covers the login page and sessions, builtin users, the server-wide defaults, forward auth, client certificates, and the OAuth/OIDC and SAML providers.

{{< theme-image light="/d2/auth_flow_light.svg" dark="/d2/auth_flow_dark.svg" alt="Request flow: the browser request is authenticated according to the app's auth type, with a login redirect to the identity provider for OAuth, OIDC and SAML types, then authorized against the RBAC grants, then handed to the app" >}}

| Auth type | Who logs in |
| :--- | :--- |
| `none` | nobody, the app is open (the default for new apps) |
| `system` | the `admin` account. The password is displayed on the screen during the initial setup of the OpenRun server config |
| `builtin` | the server-managed accounts of [Builtin Users](#builtin-users) |
| `<provider>` (`github_prod`, `oidc_oktatest`, ...) | an [OAuth/OIDC provider](#oauth-authentication) configured as `[auth.<name>]` |
| `saml_<name>` | a [SAML provider](#saml) configured as `[saml.<name>]` |
| `cert` or `cert_<name>` | a [client certificate](#client-cert-authentication-mtls) config `[client_auth.cert_<name>]` |
| `<type>+forward_<name>` | any of the above, followed by a [forward auth](#forward-auth) check |

To set the auth type, add `--auth system` to the app create command. After an app is created, the auth type can be changed by running `app update auth --promote system /myapp`.

## Login Page

For the `system` and `builtin` auth types, browser access to an app shows an HTML login page (stating whether the app uses the system admin account or OpenRun builtin accounts) and redirects back to the original app URL after sign in. The authenticated session is stored in a cookie on the app's domain.

| Setting | Default | Meaning |
| :--- | :--- | :--- |
| `security.session_max_age` | 86400 seconds (one day) | Session lifetime, the same as SSO sessions. It is an idle timeout: a session that is in use is renewed (once it is past half of its lifetime), so it only expires after `session_max_age` without activity |
| `security.session_absolute_max_age` | one week | Caps the total lifetime from login regardless of activity. 0 disables the cap |

Both settings apply to all session-based auth types and are read at startup.

- **Login page validity:** the login page itself stays valid for one hour. A form submitted later than that (or submitted twice) shows a "sign-in request has expired" message with a link back to the app, which starts a fresh sign in.
- **Live re-validation:** sessions are re-validated against the live config on every request. Changing or removing a user's password, deleting a builtin user or changing the admin username signs the affected sessions out immediately.
- **Signing out** is done through the `/_openrun/logout` page on the app domain (see below).
- **Non-browser clients are unaffected:** requests carrying an HTTP Basic `Authorization` header (or not requesting `text/html`) authenticate with Basic auth as before, so `curl -u` and API clients keep working. The Basic credentials are consumed by OpenRun and the `Authorization` header is removed before the request reaches the app, a proxied container or a forward auth service. Other `Authorization` schemes (e.g. an app's own `Bearer` token) are passed through to the app once the session cookie has authenticated the request.

### Signing out

A single sign-out page is served on the app domain at `/_openrun/logout`, and it logs the user out **regardless of how they signed in** (`system`, `builtin`, OAuth/OIDC or SAML). Every auth type stores its session as a per-provider cookie on the app domain, so the page clears whichever OpenRun session cookies the request carries without needing to know the provider.

- `GET` shows a confirmation ("Signed in as … · Sign out") and `POST` clears the sessions and shows a "signed out" page.
- Apps just link to `/_openrun/logout`, optionally with a return target: `/_openrun/logout?redirect=<app path>` (validated to be same-host, so it cannot be used as an open redirect).
- The signed-in identity on the confirmation comes from the session cookie the request already carries.
- The low-level `POST /_openrun/logout/<provider>` route remains for callers that want to target one provider.

{{< callout type="info" >}}
For SSO, clearing the local cookie ends the OpenRun session but does not perform IdP-side single logout (SAML SLO / OIDC end-session), so a subsequent login may complete silently through the IdP's own session.
{{< /callout >}}

### Auth callback domain

The login page is served only from a dedicated **auth callback domain**, so an app's own JavaScript can never be same-origin with the credential form.

- The domain is `security.auth_callback_domain` (default `auth.`): a trailing `.` is a prefix combined with `system.default_domain` (giving `auth.<default_domain>`), and a value without a trailing `.` is used as a full domain.
- No apps can be created on this domain, and the login page is served under a strict Content-Security-Policy with framing disabled.
- The domain must resolve to the OpenRun server (add a DNS record or wildcard alongside your app domains).
- The same domain serves the login and consent pages of the OAuth authorization server used by the [remote CLI and MCP clients]({{< ref "remoteaccess" >}}), for the same reason.

### Login rate limit

A client IP may start at most `security.login_start_rate_limit` login handshakes per minute (default 60; 0 disables the limit), across the form login, OAuth/OIDC and SAML types: each start records login state in the metadata database, which an anonymous client must not be able to grow at will. Further starts within the minute get a 429 response. Set the limit higher when many users share one address and the server is not behind a proxy listed in `trusted_proxies`.

Failed password checks are limited separately: a client IP may fail at most `security.login_failure_rate_limit` checks of the admin password or a builtin user password per minute (default 100; 0 disables the limit).

- **Shared count:** HTTP Basic credentials sent to a `system` or `builtin` app, the login form and the password page of the OAuth authorization server all count against the same limit.
- **When reached:** further password checks from that IP get a 429 response for the rest of the minute, without the password being checked.
- **Purpose:** this bounds online password guessing per source address, independently of the builtin user lockout.

{{< callout type="warning" >}}
All clients behind one address share the budget: when many users share an address, or the server is behind a proxy which is not listed in `trusted_proxies`, a script retrying a stale password can block password logins for everyone at that address, so raise the limit or configure `trusted_proxies`.
{{< /callout >}}

{{% details title="Which requests start an OAuth/OIDC or SAML login" closed="true" %}}
Only a request the user will see the result of starts an OAuth/OIDC or SAML login:

- a top level navigation (`Sec-Fetch-Mode: navigate`, or, where the browser sends no fetch metadata, a request accepting `text/html`), or
- an HTMX request (which turns the `HX-Redirect` into one).

A background request reaching an app without a usable session, such as a service worker script update, a `fetch` or `EventSource` poller of a tab whose session expired, or a prefetch, gets a plain `401` instead: it changes no cookie, writes no login state and does not count against the rate limit. Starting a login from such a request would overwrite the pre-auth cookie of a login the user is completing in another tab and fail it. App code can treat the `401` as a signal to reload the page, which starts the login as a navigation.

Two cases cannot be told apart from a navigation and still start a login: HTMX pollers (`hx-trigger="every ..."`), and, without fetch metadata, a background `GET` asking for `text/html`.
{{% /details %}}

### Disabling the login form

Set `security.disable_login_form = true` to turn the login page off and use the plain HTTP Basic challenge for browsers too (`auth_callback_domain` is then unused).

The form is also skipped (falling back to the Basic challenge) when `security.session_https_only` is set but the app request arrives over plain HTTP, unless both the app host and the auth callback domain are local (`localhost`, loopback or `*.localhost`): the secure session cookie could not be returned, and credentials must not be sent to a remote login page over cleartext.

## Builtin Users

The `builtin` auth type provides simple username/password authentication, without requiring an OAuth/OIDC/SAML provider. Builtin users are accounts managed by the server (stored in the metadata database) with the `openrun user` commands; changes take effect immediately, without a server restart:

```sh
openrun user add alice --groups dev,qa    # a random password is generated and printed
openrun user add bob --prompt             # prompt for the password
openrun user add carol --value mypassword # password on the command line
openrun user update alice --value newpass # change the password, keep the groups
openrun user update alice --groups dev    # change the groups, keep the password
openrun user update alice --disable       # refuse logins; --enable turns the user back on
openrun user update alice --unlock        # clear a lockout after repeated failed logins
openrun user show alice
openrun user list
openrun user delete alice                 # also revokes the user's API keys
```

- **Using it:** apps use this auth type with `--auth builtin`. Browsers get a login page; other clients authenticate with HTTP Basic auth, so `curl -u alice:mypassword https://example.com:25223/myapp` works.
- **RBAC:** for [RBAC]({{< ref "RBAC" >}}), the user id is `builtin:alice` and the user's groups are matched by `group:` references in grants, the same way SSO provider groups are.
- **Permissions:** managing users requires the `user:manage` permission (or the individual `user:read`, `user:create`, `user:update` and `user:delete` permissions); the `openrun-operator` role includes it. Creating or changing a user is a route to every permission its groups carry, so the write permissions must be named literally in API key scopes. Placing a user in a group that confers the `admin` permission (or removing one from it) additionally requires `admin:manage`, see [Managing admins]({{< ref "RBAC#managing-admins" >}}).

| Rule | Detail |
| :--- | :--- |
| Passwords | Sent to the server as entered and hashed there with argon2id (bcrypt hashes from earlier versions are accepted and upgraded on the user's next login). 8 to 128 characters, may not equal the username |
| Usernames | 1 to 64 characters, start with a letter or digit, continue with letters, digits and `. _ @ + -`, case sensitive. May not be `admin`, `anonymous` or start with `openrun-` |
| Lockout | After ten consecutive wrong passwords the account is locked for 15 minutes (`openrun user update <name> --unlock` clears it) |
| Sessions | A password change, disable or delete signs the user out of existing browser sessions immediately |

Builtin users are intended for small deployments and for testing RBAC policies with multiple users and groups; prefer OAuth/OIDC/SAML for production single sign-on.

{{% details title="Deprecated builtin_auth config section" closed="true" %}}
A `[builtin_auth.<username>]` section in `openrun.toml` (a `password` hash plus `groups`) is deprecated. Its entries are imported as users when the server starts and no user of that name exists; an existing user is never changed from the config file, and the section will be removed in a later release. Move such users to `openrun user` and delete the section.
{{% /details %}}

## Default Authentication Type

Any app when created uses the default auth type configured for the server. `none` is the default. To change this, add

```toml {filename="openrun.toml"}
[security]
app_default_auth_type = "github_prod"
```

assuming there is a `github_prod` OAuth config. Any new app created will use this as the auth unless overridden in the `app create` call or using `app update`.

## Require Authentication for All Apps

To require every app to use some form of authentication, set `auth_required` in the `security` section:

```toml {filename="openrun.toml"}
[security]
auth_required = true
```

When this is enabled, any app with `auth="none"` is denied at request time with `401 Authentication required`. This check happens when the app is accessed, not when the app metadata is created or updated.

Use this as a server-wide guardrail against accidentally exposing apps without authentication. The app can still use any supported auth mode such as `system`, OIDC/OAuth, SAML, mTLS, or the configured `app_default_auth_type`.

## Forward Auth

Forward auth lets OpenRun authenticate the user first, then call an external authorization service before the request is sent to the app. Use it when authentication should stay in OpenRun, but per-request authorization policy is owned by another service.

Forward auth is configured as a named `forward` entry in `openrun.toml`:

```toml {filename="openrun.toml"}
[forward.internal]
auth_url = "http://authz.internal:8080/check"
forward_headers = ["Authorization", "Cookie"]
copy_response_headers = ["Remote-User", "Remote-Email>X-Auth-Email"]

[system]
forward_auth_timeout_secs = 30
```

The forward config name is enabled on an app by adding `+forward_<name>` to the app auth type. For example:

```sh
openrun app create --auth=system+forward_internal --spec python-flask ./myapp /myapp
openrun app update auth --promote github_prod+forward_internal /myapp
```

In this example, OpenRun first performs `system` or `github_prod` authentication. If that succeeds, OpenRun sends a `GET` request to `auth_url`:

- A `2xx` response allows the request to continue to the app.
- Any non-`2xx` response denies the request; OpenRun returns the auth server status, headers, and body to the client.

The auth request includes these request context headers:

- `X-Forwarded-Method`: the original request method
- `X-Forwarded-Proto`: the original request scheme, honoring `security.trusted_proxies`
- `X-Forwarded-Host`: the original request host
- `X-Forwarded-Uri`: the original request path and query string
- `X-Forwarded-For`: the resolved client IP
- `X-Real-IP`: the resolved client IP

OpenRun also sends trusted identity and authorization context headers to the auth server:

- `X-Openrun-User` : The user making the API call, prefixed with provider name, like `google:test@example.com`
- `X-Openrun-User-Stripped` : The user without the provider name prefix, like `test@example.com`
- `X-Openrun-User-Id`
- `X-Openrun-User-Email`
- `X-Openrun-Perms`
- `X-Openrun-Rbac-Enabled`

Client-supplied `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, and `X-Openrun-*` values are not trusted. OpenRun removes them before setting its own values.

| Setting | Default | Meaning |
| :--- | :--- | :--- |
| `forward_headers` | empty: all request headers except hop-by-hop headers are copied | Which original client request headers are copied to the auth request. Set it explicitly when the auth service only needs selected headers such as `Authorization` or `Cookie` |
| `copy_response_headers` | no headers | Which headers from a successful auth response are copied into the request sent to the app. Use `Source>Target` to rename a header while copying it, as shown with `Remote-Email>X-Auth-Email` above. Headers from deny responses are sent back to the client with the deny response |
| `system.forward_auth_timeout_secs` | `30` seconds (also when set to zero or less) | Timeout for forward auth requests |

## Client Cert Authentication (mTLS)

Apps can be updated to use mutual TLS authentication:

1. Set `disable_client_certs` to `false` in the `https` section.
2. Add a `client_auth` config entry in server config with the CA certificate to verify against. Multiple entries can be added; the entry name should be `cert` or should start with `cert_`.
3. Update the app to use that entry: `app update auth --promote cert_test1 /myapp` or `app update auth --promote  cert_test2 /myapp`.

For example

```toml {filename="openrun.toml"}
[https]
disable_client_certs = false

[client_auth.cert_test1]
ca_cert_file="/data/certs/ca1.crt"

[client_auth.cert_test2]
ca_cert_file="/data/certs/ca2.crt"
```

defines two client_auth configs: `cert_test1` using ca1.crt and `cert_test2` using ca2.crt.

Any API call to the app has to pass the client certificates. Using curl, the call would look like:

```sh
curl -k --cert client.crt --key client.key https://localhost:25223/myapp
```

If the client cert has been signed with the root CA defined in /data/certs/ca1.crt, the API call will succeed. Otherwise it fails. HTTP requests are not allowed when client cert authentication is used.

## Callback Url

To enable any OAuth/OIDC/SAML provider, the callback URL domain has to be specified in the server config. Add

```toml {filename="openrun.toml"}
[security]
callback_url = "https://example.com:25223"
```

in the `openrun.toml`. This does not have to be the same domain as used for the apps being authenticated.

## OAuth Authentication

OAuth based authentication is supported for these providers: `github`, `google`, `digitalocean`, `bitbucket`, `amazon`, `azuread`, `microsoftonline`, `gitlab`, `auth0`, `okta` and `oidc`.

The configuration format for each is

```toml {filename="openrun.toml"}
[auth.github_test]
key = "abcdefgh"
secret = "mysecret"
scopes = ["profile", "email"] # empty by default, change as required
```

Here, the auth config entry name is `github_test`.

- **Entry names:** the entry name can be one of the supported providers, or a supported provider name followed by a `_` and a qualifier. The provider name is case sensitive. So `github`, `google`, `github_prod`, `google_my_org` etc are valid config names. `github-test` and `my_org_google` are not valid.
- **Multiple configs:** the server `openrun.toml` can have multiple auth configs defined. One of them can be set to be the default using `app_default_auth_type` config. Apps can be configured to use one of `system` or `none` or a valid auth config name as the `auth`. For example, app 1 can use `system` and app 2 can use `github_test`.
- **Callback URL:** the format is `<CALLBACK_URL>/_openrun/auth/<PROVIDER_ENTRY_NAME>/callback`, and the URL registered in the OAuth account has to exactly match it. For an entry `github_test`, the callback URL to use will be `https://example.com:25223/_openrun/auth/github_test/callback`.

## OAuth Config Details

The config details depend on the provider type. The `key` is generally the Client ID and the `secret` is the client secret. For all the providers, an optional `scopes` property is also supported: the list of scopes to configure for the OAuth account. Some providers support or require additional config entries:

| Provider | Option | Meaning |
| :--- | :--- | :--- |
| `google` | `hosted_domain` (optional) | The domain name to verify for the logged-in user. For example, this can be set to `openrun.dev` |
| `okta` | `org_url` (required) | The tenant URL to verify |
| `auth0` | `domain` (required) | The Auth0 domain |
| `oidc` | `discovery_url` (required) | The OIDC discovery document. For example, with Okta, use `https://YOURDOMAIN-admin.okta.com/.well-known/openid-configuration` |
| `oidc` | `trust_unverified_email` (optional) | `true` makes the ID token's email the user identity when the IdP sends no `email_verified` claim at all. An explicit `false` still drops the email. For a single-tenant IdP whose admins own the email attribute only; see [Identity providers that do not send `email_verified`]({{< ref "#identity-providers-that-do-not-send-email_verified" >}}) |

{{<callout type="warning" >}}
The first time a new provider is added, it is important to manually verify an app, to verify if the required authentication restrictions are in place. For example, with google, any valid google user can log in, including gmail.com accounts. The `hosted_domain` config has to be used to restrict this.
{{</callout>}}

The OAuth integration internally uses the [goth](https://github.com/markbates/goth) library, see [examples](https://github.com/markbates/goth/blob/master/examples/main.go) for implementation details.

## OpenID Connect (OIDC)

When using [RBAC]({{< ref "RBAC" >}}), the OIDC provider is recommended. This allows the group information to be read from the IdP, without having to individually add each user in the RBAC dynamic config. A sample OIDC config will look like

```toml {filename="openrun.toml"}
[auth.oidc_oktatest]
# https://localhost:25223/_openrun/auth/oidc_oktatest/callback
key = "0oavknabcd"
secret = "nBTsFRY9BUZabcd"
discovery_url = "https://YOURDOMAIN.okta.com/.well-known/openid-configuration"
scopes = ["openid", "profile", "email", "groups"]
```

The IdP has to be configured to return the group information in the user profile under the `groups` key. For example, see [Okta forum](https://devforum.okta.com/t/userinfo-not-returning-groups/31907/1) about configuring Okta.

How OIDC logins are validated:

- **Tokens:** ID token signatures are validated using the provider's `jwks_uri`, each login is bound to a nonce, and an S256 PKCE challenge is sent. The provider must return the login nonce in the ID token.
- **Discovery:** the `discovery_url` must be the issuer's `/.well-known/openid-configuration` document, and the issuer it declares must match.
- **Identity:** an email address is used as the OpenRun identity only when the IdP vouches for it: `email_verified` is `true` (a boolean, or the string `"true"` some providers send) in the ID token or in the UserInfo response for the address that response names, or Microsoft Entra ID's `xms_edov` claim is `true` (see below). The ID token and the UserInfo response each keep their own verdict: a `false` from either, or a value that is neither `true` nor `false`, drops the email even if the other says `true`. Otherwise the ID token's `sub` identifies the user as `<provider>:<sub>` and the dropped email is logged at login with the reason. Providers that send no verification claim therefore need RBAC grants for the subject or IdP groups instead of email-based grants, or `trust_unverified_email`. An email supplied by UserInfo must have its own verification claim if it differs from the ID token's email.
- **Addresses:** the discovery document, JWKS, token and userinfo endpoints must be on public addresses. An IdP on a private, loopback or link-local address is refused unless `security.sso_allow_private_hosts = true` is set in the static config (see [SAML]({{< ref "#saml" >}})).

The `oidc` provider type is stricter than the named providers (`google`, `github`, ...): those are known IdPs whose email semantics are known (GitHub API emails are verified, Google sends `verified_email`, the `azuread` provider derives the email from the verified principal name), while `oidc` talks to an unknown IdP, so an address without a verification claim is not trusted by default.

### Identity providers that do not send `email_verified`

Some IdPs never send the claim. Their users are identified by subject since v0.20.6, so grants, the `X-Openrun-User` header and apps keyed on the email stop matching after an upgrade. Two cases, with different remedies:

**The claim is absent.** The IdP has no opinion either way.

| IdP | Why | Remedy |
| :--- | :--- | :--- |
| Microsoft Entra ID | There is no `email_verified` claim | Add the `xms_edov` optional claim to the app registration (below). Or set `trust_unverified_email = true` on the auth entry |
| ADFS | The default issuance rules omit it | Add a custom issuance rule emitting `email_verified` with the value `true`, or set `trust_unverified_email = true` |
| OneLogin | Off by default | Enable the `email_verified` claim on the app |

**The claim is explicitly `false`.** The IdP says the address is not verified, usually because of its own federation defaults. OpenRun honors that, `trust_unverified_email` does not override it, and the fix is at the IdP:

| IdP | Why | Remedy |
| :--- | :--- | :--- |
| Keycloak, LDAP or brokered users | "Trust Email" defaults to off on the federation provider, and already-imported users keep `email_verified: false` | Enable Trust Email and re-sync the users, or set Email verified per user |
| Amazon Cognito, federated users | Without an `email_verified` attribute mapping the attribute defaults to false | Map the IdP's verification attribute in the user pool |

**Microsoft Entra ID: the `xms_edov` claim.** Entra sets `xms_edov` ("email domain owner verified") to `true` when the address belongs to the user's own tenant on a domain that tenant has proven to own. OpenRun accepts it as verification. This is a policy decision: OIDC's `email_verified` asserts that the user controlled the address, `xms_edov` asserts that the tenant owns the domain and assigned the address, which is the assurance that matters for an organisation's own IdP. The claim is emitted only when the `email` claim is also requested, and the portal's Token configuration page does not list it, so edit the app registration's Manifest (Microsoft Graph format):

```json
"optionalClaims": {
    "idToken": [
        { "name": "email", "source": null, "essential": false, "additionalProperties": [] },
        { "name": "xms_edov", "source": null, "essential": false, "additionalProperties": [] }
    ]
}
```

The portal may warn that `xms_edov` is not recognised; the claim is documented in Microsoft's optional claims reference and the warning can be ignored. Sign in once and check the server log: a login that still reports "sent no email verification claim" means the claim did not arrive. Guest (B2B) accounts and accounts on domains the tenant has not verified get `xms_edov: false` or no claim and stay identified by subject. This route needs no OpenRun setting, and it holds even if the app registration is later made multi-tenant.

**`trust_unverified_email`.** When the IdP cannot be made to send a verification claim, this option on the `[auth.oidc_<name>]` entry makes the signed ID token's email the identity when neither the ID token nor the UserInfo response carries `email_verified` or `xms_edov`. An explicit `false` from either still drops the email, and an address that only appears in, or differs in, the UserInfo response is never trusted. The server logs a warning at every start while the option is on. Enable it only for a single-tenant IdP whose directory admins own the email attribute: on a multi-tenant or self-service IdP it lets a user log in as any address their IdP admin assigns. The option is refused on the named provider types.

{{<callout type="warning" >}}
**Switching from subject to email identities.** Adding `xms_edov` or enabling `trust_unverified_email` changes a user's identity at their next login from `<provider>:<sub>` to `<provider>:<email>`. That string is the RBAC user id, the `X-Openrun-User` header (and `X-Openrun-User-Stripped` without the prefix) and the audit log user. `X-Openrun-User-Id` carries the `sub` claim and `X-Openrun-User-Email` the bare address; the subject header does not change, and the email header is empty while the email is dropped. List both forms in grants during the switch, `"users": ["oidc_entra:abc123", "oidc_entra:alice@corp.example"]`, and remove the subject form once the login log stops reporting dropped emails. App data keyed on the subject identity can be re-keyed using the Starlark `UserSubject` value, which is the same before and after. A bare address in a grant never matches: the provider prefix is part of the identity.
{{</callout>}}

## SAML

To configure a SAML based provider, add in config

```toml {filename="openrun.toml"}
[saml."testokta"]
metadata_url = "https://integrator-3366111.okta.com/app/exkvzxe13p1ssdsd/sso/saml/metadata"
```

Here, the provider name is `saml_testokta`. All SAML providers have the prefix `saml_`.

| Option | Type | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `metadata_url` | string | required | The url for the IdP metadata. This is the only required property. The metadata must include a nonempty `entityID`, which OpenRun uses to validate the issuer of SAML responses and assertions |
| `groups_attr` | string | `groups` | The attribute which provides the groups information |
| `use_post` | bool | false (Redirect) | Use POST request for starting the SAML flow |
| `force_authn` | bool | false | Force re-authentication when session expires |
| `sp_key_file` | string | | The service provider key file, if required by the IdP |
| `sp_cert_file` | string | | The service provider certificate file, if required by the IdP |

### Private IdP addresses

Since `[auth.*]` and `[saml.*]` entries can be set through a dynamic config update by any `config:update` holder, the metadata fetch (and, for OIDC, every call to the provider) refuses private, loopback and link-local addresses, including through `HTTPS_PROXY`, follows at most three redirects and refuses an https to http redirect. An IdP on the same private network or a local one in development needs

```toml {filename="openrun.toml"}
[security]
sso_allow_private_hosts = true
```

in the static config; the setting cannot be changed dynamically.

### IdP application settings

On the IdP, configure the application with the following details. If the `callback_url` is set to

```toml {filename="openrun.toml"}
[security]
callback_url = "https://example.com:25223"
```

then:

| IdP setting | Format | For `saml_testokta` |
| :--- | :--- | :--- |
| `Single sign-on URL` | `<CALLBACK_URL>/_openrun/sso/<PROVIDER>/acs` | `https://example.com:25223/_openrun/sso/saml_testokta/acs` |
| `Audience URI (SP Entity ID)` | `<CALLBACK_URL>/_openrun/sso/<PROVIDER>/metadata` | `https://example.com:25223/_openrun/sso/saml_testokta/metadata` |

The `PROVIDER` should have the `saml_` prefix. If using RBAC, ensure that the group info is available under the `groups` attribute, or set `groups_attr` as required.

The service provider metadata is available for download at the `https://example.com:25223/_openrun/sso/saml_testokta/metadata` endpoint if the key and cert have been specified.

### Assertion requirements

Start SAML login from the OpenRun application. Unsolicited IdP-initiated logins are rejected.

- The IdP must return exactly one assertion with an explicit audience restriction for the SP Entity ID.
- Both the response's `InResponseTo` and the assertion's `SubjectConfirmationData.InResponseTo` must match the login request.
- The assertion must be covered by its own signature or the response signature.
- Single Logout responses must be signed.
- OpenRun limits SAML XML complexity to a conservative token bound of 10,000, in addition to its 10 MiB request and decompression limits. If an IdP sends unusually large attribute or group lists, filter them to the values the application needs.
