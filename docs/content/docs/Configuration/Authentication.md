---
title: "App Authentication"
weight: 400
summary: "Details about authentication mechanisms for app access, including OAuth based auth"
---

By default, apps are created with the `none` authentication type. A `system` auth is available which uses `admin` as the username. The password is displayed on the screen during the initial setup of the OpenRun server config.

To set the auth type, add `--auth system` to the app create command. After an app is created, the auth type can be changed by running `app update auth --promote system /myapp`.

## Login Page

For the `system` and `builtin` auth types, browser access to an app shows an HTML login page (stating whether the app uses the system admin account or OpenRun builtin accounts) and redirects back to the original app URL after sign in. The authenticated session is stored in a cookie on the app's domain; its lifetime is `security.session_max_age` (default 86400 seconds, one day), the same as SSO sessions. The lifetime is an idle timeout: a session that is in use is renewed (once it is past half of its lifetime), so it only expires after `session_max_age` without activity. `security.session_absolute_max_age` (default one week) caps the total lifetime from login regardless of activity; set it to 0 to disable the cap. Both settings apply to all session-based auth types and are read at startup. The login page itself stays valid for one hour: a form submitted later than that (or submitted twice) shows a "sign-in request has expired" message with a link back to the app, which starts a fresh sign in. Sessions are re-validated against the live config on every request: changing or removing a user's password, deleting a builtin user or changing the admin username signs the affected sessions out immediately. Signing out is done through the `/_openrun/logout` page on the app domain (see below).

Non-browser clients are unaffected: requests carrying an HTTP Basic `Authorization` header (or not requesting `text/html`) authenticate with Basic auth as before, so `curl -u` and API clients keep working. Other `Authorization` schemes (e.g. an app's own `Bearer` token) are passed through to the app once the session cookie has authenticated the request.

### Signing out

A single sign-out page is served on the app domain at `/_openrun/logout`, and it logs the user out **regardless of how they signed in** — `system`, `builtin`, OAuth/OIDC or SAML. Every auth type stores its session as a per-provider cookie on the app domain, so the page clears whichever OpenRun session cookies the request carries without needing to know the provider. `GET` shows a confirmation ("Signed in as … · Sign out") and `POST` clears the sessions and shows a "signed out" page.

Apps just link to `/_openrun/logout`, optionally with a return target — `/_openrun/logout?redirect=<app path>` (validated to be same-host, so it cannot be used as an open redirect). The signed-in identity on the confirmation comes from the session cookie the request already carries. The low-level `POST /_openrun/logout/<provider>` route remains for callers that want to target one provider.

Note for SSO: clearing the local cookie ends the OpenRun session but does not perform IdP-side single logout (SAML SLO / OIDC end-session), so a subsequent login may complete silently through the IdP's own session.

The login page is served only from a dedicated **auth callback domain**, so an app's own JavaScript can never be same-origin with the credential form. The domain is `security.auth_callback_domain` (default `auth.`): a trailing `.` is a prefix combined with `system.default_domain` (giving `auth.<default_domain>`), and a value without a trailing `.` is used as a full domain. No apps can be created on this domain, and the login page is served under a strict Content-Security-Policy with framing disabled. The domain must resolve to the OpenRun server (add a DNS record or wildcard alongside your app domains). The same domain serves the login and consent pages of the OAuth authorization server used by the [remote CLI and MCP clients]({{< ref "remoteaccess" >}}), for the same reason.

A client IP may start at most `security.login_start_rate_limit` login handshakes per minute (default 60; 0 disables the limit), across the form login, OAuth/OIDC and SAML types: each start records login state in the metadata database, which an anonymous client must not be able to grow at will. Further starts within the minute get a 429 response. Set the limit higher when many users share one address and the server is not behind a proxy listed in `trusted_proxies`.

Set `security.disable_login_form = true` to turn the login page off and use the plain HTTP Basic challenge for browsers too (`auth_callback_domain` is then unused). The form is also skipped (falling back to the Basic challenge) when `security.session_https_only` is set but the app request arrives over plain HTTP, unless both the app host and the auth callback domain are local (`localhost`, loopback or `*.localhost`) — the secure session cookie could not be returned, and credentials must not be sent to a remote login page over cleartext.

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

Apps use this auth type with `--auth builtin`. Browsers get a login page; other clients authenticate with HTTP Basic auth, so `curl -u alice:mypassword https://example.com:25223/myapp` works. For [RBAC]({{< ref "RBAC" >}}), the user id is `builtin:alice` and the user's groups are matched by `group:` references in grants, the same way SSO provider groups are. Managing users requires the `user:manage` permission (or the individual `user:read`, `user:create`, `user:update` and `user:delete` permissions); the `openrun-operator` role includes it. Creating or changing a user is a route to every permission its groups carry, so the write permissions must be named literally in API key scopes. Placing a user in a group that confers the `admin` permission (or removing one from it) additionally requires `admin:manage`, see [Managing admins]({{< ref "RBAC#managing-admins" >}}).

Passwords are sent to the server as entered and hashed there with argon2id (bcrypt hashes from earlier versions are accepted and upgraded on the user's next login). A password must be 8 to 128 characters and may not equal the username. Usernames are 1 to 64 characters, start with a letter or digit, continue with letters, digits and `. _ @ + -`, are case sensitive, and may not be `admin`, `anonymous` or start with `openrun-`. After ten consecutive wrong passwords the account is locked for 15 minutes (`openrun user update <name> --unlock` clears it); a password change, disable or delete signs the user out of existing browser sessions immediately. Builtin users are intended for small deployments and for testing RBAC policies with multiple users and groups; prefer OAuth/OIDC/SAML for production single sign-on.

A `[builtin_auth.<username>]` section in `openrun.toml` (a `password` hash plus `groups`) is deprecated. Its entries are imported as users when the server starts and no user of that name exists; an existing user is never changed from the config file, and the section will be removed in a later release. Move such users to `openrun user` and delete the section.

## Default Authentication Type

Any app when created uses the default auth type configured for the server. `none` is the default. To change this, add

```toml {filename="openrun.toml"}
[security]
app_default_auth_type = "github_prod"
```

assuming there is a `github_prod` OAuth config.

Any new app created will use this as the auth unless overridden in the `app create` call or using `app update`.

## Require Authentication for All Apps

To require every app to use some form of authentication, set `auth_required` in the `security` section:

```toml {filename="openrun.toml"}
[security]
auth_required = true
```

When this is enabled, any app with `auth="none"` is denied at request time with `401 Authentication required`. This check happens when the app is accessed, not when the app metadata is created or updated.

Use this when you want a server-wide guardrail to prevent accidentally exposing apps without authentication. The app can still use any supported auth mode such as `system`, OIDC/OAuth, SAML, mTLS, or the configured `app_default_auth_type`.

## Forward Auth

Forward auth lets OpenRun authenticate the user first, then call an external authorization service before the request is sent to the app. This is useful when authentication should stay in OpenRun, but per-request authorization policy is owned by another service.

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

In this example, OpenRun first performs `system` or `github_prod` authentication. If that succeeds, OpenRun sends a `GET` request to `auth_url`. A `2xx` response allows the request to continue to the app. Any non-`2xx` response denies the request; OpenRun returns the auth server status, headers, and body to the client.

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

`forward_headers` controls which original client request headers are copied to the auth request. If it is empty, OpenRun copies all request headers except hop-by-hop headers. Set it explicitly when the auth service only needs selected headers such as `Authorization` or `Cookie`.

`copy_response_headers` controls which headers from a successful auth response are copied into the request sent to the app. It defaults to no headers. Use `Source>Target` to rename a header while copying it, as shown with `Remote-Email>X-Auth-Email` above. Headers from deny responses are sent back to the client with the deny response.

`system.forward_auth_timeout_secs` sets the timeout for forward auth requests. If it is not set or is less than or equal to zero, OpenRun uses `30` seconds.

## Client Cert Authentication (mTLS)

Apps can be updated to use mutual TLS authentication. To enable this, first set `disable_client_certs` to `false` in the `https` section. Add a `client_auth` config entry in server config with the CA certificate to verify against. Multiple entries can be added, the entry name should be `cert` or should start with `cert_`. For example

```toml {filename="openrun.toml"}
[https]
disable_client_certs = false

[client_auth.cert_test1]
ca_cert_file="/data/certs/ca1.crt"

[client_auth.cert_test2]
ca_cert_file="/data/certs/ca2.crt"
```

defines two client_auth configs: `cert_test1` using ca1.crt and `cert_test2` using ca2.crt. Apps can be updated to use this auth config by running `app update auth --promote cert_test1 /myapp` or `app update auth --promote  cert_test2 /myapp`.

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

OAuth based authentication is supported for the following providers:

- github
- google
- digitalocean
- bitbucket
- amazon
- azuread
- microsoftonline
- gitlab
- auth0
- okta
- oidc

The configuration format for each is

```toml {filename="openrun.toml"}
[auth.github_test]
key = "abcdefgh"
secret = "mysecret"
scopes = ["profile", "email"] # empty by default, change as required
```

Here, the auth config entry name is `github_test`. The entry name can be one of the supported providers, or a supported provider name followed by a `_` and a qualifier. The provider name is case sensitive. So `github`, `google`, `github_prod`, `google_my_org` etc are valid config names. `github-test` and `my_org_google` are not valid.

The server `openrun.toml` can have multiple auth configs defined. One of them can be set to be the default using `app_default_auth_type` config. Apps can be configured to use one of `system` or `none` or a valid auth config name as the `auth`. For example, app 1 can use `system` and app 2 can use `github_test`.

In the OAuth account, for an entry `github_test`, the callback URL to use will be `https://example.com:25223/_openrun/auth/github_test/callback`.

The format for the callback URL to use is `<CALLBACK_URL>/_openrun/auth/<PROVIDER_ENTRY_NAME>/callback`. The callback URL has to exactly match this format.

## OAuth Config Details

The config details depend on the provider type. The `key` is generally the Client ID and the `secret` is the client secret. For some providers, additional config entries are supported. These are:

- **google**: The google provider supports a `hosted_domain` option. This is the domain name to verify for the logged-in user. For example, this can be set to `openrun.dev`.
- **okta**: The Okta provider requires the `org_url` config, the tenant URL to verify.
- **auth0**: The Auth0 provider requires the `domain` config.
- **oidc**: OIDC requires the `discovery_url` config property. For example, with Okta, use `https://YOURDOMAIN-admin.okta.com/.well-known/openid-configuration`

For all the providers, an optional `scopes` property is also supported. This is the list of scopes to configure for the OAuth account.

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

OIDC logins validate ID token signatures using the provider's `jwks_uri`, bind each login to a nonce, and send an S256 PKCE challenge. The provider must return the login nonce in the ID token. The `discovery_url` must be the issuer's `/.well-known/openid-configuration` document, and the issuer it declares must match. An email address is used as the OpenRun identity only when its `email_verified` claim is `true` (a boolean, or the string `"true"` some providers send); otherwise the ID token's `sub` identifies the user, and the dropped email is logged at login. Providers that omit email verification therefore need RBAC grants for the subject or IdP groups instead of email-based grants. An email supplied by UserInfo must have its own verification claim if it differs from the ID token's email.

## SAML

To configure a SAML based provider, add in config

```toml {filename="openrun.toml"}
[saml."testokta"]
metadata_url = "https://integrator-3366111.okta.com/app/exkvzxe13p1ssdsd/sso/saml/metadata"
```

Here, the provider name is `saml_testokta`. All SAML providers have the prefix `saml_`. The various config options supported for a SAML provider are

- `metadata_url`(string) : The url for the IdP metadata. This is the only required property.
- `groups_attr`(string): The attribute which provides the groups information. Default `groups`
- `use_post`(bool): Use POST request for starting the SAML flow. Default is to use Redirect
- `force_authn`(bool): Force re-authentication when session expires, default false
- `sp_key_file`(string): The service provider key file, if required by the IdP
- `sp_cert_file`(string): The service provider certificate file, if required by the IdP

The `metadata_url` is required, all other options are optional. The metadata must include a nonempty `entityID`, which OpenRun uses to validate the issuer of SAML responses and assertions.

On the IdP, configure the application with the following details. If the `callback_url` is set to

```toml {filename="openrun.toml"}
[security]
callback_url = "https://example.com:25223"
```

then the `Single sign-on URL` should be set to `https://example.com:25223/_openrun/sso/saml_testokta/acs` and the `Audience URI (SP Entity ID)` should be set to `https://example.com:25223/_openrun/sso/saml_testokta/metadata`.

The format for the Single Sign-on URL is `<CALLBACK_URL>/_openrun/sso/<PROVIDER>/acs`. The SP Entity Id format is `<CALLBACK_URL>/_openrun/sso/<PROVIDER>/metadata`. The `PROVIDER` should have the `saml_` prefix.

Start SAML login from the OpenRun application. The IdP must return exactly one assertion with an explicit audience restriction for the SP Entity ID. Both the response's `InResponseTo` and the assertion's `SubjectConfirmationData.InResponseTo` must match the login request. The assertion must be covered by its own signature or the response signature. Unsolicited IdP-initiated logins are rejected.

OpenRun limits SAML XML complexity to a conservative token bound of 10,000, in addition to its 10 MiB request and decompression limits. If an IdP sends unusually large attribute or group lists, filter them to the values the application needs. Single Logout responses must be signed.

If using RBAC, ensure that the group info is available under the `groups` attribute, or set `groups_attr` as required.

The service provider metadata is available for download at the `https://example.com:25223/_openrun/sso/saml_testokta/metadata` endpoint if the key and cert have been specified.
