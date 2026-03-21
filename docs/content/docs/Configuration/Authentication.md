---
title: "App Authentication"
weight: 400
summary: "Details about authentication mechanisms for app access, including OAuth based auth"
---

By default, apps are created with the `none` authentication type. A `system` auth is available which uses `admin` as the username. The password is displayed on the screen during the initial setup of the OpenRun server config.

To set the auth type, add `--auth system` to the app create command. After an app is created, the auth type can be changed by running `app update auth --promote system /myapp`.

## Default Authentication Type

Any app when created uses the default auth type configured for the server. `none` is the default. To change this, add

```toml {filename="openrun.toml"}
[security]
app_default_auth_type = "github_prod"
```

assuming there is a `github_prod` OAuth config.

Any new app created will use this as the auth unless overridden in the `app create` call or using `app update`.

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

## SAML

To configure an SAML based provider, add in config

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

The `metadata_url` is required, all other options are optional.

On the IdP, configure the application with the following details. If the `callback_url` is set to

```toml {filename="openrun.toml"}
[security]
callback_url = "https://example.com:25223"
```

then the `Single sign-on URL` should be set to `https://example.com:25223/_openrun/sso/saml_testokta/acs` and the `Audience URI (SP Entity ID)` should be set to `https://example.com:25223/_openrun/sso/saml_testokta/metadata`.

The format for the Single Sign-on URL is `<CALLBACK_URL>/_openrun/sso/<PROVIDER>/acs`. The SP Entity Id format is `<CALLBACK_URL>/_openrun/sso/<PROVIDER>/metadata`. The `PROVIDER` should have the `saml_` prefix.

If using RBAC, ensure that the group info is available under the `groups` attribute, or set `groups_attr` as required.

The service provide metadata is available for download at the `https://example.com:25223/_openrun/sso/saml_testokta/metadata` endpoint if the key and cert have been specified.
