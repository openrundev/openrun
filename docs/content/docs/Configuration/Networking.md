---
title: "Ports and Certificates"
weight: 200
summary: "OpenRun uses unix domain sockets for client CLI requests. HTTP and HTTPS are used for application requests. Automatic signed certificate creation is supported for HTTPS."
---

The OpenRun server serves app requests on an HTTP and an HTTPS listener (the CLI uses a unix domain socket). This page covers the two listeners, how TLS certificates are found or created (files on disk, mkcert for local development, ACME for production), the default and staging domains, and binding to privileged ports.

| Listener | Default host | Default port | Reachable from |
| :--- | :--- | :--- | :--- |
| HTTP | `127.0.0.1` (localhost) | 25222 | the same machine only |
| HTTPS | `0.0.0.0` (any) | 25223 | the same machine and remotely |

For either listener, port `0` binds to any available port, port `-1` disables the listener, and host `0.0.0.0` binds to all available interfaces.

## HTTP

By default the OpenRun service listens for HTTP on port 25222, on the localhost (127.0.0.1) interface, so the HTTP port can be accessed from the same machine but not remotely. To configure this, update the config file to the desired values:

```toml {filename="openrun.toml"}
[http]
host = "127.0.0.1" # bind to localhost by default for HTTP
port = 25222 # default port for HTTP
```

## HTTPS

By default the OpenRun service listens for HTTPS on port 25223, on the any (0.0.0.0) interface, so the HTTPS port can be accessed from the same machine and also remotely. The various HTTPS config settings are:

```toml {filename="openrun.toml"}
# HTTPS port binding related Config
[https]
host = "0.0.0.0" # bind to all interfaces (if port is >= 0)
port = 25223 # port for HTTPS
enable_cert_lookup = true # enable looking for domain specific certificate files on disk
mkcert_path = "" # mkcert binary path for local dev certs, looked up on PATH by default; "disable" turns mkcert off
service_email = "" # email address for registering with the ACME CA. Set a value to enable automatic certs
use_staging = true # use Let's Encrypt staging server (ignored when acme_ca_url is set)
acme_ca_url = "" # custom ACME CA directory URL, overrides Let's Encrypt. Set a value to enable automatic certs
acme_ca_cert = "" # root CA cert (PEM file) to trust for the custom ACME CA endpoint
acme_eab_key_id = "" # ACME External Account Binding key ID, required by some CAs
acme_eab_mac_key = "" # ACME External Account Binding MAC key, required by some CAs
enable_http_challenge = false # answer ACME HTTP-01 challenges on the HTTP port (in addition to TLS-ALPN)
cert_location = "$OPENRUN_HOME/config/certificates" # where to look for existing certificate files
storage_location = "$OPENRUN_HOME/run/certmagic" # where to cache dynamically created certificates
disable_client_certs = true # set to false to enable client certificate (mTLS) authentication for apps
```

See [Client Cert Authentication]({{< ref "authentication/#client-cert-authentication-mtls" >}}) for `disable_client_certs`.

{{<callout type="info" >}}
Using the HTTPS port is recommended even for the local environment. HTTP/2 works with HTTPS only. Server Sent Events (SSE) are used by OpenRun for live reload of dev apps, [SSE works best with HTTP/2](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events#listening_for_custom_events). Without HTTP/2, there can be connection limit issues with HTTP causing connections from browser to OpenRun server to hang.
{{</callout>}}

## TLS Certificates

In the default configuration, where `service_email` and `acme_ca_url` are empty, certmagic integration is disabled and certificates are looked up in this order:

1. `$OPENRUN_HOME/config/certificates` is looked up for a crt and key file in the PEM format matching the domain name as passed to the server. If a matching certificate is found, that is used. For example, if files example.com.crt and example.com.key are found in the certificates folder, those are used for example.com domain.
2. If no domain specific certificate is found, then the default certificate `default.crt` and `default.key` are looked up. If found, that is used.
3. If the default certificate is not found, then a self-signed default certificate is auto created in the certificates folder.

The lookup is done only for domains the server is configured to serve: the default domain, the domains used by apps, the auth callback domain and the hosts in `security.callback_url`, `api.external_url` and `system.root_serve_list_apps`. Other domain names sent by clients get the default certificate.

## Redirect from HTTP to HTTPS

To enable automatic redirect from HTTP to HTTPS, add `redirect_to_https = true` in the `http` section of the config. Also, change the `host` to `0.0.0.0`. For example,

```toml {filename="openrun.toml"}
[http]
host = "0.0.0.0"
port = 80
redirect_to_https = true
```

App requests to the HTTP port receive a 308 redirect to HTTPS. Management and webhook endpoints reject plaintext requests instead of redirecting; enabled ACME HTTP-01 challenge requests are handled before the redirect.

## Dev Env Certificates

For a local dev environment, the auto generated certs result in browser warnings when connecting to the HTTPS port. To avoid this, if [mkcert](https://github.com/FiloSottile/mkcert) is installed and configured, OpenRun automatically creates a mkcert cert for any new local domain served by the server. Ensure that the mkcert installation has been done once:

```sh
mkcert -install
```

```toml {filename="openrun.toml"}
[https]
mkcert_path = "" # mkcert binary path, looked up in PATH if empty. Set to "disable" to disable mkcert
mkcert_domains = ["localhost", "*.localhost", "*.test", "*.local", "*.internal", "*.home.arpa"]
```

- **Which domains:** the domains mkcert is used for are set by `https.mkcert_domains`; other domains need the cert files to be placed in the certificates folder. An entry matches the domain exactly, `*.<domain>` matches all subdomains of the domain and `*` matches all domains.
- **Why only local domains by default:** mkcert certs are trusted only on machines where the mkcert CA is installed.
- **Served domains only:** in all cases, certs are created only for domains served by the server: the default domain, app domains, and the hosts in `security.callback_url`, `api.external_url` and `system.root_serve_list_apps`.

## Enable Automatic Signed Certificate

OpenRun uses the [certmagic](https://github.com/caddyserver/certmagic) library for fully-managed TLS certificate issuance and renewal for production deployment. Certmagic is disabled by default. To enable, the pre-requisites are:

- The https config is using 443 as the port number. Running on privileged ports requires additional [setup](#privileged-ports)
- There is a DNS entry created pointing your host name or domain wildcard to the IP address of the host running the OpenRun server. This has to be done in your DNS provider config.
- Port 443 is reachable from the public internet. This has to be done in your infrastructure provider network settings. Alternatively, the HTTP-01 challenge on port 80 can be enabled, see [ACME Challenges](#acme-challenges).

Once the pre-requisites are met, set the `service_email` config parameter to your email address. This enables certmagic based certificate creation. The config will look like:

```toml {filename="openrun.toml"}
# HTTPS port binding related Config
[https]
host = "0.0.0.0"
port = 443
enable_cert_lookup = true # enable looking for domain specific certificate files on disk
service_email = "MY_EMAIL@example.com" # CHANGE to your email address
use_staging = true # CHANGE to false for production
cert_location = "$OPENRUN_HOME/config/certificates"
storage_location = "$OPENRUN_HOME/run/certmagic"
```

Test out the certificate creation by sending HTTPS requests to port 443. If the certificate is getting created, change `use_staging` to false. Let's Encrypt has strict rate limits, use the staging config to ensure that the pre-requisites are met before using the production config.

With this config, certmagic is used to create certificates for all HTTPS requests. Self signed certificates and the `enable_cert_lookup` property are not used when certmagic is enabled.

## Custom ACME Server

Instead of Let's Encrypt, certificates can be obtained from any ACME compatible CA, such as an internal [step-ca](https://smallstep.com/docs/step-ca/) server or a commercial CA like ZeroSSL. Set `acme_ca_url` to the CA's ACME directory URL. Setting `acme_ca_url` enables certmagic based certificate creation even if `service_email` is empty (many private CAs do not require an email address), and `use_staging` is ignored.

```toml {filename="openrun.toml"}
[https]
host = "0.0.0.0"
port = 443
acme_ca_url = "https://ca.internal:8443/acme/acme/directory" # your CA's ACME directory URL
acme_ca_cert = "/etc/ssl/internal_root_ca.crt" # root CA cert, if the CA endpoint uses a private root
```

| Setting | Meaning |
| :--- | :--- |
| `acme_ca_cert` | A PEM file containing the root certificate(s) to trust when connecting to the ACME CA endpoint. Required when a private CA's directory URL is itself served with a certificate that is not trusted by the system trust store |
| `acme_eab_key_id`, `acme_eab_mac_key` | The values provided by a CA which requires [External Account Binding](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4) (such as ZeroSSL or Google Trust Services). Both have to be set together |

## ACME Challenges

| Challenge | Enabled | The CA must reach |
| :--- | :--- | :--- |
| [TLS-ALPN](https://github.com/caddyserver/certmagic#tls-alpn-challenge) | always, when certmagic is enabled | the HTTPS port (port 443 for public CAs) |
| HTTP-01 | `enable_http_challenge = true`; works with Let's Encrypt as well as with a custom ACME CA | the HTTP port, which must be enabled (port 80 for public CAs, see [privileged ports](#privileged-ports)) |
| DNS | not supported currently | |

HTTP-01 challenge requests are answered on the HTTP port, before the [HTTP to HTTPS redirect](#redirect-from-http-to-https) and any authentication is applied. For example, with Let's Encrypt:

```toml {filename="openrun.toml"}
[http]
host = "0.0.0.0"
port = 80
redirect_to_https = true

[https]
host = "0.0.0.0"
port = 443
service_email = "MY_EMAIL@example.com" # CHANGE to your email address
use_staging = true # CHANGE to false for production
enable_http_challenge = true
```

With this config, certificates are created using either the TLS-ALPN challenge on port 443 or the HTTP-01 challenge on port 80, whichever the CA validates first.

## Default Domain

The default domain is `localhost`. It is used for any app which is installed without an explicit domain being specified, and can be changed when configuring the server.

```toml {filename="openrun.toml"}
[system]
default_domain = "localhost" # default domain for apps
```

Requests are only routed to the default domain when the request `Host` matches that domain. By default, requests for unknown hostnames are not treated as requests for the default domain. To preserve the older catch-all behavior, enable `system.fallback_unknown_domains`.

```toml {filename="openrun.toml"}
[system]
fallback_unknown_domains = false # set true to route unknown hostnames to the default domain
```

## Staging Domain

New production apps get a linked staging app. By default, OpenRun creates the staging app on a staging subdomain and keeps the production path unchanged. An app created at `example.com:/reports` gets a staging app at `stage.example.com:/reports`, and an app on its own subdomain, `app.example.com:/`, gets a staging app at `app.stage.example.com:/`.

The default staging location is controlled by `system.stage_at`:

```toml {filename="openrun.toml"}
[system]
stage_at = "domain_suffix"     # "domain_suffix", "domain", "path", or a staging domain
default_stage_domain = "stage" # stage label used when stage_at is "domain_suffix" or "domain"
```

| `stage_at` value | Staging app for `app.example.com:/` | Staging app for `example.com:/reports` |
| :--- | :--- | :--- |
| `domain_suffix` (default) | `app.stage.example.com:/` | `stage.example.com:/reports` |
| `domain` | `stage.app.example.com:/` | `stage.example.com:/reports` |
| `path` | `app.example.com:/_cl_stage` | `example.com:/reports_cl_stage` |
| any domain, for example `staging.example.net` | `staging.example.net:/` | `staging.example.net:/reports` |

With `domain_suffix`, the stage label (`default_stage_domain`) goes after the first label of the app's domain: an app at `<name>.example.com` stages at `<name>.stage.example.com`. One wildcard DNS record and one wildcard certificate for `*.stage.example.com` then cover staging for all the apps that `*.example.com` covers. With `domain`, the label goes in front of the whole domain, which puts each staging app under its own app's hostname.

Some domains have no parent to put the label in. For these, `domain_suffix` prepends the label, the same as `domain`:

- the default domain itself (`default_domain`), which includes every app created without a domain
- a registrable domain such as `example.org` or `example.co.uk`, or a hosted name such as `name.github.io`. These are identified using the [Public Suffix List](https://publicsuffix.org/), so that `example.org` does not stage at `example.stage.org`
- a single label hostname or an IP address

Subdomains of `default_domain` get the label inserted whatever the list says, so `default_domain` should be a domain you control and not a public suffix. This is what makes `app.localhost` and internal names like `app.corp.internal` (with `default_domain = "corp.internal"`) stage at `app.stage.localhost` and `app.stage.corp.internal`.

{{< callout type="warning" >}}
For a domain outside `default_domain`, OpenRun cannot know which DNS zone you control. It assumes you control the parent of the app's hostname. That is wrong when the hostname is the only name you were given: if a customer points `tools.customer.com` at your server, or you control just the delegated zone `team.corp.com` and create an app on that exact name, the staging app is derived as `tools.stage.customer.com` or `team.stage.corp.com`. The same applies to a provider domain which hands out subdomains and is not on the Public Suffix List. OpenRun does not verify the derived name: it may not resolve, or may resolve to a host you do not run. For such apps, set the staging location explicitly with `--stage-at stage.tools.customer.com` or `--stage-at domain`, or set `stage_at = "domain"` for the whole server.
{{< /callout >}}

- If an app is created without an explicit domain, the domain modes use `default_domain` as the production domain when deriving the staging domain. A staging domain value ending in `.` is expanded relative to `default_domain`.
- The server setting only controls the default for new production apps. The staging location is fixed when the app is created: changing `stage_at` later, or re-applying an app with a different `stage_at`, does not move an existing staging app. `openrun app list --internal` shows where each staging app is.
- Override the default per app with `openrun app create --stage-at domain ...`, `--stage-at path ...` or `--stage-at staging.example.net ...`. In declarative apply files, use `stage_at="domain"`, `stage_at="path"` or `stage_at="staging.example.net"` in the `app(...)` definition for apps being created.
- Domains and the stage label must be lower case ASCII, with internationalized domain names entered in their punycode (`xn--`) form. Requests are matched against app domains exactly as they were entered, and deriving the staging domain does not normalize the name. A name which is not a well formed hostname (an empty label, characters that cannot be mapped) gets the label prepended.
- The stage label can have more than one label (`stage.eu`). A trailing `.` on it is ignored, and it cannot contain `:`.
- `domain_suffix` is a reserved word in `stage_at`. It cannot be used as the name of a staging domain.

### DNS and certificates for staging

For production deployments, make sure DNS and certificates cover the staging hostnames. For local development, `*.localhost` names work at any depth with the default `localhost` domain.

When apps are subdomains of `example.com`, the full set of records is:

| Record | Serves |
| :--- | :--- |
| `example.com` | apps on the default domain |
| `*.example.com` | production apps on subdomains |
| `stage.example.com` | staging for apps on the default domain |
| `*.stage.example.com` | staging for apps on subdomains |

A DNS wildcard `*.example.com` on its own also answers for `stage.example.com` and `app.stage.example.com`, but only while no other record exists at or below `stage.example.com`. Once any record is created there, including `*.stage.example.com` itself, both `stage.example.com` and `*.stage.example.com` need their own records. Creating all four records avoids the surprise.

A wildcard certificate matches exactly one label, so `*.example.com` does not cover `app.stage.example.com`. Add `*.stage.example.com` and `stage.example.com` to the certificate. Automatic certificates (Let's Encrypt and mkcert) are issued per hostname and need no extra setup.

In general, the staging name of a production hostname `app.<parent>` is `app.stage.<parent>`. An app at `x.team.example.com` stages at `x.stage.team.example.com`, which needs `*.stage.team.example.com` (or an exact record) in DNS and in the certificate.

If the stage label is changed with `default_stage_domain`, replace `stage` in the names above with that value.

### List apps page

The built-in `list_apps` app is served at the default domain root level if no app is installed there.

```toml {filename="openrun.toml"}
[system]
root_serve_list_apps = "auto"  # "auto" means serve list_apps app for default domain, "disable" means don't server for any domain,
```

To disable this, set `root_serve_list_apps` to `disable`. If another domain needs to be used, set the value to that. The list apps app uses the default authentication as set for the system.

The title and footer branding of the page can also be configured:

```toml {filename="openrun.toml"}
[system]
list_apps_title = "OpenRun Apps"
show_hosted_with = true
```

`list_apps_title` sets the page title shown on the app listing. `show_hosted_with` controls whether the page shows the `Hosted with OpenRun` text.

The list_apps app can be installed explicitly from `github.com/openrundev/apps/openrun/list_apps` source path. This allows the app to be installed with required auth settings. The listing shows apps which are available unauthenticated and apps which are using the same auth as the one set for the list_apps app.

## Privileged Ports

On Linux, binding to low ports is disabled for non-root users. To enable binding to port 80 for HTTP and 443 for HTTPS, run the command

```shell
sudo setcap cap_net_bind_service=+ep /path/to/openrun_binary
```

This would be required after any new build or update of the OpenRun binary.

## Notes

- Please provide a valid email address in service_email. This allows you to receive expiration emails and also allows the CA to contact you if required.
- Start the configuration with staging `use_staging = true`, change to production config `use_staging = false` after ensuring that DNS and networking is working fine.
- If port 0 is used, the service will bind to any available port. Look at the stdout or logs to find the port used. Clients would have to be updated after every server restarted to point to the new port.
- The [TLS-ALPN](https://github.com/caddyserver/certmagic#tls-alpn-challenge) challenge is enabled by default; the HTTP-01 challenge can be enabled with `enable_http_challenge = true`. The DNS based challenge is not supported currently.
- If OpenRun is running behind a load balancer, ensure that the load balancer is doing TLS pass-through. If TLS termination is done in the load balancer, then the automatic certificate management done by OpenRun through certmagic will not work.
- If OpenRun is running behind a reverse proxy or load balancer that sets `X-Forwarded-For` or `X-Real-IP`, add that proxy IP or CIDR range to `security.trusted_proxies`. Otherwise OpenRun will ignore those headers and use the direct peer address for `req.RemoteIP`.
