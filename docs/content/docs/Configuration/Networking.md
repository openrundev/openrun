---
title: "Ports and Certificates"
weight: 200
summary: "OpenRun uses unix domain sockets for client CLI requests. HTTP and HTTPS are used for application requests. Automatic signed certificate creation is supported for HTTPS."
---

## HTTP

For HTTP requests, by default the OpenRun service listens on port 25222, on the localhost(127.0.0.1) interface. This means the HTTP port can be accessed from the same machine, it cannot be accessed remotely. To configure this, update the config file

```toml {filename="openrun.toml"}
[http]
host = "127.0.0.1" # bind to localhost by default for HTTP
port = 25222 # default port for HTTP
```

to desired values. Port 0 means bind to any available port. Port -1 means disable HTTP access. Use host as `0.0.0.0` to bind to all available interfaces.

## HTTPS

For HTTPS requests, the OpenRun service listens on port 25223 by default, on the any(0.0.0.0) interface. This means the HTTPS port can be accessed from the same machine and also remotely. The various HTTPS config settings are:

```toml {filename="openrun.toml"}
# HTTPS port binding related Config
[https]
host = "0.0.0.0" # bind to all interfaces (if port is >= 0)
port = 25223 # port for HTTPS
enable_cert_lookup = true # enable looking for domain specific certificate files on disk
service_email = "" # email address for registering with the ACME CA. Set a value to enable automatic certs
use_staging = true # use Let's Encrypt staging server (ignored when acme_ca_url is set)
acme_ca_url = "" # custom ACME CA directory URL, overrides Let's Encrypt. Set a value to enable automatic certs
acme_ca_cert = "" # root CA cert (PEM file) to trust for the custom ACME CA endpoint
acme_eab_key_id = "" # ACME External Account Binding key ID, required by some CAs
acme_eab_mac_key = "" # ACME External Account Binding MAC key, required by some CAs
enable_http_challenge = false # answer ACME HTTP-01 challenges on the HTTP port (in addition to TLS-ALPN)
cert_location = "$OPENRUN_HOME/config/certificates" # where to look for existing certificate files
storage_location = "$OPENRUN_HOME/run/certmagic" # where to cache dynamically created certificates

```

Port 0 means bind to any available port. Port -1 means disable HTTPS access.

{{<callout type="info" >}}
Using the HTTPS port is recommended even for the local environment. HTTP/2 works with HTTPS only. Server Sent Events (SSE) are used by OpenRun for live reload of dev apps, [SSE works best with HTTP/2](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events#listening_for_custom_events). Without HTTP/2, there can be connection limit issues with HTTP causing connections from browser to OpenRun server to hang.
{{</callout>}}

## TLS Certificates

In the default configuration, where service_email and acme_ca_url are empty, certmagic integration is disabled. The certificate handling behavior is:

- `$OPENRUN_HOME/config/certificates` is looked up for a crt and key file in the PEM format matching the domain name as passed to the server. If a matching certificate is found, that is used.
- If no domain specific certificate is found, then the default certificate `default.crt` and `default.key` are looked up. If found, that is used.
- If default certificate is not found, then a self-signed default certificate is auto created in the certificates folder.

The intent is to allow custom certificates to be placed in the certificate folder, which will be used. If not found, a self-signed certificate is created and used. For example, if files example.com.crt and example.com.key are found in the certificates folder, those are used for example.com domain.

## Redirect from HTTP to HTTPS

To enable automatic redirect from HTTP to HTTPS, add `redirect_to_https = true` in the `http` section of the config. Also, change the `host` to `0.0.0.0`. For example,

```toml {filename="openrun.toml"}
[http]
host = "0.0.0.0"
port = 80
redirect_to_https = true
```

All requests to the HTTP port will 308 redirect to the HTTPS port.

## Dev Env Certificates

For local dev environment, using the auto generated certs will result in browser warnings when connecting to the HTTPS port. To avoid this, if [mkcert](https://github.com/FiloSottile/mkcert) is installed and configured, OpenRun automatically creates a mkcert cert for any new local domain. Ensure that the mkcert installation has been done once.

```sh
mkcert -install
```

## Enable Automatic Signed Certificate

OpenRun uses the [certmagic](https://github.com/caddyserver/certmagic) library for fully-managed TLS certificate issuance and renewal for production deployment. Certmagic is disabled by default. To enable, the pre-requisites are:

- The https config is using 443 as the port number. Running on privileged ports requires additional [setup](#privileged-ports)
- There is an DNS entry created pointing your host name or domain wildcard to the IP address of the host running the OpenRun server. This has to be done in your DNS provider config.
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

With this config, certmagic is used to create certificates for all HTTPS requests. Self signed certificates and enable_cert_lookup property are not used when certmagic is enabled.

## Custom ACME Server

Instead of Let's Encrypt, certificates can be obtained from any ACME compatible CA, such as an internal [step-ca](https://smallstep.com/docs/step-ca/) server or a commercial CA like ZeroSSL. Set `acme_ca_url` to the CA's ACME directory URL. Setting `acme_ca_url` enables certmagic based certificate creation even if `service_email` is empty (many private CAs do not require an email address), and `use_staging` is ignored.

```toml {filename="openrun.toml"}
[https]
host = "0.0.0.0"
port = 443
acme_ca_url = "https://ca.internal:8443/acme/acme/directory" # your CA's ACME directory URL
acme_ca_cert = "/etc/ssl/internal_root_ca.crt" # root CA cert, if the CA endpoint uses a private root
```

`acme_ca_cert` points to a PEM file containing the root certificate(s) to trust when connecting to the ACME CA endpoint. This is required when a private CA's directory URL is itself served with a certificate that is not trusted by the system trust store.

For CAs which require [External Account Binding](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4) (such as ZeroSSL or Google Trust Services), set `acme_eab_key_id` and `acme_eab_mac_key` to the values provided by the CA. Both have to be set together.

## ACME Challenges

The [TLS-ALPN](https://github.com/caddyserver/certmagic#tls-alpn-challenge) challenge is always enabled when certmagic is enabled. It requires the CA to be able to reach the HTTPS port (port 443 for public CAs).

The HTTP-01 challenge can additionally be enabled with `enable_http_challenge = true`. This works with Let's Encrypt as well as with a custom ACME CA. Challenge requests are answered on the HTTP port, before the [HTTP to HTTPS redirect](#redirect-from-http-to-https) and any authentication is applied. The HTTP listener must be enabled and reachable by the CA, on port 80 for public CAs (see [privileged ports](#privileged-ports)). For example, with Let's Encrypt:

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

The DNS challenge is not supported currently.

## Default Domain

The config has the default domain set to `localhost` by default. The default domain is used for any app which is installed without an explicit domain being specified. This can be changed to the required value when configuring the server.

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

New production apps get a linked staging app. By default, OpenRun creates the staging app on a staging subdomain and keeps the production path unchanged. For example, an app created at `example.com:/reports` gets a staging app at `stage.example.com:/reports`.

The default staging location is controlled by `system.stage_at`:

```toml {filename="openrun.toml"}
[system]
stage_at = "domain"            # "domain", "path", or a staging domain
default_stage_domain = "stage" # prefix used when stage_at is "domain"
```

The supported values are:

| `stage_at` value | Staging location                                                                                                   |
| :--------------- | :----------------------------------------------------------------------------------------------------------------- |
| `domain`         | `default_stage_domain` is prepended to the production domain, for example `stage.example.com:/reports`             |
| `path`           | The production domain is kept and `_cl_stage` is suffixed to the path, for example `example.com:/reports_cl_stage` |
| any domain       | The specified domain is used with the production path, for example `staging.example.net:/reports`                  |

If an app is created without an explicit domain, `domain` mode uses `default_domain` as the production domain when deriving the staging domain. A staging domain value ending in `.` is expanded relative to `default_domain`.

For production deployments, make sure DNS and certificates cover the staging hostnames. A wildcard DNS entry such as `*.example.com` is the simplest setup when apps use subdomains. For local development, `*.localhost` names work with the default `localhost` domain.

The server setting only controls the default for new production apps. Override it per app with `openrun app create --stage-at path ...` or `openrun app create --stage-at staging.example.net ...`. In declarative apply files, use `stage_at="path"` or `stage_at="staging.example.net"` in the `app(...)` definition for apps being created.

The built-in `list_apps` app is served at the default domain root level if no app is installed there.

```toml {filename="openrun.toml"}
[system]
root_serve_list_apps = "auto"  # "auto" means serve list_apps app for default domain, "disable" means don't server for any domain,
```

To disable this, set `root_serve_list_apps` to `disable`. The list apps app uses the default authentication as set for the system. If another domain needs to be used, set the value to that.

For the built-in list apps page served by `root_serve_list_apps`, the title and footer branding can also be configured:

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
