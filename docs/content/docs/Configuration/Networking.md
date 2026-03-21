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
service_email = "" # email address for registering with Let's Encrypt. Set a value to enable automatic certs
use_staging = true # use Let's Encrypt staging server
cert_location = "$OPENRUN_HOME/config/certificates" # where to look for existing certificate files
storage_location = "$OPENRUN_HOME/run/certmagic" # where to cache dynamically created certificates

```

Port 0 means bind to any available port. Port -1 means disable HTTPS access.

{{<callout type="info" >}}
Using the HTTPS port is recommended even for the local environment. HTTP/2 works with HTTPS only. Server Sent Events (SSE) are used by OpenRun for live reload of dev apps, [SSE works best with HTTP/2](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events#listening_for_custom_events). Without HTTP/2, there can be connection limit issues with HTTP causing connections from browser to OpenRun server to hang.
{{</callout>}}

## TLS Certificates

In the default configuration, where service_email is empty, certmagic integration is disabled. The certificate handling behavior is:

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
- Port 443 is reachable from the public internet. This has to be done in your infrastructure provider network settings.

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

## Default Domain

The config has the default domain set to `localhost` by default. The default domain is used for any app which is installed without an explicit domain being specified. This can be changed to the required value when configuring the server.

```toml {filename="openrun.toml"}
[system]
default_domain = "localhost" # default domain for apps
```

The list_app app is served at the default domain root level if no app is installed there.

```toml {filename="openrun.toml"}
[system]
root_serve_list_apps = "auto"  # "auto" means serve list_apps app for default domain, "disable" means don't server for any domain,
```

To disable this, set `root_serve_list_apps` to `disable`. The list apps app uses the default authentication as set for the system. If another domain needs to be used, set the value to that.

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
- Only the [TLS-ALPN](https://github.com/caddyserver/certmagic#tls-alpn-challenge) challenge is enabled in OpenRun. The HTTP and DNS based challenges are not supported currently.
- If OpenRun is running behind a load balancer, ensure that the load balancer is doing TLS pass-through. If TLS termination is done in the load balancer, then the automatic certificate management done by OpenRun through certmagic will not work.
