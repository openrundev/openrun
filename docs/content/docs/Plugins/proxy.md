---
title: "Proxy Plugin"
weight: 500
summary: "Proxy plugin supports proxying of API calls"
---

The `proxy.in` plugin provides the `config` API to allow proxying of API calls.

## Introduction

OpenRun can proxy API calls to external endpoints or to backend APIs implemented in a container. The `config` API is used to configure at the route level what configuration is used for the proxy.

## API

The `proxy.in` plugin has just one api, `config`

|    API     | Type |                   Notes                    |
| :--------: | :--: | :----------------------------------------: |
| **config** | Read | Configures the proxy details for the route |

The `config` API supports the following parameter:

- **url** (string, required) : The url to proxy to. Use `container.URL` to proxy to backend container
- **strip_path** (string, optional) : extra path values to strip from the proxied API call
- **preserve_host** (bool, optional) : whether to preserve the Host header. Default false, the Host header is set to the target host value
- **strip_app** (bool, optional) : whether to strip the app path from the proxied API call. Default true.

With the default server config, `proxy.config(container.URL, ...)` is approved implicitly for all apps. Explicit app permissions are still required when proxying to other upstream URLs.

When proxying, OpenRun strips inbound `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-Prefix` headers and rebuilds a clean forwarding header set for the upstream service. The client IP used for this is resolved using `security.trusted_proxies`.

## Example

This is an example app which proxies data to google.com. This app has to be installed at the root level, since google does not use relative paths.

```python {filename="app.star"}
load("proxy.in", "proxy")

app = ace.app("Proxy App",
              routes=[
                  ace.proxy("/", proxy.config("https://www.google.com"))
              ],
              permissions=[
                  ace.permission("proxy.in", "config", ["https://www.google.com"]),
              ]
       )
```
