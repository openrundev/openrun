---
title: "App-Level Isolation in Web Server Config"
summary: "Most web servers provide an update interface that does not isolate applications from one another. As a result, updating a routing rule for one app can accidentally break other apps."
date: 2025-01-17
---

{{< openrun-intro >}}

## Background

OpenRun is a platform for developing and deploying internal tools. OpenRun provides functionality usually handled separately by a web server and an application server. The web server part of OpenRun is built such that there is complete isolation between app-level routing rules. Creating a new app or updating an existing app cannot break other apps. This post goes into details about how this is done and why it is useful.

## Web Server Overview

A Web Server is software that accepts HTTP/HTTPS requests and routes them appropriately. Web Servers provide features like URL rewrites, reverse proxying, header manipulation, static file serving, and WebSocket connection handling. Web Servers can accept connections on multiple ports. A common pattern is that all requests are received on port 80 (for HTTP) and 443 (for HTTPS) and routing is done based on request domain (from the Host HTTP header) and path (from the URL). Apache, Nginx, and Caddy are popular web servers.

## Updating Routing Rules

Most web servers use a config file for specifying the rules for request routing. The config file is generally a DSL which specifies the API rules. Some servers like Caddy support JSON input. Encapsulating or grouping together rules related to an app is supported, but this encapsulation is not enforced. For updating the rules, the approach is to update the file on disk and send a reload request to the web server. Even for API-based updates, the approach is usually to send the whole config contents, partial updates are not supported.

The issue with this approach is that if there are multiple apps, updating the rules for one app can break other apps. There is no enforcement of isolation across apps. This results in app developers trying to avoid updating the web server, doing more in the application server when it would have been more efficiently done in the web server.

## App-Level Isolation

The goal of app-level isolation is for developers to confidently update web server routing rules, being sure that a broken update will not impact other apps.

To enforce isolation across apps, web servers first need a concept of an app. There needs to be a way to say which rules are for which app. Each update has to be scoped to be for a particular app. If there are rules which conflict with another app, those rules need to be rejected.

## OpenRun Approach

OpenRun has the concept of an app where each app is [installed]({{< ref "/docs/applications/routing/" >}}) for a path within a domain. If app A is installed at `appA.example.com:/`, then that domain is completely dedicated for that app. An app installed at `appB.example.com:/test` owns the `/test/*` namespace for domain `appB.example.com`, no other app can use that namespace.

This approach has the benefit that each app gets a dedicated namespace. Within that namespace, the app can do whatever it wants, without interfering with other apps. At app installation time, a check is done whether the domain path being requested is available. If some other app is using that path, the new app installation is rejected. A SQLite database is used to [store app metadata]({{< ref "/blog/sqlite/" >}}), so API driven app updates do not conflict with each other.

Within the app, rules are defined using [Starlark](https://starlark-lang.org/). This avoids the need to learn a new DSL. The [routing]({{< ref "/docs/app/routing/" >}}) config is read at app initialization only and the actual [handler]({{< ref "/docs/app/overview/#sample-starlark-app" >}}) logic can be expressed alongside the routing rules. For [containerized apps]({{< ref "/docs/container/overview/" >}}), the routing rule specifies the reverse proxy URL. Reloading an app updates its config, without impacting other apps.

## Conclusion

By enforcing app-level isolation in routing rules, OpenRun allows each app to manage its own domain and path namespace without risking conflicts or breakages. This approach encourages developers to utilize efficient web server–level routing features, confident that changes in one app won’t disrupt others. Some web server routing use cases which are more complex cannot use this approach, but this is useful for app deployment scenarios.
