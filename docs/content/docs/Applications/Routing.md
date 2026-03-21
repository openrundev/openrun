---
title: "Application Routing"
weight: 100
summary: "Details about request routing across OpenRun applications using path and domain"
---

## Request Routing

The OpenRun server can host multiple applications simultaneously. Each application gets a dedicated path, the application can use all sub-paths within that without conflicts with other applications.

When an application is created, a path needs to be specified and a domain can be optionally specified. Routing for application requests is done based on domain and path. The domain is the namespace within which the paths are resolved. If no domain is specified for the app, it is installed for the default domain. [Default domain]({{< ref "/docs/configuration/networking/#default-domain" >}}) can be set using the `system.default_domain` config property (default value is `localhost`).

Consider this scenario:

- App A is installed at /utils/appA
- App B is installed at /appB
- App C is installed at the root level / for domain example.com, example.com:/

For the above scenario:

- Requests to /utils/appA/\* for the default domain go to app A
- Requests to /appB/\* for the default domain go to App B.
- Requests to example.com for any path will always go to App C, since it is installed at the root path.

## Creating Applications

When an app is being created, a path and an optional domain need to be specified. For the above example scenario:

- No new apps can be created for example.com domain, since App C is installed at the root path.
- For the default domain, /utils/appA and /appB are taken, other paths are available.
- New apps can be created under any path, including root path, for new domains and subdomains, like test.example.com.

## Notes

- The domain specified for the app is used only for routing requests. The user has to ensure that the actual DNS routing is done properly outside of OpenRun for the API calls to land on the OpenRun server.
- Using wildcard DNS entries will reduce the configuration required in the DNS service. So if \*.example.com points to the IP address of the OpenRun service, any domain based routing done in OpenRun will work with no further DNS configuration being required. The automated certificates created by OpenRun will be domain level certificates, wildcard certificates are not currently created.
- `/_openrun/` API path at the root level and `/_openrun_app/` within an app path are reserved paths, they are used by the OpenRun internal APIs, requests will not reach the app. This applies for all domains. `_cl_` is reserved for use for internal apps, so app path last component cannot have `_cl_`.
