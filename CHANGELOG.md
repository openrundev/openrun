# Changelog

Changes to OpenRun will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added the app code setting `container.separate_stage_prod_images` for specs that need distinct staging and production container images.

### Changed

- New production apps now create their linked staging app on a staging subdomain by default, for example `stage.example.com:/app`, instead of suffixing `_cl_stage` to the production path. Use `system.stage_at`, `system.default_stage_domain`, `openrun app create --stage-at`, or declarative `stage_at` to choose path-based staging or a specific staging domain for new apps.
- Containerized staging and production apps now share the same generated image name by default when the build inputs match, avoiding a second image build during production promotion. Specs can opt out with `settings={"container": {"separate_stage_prod_images": True}}`.
- Kubernetes deploys now watch Deployment rollout status instead of relying only on repeated polling, reducing API overhead and returning sooner when Kubernetes reports readiness or rollout failure. The watch path uses the same `container.deploy_health_attempts` budget, and the best-effort EndpointSlice convergence check now skips immediately when the Kubernetes API or RBAC policy does not allow listing EndpointSlices.

## [v0.18.2] - 2026-06-28

### Added

- Added the app internal `/_openrun_app/verify_file/{file_name}` API to verify that an app-relative source file exists and return its size.

## [v0.17.8] - 2026-06-03

### Fixed

- Fixed service stop error when running as windows service

## [v0.17.7] - 2026-06-02

### Security

- Fixed an open redirect issue reported by @Fushuling https://github.com/openrundev/openrun/security/advisories/GHSA-h5g6-xmh4-hc37

## [v0.17.6] - 2026-06-01

### Added

- Added Windows Service Control Manager support for `openrun server start`, allowing OpenRun to run as a native Windows service registered with `sc.exe`.

## [v0.17.5] - 2026-05-28

### Changed

- Proxied responses now rewrite the `Location` header so upstream redirects don't leak the internal backend authority. Absolute Locations pointing at the proxy target are converted to path-only URLs, and path-absolute Locations get any stripped prefix (`strip_app` / `strip_path`) restored so the client's next request lands on the same public route. Cross-host Locations (OAuth/SSO and similar) pass through unchanged.

## [v0.17.4] - 2026-05-21

### Added

- Added forward auth support for apps using auth modifiers such as `system+forward_policy`, with named `[forward.<name>]` configs, trusted forwarded/OpenRun identity headers and configurable copied response headers.

## [v0.17.3] - 2026-05-18

### Changed

- Fix #95: Pull image and update apps which use image spec when app reload is done.

### Added

- Added background cleanup for stale Docker/Podman containers started by OpenRun. The cleanup stops running OpenRun-labeled containers that are no longer referenced by an active app, and its interval is configurable with `system.stale_container_cleanup_interval_mins`.

- Fix #94: Added `X-Openrun-User-Id` and `X-Openrun-User-Email` headers for proxied apps, and exposed the same OIDC subject/email values on the Starlark request as `UserSubject` and `UserEmail`.

## [v0.17.1] - 2026-04-27

### Changed

- Action request bodies are now capped by default at `33554432` bytes. The limit can be configured globally with `app_config.action.max_request_body_bytes` or overridden per app with `openrun app update conf --promote 'action.max_request_body_bytes=<bytes>' /myapp`.
- `http.in` requests now inherit the current request context, support an optional `timeout` argument with a default of `300` seconds, and automatically close unread response bodies through deferred plugin cleanup when `body()` or `json()` are not called.
- Fix #91: Store session info in metadata KV store to avoid cookie size limits
- Fix #85: `openrun app create --cvol` and `openrun app update cvol` now reject container volume values that start with `--`, making missing volume arguments fail clearly instead of consuming the next option as the volume name.

## [v0.17.0] - 2026-04-22

### Added

- Added `security.trusted_proxies` server config to control which reverse proxies or load balancers are allowed to supply forwarded client IP headers.
- Added `system.fallback_unknown_domains` server config to optionally preserve legacy routing of unknown hostnames to the default domain.
- Added `system.builder_auth_token` server config for delegated container builds, using a shared bearer token between the main OpenRun install and builder node(s).
- Added `security.allowed_mounts` server config to allow administrators to approve host directories that apps may use as container bind-mount sources.

### Changed

- `req.RemoteIP` now ignores `X-Forwarded-For` and `X-Real-IP` unless the direct peer is listed in `security.trusted_proxies`.
- Reverse proxied requests now strip inbound forwarding headers and rebuild a clean `X-Forwarded-*` / `X-Real-IP` set before sending the request upstream.
- Requests for unknown `Host` values no longer route to the default domain unless `system.fallback_unknown_domains` is explicitly enabled.
- Delegated builds now require a valid bearer token on `/_openrun/delegate_build`. Builder nodes should run with `builder.mode = "delegate_server"` and no longer require `security.admin_over_tcp = true` for delegated-build ingress. Existing delegated-build setups must set the same `system.builder_auth_token` value on the main install and every builder node before upgrading.
- CORS is disabled by default for apps. The default `app_config.cors.allow_origin` is now empty and `app_config.cors.allow_credentials` is now `"false"`. Apps that need browser cross-origin access must opt in with an app config override such as `cors.allow_origin="https://frontend.example.com"` or `cors.allow_origin="origin"`.
- The default server-level `container.config(...)` permission no longer allows access to all secrets. Containerized apps that pass secrets through params, build args or generated secret volumes now need an explicitly approved `container.config` permission with the required `secrets=[...]` allowlist, unless the server config is intentionally changed to allow those secrets globally.
- Container runtime options now only pass raw Docker/Podman flags from app metadata when the flag is explicitly listed in `security.allowed_container_args`. Built-in `cpus` and `memory` options continue to be parsed by OpenRun and do not require this raw flag allowlist.
- Container bind-mount sources are now restricted to the app source directory, the app runtime directory, or directories listed in `security.allowed_mounts`. Relative bind sources must stay inside the app source tree.

## [v0.16.26] - 2026-04-06

### Added

- Added `UserId`, `CustomPerms`, and `AppRBACEnabled` to the request object available in Starlark handlers and HTML templates.

## [v0.16.24] - 2026-04-03

### Added

- Added `system.list_apps_title` and `system.show_hosted_with` server config options to customize the built-in app listing page title and whether it shows the `Hosted with OpenRun` text.

- Add the `security.auth_required` server config option. When enabled, apps configured with `auth="none"` are denied at request time with `401 Authentication required`, providing a server-wide guardrail against unauthenticated app access.

## [v0.16.22] - 2026-03-25

### Added

- Added automatic app version cleanup with a default retention of 5 older versions per app, configurable globally with `app_config.fs.retain_versions` and per app with `openrun app update conf --promote fs.retain_versions=<count> /myapp`.

## [0.16.21] - 2026-03-19

### Added

- Support for default permissions in server config. Containerized apps do not require explicit approval.

## [0.16.19] - 2026-02-13

### Added

- Postgres database support for store plugin

### Changed

- Changed python appspecs to use uv for managing dependencies

## [0.16.17] - 2026-02-04

### Changed

- Updated appspecs to not use heredocs since Kaniko does not support it

## [0.16.16] - 2026-02-04

### Added

- Lots of changes for Kubernetes support.

## [0.15.14] - 2025-10-31

### Added

- Added `openrun_admin` plugin with apis to manage `sync` jobs, for use by manage_sync app

### Changed

- Changed app authentication setting and git auth setting to be stored in app metadata instead of in app settings. This allows those properties to be updated through declarative config. The property is moved over as part of a migration. Also, `app update-metadata` CLI command is renamed to `app update`.
- Changed `app update-settings` CLI command to `app settings`.

## [0.15.13] - 2025-10-28

### Added

- Added AWS Systems Manager (SSM) based secrets provider

## [0.15.12] - 2025-10-27

### Changed

- HTTP early hints is disabled by default since that seems to cause issues with HTTP/2 proxies

## [0.15.11] - 2025-10-27

### Added

- Added `/_openrun/health` health check endpoint

## [0.15.10] - 2025-10-26

### Added

- Support for passing `X-Openrun-Rbac-Enabled` header to the proxied downstream service. Value is true if RBAC is enabled for app, false otherwise.
- Added update_time field to listapps output, app listing will display that info

## [0.15.9] - 2025-10-22

### Added

- Regex support in user value for RBAC. Regex can be used in grant.users and group values, Regex has to be prefixed with `regex:`
- Support for passing `X-Openrun-User` header to the proxied downstream service. Value is the user making the request.
- Support for passing `X-Openrun-Perms` header to the proxied downstream service. Value is comma separated list of all custom perms granted for the user on that app. `custom:` prefix is trimmed from the passed values.

### Fixed

- Fixed an issue where the source path was not set to `$OPENRUN_HOME/app_src` when running `apply` in `dev` mode.

## [0.15.8] - 2025-10-14

### Added

- Enable CSRF protection for internal APIs and for apps. App level CSRF protection is enabled by default.
  Use `security.disable_csrf_protection = true` to disable. Disable in app metadata by running
  `openrun app update conf --promote 'security.disable_csrf_protection=true' /myapp`
