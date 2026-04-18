# Changelog

Changes to OpenRun will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `security.trusted_proxies` server config to control which reverse proxies or load balancers are allowed to supply forwarded client IP headers.
- Added `system.fallback_unknown_domains` server config to optionally preserve legacy routing of unknown hostnames to the default domain.
- Added `system.builder_auth_token` server config for delegated container builds, using a shared bearer token between the main OpenRun install and builder node(s).

### Changed

- `req.RemoteIP` now ignores `X-Forwarded-For` and `X-Real-IP` unless the direct peer is listed in `security.trusted_proxies`.
- Reverse proxied requests now strip inbound forwarding headers and rebuild a clean `X-Forwarded-*` / `X-Real-IP` set before sending the request upstream.
- Requests for unknown `Host` values no longer route to the default domain unless `system.fallback_unknown_domains` is explicitly enabled.
- Delegated builds now require a valid bearer token on `/_openrun/delegate_build`. Builder nodes should run with `builder.mode = "delegate_server"` and no longer require `security.admin_over_tcp = true` for delegated-build ingress. Existing delegated-build setups must set the same `system.builder_auth_token` value on the main install and every builder node before upgrading.
- CORS is disabled by default for apps. The default `app_config.cors.allow_origin` is now empty and `app_config.cors.allow_credentials` is now `"false"`. Apps that need browser cross-origin access must opt in with an app config override such as `cors.allow_origin="https://frontend.example.com"` or `cors.allow_origin="origin"`.
- The default server-level `container.config(...)` permission no longer allows access to all secrets. Containerized apps that pass secrets through params, build args or generated secret volumes now need an explicitly approved `container.config` permission with the required `secrets=[...]` allowlist, unless the server config is intentionally changed to allow those secrets globally.

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
