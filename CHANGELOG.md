# Changelog

Changes to OpenRun will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  `openrun app update-metadata conf --promote 'security.disable_csrf_protection=true' /myapp`
