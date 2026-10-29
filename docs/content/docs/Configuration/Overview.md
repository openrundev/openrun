---
title: "Config Overview"
weight: 100
summary: "Overview of OpenRun configuration, at the server level and client level and the $OPENRUN_HOME location for files"
---

## OpenRun Server

The OpenRun server picks up its configuration from the config file at startup. All the parameters have default values, specified in the code at [openrun.default.toml](https://github.com/openrundev/openrun/blob/main/internal/system/openrun.default.toml).

Select a config file with the global `--config-file` (`-c`) flag, or with `CL_CONFIG_FILE`. The flag takes precedence. Otherwise, OpenRun uses `$OPENRUN_HOME/openrun.toml` or discovers an existing installation as described below.

Values in the user specified config take precedence over the default config values in the source code.

### Server Commands

The server is managed with the `openrun server` sub-commands:

- `start`: start the server in the foreground (install as a service, see [Installation]({{< ref "docs/installation" >}})).
- `stop [--wait]`: stop the server. `--wait` blocks until the server process has fully exited (the final litestream sync runs as the process exits).
- `status`: prints `ok` when the server connection works. `version`: reports the server's build version and commit.
- `restart`: zero downtime in-place restart (Linux/macOS): re-executes the server binary, reloading `openrun.toml` and picking up a new binary while handing over the listeners. `SIGHUP` does the same. `[restart] drain_timeout_secs` (default 300) is the max wait on shutdown for in-flight requests and websockets, `upgrade_timeout_secs` (default 90) the max wait for the new process to report ready.
- `show-config` / `update-config <file> [--force]`: read and update the [dynamic config](#dynamic-config).
- `metadata-status`: reports the metadata database connection health and SQLite maintenance metrics as JSON (exit code 1 when unhealthy).

### Environment Variables

| Variable | Purpose |
| --- | --- |
| `OPENRUN_HOME` | Home directory for the server and client, see below |
| `CL_CONFIG_FILE` | Config file path, same as `--config-file` |
| `OPENRUN_SERVER_URI` | Server to connect to, same as the global `--server-uri` flag; takes precedence over `server_uri` in the config file |
| `OPENRUN_API_KEY` | Bearer credential for a [remote server]({{< ref "remoteaccess" >}}); takes precedence over `client.api_key` |
| `OPENRUN_AS_USER` | User id to run the command as, same as the global `--as` flag (see [RBAC]({{< ref "rbac" >}})) |
| `OPENRUN_NO_KEYRING` | When set, `openrun login` stores tokens in `$OPENRUN_HOME/config` instead of the OS keychain |

## Home Directory

Set `OPENRUN_HOME` to choose the server home directory. If only a config file is specified, its parent directory becomes the home. If neither is set, OpenRun looks for an existing config beside its installation, then in platform-specific Homebrew or system locations such as `/var/lib/openrun` on Linux or `%ProgramData%\openrun` on Windows. If none is found, it uses `$HOME/openrun`.

Automatic first-start initialization applies only to this final fallback. With an explicit home or config path, initialize the config yourself as described in [Initial Configuration]({{< ref "docs/installation/#initial-configuration" >}}). Without a saved password hash, a generated password changes on each server start. The home directory stores:

- The default config file, `$OPENRUN_HOME/openrun.toml`
- The sqlite database containing the metadata information, default is `$OPENRUN_HOME/metadata/clace_metadata.db`
- The logs for the service, under the `logs` folder.
- The config folder contains the certificates to use for TLS.
- The run folder contains app specific temporary files.

## OpenRun Client CLI

By default, the OpenRun client uses Unix domain sockets to connect to the OpenRun server. `$OPENRUN_HOME` should point to the same location for server and client. If no changes are done for the server defaults, then the client can connect to the server locally without any other configuration being required. See [Remote API and MCP]({{< ref "remoteaccess" >}}) for the client configuration when connecting to a remote server. The global `--server-uri` flag (or `OPENRUN_SERVER_URI`) overrides the `server_uri` value from the config file for one command.

The client settings and their defaults are:

```toml {filename="openrun.toml"}
server_uri = "$OPENRUN_HOME/run/openrun.sock" # unix domain socket path, or https://host[:port] for a remote server
admin_user = "admin"                          # the system admin username (used by the server too)

[client]
api_key = ""             # API key for a remote server; the OPENRUN_API_KEY env var takes precedence
skip_cert_check = false  # skip TLS certificate verification for self-signed server certs
default_format = "basic" # default output format: table, basic, csv, json, jsonl or jsonl_pretty
```

## App Config

In `openrun.toml`, properties which apply to all apps can be defined under the `[app_config]` section. For example

```toml {filename="openrun.toml"}
[app_config]
audit.redact_url = true
```

sets the redact property to true for all apps. The property can be further configured individually for one or more apps in the app metadata using

```sh
openrun app update conf --promote 'audit.redact_url=true' /myapp
```

App config properties can also be declared in the app definition, using the `app_config` section of the `ace.app` settings dict:

```python {filename="app.star"}
app = ace.app("My App",
    settings={"app_config": {"audit": {"redact_url": True}}})
```

When the same property is set in multiple places, the server `[app_config]` value is applied first, then the `app.star` settings, then the app metadata value set with `--conf`.

The request body of the Starlark handler routes (html, fragment and api routes) is capped by `max_request_body_bytes` under `[app_config]`, 10MB by default: a larger body is refused with a 413 status. Proxied routes are not capped, and action routes have their own `action.max_request_body_bytes` cap.

Version retention is also configured under `[app_config]`. By default, OpenRun keeps the current version plus 5 older versions for each app. Older versions are cleaned up automatically after operations which create or promote app versions.

To change the default for all apps, set `fs.retain_versions` in `openrun.toml`:

```toml {filename="openrun.toml"}
[app_config]
fs.retain_versions = 10
```

To override the retention count for a specific app, update the app metadata:

```sh
openrun app update conf --promote fs.retain_versions=10 /myapp
```

Setting `fs.retain_versions = 0` keeps only the current version for that app.

The `static_from_disk` property makes an app with a local disk source serve its files directly from the source directory instead of copying them into the metadata database, as done by the [static_disk spec]({{< ref "/docs/container/appspecs" >}}). It can be set for one app with `openrun app create --conf static_from_disk=true <source_dir> <app_path>`, and requires the app source to be a local disk directory.

## Config Access from Code

[App Params]({{< ref "docs/develop/#app-parameters" >}}) are the primary user configurable properties for apps. For cases where properties need to be read from `openrun.toml` config file or from env, the config builtin can be used. This is available as `config` in app declarations (`apps.star`) and in `params.star`. In the app definition (`app.star`), this is available as `ace.config`.

The `config`/`ace.config` builtin supports the following parameters:

- **key** (string, required) : the config key name
- **default** (any, required) : the default value

`_branch` is a special key which resolves to the git branch from which the app declaration is loaded. `_dev` is true if the apply is run in dev mode. In `app.star`, `ace.config("_app_url", "")` is a special key which resolves to the url the app is served at.

In `app.star`, a call to config like

```python {filename="app.star"}
system_list = ace.config("systems", ["local"])
```

will fetch the default value. Adding in `openrun.toml` config

```toml {filename="openrun.toml"}
[node_config]
systems = ["local", "stage", "test"]
```

will result in the configured value being available in the code. This allows for installation specific properties, while keeping the source code same across environments. In string values, references to the environment variables listed in `system.allowed_env` (default `["HOME", "OPENRUN_HOME", "PATH"]`) are expanded, so `data_dir = "$OPENRUN_HOME/data"` resolves to the server's home directory.

In app declaration, same can be accessed as

```python {filename="utils.star"}
system_list = config("systems", ["local"])
app("/utils/bookmarks", "github.com/openrundev/apps/utils/bookmarks", params={"systems": system_list})
```

If the app source code needs to be checked out from same branch as the app declaration, then do

```python {filename="apps.star"}
branch=config("_branch", "main")
app("/" + branch + "/bookmarks", "github.com/openrundev/apps/utils/bookmarks", git_branch=branch)
```

This creates the app from the same branch as used during the `apply`/`sync` command.

## Dynamic Config

The `openrun.toml` is statically read at service startup. In addition, dynamic config is supported which does not require a service restart. The current dynamic config is always available at `$OPENRUN_HOME/config/dynamic_config.json`. To make changes, copy this file to a new location, make updates and then run `openrun server update-config /tmp/dynamic-config.json`. This updates the service with the new config, persists the config to the metadata database and automatically notifies any additional OpenRun server instances to dynamically update its config.

The basic format of this config is

```json
{
  "version_id": "ver_32wLWdqboA08eCRDO1KEznxBxka",
  "rbac": {
    "groups": {},
    "roles": {},
    "grants": [
      {
        "description": "Default: authenticated principals can access and list apps",
        "users": ["*"],
        "roles": ["openrun-user"],
        "targets": ["all"]
      }
    ]
  }
}
```

[RBAC]({{< ref "RBAC" >}}) has more details about using the dynamic config.

Besides `rbac`, the dynamic config can carry two more sections, which take precedence over the static `openrun.toml` values:

- `entries`: named config entries, mirroring the named-entry sections of `openrun.toml`. This is what the console config forms write. Dynamic entries shadow a static entry with the same name.
- `settings`: individual fields of the struct sections, as section name to dotted field key, for example `{"security": {"default_git_auth": "mykey"}, "app_config": {"cors.allow_origin": "origin"}, "api": {"rest.enable": true}}`.

Only the config the console manages can be set dynamically, since `config:update` is held by operators who are not admin:

| Kind     | Dynamically settable                                                                                                                                                                                                                                                                                          |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| entries  | `git_auth`, `auth`, `saml`, `secret`, `builder_agent`, `builder_profile`, `builder_git`                                                                                                                                                                                                                       |
| settings | `security`: `app_default_auth_type`, `default_git_auth`                                                                                                                                                                                                                                                       |
|          | `system`: `default_domain`, `stage_at`, `list_apps_title`, `show_hosted_with`                                                                                                                                                                                                                                 |
|          | `api`: `external_url`, `access_token_ttl`, `refresh_token_ttl`, `grant_max_ttl`, `federated_identity_ttl`, `pat_default_ttl`, `rest.enable`, `rest.auth`, `rest.enable_apis`, `rest.disable_apis`, `mcp.enable`, `mcp.auth`, `mcp.enable_apis`, `mcp.disable_apis`, `mcp.skip_destructive_confirm`, `app_mcp.enable`, `app_mcp.allowed_auth`, `app_mcp.max_tools`, `app_mcp.list_ttl` |
|          | `app_builder`: `enabled`, `default_builder_profile`, `preview_path`, `max_sessions`, `session_idle_mins`, `system_prompt`                                                                                                                                                                                     |
|          | `app_config`, `node_config`: any key                                                                                                                                                                                                                                                                          |

Everything else, including every `unsafe_*` flag, is static `openrun.toml` config only. Setting it dynamically fails with an error naming the keys which can be set. A value persisted by an earlier version for a key which is now static only is ignored (with a warning in the server log); an `update-config` upload may carry such a value unchanged, but cannot change it.

Making a config update will automatically update the `$OPENRUN_HOME/config/dynamic_config.json` file on all instances. The `show-config` command can also show the latest config. The version id is auto-generated with a unique value. Subsequent updates need to pass the current version id, the `update-config` will fail if a stale id is passed in. The `--force` option can be used to overwrite the config. The server keeps the last `metadata.config_history_versions` (default 20) config snapshots.

## Other Server Settings

Most server sections are documented on their own pages: [Ports and Certificates]({{< ref "networking" >}}) for `[http]`, `[https]` and the domain settings in `[system]`, [Security]({{< ref "security" >}}), [Remote API and MCP]({{< ref "remoteaccess" >}}) for `[api]`, [Secrets]({{< ref "secrets" >}}), [Telemetry]({{< ref "telemetry" >}}) for `[telemetry]` and `[logging]`, [Container]({{< ref "docs/container" >}}) for the container, build and Kubernetes settings and [Litestream]({{< ref "docs/applications/litestream" >}}) for `[litestream.*]`. The remaining general settings, with their defaults, are:

```toml {filename="openrun.toml"}
[metadata]
db_connection = "sqlite:$OPENRUN_HOME/metadata/clace_metadata.db"
audit_db_connection = "sqlite:$OPENRUN_HOME/metadata/clace_audit.db"
file_cache_connection = "sqlite:$OPENRUN_HOME/metadata/file_cache.db"
auto_upgrade = true                    # upgrade the metadata schema automatically at startup
ignore_higher_version = false          # start even if the database schema is newer than the binary supports
config_history_versions = 20           # dynamic config snapshots retained
# SQLite self-maintenance for the metadata, audit and file cache databases
sqlite_journal_size_limit = 33554432   # WAL size in bytes the file is truncated back to on checkpoint, <=0 for no limit
sqlite_maintenance_interval_secs = 60  # background checkpoint/vacuum period, <=0 disables
sqlite_truncate_checkpoint_every = 10  # maintenance passes between truncate checkpoints, <=0 disables
sqlite_vacuum_pages = 2000             # max free pages returned to the OS per pass, <=0 disables

[system]
enable_compression = true              # compress HTTP responses
early_hints = false                    # HTTP early hints for HTML responses
file_watcher_debounce_millis = 300     # debounce for dev mode file watching
watch_ignore_patterns = ["**/.git/**", "**/node_modules/**"] # file watcher ignore globs (the default list is longer)
node_path = ""                         # node module lookup paths for esbuild
git_checkout_cache_entries = 0         # immutable git checkouts reused across operations, 0 disables
git_remote_check_interval_secs = 0     # reuse checked branch heads for this long, 0 always checks the remote
git_operation_timeout_secs = 600       # timeout for each remote git operation, <=0 disables
max_concurrent_builds = 1              # concurrent container builds
max_build_wait_secs = 120              # max wait for a build lock
file_workers = 4                       # parallel workers for file compression during app version creation
memory_high_water_bytes = 0            # memory in use over which running Starlark handlers are canceled; 0 uses 90% of
                                       # the Go memory limit when GOMEMLIMIT is set, else no check
leader_election_lease_secs = 30        # multi-node leader election lease and heartbeat
leader_election_heartbeat_interval_secs = 10
allowed_env = ["HOME", "OPENRUN_HOME", "PATH"] # env variables expanded in [node_config] values

[kubernetes]
namespace = "openrun"                  # namespace for app workloads
use_node_port = false                  # NodePort instead of ClusterIP services
```

The metadata connection strings support `{{secret ...}}` references and `postgres://` URLs in addition to SQLite.
