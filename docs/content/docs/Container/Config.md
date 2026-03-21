---
title: "Container Config"
weight: 200
summary: "Overview of containerized app config and state management"
---

The default configuration for the OpenRun server is defined in [openrun.default.toml](https://github.com/openrundev/openrun/blob/main/internal/system/openrun.default.toml). The container related config settings are

```toml {filename="openrun.toml"}
[app_config]

# Health check Config
container.health_url = "/"
container.health_attempts_after_startup = 30
container.health_timeout_secs = 5

# Idle Shutdown Config
container.idle_shutdown_secs = 180
container.idle_shutdown_dev_apps = false
container.idle_bytes_high_watermark = 1500 # bytes high watermark for idle shutdown
                                           # (1500 bytes sent and recv over 180 seconds)

# Status check Config
container.status_check_interval_secs = 20
container.status_health_attempts = 10

# Show logs for container startup failures in prod mode (dev is always true)
container.log_lines_to_show = 1000
container.show_logs_for_failure = true

# Kubernetes related settings
kubernetes.default_volume_size = "10Gi"
kubernetes.strict_version_check = true
kubernetes.scaling_threshold_cpu = 80
```

A health check is done on the container after the container is started. If the health check fails 30 times, the container is assumed to be down.

In the running state, a status check is done on the app every five seconds. If three of those checks fail, then the container is assumed to be down.

If an app does not receive any REST API request for 180 seconds and the total data transfer from/to the app is below 1500 bytes over 180 seconds, the app is assumed to be idle and the container is stopped. The idle shutdown does not apply for dev apps, only for prod mode apps. For frameworks like Streamlit where WebSockets is used for communication between the UI and app, there will not be any REST API calls. The data transfer is used to determine whether the app is idle.

## Changing Config

The `openrun.toml` can be updated to have a different value for any of the properties. After the server restart, the config change will apply for all apps.

To apply the config at the app level, the app metadata can be updated. For example the command

```sh
openrun app update conf --promote container.idle_shutdown_secs=600 /myapp
```

changes the idle timeout for the `/myapp` app to 600 seconds. Without the `--promote` option, the change will be staged and can be verified on the staging app. App metadata level settings take precedence over the defaults in the `openrun.toml`. Using `all` as the app name will apply the change for all current apps (but not for any new apps created later).

## Configuring the container manager

The default for the container command to use is

```toml
[system]
container_command = "auto"
```

`auto` means that OpenRun will look for `podman` executable in the path. If found, it will use that. Else it will use `docker` as the container manager command. If the value for `container_command` is set to any other value (except `kubernetes`), that will be used as the command to use. Orbstack implements the Docker CLI interface, so Orbstack also works fine with OpenRun.

Setting `container_command = "kubernetes"` enables Kubernetes mode. In Kubernetes mode, the Kubernetes APIs are used to manage the container lifecycle. No CLI commands are used in Kubernetes mode.
