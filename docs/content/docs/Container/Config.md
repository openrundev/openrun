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
container.deploy_probe_period_secs = 1
container.deploy_health_attempts = 75
container.deploy_progress_deadline_secs = 0 # Kubernetes rollout deadline, 0 lets OpenRun choose

# Idle Shutdown Config
container.idle_shutdown_secs = 180
container.idle_shutdown_dev_apps = false
container.idle_bytes_high_watermark = 1500 # bytes high watermark for idle shutdown
                                           # (1500 bytes sent and recv over 180 seconds)

# Number of older versions whose images are kept after a deploy (Docker/Podman)
container.retain_previous_images = 1

# Deploy strategy (Docker/Podman): "auto", "true" (start the new version
# beside the running one) or "false" (stop the previous version first)
container.blue_green_deploy = "auto"

# Status check Config
container.status_check_interval_secs = 20
container.status_health_attempts = 10

# Show logs for container startup failures in prod mode (dev is always true)
container.log_lines_to_show = 1000
container.show_logs_for_failure = true

# Kubernetes related settings
kubernetes.default_volume_size = "10Gi"
kubernetes.scaling_threshold_cpu = 80
```

A health check is done on the container after the container is started. If the health check fails `container.health_attempts_after_startup` times, the container is assumed to be down. The health check request timeout is controlled by `container.health_timeout_secs`.

In Kubernetes mode, `container.deploy_probe_period_secs` is used as the native startup and readiness probe interval, and `container.deploy_health_attempts` controls how long OpenRun waits for a deployment to become ready. `container.deploy_progress_deadline_secs` overrides the Deployment's `progressDeadlineSeconds` when set above `0`; the default `0` lets OpenRun choose a deadline that fits the wait budget. OpenRun watches Kubernetes Deployment status for faster readiness and rollout failure detection, but the watch uses the same configured wait budget. After blue-green promotion, OpenRun also performs a best-effort EndpointSlice convergence check; if the Kubernetes API or RBAC policy does not allow listing EndpointSlices, that check is skipped. These deployment checks are separate from the background status checks that run after the app is serving traffic.

In the running state, a status check is done on the app every `container.status_check_interval_secs` seconds. If `container.status_health_attempts` of those checks fail, then the container is assumed to be down.

If an app does not receive any REST API request for 180 seconds and the total data transfer from/to the app is below 1500 bytes over 180 seconds, the app is assumed to be idle and the container is stopped. The idle shutdown does not apply for dev apps, only for prod mode apps. For frameworks like Streamlit where WebSockets is used for communication between the UI and app, there will not be any REST API calls. The data transfer is used to determine whether the app is idle.

Set `container.idle_shutdown_secs = 0` to disable idle shutdown. Dev apps skip idle shutdown by default; set `container.idle_shutdown_dev_apps = true` to enable it for them. Kubernetes replica minimums do not override idle shutdown; see [resources and autoscaling]({{< ref "docs/container/kubernetes/#resources-and-autoscaling" >}}).

## Deploy strategy

On Docker/Podman, `container.blue_green_deploy` selects how a new version of a prod or stage app replaces the running one.

With a **blue-green** deploy (`"true"`), the new version's sidecars and container start beside the running ones, the previous version keeps serving until the new container passes its health check and the operation commits, and only then is the previous version's container stopped and removed. A failed deploy stops the new container and leaves the previous version running. There is no downtime, but the two versions briefly run at the same time, including on any named volume they share (the volume of an app or sidecar is reused across versions).

With a **stop-first** deploy (`"false"`), the previous version's app container and sidecars are stopped before the new version's sidecars and container start, so a volume never has two running versions on it. Requests to the app are held while the new version starts and are served by it once the deploy commits, so clients see a delay rather than errors. If the new version fails to start, or the operation fails for another app, the new version's containers are stopped and the held requests are released; the first of them starts the previous version's containers again, with that version's own health check, and the requests are served by them. Requests are held for at most the deploy health budget (`container.deploy_health_attempts` with the health timeout, per container); past that, requests are refused with a 503 until the deploy ends, since starting the previous version again would undo it. A second deploy of the same app which overlaps a stop-first deploy waits for it to end (at most that same budget) before replacing the containers, so two deploys never leave two versions running on a volume.

The default `"auto"` applies the rule Kubernetes uses: apps with a persistent volume (a named or unnamed volume of the app or of a sidecar, which includes the volume of a [SQLite binding]({{< ref "docs/use-cases/sqliteapps/" >}})) deploy stop-first, so the database never has two app containers on it, and apps without one deploy blue-green. Bind mounts and mounted secrets or config files do not count as persistent volumes. The per-app litestream replication container is not restarted by either strategy. Set the value explicitly to override the rule, for example to keep a blue-green deploy for an app whose volume only holds a cache:

```sh
openrun app update conf --promote container.blue_green_deploy=true /myapp
```

A bare `true` or `false` is accepted in place of the quoted string. The setting is ignored on Kubernetes: apps with persistent volumes use the `Recreate` strategy and stateless apps a rolling update, see [Kubernetes]({{< ref "docs/container/kubernetes/#architecture" >}}).

## Image and container cleanup

In Docker/Podman mode, each deploy of a prod or stage app builds an image for the new version (when the source, build args or Containerfile changed) and starts a container for it. The previous version's containers are removed when the deploy commits. The previous version's image is kept so that `version switch` and `version revert` to that version start quickly; switching to a version whose image was removed rebuilds it from the stored source.

`container.retain_previous_images` controls how many older versions keep their image: the images of the current version of each app copy (prod, stage, preview), of versions newer than the current one (after a revert) and of that many older versions are kept, and any other image of the app is removed after the deploy. The default of `1` keeps the previous version's image. Set it to `0` to keep only the images in use, or to `-1` to never remove the app's images. Versions pruned by `fs.retain_versions` cannot be switched to, so their images are never kept. Stage and prod share images by default, and the images kept for either copy are kept for both. Images of versions deployed before this setting existed are not tracked and are removed on the first deploy, unless a container still uses them. On Kubernetes, images are in the registry and are not removed by OpenRun.

`openrun app delete` removes the app's runtime assets: its containers and sidecars, generated images, named volumes and per app network on Docker/Podman, and its workloads, Service and volume claims on Kubernetes. Foreign sidecar images and images in a remote registry are not removed.

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
stale_container_cleanup_interval_mins = 5
```

`auto` means that OpenRun will look for `podman` executable in the path. If found, it will use that. Else it will use `docker` as the container manager command. If the value for `container_command` is set to any other value (except `kubernetes`), that will be used as the command to use. OrbStack implements the Docker CLI interface, so OrbStack also works fine with OpenRun.

Setting `container_command = "kubernetes"` enables Kubernetes mode. In Kubernetes mode, the Kubernetes APIs are used to manage the container lifecycle. No CLI commands are used in Kubernetes mode.

For Docker/Podman mode, `stale_container_cleanup_interval_mins` controls how often OpenRun stops running containers that were started by OpenRun but are no longer referenced by an active app. Set it to `0` or a negative value to disable stale container cleanup.
