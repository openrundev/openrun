---
title: "SQLite + Litestream Replication to S3"
weight: 550
description: "Deploy SQLite-backed web apps with continuous Litestream replication to AWS S3, Cloudflare R2, MinIO and other S3-compatible storage, with automatic restore on Docker, Podman and Kubernetes."
summary: "Continuous SQLite replication to S3-compatible storage with Litestream and automatic restore."
---

OpenRun is an open-source web app deployment platform with built-in [Litestream](https://litestream.io/) support for SQLite applications. App SQLite databases are continuously replicated to AWS S3 or S3-compatible object storage such as Cloudflare R2, MinIO and SeaweedFS, and are automatically restored before the app starts if its local volume is lost.

Applications do not need to package, configure or run Litestream themselves. OpenRun manages the replication and restore lifecycle on Docker, Podman and Kubernetes.

Two types of SQLite data can be replicated:

- **App data**: the SQLite databases behind [SQLite service bindings]({{< ref "/docs/applications/servicebindings/#sqlite-config-and-behavior" >}}).
- **Server metadata**: OpenRun's own metadata and audit databases (single node, SQLite metadata).

Replication is continuous (changes upload within about a second) and restore is automatic: a new node, a lost volume or a re-attached binding is repopulated from the replica before the app starts. Together this gives disaster recovery for a complete node loss — start a new server with the same config file and everything comes back from object storage.

## Automatic SQLite Backup and Restore

OpenRun continuously replicates SQLite app databases to S3 using Litestream. If an app volume is lost or recreated, OpenRun restores the database from object storage before starting the application.

Server metadata can also be replicated and restored, allowing a new OpenRun server to recover apps, bindings, services, versions and audit history after a complete node loss.

## S3-Compatible Storage

OpenRun's Litestream integration works with:

- AWS S3
- Cloudflare R2
- MinIO
- SeaweedFS
- Other S3-compatible object stores

## How It Works

```text
Web app
   ↓
SQLite persistent volume
   ↓
Litestream managed by OpenRun
   ↓
S3 / R2 / MinIO
```

On Docker and Podman, OpenRun manages a Litestream companion container. On Kubernetes, OpenRun creates the restore init container and Litestream sidecar automatically.

## Litestream Configs

Litestream settings are named entries in the server config. Multiple configs allow different buckets, endpoints or credentials to coexist (per team, per environment, metadata vs apps):

```toml {filename="openrun.toml"}
[litestream.mainbackup]
endpoint = "https://s3.example.com"        # S3-compatible endpoint; empty for AWS S3
bucket = "openrun-backups"
region = "us-east-1"
path_prefix = "openrun"                    # replica key prefix inside the bucket
access_key_id = '{{secret_from "env" "LITESTREAM_KEY_ID"}}'
secret_access_key = '{{secret_from "env" "LITESTREAM_KEY"}}'
force_path_style = true                    # required by most S3-compatibles
sync_interval = "1s"
retention = "72h"
snapshot_interval = "24h"

[metadata]
litestream_config = "mainbackup"           # replicate the server's own databases
```

| Key                 | Default   | Description                                                                                                       |
| :------------------ | :-------- | :---------------------------------------------------------------------------------------------------------------- |
| `type`              | `s3`      | Replica type. `file` replicates to a local directory (metadata only; not usable for app bindings)                  |
| `endpoint`          |           | S3-compatible endpoint URL; leave empty for AWS S3                                                                |
| `container_endpoint`|           | Endpoint as reachable from inside app containers, when it differs from `endpoint` (see below)                     |
| `bucket`            |           | Bucket name (required for `s3`)                                                                                   |
| `region`            |           | S3 region                                                                                                         |
| `path_prefix`       |           | Key prefix inside the bucket                                                                                      |
| `path`              |           | Local directory (required for `file`)                                                                             |
| `access_key_id`, `secret_access_key` | | Credentials; support secret references, resolved at startup                                      |
| `force_path_style`  | `false`   | Path-style S3 URLs, required by most S3-compatible servers                                                        |
| `sync_interval`     | `1s`      | How often changes are uploaded. This bounds the data loss window on a crash                                       |
| `retention`         | `24h`     | How long replica history is kept. This bounds how far back a restore can go                                       |
| `snapshot_interval` | `24h`     | Snapshot frequency; lower values make restores faster                                                             |
| `sidecar_image`     | `litestream/litestream:0.5` | Litestream image for app replication containers. Keep pinned: the replica format ties restores to the image series |
| `checkpoint_interval`, `min_checkpoint_page_count`, `truncate_page_n` | | Checkpoint tuning, see [Litestream's guide](https://litestream.io/guides/wal-truncate-threshold/). Apps with long-running reads should set `truncate_page_n = 0` |
| `storage_class`, `sse_kms_key_id` | | Optional S3 storage class and server-side encryption settings                                     |

Credentials cannot use the `db` secret provider: metadata replication must be resolvable before the metadata database is opened. All configured entries are validated at server startup.

## Metadata Replication

Set `metadata.litestream_config` to a config name to replicate the server's metadata and audit databases (the file cache is a rebuildable cache and is not replicated). This applies when the metadata database is SQLite; with PostgreSQL metadata there is nothing to do.

On startup, if a metadata database file is missing and a replica exists, it is restored before the server opens it. To rebuild a lost node: install OpenRun on a new machine, use the same config file, start the server. Apps, bindings, services, versions and audit history are restored from the replica; containerized apps then redeploy on first request, restoring their SQLite data the same way.

Replication runs inside the OpenRun server process (Litestream is embedded as a library); no separate binary or process is needed.

## App Data Replication

Enable replication for a SQLite service by referencing a config:

```shell
openrun service create sqlite/main --config litestream_config=mainbackup
openrun app create --bind sqlite/main --approve github.com/example/notes-app /notes
```

Every `*.db` file the app creates in its binding directory is replicated, including files created while the app is running (Litestream's directory watcher discovers them within seconds). The file selection can be changed per binding with the `pattern` [binding config key]({{< ref "/docs/applications/servicebindings/#sqlite-config-and-behavior" >}}), e.g. `--config "pattern=*.sqlite3"`.

How it runs:

- **Docker/Podman**: a per-app companion container (`clc-<app-id>-ls`) runs `litestream replicate` sharing the app's data volume. Before the app container starts on an empty volume, one-shot restore containers pull any replicated databases back. The sidecar survives app version updates, stops gently (after a final sync) when the app is idle-shut-down, and restarts with the app.
- **Kubernetes**: restore init containers plus a native sidecar (init container with `restartPolicy: Always`) run inside the app's pod. Requires Kubernetes 1.29 or newer. The sidecar starts before the app container and is terminated after it, so the final changes are always synced.

Replica locations are keyed by binding identity and environment:

```text
s3://<bucket>/<path_prefix>/bindings/<binding-id>/prod/...
s3://<bucket>/<path_prefix>/bindings/<binding-id>/staged/...
```

Production and staging apps replicate to separate locations. Because the replica follows the binding (not the app), detaching a binding and attaching it to a new app restores the data into the new app's fresh volume. To use different buckets or credentials per environment, link a [staging service]({{< ref "/docs/applications/servicebindings/#staging-services" >}}) whose config names a different litestream config.

Changing a service's `litestream_config` takes effect on the next app reload: replication starts fresh in the new location, and the old location stops advancing but keeps its history.

### Container-visible endpoints

The S3 endpoint must be reachable from inside app containers. For a `localhost` endpoint with Docker/Podman, OpenRun automatically substitutes the container-reachable host name (like `host.docker.internal`). Kubernetes has no automatic mapping: if pods reach the endpoint through a different address than the server, set `container_endpoint` on the litestream config. The server keeps using `endpoint` for its own access.

## Monitoring

`openrun replication status` reports the state of every replicated database:

```text
$ openrun replication status -f table
Kind       Target                              Config       State     LastSync             Files      Apps
metadata   metadata                            mainbackup   healthy   2026-07-25 16:31:42  -
metadata   audit                               mainbackup   healthy   2026-07-25 16:31:42  -
app        /auto/app_prd_.../sqlite (prod)     mainbackup   healthy   2026-07-25 23:31:30  data.db    /notes
app        /auto/app_prd_.../sqlite (staged)   mainbackup   pending   -                    -          stage.localhost:/notes
```

Use `-f json` for full detail, including the per-file breakdown and replica transaction ids. The same data is available to apps through the read-only `replication_status` function of the `openrun.in` plugin.

| State           | Meaning                                                                                                  |
| :-------------- | :-------------------------------------------------------------------------------------------------------- |
| `healthy`       | Replica advanced recently (metadata: local and replica are in sync)                                       |
| `idle`          | Replica is reachable but has not advanced recently; normal for an app that is not writing                 |
| `pending`       | Nothing replicated yet (fresh binding, or an environment that has not deployed)                           |
| `sidecar_down`  | The replication container is not running while replicated data exists; fix by reloading the app (`app reload --promote`) |
| `misconfigured` | The service references a litestream config that is not defined (or not usable for apps)                   |
| `error`         | The replica location could not be checked; see the `error` field                                          |

App states combine the replica listing in object storage with the replication container's state, so a dead sidecar is flagged even when the app is idle.

## Operational Notes

- **Data loss window**: replication is asynchronous. On a catastrophic failure, up to the last `sync_interval` of writes (1s by default) can be lost.
- **Restore window**: bounded by `retention`. Increase it (and consider `snapshot_interval`) if you need to restore older states.
- **Storage**: app volumes are Docker named volumes or block-backed PVCs. Network filesystems (NFS/SMB) are not supported for SQLite data, and NFS-backed PVCs may delay discovery of new database files.
- **Volume permissions**: fresh volumes and restored files are made writable for non-root app users with a `chmod` that runs using the Litestream image, so distroless app images work with replication enabled. Kubernetes pods additionally get `fsGroup: 65532`.
- **Deletes keep data**: deleting an app or binding keeps the volume and the replica. Replica history ages out per `retention`.
- **Image pinning**: `sidecar_image` and the embedded Litestream are on the 0.5 series (LTX replica format). Upgrades are an operator action.
- **Windows**: fully supported. App replication runs in Linux containers; metadata replication runs on the host through the embedded library.

## Frequently Asked Questions

### Does OpenRun automatically back up SQLite databases to S3?

Yes. OpenRun uses Litestream to continuously replicate SQLite databases to AWS S3 or compatible object storage. Changes are uploaded according to the configured `sync_interval`, which defaults to one second.

### Does OpenRun automatically restore SQLite after volume loss?

Yes. When an app starts with an empty or recreated volume, OpenRun restores its replicated SQLite databases from object storage before starting the application. The replica follows the binding, so data can also be restored when that binding is attached to a new app.

### Do I need to add Litestream to my Docker image?

No. On Docker and Podman, OpenRun runs Litestream in a managed companion container that shares the app's data volume. Your application image does not need to include or configure Litestream.

### Can I use Cloudflare R2 or MinIO instead of AWS S3?

Yes. OpenRun supports Cloudflare R2, MinIO, SeaweedFS and other S3-compatible object stores. Configure the provider's endpoint and enable path-style URLs when the provider requires them.

### Does Litestream replication work with OpenRun on Kubernetes?

Yes. OpenRun automatically adds a restore init container and Litestream sidecar to the app pod. Kubernetes 1.29 or newer is required for the native sidecar lifecycle used by replication.
