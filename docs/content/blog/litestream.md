---
title: "SQLite in Production with Zero-Config Litestream Replication"
description: "OpenRun continuously replicates app SQLite databases to S3-compatible storage with Litestream and restores them automatically, on a single node and on Kubernetes."
summary: "Continuous SQLite replication to S3 with automatic restore, managed by the platform instead of the app."
date: 2026-08-25
---

{{< openrun-intro >}}

OpenRun now has built-in [Litestream](https://litestream.io/) support for SQLite apps. App databases are continuously replicated to AWS S3 or S3-compatible object storage such as Cloudflare R2, MinIO and SeaweedFS. Restore is automatic: when an app starts with an empty or recreated volume, the database is pulled back from the replica before the app starts. The same setup works on a single node with Docker/Podman and on Kubernetes.

## Background

SQLite is a great fit for internal tools and small web apps: one file holds all the data, reads are fast and there is zero database server overhead. Litestream solves date replication for SQLite by streaming WAL changes to object storage. Each app has to bundle the Litestream binary in its image, write a config file and run the restore step on startup.

OpenRun moves all the Litestream setup overhead into the deployment platform. Litestream settings live in the server config, and OpenRun manages the replication and restore lifecycle outside the app container. The app image stays unchanged, adding new apps which use SQLite is much easier.

## Deploying a SQLite App

Define a Litestream config once in the server config:

```toml {filename="openrun.toml"}
[litestream.mainbackup]
bucket = "openrun-backups"
region = "us-east-1"
access_key_id = '{{secret_from "env" "LITESTREAM_KEY_ID"}}'
secret_access_key = '{{secret_from "env" "LITESTREAM_KEY"}}'
```

Then create a SQLite service that references it and bind apps to the service:

```sh
openrun service create sqlite/main --is-default --config litestream_config=mainbackup
openrun app create --bind sqlite --approve github.com/example/notes-app /notes
```

The same app can be defined declaratively. Put the definition in an apply file, in Git alongside your other config:

```python {filename="apps.star"}
app("/notes", "github.com/example/notes-app", bindings=["sqlite"])
```

```sh
openrun apply --promote github.com/example/config/apps.star
```

`openrun apply` works like Kubernetes apply: it creates apps that are new, updates apps whose config changed and leaves the rest alone. All app management, including the SQLite binding, can be driven through GitOps.

That is the whole setup. The app gets a persistent volume mounted at `/data` and finds its database through injected environment variables (`SQLITE_DB_PATH`, `SQLITE_DIR`). Every `*.db` file the app creates in that directory is replicated, including files created at runtime.

Changes upload within about a second (the `sync_interval`, configurable).

## Single Node

On Docker and Podman, OpenRun runs Litestream in a per-app companion container that shares the app's data volume. Before the app container starts on an empty volume, restore containers pull any replicated databases back. When the app scales down to zero on idle, the sidecar performs a final sync and stops with it.

<picture class="responsive-picture" style="display: block; margin-left: auto; margin-right: auto;">
  <img alt="Single-node deployment with Litestream replication of app data and server metadata to S3-compatible storage" src="/d2/single-node-litestream.svg">
</picture>

The server's own metadata can be replicated the same way. Litestream is embedded in the OpenRun binary as a Go library, so setting `metadata.litestream_config` in the server config replicates the metadata and audit databases with zero extra processes.

## Kubernetes

The same app config works when OpenRun [deploys to a Kubernetes cluster]({{< ref "/docs/container/kubernetes" >}}). The binding's volume becomes a PersistentVolumeClaim, and OpenRun adds a restore init container plus a native Litestream sidecar (Kubernetes 1.29 or newer) to the app pod automatically. The sidecar starts before the app container and is terminated after it, so the final changes are always synced. Apps with a SQLite binding run as a single replica with the `Recreate` update strategy, which respects SQLite's single-writer model.

<picture class="responsive-picture" style="display: block; margin-left: auto; margin-right: auto;">
  <img alt="Kubernetes deployment with a restore init container, app container and Litestream sidecar in the app pod, replicating the SQLite PVC to S3-compatible storage" src="/d2/k8s-litestream.svg">
</picture>

## What Happens on a Volume or Node Loss

For a lost app volume, recovery is automatic and invisible to the app. The next time the app starts, OpenRun sees the empty volume, runs the restore containers to pull the databases back from the replica, and then starts the app container against the restored data. The replica is keyed by the binding, so attaching the binding to a new app restores the data into that app's fresh volume too.

For a complete node loss, with metadata replication enabled, the recovery procedure is:

1. Install OpenRun on a new machine.
2. Start the server with the same config file.

On startup, the server finds its metadata database missing, restores the metadata and audit databases from the replica, and comes up with all apps, bindings, services, versions and audit history intact. Each app then redeploys on first request, restoring its SQLite data from its own replica before the container starts. The config file is the single thing to keep safe outside the node.

Replication is asynchronous, so up to the last `sync_interval` of writes (one second by default) can be lost in a crash.

The node loss scenario is exercised end to end in [CI tests](https://github.com/openrundev/openrun/blob/7baff958df092121b014ac36d469771bc54f547b/tests/run_cli_tests.sh#L1344).

## Monitoring

`openrun replication status` reports the state of every replicated database:

```text
$ openrun replication status -f table
Kind       Target                              Config       State     LastSync             Files      Apps
metadata   metadata                            mainbackup   healthy   2026-08-25 16:31:42  -
metadata   audit                               mainbackup   healthy   2026-08-25 16:31:42  -
app        /auto/app_prd_.../sqlite (prod)     mainbackup   healthy   2026-08-25 23:31:30  data.db    /notes
app        /auto/app_prd_.../sqlite (staged)   mainbackup   pending   -                    -          stage.localhost:/notes
```

App states combine the replica listing in object storage with the replication container's state, so a dead sidecar is flagged even when the app is idle.

See the [Litestream reference]({{< ref "/docs/applications/litestream" >}}) for the full config options and the [SQLite hosting use case]({{< ref "/docs/use-cases/sqliteapps" >}}) for app best practices (WAL mode, busy timeouts, short write transactions).

The replication status is also visible in the [Console App]({{< ref "/console-tour" >}}), see [demo](https://utils.demo.clace.io/console/containers?query=&filter=litestream).
