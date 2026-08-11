---
title: "SQLite Web App Hosting"
weight: 400
description: "Host SQLite web apps on a self-hosted server or Kubernetes: persistent volumes per app, safe updates with staging and promotion, and continuous Litestream backups to S3."
summary: "Deploy SQLite-backed web apps with persistent volumes, staged updates and automatic backups, on a single node or Kubernetes."
---

SQLite is a good fit for internal tools and small web apps: no database server to run, one file to back up and excellent read performance. What SQLite hosting needs from a platform is persistent storage per app, safe updates that respect SQLite's single-writer model and backups. OpenRun provides all three: each app gets a persistent volume through a [SQLite service binding]({{< ref "docs/applications/servicebindings/#sqlite-config-and-behavior" >}}), updates go through staged deployment, and [Litestream replication]({{< ref "docs/applications/litestream/" >}}) continuously backs the database up to S3-compatible storage.

## Scenario

This use case covers the scenario where you want to:

- Deploy web apps that store their data in SQLite, with no external database server
- Keep each app's data on a persistent volume that survives app updates and redeploys
- Update apps safely, verifying changes in staging before promoting to production
- Back up databases continuously and restore automatically after a volume or node loss
- Run on a single server first, with the option to move to Kubernetes later

## Deploying a SQLite App

Create a SQLite service once, then bind apps to it:

```sh
openrun service create sqlite/main --is-default
openrun app create --bind sqlite --approve github.com/example/notes-app /notes
```

The app finds its database through environment variables injected by OpenRun:

```text
SQLITE_URL=file:/data/data.db
SQLITE_DB_PATH=/data/data.db
SQLITE_DIR=/data
```

The app opens the database at `SQLITE_DB_PATH` and needs no other configuration. Apps can also create additional database files under `SQLITE_DIR`, for example per-tenant databases.

The mount directory (default `/data`) can be changed per binding with the `path` [binding config key]({{< ref "docs/applications/servicebindings/#sqlite-config-and-behavior" >}}), either on the binding source when the app is created or on an explicitly created binding:

```sh
openrun app create --bind "sqlite;path=/var/lib/app" --approve github.com/example/notes-app /notes
# or
openrun binding create --config path=/var/lib/app sqlite/main /apps/notes-db
```

The environment variables follow the configured path, so the app itself needs no change.

How the app opens and uses the database matters for reliability; see [App Best Practices](#app-best-practices) below.

## App Best Practices

OpenRun handles volumes, updates and backups outside the container. Inside the container, a few practices keep SQLite reliable under this setup:

- **Read the database path from the environment**: open the database at `SQLITE_DB_PATH`, or build file paths under `SQLITE_DIR`, instead of hardcoding a location. Binding config changes (like a custom `path`) then require no app change.
- **Enable WAL mode**: [write-ahead logging](https://www.sqlite.org/wal.html) lets reads proceed concurrently with writes and is required for replication. Litestream enables it automatically if the app has not, but setting it in the app avoids a journal mode change on a live database.
- **Set a busy timeout**: with a [busy timeout](https://www.sqlite.org/pragma.html#pragma_busy_timeout) (for example 5000 ms), a connection waits for a competing write to finish instead of failing immediately with `SQLITE_BUSY`.
- **Use `synchronous=NORMAL`**: in WAL mode, [`PRAGMA synchronous=NORMAL`](https://www.sqlite.org/pragma.html#pragma_synchronous) is significantly faster than the default `FULL` and cannot corrupt the database; it is the setting [recommended by Litestream](https://litestream.io/tips/).
- **Keep write transactions short**: a long-running write transaction blocks WAL checkpointing, which grows the WAL file and delays replication.
- **Serialize writes in the app**: SQLite allows a single writer at a time. Most drivers behave best with one write connection (for example, a Go `database/sql` pool limited to one connection, or a separate read pool alongside a dedicated writer).
- **Do not delete, rename or replace the database file while running**: replication tracks the file itself, so patterns like `VACUUM INTO` a new file followed by a rename break it. Run [`VACUUM`](https://www.sqlite.org/lang_vacuum.html) in place if needed, and let restores come from the replica rather than copying database files around.
- **Close the database on shutdown**: the container receives a stop signal when the app idles out or a new version deploys. Handling `SIGTERM` and closing connections lets SQLite flush the WAL cleanly before the final replication sync.

As a combined example, Go SQLite drivers accept these settings in the DSN: `file:...?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)`. The exact syntax is driver dependent; see [Litestream's tips page](https://litestream.io/tips/) for equivalents in other languages.

## How Volumes Are Handled

On a single node with Docker or Podman, a SQLite binding is backed by a named volume mounted into the app container at the binding's data path (default `/data`):

- The volume is created automatically when the app container first starts, and is reused on every subsequent start of that app.
- The volume identity is derived from the app and its binding, so attaching the binding to a different app later starts with a fresh volume rather than inheriting another app's database (with replication enabled, the new volume is restored from the binding's replica).
- Fresh volumes are made writable for non-root app users automatically, so images running as an unprivileged user work without changes.
- Deleting an app or binding keeps the volume and any replicated data. Volumes are only removed by explicit cleanup.
- Storage should be a local disk. Network filesystems (NFS/SMB) are not supported for SQLite data.

An app can have at most one SQLite binding and a SQLite binding attaches to only one app, matching SQLite's single-writer file model.

## How Updates Work on a Single Node

App updates preserve the volume. When a new app version deploys, the running container is stopped and a new container for the new version starts with the same volume attached, so the database carries over. Because there is one volume and one app container, there is never more than one writer.

[Staged deployment]({{< ref "docs/applications/lifecycle/#staging-apps" >}}) makes updates safe to verify first. The staging version of an app is a separate app with its own volume: staged changes run against staging data, not the production database. With replication enabled, production and staging replicate to separate locations. Verify the change at the staging URL, then promote:

```sh
openrun app reload --promote /notes
```

Rollbacks switch the app back to a previous version; the volume is untouched. Schema migrations are the app's responsibility, so a rollback across a schema change needs the older version to tolerate the newer schema.

When the app is idle, OpenRun stops the container to scale resource usage to zero; the volume persists and the next request starts the container against the same data. With replication enabled, the replication container performs a final sync before stopping.

## Backups with Litestream

Enable continuous backup by referencing a [Litestream config]({{< ref "docs/applications/litestream/" >}}) on the service:

```toml {filename="openrun.toml"}
[litestream.mainbackup]
bucket = "openrun-backups"
region = "us-east-1"
access_key_id = '{{secret_from "env" "LITESTREAM_KEY_ID"}}'
secret_access_key = '{{secret_from "env" "LITESTREAM_KEY"}}'
```

```sh
openrun service create sqlite/main --is-default --config litestream_config=mainbackup
```

Changes replicate to S3, Cloudflare R2, MinIO or any S3-compatible store within about a second. Litestream replicates every file in the binding directory that matches the binding's `pattern` config key, a file glob relative to the binding directory. The default pattern is `*.db`. Apps that use a different naming convention can change it per binding, either on an explicitly created binding or in the binding source (config keys after `;` are comma separated, so `path` and `pattern` can be set together):

```sh
openrun binding create --config "pattern=*.sqlite3" sqlite/main /apps/notes-db
# or, with an auto binding, setting both path and pattern
openrun app create --bind "sqlite;path=/var/lib/app,pattern=*.sqlite3" \
  --approve github.com/example/notes-app /notes
```

New files matching the pattern are discovered within seconds, so per-tenant databases created at runtime are picked up automatically. Note that the default database file is `data.db`, so a custom pattern should either match `data.db` or the app should use its own file names.

Restore is automatic: if the app starts with an empty or recreated volume, the database is restored from the replica before the app starts. The server's own metadata can be replicated the same way, giving full disaster recovery for a node loss. Monitor replication with `openrun replication status`.

## SQLite Apps on Kubernetes

The same app config works when OpenRun runs on a [Kubernetes cluster]({{< ref "docs/container/kubernetes/" >}}). The differences are in how the pieces map to Kubernetes resources:

- The binding's volume is a PersistentVolumeClaim. The size comes from the service's `volume_size` config key (default `kubernetes.default_volume_size`, 10Gi). Use a block-backed storage class; NFS-backed PVCs are not recommended for SQLite data.
- Apps with a SQLite binding automatically run as a single replica with the `Recreate` update strategy: the old pod stops before the new one starts, which respects both SQLite's single-writer model and the ReadWriteOnce PVC.
- Pods with a SQLite binding get `fsGroup: 65532`, making the volume writable for non-root images on storage classes with ownership management.
- With replication enabled, OpenRun adds a restore init container and a native Litestream sidecar to the app pod automatically. Kubernetes 1.29 or newer is required for the sidecar lifecycle, which guarantees the final changes are synced when the pod stops.
- If pods reach the S3 endpoint through a different address than the OpenRun server, set `container_endpoint` on the Litestream config.

PVCs are preserved when an app moves from a persistent-volume configuration to a stateless one; adding the volume back reuses the existing PVC with its data intact.

## Frequently Asked Questions

### Can I host SQLite web apps on a single server?

Yes. OpenRun runs SQLite apps on a single server with Docker or Podman, giving each app a persistent volume, staged updates and optional continuous backup to S3-compatible storage.

### Does the database survive app updates?

Yes. The volume is reused across app updates, redeploys and idle restarts. Deleting the app also keeps the volume and any replicated data.

### How are SQLite databases backed up?

Through built-in [Litestream replication]({{< ref "docs/applications/litestream/" >}}): changes upload continuously to AWS S3, Cloudflare R2, MinIO or other S3-compatible storage, and restore is automatic when a volume is lost. The app image does not need to include Litestream.

### Can SQLite apps run on Kubernetes?

Yes. The binding becomes a PVC, the app runs as a single replica with the `Recreate` strategy, and replication runs as an automatically managed init container and sidecar (Kubernetes 1.29 or newer).

### When should I use PostgreSQL instead?

Use a [PostgreSQL or MySQL service binding]({{< ref "docs/applications/servicebindings/" >}}) when the app needs multiple writers, horizontal scaling of the app across nodes, or shared access to the data from outside the app. A SQLite app is bound to one volume and one running container.
