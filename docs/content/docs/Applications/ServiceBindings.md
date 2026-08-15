---
title: "Service Bindings: PostgreSQL, MySQL, SQLite, Redis and More"
weight: 500
description: "Provision isolated PostgreSQL schemas, MySQL databases, Redis/Valkey ACL accounts and persistent SQLite storage for web apps, plus SQL Server, Oracle, MongoDB, Snowflake and ClickHouse through installable binding providers."
summary: "Managed PostgreSQL, MySQL, SQLite and Redis database access for deployed web apps, extensible to SQL Server, Oracle, MongoDB, Snowflake and ClickHouse."
keywords:
  [
    "PostgreSQL service binding",
    "MySQL service binding",
    "SQLite persistent volume",
    "Redis service binding",
    "Valkey ACL isolation",
    "SQL Server binding provider",
    "Oracle database binding",
    "MongoDB service binding",
    "MongoDB Atlas provisioning",
    "Snowflake service binding",
    "ClickHouse service binding",
    "managed database access",
    "database provisioning for web apps",
    "least-privilege database credentials",
  ]
---

OpenRun is an open-source web app deployment platform with built-in PostgreSQL, MySQL, SQLite and Redis/Valkey service bindings, plus installable binding providers for SQL Server, Oracle, MongoDB (including Atlas), Snowflake and ClickHouse. A service binding automatically provisions isolated database access for an application and injects the generated connection information into its environment.

For PostgreSQL, OpenRun creates an application-specific schema and login role. For MySQL, it creates a database and user. For Redis and Valkey, it creates a server-enforced ACL user restricted to an app-specific key prefix. SQLite bindings provide a persistent volume for database files, with optional [continuous SQLite replication to S3 with Litestream]({{< ref "/docs/applications/litestream" >}}). Applications never need the administrator credentials of any bound service.

Service bindings let teams configure a managed or self-hosted database once—with its backups, monitoring, fault tolerance and capacity management—and safely share that installation across multiple apps. Production and staging environments get separate accounts, while derived bindings allow multiple apps to share a schema or database with distinct least-privilege credentials.

The service types compiled into the server are:

| Service type | Purpose                                                          |
| :----------- | :--------------------------------------------------------------- |
| `postgres`   | Create Postgres schemas and roles                                |
| `mysql`      | Create MySQL databases and users                                 |
| `sqlite`     | Provide a persistent volume with SQLite database files per app   |
| `redis`      | Create Redis ACL users isolated by key prefix (Redis 7+)         |
| `valkey`     | Valkey servers, same ACL-based implementation as `redis`         |

Additional service types come from out-of-process [binding providers]({{< ref "/docs/applications/servicebindings/#binding-providers-sql-server-oracle-mongodb-snowflake-clickhouse" >}}), installed with `openrun provider install`:

| Provider     | Service types      | Purpose                                                    |
| :----------- | :----------------- | :--------------------------------------------------------- |
| `sqlserver`  | `sqlserver`        | Create SQL Server schemas and users (SQL Server 2019+)     |
| `oracle`     | `oracle`           | Create Oracle users and schemas (pure-Go driver)           |
| `mongodb`    | `mongodb`, `atlas` | Create MongoDB databases and users, self-hosted or Atlas   |
| `snowflake`  | `snowflake`        | Create Snowflake roles and schemas with key-pair accounts  |
| `clickhouse` | `clickhouse`       | Create ClickHouse users, self-hosted or ClickHouse Cloud   |
| `databricks` | `databricks`       | Databricks SQL warehouses, Unity Catalog schema isolation  |

All service types share the same workflow: services, base and derived bindings, staging/prod accounts, grants and promotes work identically whether the binding is built in or provider-installed.

## Managed PostgreSQL, MySQL and Redis Access

OpenRun automates the database provisioning work normally performed for each web app:

- Create an isolated PostgreSQL schema and role, MySQL database and user, or key-prefix scoped Redis ACL user.
- Generate a unique password and application connection URL.
- Inject database connection information into the app environment.
- Maintain separate production and staging database accounts.
- Create derived accounts with read-only, scoped or full-access grants.

The database server remains under the operator's control and can be self-hosted or provided by a managed database service. OpenRun connects with the configured administrator URL only when it needs to create accounts, apply grants or inspect a binding.

## Concepts

A **Service** is an admin connection to an endpoint (database). Apps do not use this connection directly. OpenRun uses the service connection to create database users and apply grants.

A **Base Binding** is created from a service. It creates the main database account for an app. For Postgres, this creates a schema and role. For MySQL, this creates a database and user.

A **Derived Binding** is created from a base binding. It uses the same schema or database as the base binding, but gets a separate account. Grants on the derived binding control what that derived account can do.

Bindings always have a staging and a prod environment. Grant related binding changes are applied to the staged binding first. Use `binding update --promote` to promote the staged grants to prod. Staging apps are bound to the stage binding env and prod apps are bound to the prod env. This gives an easy way to ensure that the staging app has access to an isolated test environment which is very similar to the prod env.

## Create Services

Use `openrun service create` to create a service. The service id is `<service_type>/<service_name>`.

```shell
openrun service create postgres/main \
  --is-default \
  --config url=postgres://admin:secret@db.example.com:5432/appdb

openrun service create mysql/main \
  --is-default \
  --config url=mysql://admin:secret@db.example.com:3306/
```

The first service of a type is automatically marked as default. Use `--is-default` to explicitly mark a service as the default. When creating a binding, the source can be the full service id like `postgres/main`, or just the service type like `postgres`. If only the service type is specified, OpenRun uses the default service for that type.

Service config values can reference [secrets](/docs/configuration/secrets/) with `{{secret ...}}` or `{{secret_from ...}}` template references, so credentials do not have to be stored in the metadata database:

```shell
openrun service create postgres/main \
  --config 'url={{secret_from "asm" "prod_db_admin_url"}}'
```

The reference is stored as is and resolved through the secret provider each time the service connection is used, so a rotated secret value takes effect on the next operation without a service update.

Under [RBAC]({{< ref "/docs/configuration/rbac" >}}), creating or updating a service whose config references a secret additionally requires the `secret:read` permission: the referenced value flows resolved to the service's binding provider, so selecting which secrets a service uses is restricted to users allowed to use the secret store, rather than implied by `service:manage` alone.

```shell
openrun binding create postgres /apps/reporting-db
```

List services with:

```shell
openrun service list
openrun service list postgres
openrun service list postgres/main
```

Update service default status with:

```shell
openrun service update postgres/main --set-default=true
```

Delete a service with:

```shell
openrun service delete postgres/main
```

A service cannot be deleted while bindings created from it exist; delete the bindings first. A service that is linked as the staging service of another service is likewise blocked while that other service has bindings, since their staged accounts are provisioned on the staging service. Deleting a service removes only OpenRun's record of the admin connection — nothing is changed on the backend database itself.

## Hostname Mapping Basics

Service connection URLs are used in two different places: OpenRun uses the admin URL to create and manage binding accounts, and app containers use generated account URLs to connect at runtime. These hostnames can be different.

Generated binding accounts include both `url` and `url_direct`. `url` is intended for app containers and can replace the service URL hostname using the service config key `binding_hostname`. `url_direct` keeps the original service URL hostname and is used by OpenRun commands such as `binding run-command`.

This matters for local database services. If a Postgres or MySQL service URL points at `localhost` or `127.0.0.1`, app containers usually cannot use that hostname to reach the host database. Outside Kubernetes, OpenRun automatically maps those local hostnames to a container-reachable hostname. Docker uses `host.docker.internal`; other local container runtimes use `host.containers.internal`. Set `binding_hostname` explicitly to override that value, or set `binding_hostname=disable` to keep the service URL hostname unchanged.

## Staging Services

A service can specify a separate staging service. The staging service has to be of the same service type. When a binding is created, OpenRun creates the staged account using the staging service and the prod account using the main service. Create the staging service first, then reference it from the main service:

```shell
openrun service create postgres/stage \
  --config url=postgres://admin:secret@stage-db.example.com:5432/appdb

openrun service create postgres/main \
  --is-default \
  --staging stage \
  --config url=postgres://admin:secret@prod-db.example.com:5432/appdb
```

You can add, change, or clear the staging service later:

```shell
openrun service update postgres/main --staging stage
openrun service update postgres/main --staging ""
```

The staging service cannot refer to itself. If no staging service is linked, then stage bindings are created on the same endpoint as the prod, just a separate schema/database. Stage performance issues can impact prod in that case.

## Create Base Bindings

Create a base binding using a service source:

```shell
openrun binding create postgres/main /apps/reporting-db
openrun binding create mysql/main /apps/inventory-db
```

Base bindings cannot have grants. The generated account owns the bindings schema or database.

The account information is not shown by `binding get` or `binding list`. Use
`binding show-account` to view the generated connection information. With RBAC
enabled, `show-account` needs the `binding:reveal` permission, which requires
an explicit grant (it is not implied by `binding:manage` and binding owners do
not hold it by default).

```shell
openrun binding show-account /apps/reporting-db
openrun binding show-account --staging /apps/reporting-db
```

For testing, SQL can be run as the binding account. Output can be truncated for large results sets.

```shell
openrun binding run-command /apps/reporting-db "select current_user"
openrun binding run-command --staging /apps/reporting-db "select current_user"
```

## Create Derived Bindings

Create a derived binding by using a base binding path as the source.

```shell
openrun binding create --grant "read:*" /apps/reporting-db /apps/reporting-read
openrun binding create --grant "create:*" /apps/reporting-db /apps/reporting-writer
openrun binding create --grant "full:events" /apps/reporting-db /apps/reporting-events-admin
```

Derived bindings have to be created from base bindings. A derived binding cannot be used as the source for another derived binding.

Grants are supported only on derived bindings. A grant is specified as `type:target`.

| Grant          | Meaning                                                                 |
| :------------- | :---------------------------------------------------------------------- |
| `read:*`       | Read all tables                                                         |
| `read:<table>` | Read one table. If the table does not exist yet, the grant is deferred. |
| `create:*`     | Create tables                                                           |
| `full:*`       | Read, write and create                                                  |
| `full:<table>` | Read and write one table                                                |

`create:<table>` is not supported. Create access applies to the schema or database.

If a table-specific grant references a table which does not exist yet, the grant is kept in the metadata and will be applied later on next update call or using `--reapply-all`.

## Update and Promote Grants

Grant updates are staged. The update is applied to the staged account first.

```shell
openrun binding update --add-grant "read:*" /apps/reporting-read
openrun binding update --delete-grant "read:old_table" /apps/reporting-read
```

Prod is not updated until the binding is promoted:

```shell
openrun binding update --promote /apps/reporting-read
```

You can update and promote in one command:

```shell
openrun binding update \
  --add-grant "read:*" \
  --delete-grant "read:old_table" \
  --promote \
  /apps/reporting-read
```

Use `--reapply-all` to apply all grants again. This is useful after creating a table for which a table-specific grant was previously deferred, or after manual database changes.

```shell
openrun binding update --reapply-all --promote /apps/reporting-read
```

Binding promotion is separate from app promotion. `app promote` promotes the app version and app metadata, including the list of binding paths attached to the app. It does not promote staged grant changes inside a binding. Use `binding update --promote` or `apply --promote` for that.

## Health Checks

Verify a service or a binding account end to end — the server actually connects to the backend and runs a no-op operation (`select 1` / ping), so the checks catch unreachable endpoints, rotated or expired admin credentials, and binding accounts dropped or disabled outside OpenRun:

```shell
openrun service health postgres/main
openrun binding health /apps/reporting-db
openrun binding health --staging /apps/reporting-db
```

`service health` connects with the service's admin credentials (secret references resolved the same way as other operations). `binding health` connects **as** the binding's generated account — the production account by default, the staged account (against the linked staging service, when one is configured) with `--staging`. A healthy check exits 0; any failure exits non-zero with the backend error.

The checks work uniformly for the built-in service types and installed provider service types (a provider built with an SDK that predates health checks reports that the provider needs an update). SQLite bindings have no endpoint or accounts to probe; their checks validate the binding configuration and otherwise always report healthy.

Under [RBAC]({{< ref "/docs/configuration/rbac" >}}), `service health` requires `service:read` on the service and `binding health` requires `binding:read` on the binding path.

## Delete Bindings

```shell
openrun binding delete /apps/reporting-read
openrun binding delete --dry-run /apps/reporting-db
```

Deleting a binding also deletes the account objects that were created for it on the backend service, for both the production and staging accounts (using the linked staging service when one is configured). The objects recorded when the binding account was generated are dropped in reverse creation order:

- **Postgres**: the binding's role and schema are dropped, including everything in the schema (`CASCADE`) and any objects the role still owns elsewhere.
- **MySQL**: the binding's user and database are dropped, including the database contents.
- **Redis/Valkey**: the binding's ACL users are removed. Keys under the binding's prefix are not touched.
- **SQLite**: the volume and any replicated data are kept ([details]({{< ref "/docs/applications/servicebindings/#sqlite-config-and-behavior" >}})).
- **Providers**: provider service types drop the users/schemas/databases the binding created, per the provider's documentation.

For Postgres and MySQL this means deleting a base binding deletes the schema or database **data**; there is no separate confirmation, so treat `binding delete` of a base binding like a `DROP` statement. Deleting a derived binding drops only that binding's role or user (plus objects it still owns, such as tables it created in the shared schema); the base binding's schema/database and data are untouched.

A base binding cannot be deleted while bindings derived from it exist — their accounts live in the base binding's schema/database — so the derived bindings must be deleted first.

`--dry-run` validates the delete without removing anything, on the backend or in the metadata. If dropping a backend object fails, the whole delete is rolled back and can be retried; the drops are idempotent, so a partially completed delete retries cleanly. Bindings created by OpenRun versions that did not record their created objects are deleted from the metadata only: a warning is logged and the backend objects are left in place for manual cleanup.

## Attach Bindings to Apps

Attach existing bindings when creating an app:

```shell
openrun app create \
  --bind /apps/reporting-db \
  github.com/example/reporting-app \
  /reporting
```

Binding order is preserved. To update the binding list for an existing app:

```shell
openrun app update bindings /apps/reporting-read /apps/metrics-read /reporting
```

This updates staging. Add `--promote` to update prod in the same command.

## Binding Access Control

Access to services and bindings is controlled through [RBAC]({{< ref "/docs/configuration/rbac" >}}). The `service:*` and `binding:*` permissions are scoped by the grant's `service:<glob>` / `binding:<glob>` target entries. Attaching a binding to an app requires the `binding:use` permission on that binding path (or `service:bind` on the service, for auto bindings created from a service source), in addition to the app permission for the update itself. The creator of a service or binding holds the owner permissions (`service:manage` / `binding:manage` by default) on their own entries.

When RBAC is not enabled, management operations are restricted to the admin user, so no separate approval step applies to binding access.

## Auto Bindings

When the value passed to `--bind` starts with `/`, OpenRun treats it as an existing binding path. When it does not start with `/`, OpenRun treats it as a service source and creates a base binding automatically if the binding does not already exist.

```shell
openrun app create \
  --bind postgres/main \
  --approve \
  github.com/example/reporting-app \
  /reporting
```

The generated binding is stored under:

```text
/auto/<main-app-id>/<service-type>
```

For example, a Postgres auto binding is stored as `/auto/app_prd_.../postgres`. Duplicate service references in the same command resolve to one auto binding.

The `/auto` path is reserved for auto bindings. Users cannot create bindings under that path directly. Auto bindings are owned by their app and cannot be shared: they cannot be used as the source for a derived binding, and another app cannot attach them with `--bind`. Use a regular base binding when multiple apps or derived accounts need to share a schema or database.

Deleting the app deletes its auto bindings along with it, dropping their backend account objects the same way as [`binding delete`]({{< ref "/docs/applications/servicebindings/#delete-bindings" >}}) — for Postgres/MySQL auto bindings this drops the schema or database including its data. An auto binding that (from an older OpenRun version) still has derived bindings blocks the app delete until the derived bindings are deleted.

Binding config can be passed through the service source using `;` followed by comma separated `key=value` entries. The params become the auto binding's config, exactly like `binding create --config`:

```shell
openrun app create \
  --bind "sqlite;path=/mydata" \
  --approve \
  github.com/example/notes-app \
  /notes
```

This works for any service type. The config is used when the auto binding is first created; referencing an existing auto binding with a different config is an error (delete the auto binding to recreate it with new config).

## Declarative Apply

Apply files can define bindings using the `binding` builtin.

```python {filename="apps.ace"}
binding("/apps/reporting-db", "postgres/main", config={"inherit_default": "false"})
binding("/apps/reporting-read", "/apps/reporting-db", grants=["read:*"])

app("/reporting", "github.com/example/reporting-app", bindings=["/apps/reporting-read"])
```

The builtin format is:

```python
binding(path, source, grants=[], config={})
```

| Property | Optional |     Type     | Default |                         Notes                         |
| :------: | :------: | :----------: | :-----: | :---------------------------------------------------: |
|   path   |  False   |    string    |         |            The unique path for the binding            |
|  source  |  False   |    string    |         | The source for binding, service or based binding path |
|  grants  |   true   | string array |         |      The permission grants for a derived binding      |
|  config  |   true   |     dict     |         |                    The config map                     |

The source rules are the same as the CLI:

- `source="postgres/main"` or `source="postgres"` creates a base binding.
- `source="/apps/reporting-db"` creates a derived binding.
- `grants` is valid only for derived bindings.
- `config` is used only when the binding is first created.

`openrun apply` creates bindings even if the app glob does not match any apps. Existing binding sources and binding config cannot be changed.

For existing bindings, apply does a three-way merge for grants. Grant changes in the apply file are applied, and grant changes made using the CLI are preserved. Use `--clobber` to make the staged grants match the apply file.

```shell
openrun apply --reload=none apps.ace /reporting
openrun apply --promote --reload=none apps.ace /reporting
```

With `--promote`, apply promotes binding metadata after updating staged metadata.

<span id="postgres-config-and-behavior"></span>

## PostgreSQL (Postgres) Service Bindings

PostgreSQL service bindings automatically create a schema and login role for each base binding. PostgreSQL services require an administrator `url` and also support `binding_hostname`.

| Key                | Required | Description                                                                                                                                                                                                                                                                                                                 |
| :----------------- | :------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `url`              | Yes      | Admin Postgres connection URL                                                                                                                                                                                                                                                                                               |
| `binding_hostname` | No       | Hostname to substitute into generated `url` account URLs. `url_direct` keeps the original service URL hostname. If omitted for a `localhost` or `127.0.0.1` service URL outside Kubernetes, OpenRun automatically uses a container-reachable host name. Set to `disable` to keep `url` unchanged and skip automatic mapping |

For example:

```shell
openrun service create postgres/main \
  --config url=postgres://admin:secret@localhost:5432/appdb
```

The admin user in the URL must be able to create roles, create schemas, grant privileges and alter default privileges.

Postgres bindings support one create-time binding config key:

| Key               | Default | Description                                                                         |
| :---------------- | :------ | :---------------------------------------------------------------------------------- |
| `inherit_default` | `true`  | Whether the generated role inherits privileges from other roles, including `PUBLIC` |

For example:

```shell
openrun binding create \
  --config inherit_default=false \
  postgres/main \
  /apps/reporting-db
```

If `inherit_default` is set to `false`, the generated role is created with `NOINHERIT`.

For a base binding, OpenRun creates a schema and a login role. The generated account includes `url` and `url_direct`. `url` uses the service URL with the generated username and password, replacing the hostname with `binding_hostname` when that service option is set. If `binding_hostname` is omitted, the service URL hostname is `localhost` or `127.0.0.1`, and OpenRun is not running in Kubernetes mode, OpenRun automatically uses `host.docker.internal` for Docker and `host.containers.internal` for other local container runtimes. Set `binding_hostname=disable` to opt out of both explicit hostname substitution and automatic mapping. `url_direct` uses the original service URL hostname. Containers receive both values as environment variables, for example `POSTGRES_URL` and `POSTGRES_URL_DIRECT`. `binding run-command` uses `url_direct`. OpenRun sets the generated role's default `search_path` to the binding schema.

For a derived binding, OpenRun creates a separate login role and uses the base binding schema. The derived role gets `USAGE` on the schema before grants are applied.

Postgres grants work as follows:

- `read:*` grants `SELECT` on all current tables and changes default privileges
  so future tables created by the base role are readable by the derived role.
- `create:*` grants `CREATE` on the schema.
- `full:*` grants all table privileges, all sequence privileges and `CREATE` on
  the schema. Default privileges are also updated for future tables and
  sequences.
- `read:<table>` and `full:<table>` apply only to the specified table.

If a table-specific grant references a table which does not exist, OpenRun skips
the grant for that run. Skipped grants are applied on the next update/apply run.

<span id="mysql-config-and-behavior"></span>

## MySQL Service Bindings

MySQL service bindings automatically create a database and user for each base binding. MySQL services require an administrator `url` and also support `host_pattern` and `binding_hostname`.

| Key                | Required | Description                                                                                                                                                                                                                                                                                                                 |
| :----------------- | :------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `url`              | Yes      | Admin MySQL URL                                                                                                                                                                                                                                                                                                             |
| `host_pattern`     | No       | Host part for generated MySQL users. Defaults to `%`                                                                                                                                                                                                                                                                        |
| `binding_hostname` | No       | Hostname to substitute into generated `url` account URLs. `url_direct` keeps the original service URL hostname. If omitted for a `localhost` or `127.0.0.1` service URL outside Kubernetes, OpenRun automatically uses a container-reachable host name. Set to `disable` to keep `url` unchanged and skip automatic mapping |

For example:

```shell
openrun service create mysql/main \
  --config url=mysql://admin:secret@localhost:3306/ \
  --config host_pattern=10.0.%
```

The admin user in the URL must be able to create users, create databases, and grant and revoke privileges.

For a base binding, OpenRun creates a database and user. The base user gets `ALL PRIVILEGES` on the generated database. The generated account includes `url` and `url_direct`; `url` uses `binding_hostname` when that service option is set. If `binding_hostname` is omitted, the service URL hostname is `localhost` or `127.0.0.1`, and OpenRun is not running in Kubernetes mode, OpenRun automatically uses `host.docker.internal` for Docker and `host.containers.internal` for other local container runtimes. Set `binding_hostname=disable` to opt out of both explicit hostname substitution and automatic mapping. `url_direct` keeps the original service URL hostname. Containers receive both values as environment variables, for example `MYSQL_URL` and `MYSQL_URL_DIRECT`. `binding run-command` uses `url_direct`.

For a derived binding, OpenRun creates a separate user and uses the base binding database. The derived user gets a minimal database-level `SHOW VIEW` grant so it can connect using the generated database as the default database.

MySQL grants work as follows:

- `read:*` grants `SELECT` on the database. This applies to current and future tables.
- `create:*` grants `CREATE`, `ALTER`, `INDEX`, `DROP`, and `REFERENCES` on the
  database.
- `full:*` grants read, write, create, alter, index, drop, references, trigger,
  create view, temporary table and lock privileges on the database.
- `read:<table>` and `full:<table>` apply only to the specified table.

If a table-specific grant references a table which does not exist, OpenRun skips the grant for that run. Skipped grants are applied on the next update/apply run.

MySQL DDL statements auto-commit. If binding creation fails part way through, OpenRun does best-effort cleanup for users and databases created during that operation.

## Redis and Valkey Service Bindings

Redis service bindings automatically create a dedicated ACL user for each base binding, restricted to a unique key prefix with server-enforced ACLs. The same implementation serves the `valkey` service type; `valkey://` and `valkeys://` service URLs are normalized to `redis://`/`rediss://` in generated account URLs. Redis 7 or newer (or any Valkey release) is required, running as a standalone server (cluster mode is not supported).

| Key                | Required | Description                                                                                                                                                                                                                                                                                                                 |
| :----------------- | :------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `url`              | Yes      | Admin Redis/Valkey connection URL (`redis://`, `rediss://`, `valkey://` or `valkeys://`)                                                                                                                                                                                                                                    |
| `binding_hostname` | No       | Hostname to substitute into generated `url` account URLs. `url_direct` keeps the original service URL hostname. If omitted for a `localhost` or `127.0.0.1` service URL outside Kubernetes, OpenRun automatically uses a container-reachable host name. Set to `disable` to keep `url` unchanged and skip automatic mapping |

For example:

```shell
openrun service create redis/main \
  --config url=redis://admin:secret@localhost:6379
```

Unlike SQL databases, Redis has no schema to scope: isolation comes from a generated key prefix. The account exposes `url`, `url_direct`, `username`, `password` and `key_prefix` (as `REDIS_URL`, `REDIS_KEY_PREFIX` and so on in the app environment). Apps must prepend `key_prefix` to every key they use; access outside the prefix fails with a Redis `NOPERM` error, so a misconfigured app fails loudly instead of silently reading or clobbering another app's keys. Production and staging accounts get separate ACL users and separate key prefixes.

The base binding user gets full access to its key prefix and to pub/sub channels under the same prefix. Administrative and cross-keyspace commands (`CONFIG`, `ACL`, `FLUSHALL`, `KEYS`, `RANDOMKEY`, `PUBSUB` introspection and similar) are denied for binding accounts; `SCAN` is allowed so apps can enumerate and clear their own keys.

For a derived binding, OpenRun creates a separate ACL user that shares the base binding's key prefix, with no access until grants are applied. Redis grants work as follows:

- `read:*` grants server-enforced read-only access to all keys under the base
  prefix. Writes fail with `NOPERM`. Read grants include no pub/sub access.
- `full:*` grants read-write access to all keys under the base prefix, plus
  pub/sub channels under the prefix.
- `read:<target>` and `full:<target>` scope the grant to keys starting with
  `<key_prefix><target>`. Targets may use letters, digits and `_ . : -`; glob
  characters are rejected. `create` grants are not supported.

ACL changes only modify the server's in-memory state. Configure an `aclfile` on the Redis/Valkey server so binding users survive a server restart (OpenRun runs `ACL SAVE` after every change when an aclfile is configured, and logs a warning at service creation when none is). Without an aclfile, a derived user lost to a restart can be recreated with `binding update --reapply-all`; base users need the aclfile.

Deleting a binding deletes its ACL users (production and staging). Keys under the binding's prefix are not touched — unlike Postgres/MySQL, where deleting a base binding drops the schema or database with its data — so have the app clear its keys first if the data should go too.

## SQLite Config and Behavior

The `sqlite` service type has no external endpoint. A SQLite binding gives the app a persistent named volume (Docker/Podman) or PersistentVolumeClaim (Kubernetes) mounted into the app container, holding the app's SQLite database files. Creating the service and binding needs no connection information:

```shell
openrun service create sqlite/main --is-default
openrun app create --bind sqlite --approve github.com/example/notes-app /notes
```

The app finds its database through environment variables:

```text
SQLITE_URL=file:/data/data.db
SQLITE_DB_PATH=/data/data.db
SQLITE_DIR=/data
```

The volume is created automatically when the app first starts and is reused across app updates and redeploys. The volume identity follows the binding, so attaching the binding to a different app later does not carry over another binding's data. On Kubernetes, apps with a SQLite binding automatically run as a single replica with the `Recreate` deploy strategy, matching SQLite's single-writer model.

For disaster recovery, enable [continuous SQLite replication to S3 with Litestream]({{< ref "/docs/applications/litestream" >}}). OpenRun continuously replicates the binding's database files to S3-compatible storage and automatically restores them before the app starts after volume or node loss.

SQLite services support these config keys (all optional):

| Key                 | Description                                                                                                          |
| :------------------ | :------------------------------------------------------------------------------------------------------------------- |
| `litestream_config` | Name of a `[litestream.<name>]` server config entry. Enables [continuous replication]({{< ref "/docs/applications/litestream" >}}) to S3-compatible storage for bindings of this service |
| `path_prefix`       | Overrides the litestream config's replica key prefix for bindings of this service                                     |
| `volume_size`       | Kubernetes PVC size (default `kubernetes.default_volume_size`, 10Gi). Ignored for Docker/Podman                       |

SQLite bindings support these create-time binding config keys:

| Key       | Default | Description                                                                                             |
| :-------- | :------ | :------------------------------------------------------------------------------------------------------ |
| `path`    | `/data` | Absolute path where the volume is mounted in the container                                               |
| `pattern` | `*.db`  | File glob (relative to the binding directory) selecting which files are replicated when replication is enabled |

```shell
openrun binding create --config path=/mydata sqlite/main /apps/notes-db
openrun binding create --config "pattern=*.sqlite3" sqlite/main /apps/notes-db
```

Apps can create additional database files under `SQLITE_DIR` (for example per-tenant databases); with replication enabled, every file matching the binding's `pattern` (default `*.db`) in the directory is replicated. The default database file the binding's environment variables point at is `data.db`, so a custom `pattern` should either match `data.db` or the app should use its own file names.

Differences from Postgres/MySQL bindings:

- An app can have at most one SQLite binding, and a SQLite binding can be attached to only one app: the database is a single-writer file on a per-app volume.
- Derived bindings and grants are not supported. SQLite has no accounts or roles to scope; bind the base binding directly.
- `binding run-command` is not supported: the database file is only reachable inside the app container.
- `binding show-account` shows the computed paths; there are no credentials.
- SQLite bindings are not available for preview apps.
- Deleting a binding or app keeps the volume and any replicated data. SQLite bindings have no backend accounts to remove, so unlike Postgres/MySQL nothing is dropped on delete.

A [staging service]({{< ref "/docs/applications/servicebindings/#staging-services" >}}) can be linked like any other service type. Staged apps then follow the staging service's config: its own `litestream_config` (or none), `path_prefix` and `volume_size`, so staged data can replicate to a separate location or skip replication entirely.

For best results the app should open the database in WAL mode with a busy timeout, for example `file:...?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)` (driver dependent). With replication enabled, WAL mode is required, but litestream enables it automatically if the app has not.

OpenRun makes the volume writable for non-root app users automatically. With replication enabled, the `chmod` runs using the Litestream image, so any app image works. For local-only SQLite bindings (no `litestream_config`), the `chmod` runs with the app's own image, so the app image must not be distroless. On Kubernetes, pods with a SQLite binding additionally get `fsGroup: 65532`, which makes the volume group-writable at mount time on storage classes with ownership management.

## Binding Providers (SQL Server, Oracle, MongoDB, Snowflake, ClickHouse)

Beyond the built-in service types, OpenRun supports out-of-process binding providers: standalone executables from the [openrundev/bindings](https://github.com/openrundev/bindings) repository that add more service types. Providers exist for Microsoft SQL Server (schema-based isolation, SQL Server 2019+), Oracle Database (pure-Go driver, no Oracle client needed), MongoDB (self-hosted servers and MongoDB Atlas, via the `mongodb` and `atlas` service types), Snowflake (role/schema isolation with key-pair authentication), ClickHouse (self-hosted and ClickHouse Cloud) and Databricks (SQL warehouses with Unity Catalog schema isolation; Databricks Lakebase needs no provider — it speaks the Postgres protocol and works with the built-in `postgres` binding).

Install a provider by name and version; the binary is downloaded from the provider releases (or a configured mirror), checksum-verified and registered:

```shell
openrun provider install sqlserver --version v0.1.0
openrun provider list
```

The provider's service types then work exactly like the built-in ones:

```shell
openrun service create sqlserver/main \
  --config url=sqlserver://admin:secret@db.example.com:1433
openrun binding create sqlserver/main /apps/reporting-db
```

Provider processes are launched on demand when a service connection is needed and stopped when it is closed. `openrun provider uninstall <name>` removes a provider once no services of its types exist. For declarative, config-managed deployments, providers can instead be declared in the `[bindings.install]` server config section (or the equivalent [Helm values / Terraform variables for Kubernetes]({{< ref "/docs/container/kubernetes/#binding-providers" >}})), with optional `@sha256:<hex>` digest pinning. Per-provider configuration details (service config keys, grant semantics) are documented in the [bindings repository](https://github.com/openrundev/bindings).

## Frequently Asked Questions

### How do I connect a web app to PostgreSQL with OpenRun?

Create a PostgreSQL service with an administrator connection URL, then create or automatically attach a binding from that service. OpenRun creates an isolated schema and login role and supplies the generated PostgreSQL connection information to the app environment.

### How do MySQL service bindings work?

Create a MySQL service that points to an existing managed or self-hosted MySQL server. For each base binding, OpenRun creates a dedicated database and user, then makes the generated connection URL available to the application.

### Does each app get a separate PostgreSQL schema or MySQL database?

Yes. A PostgreSQL base binding owns its own schema and role, while a MySQL base binding owns its own database and user. Staging and production also use separate accounts and separate schemas or databases.

### Can multiple apps securely share a PostgreSQL schema or MySQL database?

Yes. Derived bindings create a separate role or user for each app while sharing the base binding's schema or database. Grants can provide read-only, table-specific, create or full access without sharing credentials between apps.

### How do Redis service bindings keep apps isolated?

Each base binding gets a dedicated Redis ACL user restricted to a unique key prefix (and matching pub/sub channel prefix), enforced by the server: any access outside the prefix fails with `NOPERM`. Derived bindings share the base prefix with separate ACL users whose access is controlled by grants. Redis 7+ or Valkey is required.

### Can OpenRun provision SQL Server, Oracle, MongoDB, Snowflake or ClickHouse access?

Yes. Install the matching binding provider with `openrun provider install <name>` and the provider's service types (`sqlserver`, `oracle`, `mongodb`/`atlas`, `snowflake`, `clickhouse`, `databricks`) become available for `service create`, with the same binding, grant and staging workflow as the built-in types.

### Are database administrator credentials exposed to applications?

No. OpenRun uses the administrator URL to provision and manage binding accounts, but applications receive only their generated binding credentials. The administrator URL can reference OpenRun's supported secret providers instead of being stored directly.
