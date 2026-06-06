---
title: "Service Bindings"
weight: 500
summary: "Managing services (like Postgres/MySQL) and providing bindings for applications"
---

Service bindings are used to give applications access to endpoint credentials. Postgres and MySQL databases are currently supported by OpenRun. The administrator creates a service with connection information for the database. Apps can easily get access to an isolated database/schema without any manual configuration being required. OpenRun uses the admin credentials to create binding accounts for applications. Apps can share access to a schema, with support for granting limited permissions across applications.

Service bindings are an easy way to configure one database installation properly (with backups, fault tolerance, security etc) and then safely share that database across multiple apps. This is an alternate approach as against usual deployment tooling where each app is assumed to create its own database from scratch, which ignores the challenges with ensuring that the database is properly administered.

The currently supported service types are:

| Service type | Purpose                           |
| :----------- | :-------------------------------- |
| `postgres`   | Create Postgres schemas and roles |
| `mysql`      | Create MySQL databases and users  |

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
`binding show-account` to view the generated connection information.

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

## Binding Source Permissions

Apps can only use bindings whose source is allowed by the app metadata (or at the system level in `openrun.toml`). The `--bind-perm` option records the allowed binding sources for an app. If `--approve` is also used, the requested binding source permissions are copied into the approved list.

```shell
openrun app create \
  --bind-perm postgres/main \
  --approve \
  github.com/example/reporting-app \
  /reporting

openrun app update bind-perm --approve postgres/main /reporting
```

By default at the system level, bindings are allowed to the default postgres and mysql services. This can be configured by updating `openrun.toml`:

```toml {filename="openrun.toml"}
[permissions]
binding_source_perms = ["postgres", "mysql"] # default postgres and mysql binding sources are allowed by default
```

For declarative apply files, use `bind_perm` in the app definition:

```python {filename="apps.ace"}
app(
    "/reporting",
    "github.com/example/reporting-app",
    bindings=["/apps/reporting-db"],
    bind_perm=["postgres/main"],
)
```

## Auto Bindings

When the value passed to `--bind` starts with `/`, OpenRun treats it as an existing binding path. When it does not start with `/`, OpenRun treats it as a service source and creates a base binding automatically.

```shell
openrun app create \
  --bind postgres/main \
  github.com/example/reporting-app \
  /reporting
```

The generated binding is stored under:

```text
/auto/<main-app-id>/<service-type>
```

For example, a Postgres auto binding is stored as `/auto/app_prd_.../postgres`. Duplicate service references in the same command resolve to one auto binding.

The `/auto` path is reserved for auto bindings. Users cannot create bindings under that path directly. A derived binding can use an auto binding path as its source.

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

## Postgres Config and Behavior

Postgres services require `url`. They also support `binding_hostname`.

| Key                | Required | Description                                                                                      |
| :----------------- | :------- | :----------------------------------------------------------------------------------------------- |
| `url`              | Yes      | Admin Postgres connection URL                                                                    |
| `binding_hostname` | No       | Hostname to use in generated `url_binding` account URLs. The original `url` hostname is unchanged |

For example:

```shell
openrun service create postgres/main \
  --config url=postgres://admin:secret@localhost:5432/appdb \
  --config binding_hostname=host.docker.internal
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

For a base binding, OpenRun creates a schema and a login role. The generated `url` account value uses the service URL with the generated username and password. The generated `url_binding` account value uses the same URL, but replaces the hostname with `binding_hostname` when that service option is set. OpenRun sets the generated role's default `search_path` to the binding schema.

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

## MySQL Config and Behavior

MySQL services require `url`. They also support `host_pattern` and `binding_hostname`.

| Key                | Required | Description                                                                                      |
| :----------------- | :------- | :----------------------------------------------------------------------------------------------- |
| `url`              | Yes      | Admin MySQL URL                                                                                  |
| `host_pattern`     | No       | Host part for generated MySQL users. Defaults to `%`                                              |
| `binding_hostname` | No       | Hostname to use in generated `url_binding` account URLs. The original `url` hostname is unchanged |

For example:

```shell
openrun service create mysql/main \
  --config url=mysql://admin:secret@localhost:3306/ \
  --config host_pattern=10.0.% \
  --config binding_hostname=host.docker.internal
```

The admin user in the URL must be able to create users, create databases, and grant and revoke privileges.

For a base binding, OpenRun creates a database and user. The base user gets `ALL PRIVILEGES` on the generated database. The generated account includes `url` and `url_binding`; `url_binding` uses `binding_hostname` when that service option is set.

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
