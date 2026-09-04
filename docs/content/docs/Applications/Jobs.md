---
title: "Jobs and Deploy Hooks"
weight: 450
summary: "Scheduled, manual and before-deploy jobs: finite work run from the app's image or as a Starlark function"
---

An app serves requests; a **job** is finite work that belongs to the app: a nightly report, a cache rebuild, a backup, a database migration that must run before a new version takes traffic, or an operator one-off like a reindex. A job runs either as a **command** in a fresh container from the app's deployed image (or from another image), or as a **Starlark function** called inside OpenRun, with the app's params, secrets and service binding credentials. Every run is recorded, with its status and its output available while the run's container exists.

A job has one executor and one trigger:

- `manual` (the default): started from the CLI, the console or through API.
- `cron`: started on a schedule by the OpenRun server, on the app's prod and stage instances.
- `before_deploy`: run as a deploy gate before a new version of the app is written, from the image just built and against the instance being deployed to. A failing gate stops the deploy.

Every job, whatever its trigger, can also be run manually.

## Declaring jobs in app.star

Jobs are declared with `ace.job` and passed to `ace.app` in `jobs=`:

```python {filename="app.star"}
load("container.in", "container")
load("proxy.in", "proxy")
load("store.in", "store")

def expire_sessions(dry_run, args):
    # the action handler shape: a job can call the same function an action uses
    n = store.delete(table.sessions, {"expires": {"$lt": args.cutoff}}).value
    return ace.result("Deleted %d sessions" % n)

app = ace.app("orders",
    routes=[ace.proxy("/", proxy.config(container.URL))],
    container=container.config(container.AUTO, port=8000),
    jobs=[
        ace.job("migrate", command=["python", "manage.py", "migrate", "--noinput"],
            trigger=ace.before_deploy(), timeout="10m"),
        ace.job("nightly-report", command=["python", "manage.py", "send_report"],
            trigger=ace.cron("0 3 * * *", timezone="America/Los_Angeles"),
            timeout="1h", params=["region"], description="Emails the daily orders summary"),
        ace.job("db-backup", image="image:postgres:16", inherit_env=True, shell=True,
            command=["pg_dump $POSTGRES_URL | gzip > /backup/$(date +%F).sql.gz"],
            trigger=ace.cron("@daily"), volumes=["backup:/backup"]),
        ace.job("expire-sessions", run=expire_sessions, trigger=ace.cron("@hourly"), params=["cutoff"]),
    ],
    permissions=[
        ace.permission("proxy.in", "config", [container.URL]),
        ace.permission("container.in", "config", [container.AUTO]),
        ace.permission("store.in", "delete", [table.sessions]),
    ])
```

`ace.job(name, command=[], args=[], shell=False, image="", run=None, env={}, inherit_env=None, volumes=[], options={}, trigger=ace.manual(), timeout="1h", enabled=True, params=[], description="")`:

- `name`: lower case letters, digits and dashes, up to 20 characters; unique across the app's jobs and sidecars.
- `command` and `args`: the command line, run in place of the image entrypoint. `shell=True` runs it through `sh -c`.
- `image`: `image:<ref>` (or a bare reference) to run another image instead of the app's own. Foreign images must be allowed by the `security.allowed_job_images` server config (exact references or `regex:` entries; the default `["*"]` allows any image).
- `run`: a Starlark function `fn(dry_run, args)` with the [action handler](/docs/actions/) shape, called in the OpenRun process instead of running a container. `dry_run` is always `False`; `args` carries the `params.star` values with the run arguments applied. Use `run` for Starlark apps, and for anything that touches an app's SQLite data: a job container must never open the database of a running app. Only `app.star` can declare `run` jobs.
- `env`: the job's own env. `inherit_env` copies the app env (params, binding env vars, `CL_APP_PATH`, `CL_APP_URL`) into the job container first; it defaults to true for app image jobs and false for foreign images, which get no credentials unless asked (a backup job must ask).
- `volumes` (Docker/Podman): named volumes, `name:/path`; a named volume also used by the app is the same volume. The managed SQLite volume cannot be mounted by a job.
- `options`: container options for the job, same keys as `--copt`. Defaults to the app's container options.
- `trigger`: `ace.manual()`, `ace.cron(schedule, timezone="UTC")` or `ace.before_deploy()`. The schedule is a five field cron expression or a descriptor like `@daily` or `@hourly`, in the given IANA timezone; interval schedules (`@every`) are not supported, use an expression like `*/15 * * * *`.
- `timeout`: a Go duration; the run is killed at the deadline and recorded as `timed_out`.
- `enabled`: a disabled job keeps its history and is never scheduled or gated; `openrun job run --force` still runs it.
- `params`: the `params.star` params a manual run may set with `--arg name=value`; values are checked against the param type. A command job receives every declared param as a `CL_JOB_ARG_<NAME>` env var (the argument when given, the app's configured param value otherwise); a `run` job gets them as `args.<name>`, typed by the param definition.

The job definitions are part of the app version: they are stored when the app loads, and `openrun job list` reads them from the app metadata.

## Job containers

A command job runs in a new container from the image the app instance last deployed (the built image, or for `image:` apps the upstream image at the digest recorded by the last reload, so a moved tag does not change what a job runs), so `job run` on an app that has never been deployed fails with "deploy the app first". The container gets the app env when `inherit_env` is set, the job's `env`, and:

| Env var                                   | Value                                                                                       |
| ----------------------------------------- | ------------------------------------------------------------------------------------------- |
| `CL_APP_STAGE`                            | `prod`, `stage`, `preview` or `dev`                                                         |
| `CL_APP_VERSION`                          | the app version                                                                             |
| `CL_JOB_NAME`, `CL_JOB_RUN_ID`            | the job and run identity, for logs and idempotency keys                                     |
| `CL_JOB_TRIGGER`                          | `manual`, `cron` or `before_deploy`                                                         |
| `CL_JOB_SCHEDULED_AT`                     | the intended cron tick (RFC 3339), cron runs only                                           |
| `CL_DEPLOY_REASON`, `CL_PREVIOUS_VERSION` | deploy gates only: `reload`, `apply`, `create` or `promote`, and the version being replaced |
| `CL_JOB_ARG_<NAME>`                       | the run arguments                                                                           |

`PORT` is not set and no health check runs; exit code 0 is success. On Docker/Podman the run is a labeled container; on Kubernetes it is a `batch/v1 Job` in the apps namespace with `restartPolicy: Never` and no service account token. The container is left in place when it exits so its output can be read with `openrun job logs`, and is removed when its run record is retired by retention (`jobs.retain_runs` in `[app_config]`, default 50 runs per job, overridable per app with `openrun app update conf jobs.retain_runs=N`). Output is read from the container runtime and is not copied or redacted: a job that prints a credential shows it to anyone with `app:read` on the app.

## Scheduled runs

The server checks the cron jobs of every prod and stage app once a minute, on the leader. A tick starts a run unless the job already has an active run, in which case the tick is skipped; there are no retries, and ticks that pass while no server is running are not replayed. Stage schedules run against the stage instance and its staging binding accounts, so a staged job change is exercised before it is promoted; preview and dev apps run no schedules. A job that must not run on stage can check `CL_APP_STAGE` and exit.

A run executes on the node that started it. If that node stops, the run is marked `lost` after a minute and can be started again by hand. Jobs should therefore be idempotent.

## Deploy gates

A `before_deploy` job runs when a new version deploys to an app instance: on the stage instance for `app reload`, `apply` and sync runs (before the reload transaction opens, from the image just built), and on the prod instance for `app promote` (from the stage code, with the prod binding accounts). With `--promote` on a reload or apply, the stage gate and then the prod gate run before the operation writes anything. On `app create` the gate runs inside the create; a failure rolls the create back. Gates run in declaration order, and the first failure stops the operation with the run id and the tail of its output. Dry runs skip gates: they have real side effects. The previous version keeps serving during a gate, so migrations must be backward compatible with it (expand/contract). Preview and dev apps run no gates; a gate job can still be run manually on them.

`app version switch` and metadata-only updates like `param update --promote` run no gates.

## Declaring jobs in apps.ace and on the CLI

The same fields are accepted as `job(...)` calls, dict literals or JSON strings in `apps.ace`, on `app create --job` and with `app update jobs`. Operator-set jobs replace a same-name job of the app definition whole, and add new ones; `run` jobs can only come from `app.star`.

```python {filename="apps.ace"}
backup = job("db-backup", image="image:postgres:16", inherit_env=True, shell=True,
             command=["pg_dump $POSTGRES_URL | gzip > /backup/$(date +%F).sql.gz"],
             trigger=cron("0 2 * * *"), volumes=["backup:/backup"], timeout="30m")

app("/orders", "github.com/acme/orders", spec="python-django", bindings=["/db/orders"],
    sidecars=[sidecar("cache", image="image:memcached:1.6-alpine", port=11211)],
    jobs=[
        job("migrate", command=["python", "manage.py", "migrate", "--noinput", "--database", "primary"],
            trigger=before_deploy(), timeout="20m"),
        backup,
    ])

# the same job attached to several apps
for p in ["/billing", "/inventory"]:
    app(p, "github.com/acme" + p, spec="python-django", bindings=["/db" + p], jobs=[backup])
```

```sh
openrun app create --spec python-django --bind /db/orders \
  --job '{"name":"nightly-report","command":["python","manage.py","send_report"],"trigger":{"type":"cron","schedule":"0 3 * * *","timezone":"UTC"}}' \
  github.com/acme/orders /orders

# Replace the metadata jobs (staged, promote to apply to prod); "-" clears them
openrun app update jobs --promote @jobs.json /orders
```

The JSON trigger forms are `{"type": "manual"}`, `{"type": "before_deploy"}` and `{"type": "cron", "schedule": "0 3 * * *", "timezone": "UTC"}`. `--job` and `app update jobs` accept a JSON object, or `@file` holding an object or a list.

## Running and inspecting jobs

```sh
openrun job list [appPathGlob]                                # jobs, next scheduled run and last status; a staged job change shows as a stage row
openrun job run nightly-report /orders                        # start on prod, returns the run id
openrun job run --stage --wait migrate /orders                # run on stage and wait for the result
openrun job run --arg region=eu nightly-report /orders        # run arguments for the job's params
openrun job run --force expire-sessions /orders               # run a disabled job, or alongside an active run
openrun job runs [--job name] [--status failed] /orders       # run history of the prod and stage instances
openrun job logs <run-id>                                     # output, while the run's container exists
openrun job cancel <run-id>                                   # stop an active run (on the node executing it)
```

Run statuses are `running`, `succeeded`, `failed`, `timed_out`, `canceled` and `lost`. Every job timestamp is UTC: schedules evaluate in the job's `timezone` (default UTC), and run times, `CL_JOB_SCHEDULED_AT` and the CLI output are RFC 3339 UTC. Listing jobs, runs and logs needs `app:read` on the app; running and canceling needs `app:update`. The same operations are available as REST APIs (`/_openrun/jobs`, `/_openrun/jobs/run`, `/_openrun/jobs/runs`, `/_openrun/jobs/logs`, `/_openrun/jobs/cancel`) and as MCP tools. Every finished run writes a `job` audit event with the run id and status.
