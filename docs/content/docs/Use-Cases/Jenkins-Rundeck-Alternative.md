---
title: "Alternative to Jenkins and Rundeck Jobs for Operational Tools"
linkTitle: "Jenkins and Rundeck Alternative"
weight: 500
description: "Open source, self-hosted alternative to Jenkins and Rundeck jobs: ops tools kept in git and deployed with GitOps, run from a web form, the CLI or by AI agents over MCP, with RBAC, confirmation and audit."
summary: "Replace Jenkins parameterized jobs and Rundeck jobs with actions kept in git: one function gives a web form, a CLI command and an MCP tool for AI agents, with RBAC, confirmation and audit built in."
keywords:
  [
    "Jenkins alternative",
    "Rundeck alternative",
    "open source Rundeck alternative",
    "self-hosted Jenkins alternative",
    "Jenkins parameterized job alternative",
    "runbook automation",
    "GitOps ops tools",
    "MCP tools for AI agents",
    "internal tools",
  ]
---

Most teams have a set of small operational tasks: restart a service, rotate a key, re-run a job, look up a record. Their usual home is a job runner, a Jenkins parameterized job or a Rundeck job. OpenRun [actions]({{< ref "docs/actions/" >}}) are an alternative to both: each task is one function in an app kept in git and deployed with GitOps. The same function is then a web form, a CLI command and an MCP tool for AI agents, with the same access checks and the same audit trail on every path.

## Scenario

This use case covers the scenario where you want to:

- Replace Jenkins or Rundeck jobs used as operations tools with something lighter to write and run
- Keep the tools in git and deploy them with GitOps, so a new tool or a changed validation rule is a reviewed pull request, not a job edited in a UI
- Give the team a set of operational tools with a form UI, without writing templates or a frontend
- Run the same tools from the command line, on the server or from a laptop with the user's own identity
- Let AI agents such as Claude Code call the tools as typed MCP tools, with a confirmation step before anything destructive runs
- Restrict who can run each tool with RBAC, and record every run under the user who started it

## Why Ops Tools End Up as Jenkins and Rundeck Jobs

The usual home for these tasks has been a job runner. A parameterized Jenkins or Rundeck job gives the task a form, an access policy and a run history, which is why ops teams kept using CI servers for things that are not builds. The cost is that each job is glued together (with lots of security holes) from shell steps and plugin configuration and is reachable only through that server's UI and API.

AI agents change what the invocation surface needs to be. An agent working an incident needs a typed tool: a name, a schema for the arguments, a description, and a signal for whether the call changes anything. A job runner has none of that. The practical options have been to give the agent a shell or a cluster credential, which is all or nothing, or to hand write a tool wrapper per task. Neither gets you a tool the agent can be trusted with.

## OpenRun Actions as a Jenkins and Rundeck Alternative

A parameterized Jenkins build or a Rundeck job is the closest existing shape for these tasks. The table is about the job as an operations tool, not about Jenkins as a CI server, which is a different job it does well.

|                           | Jenkins parameterized job                                                                                             | Rundeck job                                                 | OpenRun action                                                                                                                   |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Definition                | Jenkinsfile or UI-configured build, shell steps and plugins                                                           | YAML or UI-defined job with steps, options and node filters | One Starlark function next to its params, in the app's source                                                                    |
| Input form                | Generated from build parameters                                                                                       | Generated from job options                                  | Generated from `param` declarations, with dropdowns, validation and a dry run                                                    |
| Validation before running | None built in; the build fails part way                                                                               | Option regex and allowed values                             | The handler itself runs with `dry_run=True` and returns per-param errors                                                         |
| Access control            | Per-job matrix or Role Strategy plugin, Jenkins users                                                                 | Project ACL policies, Rundeck users and roles               | `permit` on the action plus server RBAC, with the same SSO users and groups as every other app                                   |
| Command line              | Jenkins CLI or `curl` against the build API, job specific scripting                                                   | `rd` CLI                                                    | `openrun action` with the same list, validate, run, follow and runs operations for every action                                  |
| AI agent access           | None native; a shell credential or a hand-written wrapper per job                                                     | None native                                                 | Every action is an MCP tool with a schema, enums, a description and side-effect annotations, from one endpoint                   |
| Guarding destructive runs | A confirmation step added to the pipeline by hand                                                                     | Job-level "require confirmation" in the UI                  | `destructive=True` asks the MCP client to confirm after a server-side dry run, refuses clients which cannot, and badges the form |
| Change management         | Jenkinsfile in git for pipelines; job and controller configuration on the controller or through configuration plugins | Job YAML export and import, or the SCM plugin               | The app and its declaration live in git; a sync deploys merged changes, staged first, with `openrun version revert` to roll back |
| History                   | Build records on the controller                                                                                       | Execution history                                           | Run records with arguments, streamed output and who ran it, plus an `action` audit event on every path                           |
| Operating it              | A controller and agents to patch, back up and keep plugins compatible on                                              | A Rundeck server with its database                          | The OpenRun server which already runs the team's apps; nothing extra per tool                                                    |
| Environments              | Job copies or folders per environment                                                                                 | Projects per environment                                    | One declaration applied per server, with `config()` reading each server's `[node_config]`                                        |

Three differences carry most of the weight. The first is cost per tool: an action is a function, so adding a tool is a few lines in an app that already exists, not a new job to configure and maintain. The second is that the CLI and the MCP tool are the same code path as the form, with the same user, the same `permit` check and the same audit row, rather than extra integrations with their own access rules. The third is the dry run: the validation an agent or a person sees before a destructive run comes from the handler's own logic, so the message says what the app is about to do, not just that a regex matched.

Jobs are still the better choice when the task is a build or a long multi-stage pipeline with artifacts, fan-out across many nodes with node filters, or a workflow which a team has already automated and audited there. Actions are for the small, frequent, person-or-agent-triggered tasks which end up as jobs because nothing lighter had a form, an access policy and a history.

## An Action App

The example below is a service restart, with a read only status action next to it. The restart script is a stand-in which logs what a rolling restart would do. The params are declared once:

```python {filename="params.star"}
param("service", description="Service to operate on", default="api")
param("options_service", type=LIST, default=["api", "worker", "scheduler"])

param("env", description="Environment", default="staging")
param("options_env", type=LIST, default=["staging", "prod"])

param("replicas", type=INT, description="Instances to restart, one at a time", default=2)
```

The handlers get the submitted values as `args`. The restart validates first, answers the dry run, then streams the output of the script:

```python {filename="app.star"}
load("exec.in", "exec")

def status(dry_run, args):
    rows = []
    for i in range(1, args.replicas + 1):
        rows.append({"instance": "%s-%d" % (args.service, i), "env": args.env, "state": "healthy", "uptime": "%dh" % (12 * i)})
    return ace.result("%s instances in %s" % (args.service, args.env), rows, ace.TABLE)

def restart(dry_run, args):
    if args.env == "prod" and args.replicas < 2:
        return ace.result("Validation failed", param_errors={"replicas": "prod keeps at least 2 instances during a restart"})
    if dry_run:
        return ace.result("Ready to restart %d %s instances in %s" % (args.replicas, args.service, args.env))
    return exec.run("./restart.sh", [args.service, args.env, str(args.replicas)], cwd="/opt/ops", stream=True)

app = ace.app("Service Ops",
    actions=[
        ace.action("Status", "/", status, read_only=True,
                   description="Show the instances of a service"),
        ace.action("Restart", "/restart", restart, is_async=True, timeout="10m",
                   show_validate=True, destructive=True, permit=["svc_restart"],
                   description="Rolling restart of a service, one instance at a time"),
    ],
    permissions=[ace.permission("exec.in", "run", ["./restart.sh"])],
)
```

Three things on the action definitions matter for what follows. `permit=["svc_restart"]` means only users holding that [RBAC]({{< ref "docs/configuration/rbac/" >}}) permission see or run the restart. `destructive=True` and `read_only=True` are [side-effect hints]({{< ref "docs/actions/#side-effect-hints" >}}). `is_async=True` makes the restart a background [run]({{< ref "docs/actions/#async-actions" >}}) with a record, so a ten minute restart does not depend on a browser tab staying open.

The app is deployed with one command, and the permission is granted through a role. Here `test1` has the `ops` role and `test2` does not:

```sh
openrun app create --approve --auth builtin ./svcapp /ops/svc
```

```json
"roles": {"ops": ["custom:svc_restart"]},
"grants": [
  {"users": ["builtin:test1"], "roles": ["openrun-user", "ops"], "targets": ["/ops/**"]},
  {"users": ["builtin:test2"], "roles": ["openrun-user"], "targets": ["/ops/**"]}
]
```

That gives a form UI at `/ops/svc` with a dropdown for the service and the environment, a Validate button, a **Destructive** badge on the restart and a run history page. No templates were written.

## Ops Tools in Git, Deployed with GitOps

The command above is the quick path. For a team install the app source lives in a repository and the server is told about it through a [declaration]({{< ref "docs/applications/overview/#declarative-app-management" >}}) in git:

```python {filename="apps.star"}
app("/ops/svc", "github.com/myorg/ops-apps/svcapp", auth="builtin")
```

```sh
openrun sync schedule --approve --promote github.com/myorg/ops-apps/apps.star
```

The [sync]({{< ref "docs/applications/overview/#automated-sync" >}}) checks the repository on a schedule (or on a webhook) and applies what changed: a new app in the declaration is created, a commit to the app source is deployed, and a param or config change in the declaration is applied to the existing app. Each change is staged first and promoted by the sync, with `openrun version revert` to go back.

That is the difference from a job runner's change process. Adding a tool, changing a validation rule or tightening who may run the restart is a pull request to the `ops-apps` repository, reviewed and merged like any other code, and the history of every tool is the git history. Nobody edits a job in a UI on the server, and a rebuilt server comes back with the same tools from the same declaration. The [environments section]({{< ref "#customizing-actions-across-environments" >}}) below extends the declaration so that one file serves staging and production.

## The CLI Interface

The [`openrun action`]({{< ref "docs/actions/#command-line" >}}) commands work against every action app with no change to the app. The listing is per user:

```sh
$ openrun action list
App       Action   Name     Path      Suggest  Hints        Description
/ops/svc  status   Status   /         false    readonly     Show the instances of a service
/ops/svc  restart  Restart  /restart  false    destructive  Rolling restart of a service, one instance at a time
```

`test2` sees only the status action. Running the restart as `test2` fails with `action "restart" not found`, because the action is not in that user's view at all.

Validation runs the handler with `dry_run=True` and reports param errors with exit code 2:

```sh
$ openrun action validate /ops/svc restart service=api env=prod replicas=1
Validation failed
error: param replicas: prod keeps at least 2 instances during a restart
```

A run of the async action starts it in the background. `--follow` reports the run id at once and tails the output:

```sh
$ openrun action run --follow /ops/svc restart service=api env=prod replicas=2
Run 3knua9eqjev1zohoeqsrpwviiax started, following its output (Ctrl-C stops following and leaves the run running)
[prod] api-1: draining connections
[prod] api-1: stopped, starting new instance
[prod] api-1: healthy
[prod] api-2: draining connections
[prod] api-2: stopped, starting new instance
[prod] api-2: healthy
[prod] api: rolling restart complete (2 instances)

$ openrun action runs /ops/svc
Run                          App       Action   Status     Started (UTC)         Duration  By
3knua9eqjev1zohoeqsrpwviiax  /ops/svc  Restart  succeeded  2026-10-17T02:55:13Z  4s        builtin:test1
```

Result values go to stdout and the status line to stderr, so `--format json` output pipes into `jq`. On the server machine the CLI runs as the admin over the unix socket. From a laptop, `openrun login` gives the CLI the user's own identity and the same checks as the form.

## The Same Actions as MCP Tools

Every action app serves its actions as [MCP tools]({{< ref "docs/actions/#mcp-tools" >}}), and `/_openrun/app_mcp` is [one endpoint]({{< ref "docs/actions/#one-endpoint-for-all-apps" >}}) for the actions of every app the user can run. One line connects an agent to all of them:

```sh
claude mcp add --transport http ops "https://openrun.example.com/_openrun/app_mcp?auth=builtin"
```

The tool list the agent sees is the same list `openrun action list` shows that user. Each tool has the params as its input schema, the dropdown values as enums, and the side-effect hints as its annotations. Asking Claude Code to deal with the service produces this:

```text
> The api service in prod is misbehaving. Check its instances, then do a
  rolling restart of it, and confirm it came back healthy.

● ops_svc__status(env: "prod", service: "api")
  api instances in prod
  api-1  healthy  12h
  api-2  healthy  24h

● ops_svc__restart(env: "prod", service: "api", replicas: 2, wait_seconds: 60)
  declined by the user, no changes were made

The rolling restart was declined at the permission prompt, so no changes
were made to prod. I stopped there rather than retrying.
```

The status call ran at once. The restart did not. Because the action is declared destructive, the server validated the arguments and asked the client to confirm before running anything. This session ran headless, so nobody was there to answer and the confirmation came back declined. The agent reported that and stopped. In an interactive session the user sees the prompt the server sent:

```text
Confirm Restart on /ops/svc: Rolling restart of a service, one instance at a time
Arguments:
  env="prod"
  replicas=2
  service="api"
Ready to restart 2 api instances in prod
Accept to run the action, decline to leave everything unchanged.
```

On accept, the run starts and the tool returns the run id, its status and the output, the same output the CLI tailed above. The validation status line in the prompt comes from the handler's own dry run, so the person confirming sees what the app thinks is about to happen, not just the arguments.

The confirmation is one layer. The `permit` list is the one that holds regardless of the client: an agent connected as `test2` does not get a restart tool at all. A client that cannot confirm, such as a script posting to the endpoint directly, is refused by default rather than let through, and the error says what the request declared and what it needs:

## Customizing Actions Across Environments

The same action app usually runs in more than one place: a dev or staging server and production, and on each server as a stage instance and a production instance. The source, the action definitions and the declaration in git stay identical everywhere. What differs is set in the declaration itself, where `config()` reads per-server values from the server config, and in the `[app_config]` settings which decide how runs behave.

### One Declaration, Per-Server Values with `config()`

With [declarative app management]({{< ref "docs/applications/overview/#declarative-app-management" >}}) the apps a server runs are listed in an `apps.star` file, applied with `openrun apply` or kept in sync from git. The [`config()`]({{< ref "docs/configuration/overview/#config-access-from-code" >}}) builtin is available in that file and returns the matching key from the `[node_config]` section of that server's `openrun.toml`, or the default given in the declaration. One declaration then produces a different app on each server:

```python {filename="apps.star"}
ops_envs = config("ops_envs", ["staging"])

app("/ops/svc", "github.com/example/ops-apps/svcapp",
    auth="builtin",
    git_branch=config("_branch", "main"),
    params={"options_env": ops_envs, "env": ops_envs[0]},
    app_config={
        "action.retain_runs": config("action_retain_runs", 100),
        "action.destructive_confirm": config("destructive_confirm", ""),
    })
```

```toml {filename="openrun.toml, production server"}
[node_config]
ops_envs = ["staging", "prod"]
action_retain_runs = 500
destructive_confirm = "require"
```

The staging server has no `[node_config]` entries, so it takes the defaults: the environment dropdown and the MCP enum of the restart action list only `staging`, and an agent connected to that server cannot even name `prod`. The production server offers both environments, keeps more run history and pins the confirmation mode regardless of what its `[api.mcp]` default says. The special key `_branch` resolves to the git branch the declaration was loaded from, so a sync of the `staging` branch deploys the action app from `staging` and a sync of `main` deploys it from `main`, with no edit to the file.

Values from `[node_config]` can be any TOML type and lists are passed to params as JSON. String values expand the environment variables listed in `system.allowed_env`, so a path like `"$OPENRUN_HOME/ops"` is valid. Params and app config set through the CLI or the console after the apply are kept on the next apply unless the declaration changes the same key or `--clobber` is passed, so a one-off adjustment on a server does not fight the declaration.

The same builtin is available in the app code as `ace.config`, if the value belongs in the app code rather than to the app declaration, such as the directory the restart script lives in: `exec.run("./restart.sh", ..., cwd=ace.config("ops_dir", "/opt/ops"))`. Prefer the declaration when a value can be a param or an app config setting, since those show in `openrun app list` and the console and can be changed without a code read.

### Stage and Production Instances on One Server

Within a server, every change to an app's params or app config lands on the stage instance first and reaches production with `--promote`, which is where the per-instance differences are made and tested:

```sh
# narrow the stage instance to staging only, try it at /ops/svc_cl_stage
openrun param update options_env '["staging"]' /ops/svc
# the production instance of the same app
openrun param update --promote options_env '["staging","prod"]' /ops/svc
```

Both instances share the source version and the action definitions. The stage instance has its own run history and its own MCP tools, so a changed action can be exercised by an agent against the stage instance before it is promoted.

### `[app_config]` Settings for How Actions Run

How runs are kept, how long they may take, how long an MCP client may cache the tool list and whether a destructive action needs confirmation are `[app_config]` settings. The server's `openrun.toml` sets the defaults for all apps on that server; the declaration above or `openrun app update conf` overrides them for one app:

```toml {filename="openrun.toml"}
[app_config]
action.run_timeout = "1h"           # async runs without their own timeout
action.max_async_runs = 20          # concurrent runs per app instance on a node
action.retain_runs = 100            # run records kept per app instance
action.mcp_list_ttl = "3m"          # how long an MCP client may cache the tool list
action.destructive_confirm = ""     # require, ask or skip; "" inherits [api.mcp] destructive_confirm
```

```sh
# a dev app whose actions change often
openrun app update conf --promote 'action.mcp_list_ttl="30s"' /ops/svc
```

`destructive_confirm` layers in the same direction as the rest: the `[api.mcp]` server setting is the default, `action.destructive_confirm` on the app overrides it, and an API key created with `openrun apikey create --confirm skip` can bypass the prompt for one deliberately trusted automation. A pipeline on the staging server can hold such a key while the production server keeps `require` and no such key exists there.

Taken together: the source is identical in every environment, the declaration with `config()` decides what each server's app exposes and how its runs behave, stage and promote separate the two instances on a server, and `[node_config]` is the only file that differs between servers.

## What Is Recorded

Every path writes the same [audit events]({{< ref "docs/applications/audit/" >}}) under the user who ran the action. The headless session, an accepted restart from an interactive client, and the refused direct call above left these rows:

```text
action  mcp_execute   builtin:test1  Success
action  mcp_validate  builtin:test1  Success
action  mcp_execute   builtin:test1  Failed   confirm=declined
action  mcp_validate  builtin:test1  Success
action  mcp_execute   builtin:test1  Success  3knuh3uihoiwrt2kvgvu8oaksps confirm=accepted
action  run_finish    builtin:test1  Success  3knuh3uihoiwrt2kvgvu8oaksps succeeded
action  mcp_execute   builtin:test1  Failed   confirm=refused
```

The first row is the read only status call. Every destructive call says how it got past the prompt, or that it did not, so that is a query, not a guess. The run record keeps the arguments, the output and who started it, and is what `openrun action runs` and the Run History page show.

## Where This Fits

An action is one function next to the app it operates, kept in git and deployed with GitOps like any other OpenRun app, and the CLI command and the MCP tool are not extra work. The agent gets a typed tool with a description, a dry run, a destructive flag and a confirmation step, and the team gets the same checks and the same log whether a person clicked the button, typed the command or asked an agent.

## Frequently Asked Questions

### Is OpenRun an alternative to Jenkins?

For Jenkins used as an operations tool, yes: a parameterized job which restarts, rotates, re-runs or looks something up becomes an OpenRun action with a generated form, a CLI command and an MCP tool, kept in git and deployed with GitOps. OpenRun does not replace Jenkins as a CI server for builds and multi-stage pipelines. For deploying iternal tools which are containerized apps, OpenRun handles the container build, no Jenkins is required.

### Is OpenRun an open source Rundeck alternative?

Yes, for self-service operations tasks. Rundeck jobs with options, ACL policies and execution history map to actions with params, `permit` plus RBAC, and run records with audit events. OpenRun is Apache-2.0 licensed and self-hosted on a single server or Kubernetes. Rundeck remains a better fit for fan-out across many nodes with node filters.

### How are the ops tools deployed with GitOps?

The app source and an `apps.star` declaration live in git, and `openrun sync schedule` applies changes on a schedule or webhook, staged first and then promoted. Changes to a tool are pull requests, and `openrun version revert` rolls a deployment back.

### Do I need to write a UI for each tool?

No. The form, the Validate button, Suggest button, the result rendering and the run history page are generated from the param declarations and the action definition. [Custom templates]({{< ref "docs/actions/#custom-templates" >}}) are available when the default page is not enough.

### Can an AI agent run a destructive action without a human confirming?

Not by default. The server asks the MCP client to confirm a destructive action before it runs, and refuses clients that cannot confirm. The `destructive_confirm` setting can be relaxed per server, per app or per API key for automation that has deliberately been granted it, and `permit` plus RBAC still decide who can run the action at all.

### How do CLI users authenticate from their own machines?

`openrun login` gives the CLI the user's own identity, so `openrun action` commands see the same action list and pass the same checks as the web form. On the server machine the CLI runs as the admin over the unix socket. See [Remote Access]({{< ref "docs/configuration/remoteaccess/" >}}).

### Is a job runner still needed for long running tasks?

Async actions run in the background with a run record, a timeout and streamed output, so a browser tab or CLI session does not need to stay open. The run can be followed, listed and cancelled from the UI, the CLI and the MCP tools.
