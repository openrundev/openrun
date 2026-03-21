---
title: "App Management Overview"
weight: 50
summary: "Overview of managing OpenRun applications"
---

The various commands for managing OpenRun apps are

```shell
$ openrun
NAME:
   openrun - OpenRun client and server https://openrun.dev/

USAGE:
   openrun [global options] command [command options] [arguments...]

COMMANDS:
   server       Manage the OpenRun server
   app          Manage OpenRun apps
   preview      Manage OpenRun preview apps
   account      Manage OpenRun accounts
   param        Manage app parameter values
   version      Manage app versions
   app-webhook  Manage app level webhooks
   password     Generate a password bcrypt config entry
   help, h      Shows a list of commands or help for one command

$ openrun app
NAME:
   openrun app - Manage OpenRun apps

USAGE:
   openrun app command [command options] [arguments...]

COMMANDS:
   create           Create a new app
   list             List apps
   delete           Delete an app
   approve          Approve app permissions
   reload           Reload the app source code
   promote          Promote the app from staging to production
   settings  Update OpenRun apps settings. Settings changes are NOT staged, they apply immediately to matched stage, prod and preview apps.
   update  Update OpenRun app metadata. Metadata updates are staged and have to be promoted to prod. Use "openrun param" to update app parameter metadata.
   help, h          Shows a list of commands or help for one command
```

The app management subcommands are under the `app` command. The `preview` command manages preview apps for an app and `version` command manages versions for an app. The `account` command is for managing accounts for an app.

## App Management

All the app management subcommands except `create` take a glob pattern, so multiple apps can be updated using one command. Use the `--dry-run` option with any update CLI call to verify if the options specified are correct before the actual run. No database changes are committed during dry-run and no changes are done in memory.

## Glob Pattern

The `reload/delete/promote/approve/list/update` commands accept a glob pattern. `example.com:**` will match apps under the example.com domain. `*:**` will match all apps in all domains, `all` is a shortcut for this. When using glob patterns, place the pattern inside double-quotes to avoid issues with shell star expansion. For example, `"example.com:**"`

The default for `app list` command is to list all apps. All other commands require a glob pattern to be specified explicitly.

When multiple apps are being updated, if any one app fails, the whole operation is rolled back. This allows for atomic updates across multiple applications.

## App Listing

Use the `app list` command to list apps. If the `--internal` option is used, then the internal staging and preview apps for each matched prod app are also listed.

```shell

$ openrun app list
Id                                  Type  Version Auth GitInfo                        Domain:Path                                                  SourceUrl
app_prd_2d3kCRk43FOuIGy979NbBWakRMm PROD        3 NONE main:9ce5e1adfc28983f7894      memory.demo.clace.io:/                                       github.com/openrundev/openrun/examples/memory_usage/
app_prd_2d3kCZ28w6VIzoXMsT9yldwijxL PROD        3 NONE main:9ce5e1adfc28983f7894      cowbull.co:/                                                 github.com/openrundev/openrun/examples/cowbull
app_prd_2d3kCjmw8ldQ2LaOd0CLmWXDApq PROD        3 NONE main:9ce5e1adfc28983f7894      /                                                            github.com/openrundev/openrun/examples/demo
app_prd_2d3kKVvSsSgUHqtNGZaD95NuLK3 PROD        3 NONE main:9ce5e1adfc28983f7894      du.demo.clace.io:/                                           github.com/openrundev/openrun/examples/disk_usage/
app_prd_2d6KcZmNwHIB8cSzNCotqBHpeje PROD        5 NONE main:ed7545ae739dfe85140a      utils.demo.clace.io:/bookmarks                               github.com/openrundev/apps/utils/bookmarks

$ openrun app list -i
Id                                  Type  Version Auth GitInfo                        Domain:Path                                                  SourceUrl
app_prd_2d3kCRk43FOuIGy979NbBWakRMm PROD        3 NONE main:9ce5e1adfc28983f7894      memory.demo.clace.io:/                                       github.com/openrundev/openrun/examples/memory_usage/
app_stg_2d3kCRk43FOuIGy979NbBWakRMm STG         3 NONE main:9ce5e1adfc28983f7894      memory.demo.clace.io:/_cl_stage                              github.com/openrundev/openrun/examples/memory_usage/
app_prd_2d3kCZ28w6VIzoXMsT9yldwijxL PROD        3 NONE main:9ce5e1adfc28983f7894      cowbull.co:/                                                 github.com/openrundev/openrun/examples/cowbull
app_stg_2d3kCZ28w6VIzoXMsT9yldwijxL STG         3 NONE main:9ce5e1adfc28983f7894      cowbull.co:/_cl_stage                                        github.com/openrundev/openrun/examples/cowbull
app_prd_2d3kCjmw8ldQ2LaOd0CLmWXDApq PROD        3 NONE main:9ce5e1adfc28983f7894      /                                                            github.com/openrundev/openrun/examples/demo
app_stg_2d3kCjmw8ldQ2LaOd0CLmWXDApq STG         3 NONE main:9ce5e1adfc28983f7894      /_cl_stage                                                   github.com/openrundev/openrun/examples/demo
app_prd_2d3kKVvSsSgUHqtNGZaD95NuLK3 PROD        3 NONE main:9ce5e1adfc28983f7894      du.demo.clace.io:/                                           github.com/openrundev/openrun/examples/disk_usage/
app_stg_2d3kKVvSsSgUHqtNGZaD95NuLK3 STG         3 NONE main:9ce5e1adfc28983f7894      du.demo.clace.io:/_cl_stage                                  github.com/openrundev/openrun/examples/disk_usage/
app_prd_2d6KcZmNwHIB8cSzNCotqBHpeje PROD        5 NONE main:ed7545ae739dfe85140a      utils.demo.clace.io:/bookmarks                               github.com/openrundev/apps/utils/bookmarks
app_stg_2d6KcZmNwHIB8cSzNCotqBHpeje STG         5 NONE main:ed7545ae739dfe85140a      utils.demo.clace.io:/bookmarks_cl_stage                      github.com/openrundev/apps/utils/bookmarks
```

Use the `version list` command to list versions for particular apps. This command works on prod app or staging app specifically.

```shell
$ openrun version list utils.demo.clace.io:/bookmarks_cl_stage
Active  Version Previous CreateTime                     GitCommit            GitMessage
              1        0 2024-03-01 19:59:27 +0000 UTC  86385ff67deab288c362 Updated bookmarks app

              2        1 2024-03-01 20:00:20 +0000 UTC  86385ff67deab288c362 Updated bookmarks app

              3        2 2024-03-01 20:16:08 +0000 UTC  86385ff67deab288c362 Updated bookmarks app

              4        3 2024-03-02 00:12:28 +0000 UTC  8080fcfe6be832a1f6f5 Update styling for bookmarks app

=====>        5        4 2024-03-02 00:23:35 +0000 UTC  ed7545ae739dfe85140a Update styling for bookmarks app

$ openrun version list utils.demo.clace.io:/bookmarks
Active  Version Previous CreateTime                     GitCommit            GitMessage
              1        0 2024-03-01 19:59:27 +0000 UTC  86385ff67deab288c362 Updated bookmarks app

              2        1 2024-03-01 20:00:20 +0000 UTC  86385ff67deab288c362 Updated bookmarks app

=====>        5        2 2024-03-02 00:23:35 +0000 UTC  ed7545ae739dfe85140a Update styling for bookmarks app
```

The `version switch` command can be used to switch versions, up or down or to particular version. The `version revert` command can be used to revert the last change. `app promote` makes the prod app run the same version as the current staging app.

In the above listing, the staging app has five versions. Three of those (1,2 and 5) were promoted to prod. `version switch previous utils.demo.clace.io:/bookmarks_cl_stage` will change the stage app to version 4. `version switch previous utils.demo.clace.io:/bookmarks` will change the prod app to version 2. After that, `app promote utils.demo.clace.io:/bookmarks` will change prod to also be at version 4, same as stage. The `version switch` command accepts `previous`, `next` and actual version number as version to switch to.

A star, like `PROD*` in the `app list` output indicates that there are staged changes waiting to be promoted. That will show up any time the prod app is at a different version than the stage app.

## App Authentication

By default, apps are created with the no authentication type. `system` auth uses `admin` as the username. The password is displayed on the screen during the initial setup of the OpenRun server config.

To change app auth type, add `--auth system` to the `app create` command. After an app is created, the auth type can be changed by running `app update auth --promote system /myapp`. OAuth based authentication is also supported, see [authentication]({{< ref "docs/configuration/authentication" >}}) for details.

{{<callout type="warning" >}}
Changes done to the app settings using the `app settings` command are **NOT** staged or versioned, they apply immediately to the stage/prod/preview apps.

All other changes done to app metadata using `app update`, `app reload`, `param update` etc are staged before deployment. Use the `--promote` option on the change to promote the change immediately when applying it on the staging app. Use `app promote` command to promote later. When a promotion is done, **ALL** currently staged changes for that app are promoted, not just the most recent change. After promote, the prod app is exactly same as staging app.
{{</callout>}}

## Declarative App Management

The CLI and management apps allow imperative management of OpenRun apps. OpenRun apps can also be managed declaratively. The app definition has to be defined in a file and OpenRun can apply the configuration. This works similar to the Kubernetes `apply` functionality.

To use this feature, create an app config file, with `.ace` extension. The config file should contain one or more `app` definitions. For example, in a file called `apps.ace`

```python {filename="apps.ace"}
app("/myapps/disk_usage", "github.com/openrundev/apps/system/disk_usage")
app("/myapps/memory_usage", "github.com/openrundev/apps/system/memory_usage")
app("/myapps/list_files", "github.com/openrundev/apps/system/list_files")
```

defines three apps. Running

```sh
openrun apply --approve apps.ace
```

will create the apps if not already present. If present, the app configuration is updated to match the new configuration.

### Apply Command

The `apply` command takes one or two arguments: `<filePath> [<appPathGlob>]`. The first is a file path, which can be a glob pointing to multiple files. The files can be from local disk or from a Git URL. The second optional argument is an app path glob which specifies which apps to apply from the loaded files. By default, all apps in the file(s) are applied.

The options the `apply` command takes are:

```
OPTIONS:
   --dev, -d                   Create apps in development mode (default: false)
   --branch value, -b value    The branch to checkout if using git source (default: "main")
   --commit value, -c value    The commit SHA to checkout if using git source. This takes precedence over branch
   --git-auth value, -g value  The name of the git_auth entry in server config to use
   --approve, -a               Approve the app permissions (default: false)
   --reload value, -r value    Which apps to reload: none, updated, matched
   --promote, -p               Promote changes from stage to prod (default: false)
   --clobber                   Force update app config, overwriting non-declarative changes (default: false)
   --force-reload, -f          Force reload even if there is no new commit (default: false)
   --dry-run                   Verify command but don't commit any changes (default: false)
   --help, -h                  show help
```

The branch/commit/git-auth arguments are for the apply file itself (if the file path is a Git URL). For the app source code, the git config has to be specified in the config file.

By default, changes are applied to the stage app. Add the `--promote` option to promote the changes. Use the `--approve` option to approve any permission changes required by apps.

The `--reload` option controls whether new source code is loaded for apps during the apply operation. Setting it to `none` means no apps are reloaded, `updated` means apps which have a config update are reloaded. `matched` (the default) means all apps matched by the app glob are reloaded, even if there is no config update.

By default, changes are applied as a three way merge. The old config and new config are compared against the live config. If there are changes between old and new declarative config, those changes are applied. Changes done imperatively are not overwritten. Using the `--force` option will overwrite any changes applied imperatively through the CLI or UI. The new declarative config overwrites any existing state when `--force` is used.

If `--dev` option is specified for the apply, the apps are created in dev mode. For apps with source path pointing to git, a local source folder is created under `$OPENRUN_HOME/app_src`. This allows for easy zero-config dev environment setup.

### App Configuration

The declarative app configuration uses Starlark syntax. An app is defined using the `app` struct which has these properties:

|    Property    | Optional |    Type     | Default |                                Notes                                |
| :------------: | :------: | :---------: | :-----: | :-----------------------------------------------------------------: |
|      path      |  false   |   string    |         |                  The app installation domain:path                   |
|     source     |  false   |   string    |         |                       The app source code url                       |
|      dev       |   true   |    bool     |  false  |                     Whether app is in dev mode                      |
|      auth      |   true   |   string    | default | The app authentication type (none or system or default or <custom>) |
|    git_auth    |   true   |   string    | default |                      The git auth entry to use                      |
|   git_branch   |   true   |   string    |  main   |                        The git branch to use                        |
|   git_commit   |   true   |   string    |         |                        The git commit to use                        |
|     params     |   true   |    dict     |         |                       The params for the app                        |
|      spec      |   true   |   string    |         |                   The app spec to use for the app                   |
|   app_config   |   true   |    dict     |         |                   The config settings for the app                   |
| container_opts |   true   |    dict     |         |                  The container options for the app                  |
| container_args |   true   |    dict     |         |            The container build args options for the app             |
| container_vols |   true   | list string |         |                  The container volumes for the app                  |

For example, a definition like

```python
app("/streamlit", "github.com/streamlit/streamlit-example",
    git_branch="master", spec="python-streamlit",
    params={"p1":["1", "2"]}, container_opts={"cpus": 1},
    container_vols=["/v1", "/v2"], app_config={"ac1": 11}
)
```

defines a Streamlit based app. Applying this file will create the app. Config can be updated through the CLI or UI. Subsequent runs of apply will not overwrite the imperative changes. For example, if a new param "p2" is defined using the CLI, that will be retained during subsequent runs. If the value of "p1" is updated in the config file, the next apply run will modify the value.

{{<callout type="warning" >}}
Apps are identified by their path and source URL, so those cannot be changed. Dev mode is set during app creation and cannot be updated. App auth and git_auth are settings which are directly applied without being staged. They can be updated through the CLI but not through the config file. All other properties are metadata changes which are staged. They can be updated through the app config. New app versions are created during apply and versions can be reverted at the app level.
{{</callout>}}

## Automated Sync

OpenRun supports automatically syncing the app definition from Git. The commands to manage sync are:

```
openrun sync
NAME:
   openrun sync - Manage sync operations, scheduled and webhook

USAGE:
   openrun sync command [command options]

COMMANDS:
   schedule  Create scheduled sync job for updating app config
   list      List the sync jobs
   delete    Delete specified sync job
   help, h   Shows a list of commands or help for one command
```

`openrun sync schedule --approve --promote github.com/openrundev/openrun/examples/utils.star` will create a scheduled sync which will run every 15 minutes and check for app config updates to apply. Use `--minutes` option to change the frequency.

```
openrun sync schedule --help
NAME:
   openrun sync schedule - Create scheduled sync job for updating app config

USAGE:
   args: <filePath>

   <filePath> is the path to the apply file containing the app configuration.

   Examples:
     Create scheduled sync, reloading apps with code changes: openrun sync schedule ./app.ace
     Create scheduled sync, reloading only apps with a config change: openrun sync schedule --reload=updated github.com/openrundev/apps/apps.ace
     Create scheduled sync, promoting changes: openrun sync schedule --promote --approve github.com/openrundev/apps/apps.ace
     Create scheduled sync, overwriting changes: openrun sync schedule --promote --clobber github.com/openrundev/apps/apps.ace


OPTIONS:
   --branch value, -b value    The branch to checkout if using git source (default: "main")
   --git-auth value, -g value  The name of the git_auth entry in server config to use
   --approve, -a               Approve the app permissions (default: false)
   --reload value, -r value    Which apps to reload: none, updated, matched
   --promote, -p               Promote changes from stage to prod (default: false)
   --minutes value, -s value   Schedule sync for every N minutes (default: 0)
   --clobber                   Force update app config, overwriting non-declarative changes (default: false)
   --force-reload, -f          Force reload even if there are no new commits (default: false)
   --dry-run                   Verify command but don't commit any changes (default: false)
   --help, -h                  show help
```

Scheduled sync takes all the same options as the `apply` command. The apply is done automatically by OpenRun on schedule.

Use `openrun sync list` to list all jobs and `openrun sync delete <sync_id>` to delete a sync job.

## Sync Frequency

The default sync frequency is every 15 minutes. This can be changed for each sync by passing `--minutes 10` during sync creation. To change the default globally, for any new sync being created, set

```python {filename="openrun.toml"}
[system]
default_schedule_mins = 10
```

GitHub imposes a [rate limit](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) for API calls. Every sync run make one list API call to the apply file repo and one API call to each source file repo. So if apply files and source files are in the same repo, there is just one API call in total. If there are multiple sync operation, each runs independently. If there a new commit found, then a clone is done on the repo.

Sync can be run more frequently, making sure rate limits are respected. If a [default git auth]({{< ref "/docs/configuration/security/#private-repository-access" >}}) entry is added, that will be used for all list API calls. The rate limits are higher for authenticated requests.
