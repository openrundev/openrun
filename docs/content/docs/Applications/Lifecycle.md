---
title: "Application Lifecycle"
weight: 200
summary: "Lifecycle for OpenRun applications, pushing changes live safely"
---

## Application Types

An OpenRun application can be one of four types:

- **Development Apps** : Used for developing apps, supports live reload from code changes on disk.
- **Production Apps** : For production use. Can be created from Git-hosted source or from sources on local disk.
- **Staging Apps** : For reviewing code and config changes before they are pushed to prod. Every prod app has one staging app.
- **Preview Apps** : For creating a review environment for code changes, useful as part of code review.

## Lifecycle without Git

If not using git, a workflow would be:

- Create a dev mode app, like `openrun app create --dev --approve ~/myappcode /myapp_dev`
- Create a prod mode app, like `openrun app create --approve ~/myappcode /myapp`
- As code changes are saved to disk, the changes are immediately live at `https://localhost:25223/myapp_dev`
- When code is in a stable state, run `openrun app reload /myapp`. This will update the staging app with the most recent code from `~/myappcode` folder.
- The staging app is available at `https://stage.localhost:25223/myapp` for verification.
- To promote the code to prod, run `openrun app promote /myapp`. The staged code is promoted to prod, live at `https://localhost:25223/myapp`.

Having a staging environment helps catch code and config issues before the changes are live on prod. OpenRun implements versioning for prod apps, even when source is not from git.

## Lifecycle With Git

If using git, a workflow would be:

- Create a dev mode app on dev machine, like `openrun app create --dev --approve ~/myappcode /myapp_dev`
- Create a prod mode app on prod server, like `openrun app create --approve github.com/myorg/repo /myapp`
- As code changes are saved to disk, the changes are immediately live at `https://localhost:25223/myapp_dev`
- When code is in a stable state, check in the dev code to git.
- Run `openrun app reload /myapp`. This will update the staging app with the most recent code from `main` branch in git.
- The staging app is live at `https://stage.localhost:25223/myapp`. Verify the functionality of the staging app.
- To promote the code to prod, run `openrun app promote /myapp`. The staged code is promoted to prod, live at `https://localhost:25223/myapp`.

To avoid need to manually reload, setup a [sync]({{< ref "/docs/applications/overview/#automated-sync" >}}) job which will automatically update existing apps and create new apps.

## Development Apps

Development mode apps are used for developing or updating OpenRun apps. The source for these apps has to be on local disk, it cannot be git. Any code or config changes are live reloaded immediately for dev apps. To create a dev mode app, add the `--dev` option to the `app create` command. For example,

```sh
openrun app create --dev --approve /home/user/mycode /myapp
```

## Production Apps

Without the `--dev` option, apps are created as production apps by default. Production apps can be created from Git sources or from local disk. In either case, the source code for the app is uploaded to the OpenRun metadata database. For example:

```sh
openrun app create --approve /home/user/mycode example.com:/
```

creates a production app. After app creation, the original source location is not read, until a `app reload` operation is done to update the sources. The source folder `/home/user/mycode` can be deleted if reload is not required, since the sources are present in the OpenRun metadata database. Every production app automatically has one staging app associated with it.

## Staging Apps

Staging apps are created for each production app. The purpose of the staging app is to be able to verify config and code changes before they are made live in the prod app. For example, after the previous `app create` command, a call to `app list` with the `--internal` option will show two apps:

```sh
openrun app list --internal
Id                                  Type Version GitCommit                                GitBranch       Domain:Path                    SourceUrl
app_prd_2aMvX3fc9fH18n6i2Jew0tNxnky PROD 1                                                                example.com:/                  /home/user/mycode
app_stg_2aMvX3fc9fH18n6i2Jew0tNxnky STG  1                                                                stage.example.com:/            /home/user/mycode

```

The second app is the staging app for the first. `app list` shows only the main apps by default, the `--internal` option makes it show the linked apps.

By default, the staging app uses a staging subdomain and the same path as the production app. So for an app at `https://example.com/`, the staging URL is `https://stage.example.com/`. For an app at `https://example.com/utils/app1`, the staging app URL is `https://stage.example.com/utils/app1`.

The staging location can be changed when creating the app. Use `openrun app create --stage-at path ...` to use the older path based location, where `_cl_stage` is suffixed to the production path. Use `--stage-at <domain>` to put the staging app on a specific domain. The server default is configured with `system.stage_at`.

## Promoting Changes

When there are code changes, running `app reload` will update the staging environment.

```sh
openrun app reload example.com:/
Reloaded apps: stage.example.com:/
1 app(s) reloaded, 0 app(s) approved, 0 app(s) promoted.
```

The staging app is version 2 now, prod app is still at version 1.

```sh
openrun app list -i
Id                                  Type  Version GitCommit                                GitBranch       Domain:Path                    SourceUrl
app_prd_2aMvX3fc9fH18n6i2Jew0tNxnky PROD* 1                                                                example.com:/                  /home/user/mycode
app_stg_2aMvX3fc9fH18n6i2Jew0tNxnky STG   2                                                                stage.example.com:/            /home/user/mycode
```

At this point, going to `https://stage.example.com/` will show the updated code while `https://example.com/` has not been updated.

{{<callout type="info" >}}
The `*` next to PROD indicates that there are staged changes waiting to be promoted to PROD.
{{</callout>}}

To promote the changes to prod, run `app promote`

```sh
openrun app promote example.com:/
Promoting example.com:/
1 app(s) promoted.
```

The prod app is at the same version as the staging app now

```sh
openrun app list -i
Id                                  Type Version GitCommit                                GitBranch       Domain:Path                    SourceUrl
app_prd_2aMvX3fc9fH18n6i2Jew0tNxnky PROD 2                                                                example.com:/                  /home/user/mycode
app_stg_2aMvX3fc9fH18n6i2Jew0tNxnky STG  2                                                                stage.example.com:/            /home/user/mycode
```

If the application code change requires new permissions, the reload operation will fail unless `--approve` is added.

To reload, approve and promote in one step, run `openrun app reload --approve --promote example.com:/`.

Add `--verify` to check that the reloaded app container starts successfully before promotion:

```sh
openrun app reload --verify --promote example.com:/
```

For production apps, reload updates the staging app first. With `--verify`, OpenRun reloads the staging container during verification. If `--promote` is also set, the prod container is verified before promotion completes. If verification fails for any matched app, the reload operation fails and the staged changes are not promoted. `--dry-run` does not start containers, so verification is skipped in dry-run mode.

## GitHub Reload

OpenRun supports GitHub, GitLab and other Git hosts, as well as local disk sources. The rules for fetching source code are:

- Sources starting with `http://`, `https://` or `git@`, and host paths such as `github.com/org/repo`, are treated as Git sources. Paths starting with `/`, `.` or `~` are local to the OpenRun server. See [Git configuration]({{< ref "docs/configuration/security/#private-repository-access" >}}) for authentication and host-specific URL formats.
- If OpenRun client and server are on different machines and local disk is being used, the code needs to be copied to the server node first.
- For GitHub source, the format is https://domain_name/org_name/repo_name/sub/folder, like `github.com/openrundev/openrun/examples/disk_usage`. The sub_folder should contain the `app.star` config file.
- During `app create` and `app reload`, the commit id takes precedence over the branch name if both are specified.
- During `app reload`, if no branch and commit are specified, the newest code is checked out from the current branch. `main` is used as current branch if no branch was previously specified for the app.

## Preview Apps

Preview allows the creation of any number of linked preview apps for a main app. This is supported for apps created from Git sources. The commit id to use needs to be specified when creating the preview. For example,

```sh
openrun preview create 49182d4ca1cacbd8e3463a77c2174a6da1fb66c9 /myapp
```

creates an app accessible at `/myapp_cl_preview_49182d4ca1cacbd8e3463a77c2174a6da1fb66c9` which runs the app code in the specified commit id.

Preview apps cannot be changed once they are created. If preview app requires new permissions, add the `--approve` option to the `preview create` command.

## Write Mode Access

Staging and preview apps allow approved WRITE plugin calls by default, controlled by `security.stage_enable_write_access` and `security.preview_enable_write_access`. To create new apps with read-only staging and preview plugin access, set both options to `false` in `openrun.toml`. Plugin permissions and server-level restrictions still apply in either mode.

In read-only mode, only calls classified as READ are permitted. The HTTP plugin classifies GET/OPTIONS/HEAD as READ and POST/PUT/DELETE/PATCH as WRITE. The Exec plugin classifies `run` as WRITE because the command may modify data.

For cases where the plugin defines an API as Write, the app permission can overwrite the default type and define the operation to be a READ operation. For example, the disk_usage app runs the `du` command, which is a read operation. The [app config defines](https://github.com/openrundev/openrun/blob/49182d4ca1cacbd8e3463a77c2174a6da1fb66c9/examples/disk_usage/app.star#L45) the run plugin call as `type="READ"`, over-riding the default WRITE type defined in the plugin. If no type is specified in the permission, the type defined in the plugin takes effect.

To restrict existing apps, run `openrun app settings stage-write-access false all` and `openrun app settings preview-write-access false all`. Change `all` to the desired app glob pattern. These settings apply immediately and are not staged. Use `true` to allow approved WRITE calls again.

To allow preview apps access to WRITE operation, run `openrun app settings preview-write-access true example.com:/`. This changes the existing preview apps and any new preview apps created for example.com:/ to allow write operations, if the permissions have been approved.

These controls apply to Starlark plugin calls. They do not make a proxied container or its database read-only. Use separate staging credentials and appropriately restricted [service bindings]({{< ref "servicebindings" >}}) to control database access.
