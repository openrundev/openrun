---
title: "Application Lifecycle"
weight: 200
summary: "Lifecycle for OpenRun applications, pushing changes live safely"
---

This page describes the four app types, the dev to staging to prod workflow with and without Git, how to promote and verify changes, and the write access rules for staging and preview apps.

## Application Types

An OpenRun application can be one of four types:

| Type | Purpose |
| :--- | :--- |
| **Development Apps** | Used for developing apps, supports live reload from code changes on disk. |
| **Production Apps** | For production use. Can be created from Git-hosted source or from sources on local disk. |
| **Staging Apps** | For reviewing code and config changes before they are pushed to prod. Every prod app has one staging app. |
| **Preview Apps** | For creating a review environment for code changes, useful as part of code review. |

{{< theme-image light="/d2/app_lifecycle_light.svg" dark="/d2/app_lifecycle_dark.svg" alt="Dev apps run from local disk with live reload. Reloads from disk or git update the staging app, which is promoted to the production app. Preview apps are created from a git commit" caption="Dev, staging, production and preview apps" >}}

## Lifecycle without Git

If not using git, a workflow would be:

1. Create a dev mode app, like `openrun app create --dev --approve ~/myappcode /myapp_dev`
2. Create a prod mode app, like `openrun app create --approve ~/myappcode /myapp`
3. As code changes are saved to disk, the changes are immediately live at `https://localhost:25223/myapp_dev`
4. When code is in a stable state, run `openrun app reload /myapp`. This updates the staging app with the most recent code from the `~/myappcode` folder.
5. The staging app is available at `https://stage.localhost:25223/myapp` for verification.
6. To promote the code to prod, run `openrun app promote /myapp`. The staged code is promoted to prod, live at `https://localhost:25223/myapp`.

Having a staging environment helps catch code and config issues before the changes are live on prod. OpenRun implements versioning for prod apps, even when source is not from git.

## Lifecycle With Git

If using git, a workflow would be:

1. Create a dev mode app on the dev machine, like `openrun app create --dev --approve ~/myappcode /myapp_dev`
2. Create a prod mode app on the prod server, like `openrun app create --approve github.com/myorg/repo /myapp`
3. As code changes are saved to disk, the changes are immediately live at `https://localhost:25223/myapp_dev`
4. When code is in a stable state, check in the dev code to git.
5. Run `openrun app reload /myapp`. This updates the staging app with the most recent code from the `main` branch in git.
6. The staging app is live at `https://stage.localhost:25223/myapp`. Verify the functionality of the staging app.
7. To promote the code to prod, run `openrun app promote /myapp`. The staged code is promoted to prod, live at `https://localhost:25223/myapp`.

To avoid the need to manually reload, set up a [sync]({{< ref "/docs/applications/overview/#automated-sync" >}}) job which automatically updates existing apps and creates new apps.

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

creates a production app.

- After app creation, the original source location is not read until an `app reload` operation is done to update the sources.
- The source folder `/home/user/mycode` can be deleted if reload is not required, since the sources are present in the OpenRun metadata database.
- Every production app automatically has one staging app associated with it.

## Staging Apps

Staging apps are created for each production app, to verify config and code changes before they are made live in the prod app. For example, after the previous `app create` command, a call to `app list` with the `--internal` option will show two apps:

```sh
openrun app list --internal
Name                           Type   Ver Auth    AppPath
mycode                         PROD     1 NONE    example.com:/
mycode                         STG      1 NONE    stage.example.com:/
```

The second app is the staging app for the first. `app list` shows only the main apps by default, the `--internal` option makes it show the linked apps.

By default, the staging app uses a staging subdomain (`system.default_stage_domain`, default `stage`) and the same path as the production app. So for an app at `https://example.com/`, the staging URL is `https://stage.example.com/`. For an app at `https://example.com/utils/app1`, the staging app URL is `https://stage.example.com/utils/app1`. For an app on its own subdomain, the stage label goes after the app's label: the staging URL for `https://app1.example.com/` is `https://app1.stage.example.com/`.

The staging location can be changed when creating the app. The server default is configured with `system.stage_at`. See [staging domain]({{< ref "docs/configuration/networking#staging-domain" >}}) for how the location is derived and the DNS and certificate setup for it.

| `app create` option | Staging location |
| :--- | :--- |
| `--stage-at domain_suffix` | The default. The stage label goes after the first label of the app's domain: `app1.stage.example.com` for `app1.example.com`, `stage.example.com` for `example.com` |
| `--stage-at domain` | The stage label goes in front of the app's domain: `stage.app1.example.com` for `app1.example.com`. This was the default before `domain_suffix`, use it to keep that shape |
| `--stage-at path` | The older path based location, where `_cl_stage` is suffixed to the production path |
| `--stage-at <domain>` | The staging app is put on the specified domain |

The staging location is set when the app is created and does not change afterwards.

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
Name                           Type   Ver Auth    AppPath
mycode                         PROD*    1 NONE    example.com:/
mycode                         STG      2 NONE    stage.example.com:/
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
Name                           Type   Ver Auth    AppPath
mycode                         PROD     2 NONE    example.com:/
mycode                         STG      2 NONE    stage.example.com:/
```

| `app reload` option | Effect |
| :--- | :--- |
| `--approve` | Approve new permissions required by the code change. Without it, the reload fails if new permissions are required |
| `--promote` | Promote the staged changes to prod in the same step |
| `--verify` | Check that the reloaded app container starts successfully before promotion |

To reload, approve and promote in one step, run `openrun app reload --approve --promote example.com:/`. To verify before promoting:

```sh
openrun app reload --verify --promote example.com:/
```

- For production apps, reload updates the staging app first. With `--verify`, OpenRun reloads the staging container during verification.
- If `--promote` is also set, the prod container is verified before promotion completes.
- If verification fails for any matched app, the reload operation fails and the staged changes are not promoted.
- `--dry-run` does not start containers, so verification is skipped in dry-run mode.

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

Preview apps cannot be changed once they are created. If a preview app requires new permissions, add the `--approve` option to the `preview create` command.

## Write Mode Access

Staging and preview apps allow approved WRITE plugin calls by default. Plugin permissions and server-level restrictions still apply in either mode.

| Setting | Default | Meaning |
| :--- | :--- | :--- |
| `security.stage_enable_write_access` | `true` | Whether new staging apps allow approved WRITE plugin calls |
| `security.preview_enable_write_access` | `true` | Whether new preview apps allow approved WRITE plugin calls |

To create new apps with read-only staging and preview plugin access, set both options to `false` in `openrun.toml`.

**How calls are classified:** in read-only mode, only calls classified as READ are permitted.

- The HTTP plugin classifies GET/OPTIONS/HEAD as READ and POST/PUT/DELETE/PATCH as WRITE.
- The Exec plugin classifies `run` as WRITE because the command may modify data.
- Where the plugin defines an API as WRITE, the app permission can override the default type and define the operation to be a READ operation. For example, the disk_usage app runs the `du` command, which is a read operation. The [app config defines](https://github.com/openrundev/openrun/blob/49182d4ca1cacbd8e3463a77c2174a6da1fb66c9/examples/disk_usage/app.star#L45) the run plugin call as `type="READ"`, over-riding the default WRITE type defined in the plugin. If no type is specified in the permission, the type defined in the plugin takes effect.

**Changing existing apps:** these settings apply immediately and are not staged. Change `all` to the desired app glob pattern.

| Command | Effect |
| :--- | :--- |
| `openrun app settings stage-write-access false all` | Restrict existing staging apps to READ calls |
| `openrun app settings preview-write-access false all` | Restrict existing preview apps to READ calls |
| `openrun app settings preview-write-access true example.com:/` | Allow WRITE operations for the existing preview apps and any new preview apps created for example.com:/, if the permissions have been approved |

Use `true` to allow approved WRITE calls again.

**Proxied apps:** for Starlark apps these controls apply to plugin calls. For proxied (containerized) apps, a staging or preview app without write access refuses every proxied request whose method is not GET, HEAD or OPTIONS with `403`; MCP calls authenticated with a bearer token are governed by RBAC and the app's tool scopes instead. The container itself and its database are not made read-only. Use separate staging credentials and appropriately restricted [service bindings]({{< ref "servicebindings" >}}) to control database access.
