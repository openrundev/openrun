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

## Development Apps

Development mode apps are used for developing or updating OpenRun apps. The source for these apps has to be on local disk, it cannot be git. Any code or config changes are live reloaded immediately for dev apps. To create a dev mode app, add the `--dev` option to the `app create` command. For example,

```sh
openrun app create --dev --approve /home/user/mycode /myapp
```

## Production Apps

Without the `--dev` option, apps are created as production apps by default. Production apps can be created from source on GitHub or from local disk. In either case, the source code for the app is uploaded to the OpenRun metadata database. For example:

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
app_stg_2aMvX3fc9fH18n6i2Jew0tNxnky STG  1                                                                example.com:/_cl_stage         /home/user/mycode

```

The second app is the staging app for the first. `app list` shows only the main apps by default, the `--internal` option makes it show the linked apps.

The staging app URL is available by suffixing `_cl_stage` at the end of the app path. So for an app at `https://example.com/`, the staging URL is `https://example.com/cl_stage`. For an app at `https://example.com/utils/app1`, the staging app URL is `https://example.com/utils/app1_cl_stage`.

## Promoting Changes

When there are code changes, running `app reload` will update the staging environment.

```sh
openrun app reload example.com:/
Reloaded apps: example.com:/_cl_stage
1 app(s) reloaded, 0 app(s) approved, 0 app(s) promoted.
```

The staging app is version 2 now, prod app is still at version 1.

```sh
openrun app list -i
Id                                  Type  Version GitCommit                                GitBranch       Domain:Path                    SourceUrl
app_prd_2aMvX3fc9fH18n6i2Jew0tNxnky PROD* 1                                                                example.com:/                  /home/user/mycode
app_stg_2aMvX3fc9fH18n6i2Jew0tNxnky STG   2                                                                example.com:/_cl_stage         /home/user/mycode
```

At this point, going to the URL `example.com:/_cl_stage` will show the updated code while `example.com:/` has not been updated.

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
app_stg_2aMvX3fc9fH18n6i2Jew0tNxnky STG  2                                                                example.com:/_cl_stage         /home/user/mycode
```

If the application code change requires new permissions, the reload operation will fail unless `--approve` is added.

To do the reload, approval and promotion is one step, do `openrun app reload --approve --promote example.com:/`.

## GitHub Reload

The rules for fetching source code from local disk and GitHub are:

- If the source URL starts with `http://`, `https://` or `github.com`, the source is assumed to be from a GitHub API endpoint. Otherwise the source is assumed to be local disk on the OpenRun server.
- If OpenRun client and server are on different machines and local disk is being used, the code needs to be copied to the server node first.
- For GitHub source, the format is https://domain_name/org_name/repo_name/sub/folder, like `github.com/openrundev/openrun/examples/disk_usage`. The sub_folder should contain the `app.star` config file.
- During `app create` and `app reload`, the commit id takes precedence over the branch name if both are specified.
- During `app reload`, if no branch and commit are specified, the newest code is checked out from the current branch. `main` is used as current branch if no branch was previously specified for the app.

## Preview Apps

Preview allows the creation of any number of linked preview apps for a main app. This is supported for apps created from GitHub source. The commit id to use needs to be specified when creating the preview. For example,

```sh
openrun preview create 49182d4ca1cacbd8e3463a77c2174a6da1fb66c9 /myapp
```

creates an app accessible at `/myapp_cl_preview_49182d4ca1cacbd8e3463a77c2174a6da1fb66c9` which runs the app code in the specified commit id.

Preview apps cannot be changed once they are created. If preview app requires new permissions, add the `--approve` option to the `preview create` command.

## Write Mode Access

Staging and Preview apps have read-only access by default to plugin APIs. This means that when they make calls to plugin APIs, only APIs defined as READ by the plugin are permitted. The HTTP plugin defines GET/OPTIONS/HEAD requests as READ type, POST/PUT/DELETE are defined as WRITE. For the CLI Exec plugin, the run API is defined as WRITE since the CLI command run might do write operations.

For cases where the plugin defines an API as Write, the app permission can overwrite the default type and define the operation to be a READ operation. For example, the disk_usage app runs the `du` command, which is a read operation. The [app config defines](https://github.com/openrundev/openrun/blob/49182d4ca1cacbd8e3463a77c2174a6da1fb66c9/examples/disk_usage/app.star#L45) the run plugin call as `type="READ"`, over-riding the default WRITE type defined in the plugin. If no type is specified in the permission, the type defined in the plugin takes effect.

Staging and Preview apps are allowed only READ calls by default, even if the app permissions allow WRITE operations. To allow stage apps access to WRITE operations, run `openrun app settings stage-write-access true all`. Change `all` to the desired app glob pattern.

To allow preview apps access to WRITE operation, run `openrun app settings preview-write-access true example.com:/`. This changes the existing preview apps and any new preview apps created for example.com:/ to allow write operations, if the permissions have been approved.
