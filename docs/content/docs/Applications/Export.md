---
title: "Exporting App Configuration"
weight: 250
summary: "Move existing apps and bindings into declarative GitOps configuration, or recreate their configuration on another server"
---

`openrun export` writes existing apps and service bindings as a Starlark declaration file that can be used with `openrun apply`. Use it to bring CLI- or console-created resources under GitOps management, or to prepare configuration for another OpenRun server.

## Export Current Configuration

```sh
openrun export --output apps.ace
openrun export --exclude-declarative --output unmanaged.ace
openrun export --exact-commit --service-ref exact --git-auth exact --output snapshot.ace
openrun export "example.com:**"
```

The export contains the current production configuration of matching apps. Dev apps are included with `dev=True`; staging and preview apps are excluded. The optional glob filters **apps only**: the output still includes all exportable bindings visible to the caller. Auto bindings are represented by the app's binding references so that apply recreates them.

| Option | Default | Effect |
| --- | --- | --- |
| `--service-ref` | `default` | Write a service type such as `postgres`, resolved using the destination server's default service. Use `exact` to retain names such as `postgres/main`. |
| `--git-auth` | `default` | Omit the app's Git credential name so the destination uses `security.default_git_auth`. Use `exact` to retain the configured entry name. |
| `--exact-commit` | `false` | Pin Git apps to their exported commit instead of following the branch. |
| `--exclude-declarative` | `false` | Omit apps and bindings already managed declaratively. |
| `--output`, `-o` | stdout | Write to a local file. |

Review the prerequisite and warning comments at the top of the generated file. For example, exporting with default service references can map bindings from several PostgreSQL services onto a single destination service. Use `--service-ref exact` when those services need to remain distinct.

## Apply or Schedule the Export

```sh
openrun apply --dry-run apps.ace
openrun apply --approve apps.ace
```

Existing production apps receive staged changes. Test them and use `openrun app promote <appPathGlob>` when ready. Newly created apps start with both production and staging instances.

To manage the exported configuration through Git, commit the reviewed file to a repository, then schedule it:

```sh
openrun sync schedule --approve --promote github.com/myorg/platform/apps.ace
```

On another server, configure the referenced services, secrets, authentication providers and Git credentials first. Local source directories must also exist on that server. Export preserves configuration, including parameter values and secret references; it does not package source files, database contents, volumes, secret-store values, version history or server configuration. Treat literal credentials in parameters as sensitive before committing an export. Use [Litestream replication]({{< ref "litestream" >}}) or your database's backup tools for data recovery.

## Format a Declaration File

`openrun pretty-print` (alias `openrun fmt`) evaluates a declaration file and emits the same canonical format as export:

```sh
openrun pretty-print ./apps.ace
openrun pretty-print --output resolved.ace ./apps.ace
openrun pretty-print --write ./apps.ace
```

This evaluates Starlark logic: loops, helper functions, comments and `config(...)` lookups are replaced by the resulting declarations and literal values. Review the output before using `--write` on a hand-maintained file. Evaluation happens on the OpenRun server, so with a remote CLI the input path must be available on the server; the output file is written on the client.
