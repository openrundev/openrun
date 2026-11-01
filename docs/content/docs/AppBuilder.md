---
title: "AI App Builder"
weight: 320
summary: "Configure coding agents, preview generated apps, and publish through local files or Git"
---

The console's AI app builder creates and edits apps through a coding-agent conversation. Each session has a source workspace, a preview app and an agent running in a Docker or Podman container. You can inspect the files and preview, continue editing, and publish when ready.

- **Default:** disabled. Enable it under `[app_builder]` in `openrun.toml`.
- **Requires:** a local Docker or Podman runtime. Not supported when `system.container_command = "kubernetes"`.
- **Not to be confused with:** the container image [build service]({{< ref "container/build" >}}), configured under `[builder]`.

{{< theme-image light="/d2/app_builder_light.svg" dark="/d2/app_builder_dark.svg" alt="A builder session has a coding agent in a container which edits the source workspace, and a preview app running that workspace. The console user talks to the agent, inspects the preview and publishes the app" >}}

## Enable the Builder

{{% steps %}}

### Configure an agent and a profile

Add them to `openrun.toml`. This example uses the bundled OpenCode agent and a credential stored in the [embedded secrets store]({{< ref "configuration/secrets/#embedded-secrets-store-db" >}}):

```toml {filename="openrun.toml"}
[app_builder]
enabled = true
default_builder_profile = "tools"

[builder_agent.opencode]
env = { ANTHROPIC_API_KEY = '{{secret_from "db" "builder_api_key"}}' }

[builder_profile.tools]
agent = "opencode"
publish_mode = "path"
publish_target = "/tools"
services = ["defaults"]
description = "Build internal tools under /tools"
```

### Store the provider credential

Store the credential as `builder_api_key` before creating a session. Use the environment variable appropriate to the agent's model provider. Agent credentials are resolved at launch and made available to the agent container.

### Restart the server

Restart the server after editing the static config.

### Enable the builder area in the console

Install the [console]({{< ref "installation/#install-the-console-app" >}}) with `--auth system`, `--param enable_builder=true` and `--param enable_updates=true`. For an existing console:

```sh
openrun param update enable_builder true /console
openrun param update enable_updates true /console
openrun app approve --promote /console
```

### Create a session

Open the Builder area, create a session, select a profile if prompted, and describe the app. The first session builds the agent image, so startup may take longer than subsequent sessions.

{{% /steps %}}

{{< callout type="warning" >}}
The agent always runs inside a container sandbox, which is the safety boundary for its auto-approved tool calls. The `security.unsafe_agent_without_sandbox` setting runs the agent command directly on the host as the server user instead; it is a development-only escape hatch and is not recommended.
{{< /callout >}}

## Agents and Profiles

OpenRun includes agent images for `opencode`, `claude`, `codex` and `pi`. A `[builder_agent.<name>]` entry uses the name's prefix to choose the agent type: `opencode_team` uses OpenCode. Supported agent fields are:

| Field | Purpose |
| :--- | :--- |
| `env` | Agent environment variables; values support secret references. |
| `model`, `effort` | Model and reasoning settings, using the agent's supported values. |
| `config_files` | Host files mounted as `host:container[:ro]`; both paths must be absolute. An agent set through the console or the dynamic config can only mount from within `security.allowed_mounts`. |
| `dockerfile` | A custom Dockerfile path on the OpenRun server. Set through the console or the remote API, it must be under `security.remote_disk_read_paths`. |
| `command` | A command array that speaks the Agent Client Protocol over standard input/output. |
| `type` | Optional; must match the agent type inferred from the entry name. |

Names beginning with `custom_` require both `dockerfile` and `command`. The configured mounts and credentials are accessible to the agent; keep them limited to what the session needs.

A `[builder_profile.<name>]` combines an `agent` with optional settings:

| Setting | Purpose |
| :--- | :--- |
| `git_config` | A named `[builder_git.*]` target. Omit it for local publication. |
| `spec` | The default app spec used to scaffold new apps. |
| `services` | Backing services offered for auto bindings, such as `["postgres/main"]`. `["defaults"]` offers the default service of each type; an empty list offers none. Service permissions still apply. |
| `prompt` | Instructions appended to the system prompt. Set `replace=true` to replace the system prompt instead. |
| `publish_mode`, `publish_target` | Restrict publication to a path prefix (`path`), a subdomain (`subdomain`), or an app glob (`glob`). An empty mode allows any path authorized by RBAC. For subdomains, a target ending in `.` appends `system.default_domain`. |
| `description` | Shown in the new-app form when the user picks a profile. |

How the profile and system prompt are chosen:

- `app_builder.system_prompt` replaces the embedded base system prompt for all profiles when set.
- The default profile comes from `app_builder.default_builder_profile`. With no explicit default, a single configured profile is selected automatically; with several profiles, the user chooses.
- With no profiles configured, OpenRun uses OpenCode with local publication and no profile-level path restriction.

## Preview and Publish

The session's preview is a dev app under `app_builder.preview_path`, which defaults to `/builder/preview`. Source edits are picked up through dev reload. Inspect the preview and generated files before publishing; agent tool calls run automatically inside the sandbox, while app execution follows OpenRun's plugin and container permissions.

**Local mode:** publishing copies the source into `$OPENRUN_HOME/app_src` and maintains a declaration file there. The first publish creates a production app with a staging instance. Later publishes update staging; use `openrun app promote <appPath>` after verifying the change. Stopping or deleting the builder session is separate from unpublishing the deployed app.

**Git mode:** configure a target and reference it from the profile:

```toml {filename="openrun.toml"}
[builder_git.team]
repo = "github.com/myorg/internal-tools"
branch = "main"
auth = "team_git"
apps_file = "apps.star"
source_dir = "apps"

[builder_profile.tools]
agent = "opencode"
git_config = "team"
publish_mode = "path"
publish_target = "/tools"
```

The `team_git` entry in `[git_auth]` must have write access to the repository. Publishing commits and pushes the app source and declaration. Set up a sync to deploy those commits:

```sh
openrun sync schedule --git-auth team_git --approve \
  github.com/myorg/internal-tools/apps.star
```

This keeps updates staged for review. Add `--promote` if that pipeline should promote changes automatically. Removing an app from the Git declaration does not itself delete the deployed app; use a sync with `--prune` for resources it created, or delete the app explicitly.

## Access and Session Lifetime

- **Permissions:** builder operations require an authenticated user and `builder:*` permissions. The `openrun-builder` role includes these permissions and the developer role; publishing also checks app permissions on the destination.
- **Local publication:** requires explicit `app:approve`, which the builder role does not include. Grant it only on intended publication paths or have an operator publish.
- **Session access:** session owners can access their own sessions; accessing another user's session requires `admin`.

| Setting                         | Default                  | Meaning                                       |
| :------------------------------ | :----------------------- | :-------------------------------------------- |
| `app_builder.max_sessions`      | `5`                      | Limits live agent sandboxes                   |
| `app_builder.session_idle_mins` | `120`                    | Idle sandboxes are stopped after this many minutes |
| `app_builder.workspace_dir`     | `$OPENRUN_HOME/run/builder` | Location of the session workspaces          |

Stopping a session preserves its workspace and agent state for resumption. Deleting it removes the session workspace, preview app and agent state volume.
