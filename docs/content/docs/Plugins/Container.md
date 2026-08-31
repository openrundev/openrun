---
title: "Container Plugin"
weight: 400
summary: "Container plugin supports configuring container backend"
---

The `container.in` plugin allows configuring and using the container backend for an app.

## Introduction

OpenRun can build and manage containers for implementing the app backend APIs. The `config` API is used to configure at the app level what configuration is used for the container. The `sidecar` API declares additional containers which run alongside the app container. The `run` API runs a command inside a container created from the app's image.

## APIs

The `container.in` plugin has the following APIs:

|     API     | Type  |                            Notes                            |
| :---------: | :---: | :---------------------------------------------------------: |
| **config**  | Read  |        Configures the container details for the app         |
| **sidecar** | Read  | Declares one sidecar container, for `config(sidecars=[..])` |
|   **run**   | Write |     Runs a command in a container using the app's image     |

The plugin also defines the following constants:

|         Constant         |  Value  |                                              Notes                                              |
| :----------------------: | :-----: | :---------------------------------------------------------------------------------------------: |
|     `container.URL`      |         | Placeholder for the container URL, for use with the proxy plugin, like `proxy.config(container.URL)` |
|     `container.AUTO`     | `auto`  |                    `src` value to auto detect the `Containerfile`/`Dockerfile`                  |
| `container.IMAGE_PREFIX` | `image:` |                   Prefix for the `src` value when using a prebuilt image                       |
|   `container.COMMAND`    | `command` |                            `lifetime` value for command-only apps                             |
|   `container.NIXPACKS`   | `nixpacks` |                         Reserved for nixpacks builds, not supported yet                      |

## config

The `config` API supports the following parameters:

- **src** (string, optional) : the source for the containerfile, `auto` (`container.AUTO`) by default
- **port** (int, optional) : the port number exposed from the container
- **scheme** (string, optional) : the url scheme, `http` by default
- **health** (string, optional) : the health check API, `/` by default
- **lifetime** (string, optional) : the lifetime for the container, default is to start a service when the app is initialized. Set to `container.COMMAND` to allow running commands against the container using `container.run` without starting a service.
- **build_dir** (string, optional) : the build directory for the build, `/` by default
- **volumes** (list of strings, optional) : the [volumes]({{< ref "docs/container/overview/#volumes" >}}) to mount in the container. Supports named volumes (`myvolume:/data`), bind mounts (`./config.yaml:/app/config.yaml`) and generated secret mounts (`cl_secret:secret.tmpl:/app/secret.ini`)
- **cargs** (dict, optional) : the container build arguments, `Containerfile` `ARG` values passed as `--build-arg` during the image build. Values set in the app metadata with `openrun app create/update --container-arg key=value` (alias `--carg`) override values set here
- **dev_settings** (dict, optional) : settings for the dev mode [fast reload]({{< ref "docs/container/devreload" >}}) flow. The allowed keys are `target`, `command`, `dir`, `reload`, `env_files`, `additional_mounts`, `port`, `dev_stage` and `disable`. These settings apply in dev mode only
- **sidecars** (list, optional) : the [sidecar containers]({{< ref "docs/container/overview/#sidecar-containers" >}}) for the app. Each entry must be created with `container.sidecar(...)`, a plain dict is not accepted

When the `src` is auto, the container file is auto detected. It checks for presence of either `Containerfile` or `Dockerfile`. If the value begins with `image:` (`container.IMAGE_PREFIX`), the subsequent portion is treated as the image to download. No image build is done in that case. Any other value for `src` is treated as the file name to use as the container file.

`port` can be specified in the container file, using a EXPOSE directive. If a value other than zero is specified in the config, that takes precedence over the value in the Expose.

A sample program using the container `config` is

<!-- prettier-ignore -->
```python {filename="app.star"}
load("proxy.in", "proxy")
load("container.in", "container")

app = ace.app("My App",
              routes=[
                  ace.proxy("/", proxy.config(container.URL))
              ],
              container=container.config(container.AUTO)
       ) 
```

With the default server config, both `proxy.config(container.URL)` and `container.config(...)` are approved implicitly. That default `container.config(...)` approval does not allow secrets. Add an explicit `ace.permission("container.in", "config", ..., secrets=[...])` entry when the app needs to pass secrets to the container, or when you want to narrow the allowed arguments.

## sidecar

The `sidecar` API declares one sidecar container: a background worker running the app's own image with a different command, or a companion service from another image. The result is passed to `container.config` in the `sidecars` list. The API supports the following parameters:

- **name** (string, required) : the sidecar name, lower case letters, digits and dashes. Used as the container name suffix and in the `CL_SIDECAR_<NAME>_ADDR` env var name
- **image** (string, optional) : the image for the sidecar, like `image:memcached:1.6-alpine` (the `image:` prefix is optional). If empty, the sidecar runs the app's own image
- **command** (list of strings, optional) : overrides the image entrypoint. Required for sidecars running the app image, since the image default command is the app's web server
- **args** (list of strings, optional) : arguments passed to the command (or to the image entrypoint)
- **env** (dict, optional) : the sidecar's own environment variables, overlaid on the inherited app env
- **inherit_env** (bool, optional) : whether to copy the app's env (params, binding env vars, `CL_*` vars) into the sidecar. Defaults to True for app image sidecars and False for foreign images. The app `PORT` is never inherited; a sidecar with a `port` gets `PORT` set to its own port
- **port** (int, optional) : the port the sidecar listens on. Sidecars with a port are readiness checked before the app container starts, and the app gets `CL_SIDECAR_<NAME>_ADDR` to reach them. Must differ from the app port and from other sidecars
- **health** (string, optional) : the readiness probe for sidecars with a port. Empty does a TCP connect to the port, `http:/path` does an HTTP GET expecting a 200 response
- **volumes** (list of strings, optional) : same syntax as the `config` `volumes`; a named volume also used by the app refers to the same volume
- **always_on** (bool, optional) : Docker/Podman only, keep the sidecar running when the app container is stopped for idleness. Defaults to True for sidecars without a port (workers) and False for sidecars with a port
- **options** (dict, optional) : container options for the sidecar, same keys as the app container options `--copt` (`kubernetes.cpus`, `kubernetes.memory`, ...)

Each `container.sidecar` call needs its own `container.in sidecar` permission, with the sidecar name and image as the positional arguments, so foreign images are visible during app approval:

```python {filename="app.star"}
load("container.in", "container")

app = ace.app("Orders",
    container=container.config(container.AUTO, port=8000,
        sidecars=[
            container.sidecar("cache", "image:memcached:1.6-alpine", port=11211, args=["-m", "64"]),
            container.sidecar("worker", command=["python", "-m", "orders.worker"], env={"ORDERS_ROLE": "worker"}),
        ]),
    permissions=[
        ace.permission("container.in", "sidecar", ["cache", "image:memcached:1.6-alpine"]),
        ace.permission("container.in", "sidecar", ["worker"]),
    ],
)
```

See [Sidecar Containers]({{< ref "docs/container/overview/#sidecar-containers" >}}) for details on how sidecars are run and how operators can add sidecars through the app metadata.

## run

The `run` API runs a command inside a new container created from the app's image (like `docker run --rm image command args...`), with the app's environment (params, binding env vars) and configured volumes. The container is removed after the command completes. The API supports the following parameters:

- **path** (string, required) : the command to run inside the container
- **args** (list of strings, optional) : arguments to pass to the command
- **process_partial** (bool, optional) : whether to process the output when the command fails
- **stdout_file** (bool, optional) : whether to send the stdout for the command to a temporary file on disk. The response `value` is then the temp file name; the app is responsible for deleting the file
- **parse** (string, optional) : whether to parse the stdout. Supported options are `json` (the whole output is one JSON document) and `jsonlines` (each output line is a JSON document)
- **stream** (bool, optional) : return the output as a stream which is lazily read as the response is being generated, instead of buffering the full output. Not supported with `parse="json"`
- **include_stderr** (bool, optional, default True) : whether to include the stderr output in the command output. If False, stderr is reported only in the error message when the command fails

The response format is the same as the `exec` plugin [`run`]({{< ref "/docs/plugins/catalog/#run" >}}) API: a list of output lines by default, parsed JSON with `parse`, a temp file name with `stdout_file`. The `env` and `cwd` parameters of `exec.run` are not used in container mode; the container gets the app's environment.

An app which runs a command against a specified image (see [image-cmd spec](https://github.com/openrundev/appspecs/blob/main/image-cmd/app.star)) is

```python {filename="app.star"}
load("container.in", "container")

def run(dry_run, args):
    split = args.command.split(" ")
    res = container.run(split[0], split[1:], parse="json" if args.json else "").value
    return ace.result("Command output", res)

app = ace.app(param.app_name + " : " + param.image ,
    actions=[
       ace.action("Run Command using " + param.image, "/", run, description="Run specified command in container", hidden=["secrets", "app_name", "image"])
    ],
    container=container.config("image:" + param.image, lifetime=container.COMMAND),
    permissions=[
       ace.permission("container.in", "run", secrets=param.secrets)
    ]
)
```

The explicit `container.in.run` permission is still required in this example. `container.config(...)` is implicitly approved by default without secret access. Add an explicit `ace.permission("container.in", "config", ..., secrets=[...])` entry if the config call needs to resolve secrets, or if the app needs to restrict the allowed arguments for that config call.

<!-- prettier-ignore-end -->
