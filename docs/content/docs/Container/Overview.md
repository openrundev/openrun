---
title: "Overview"
weight: 100
summary: "Overview of OpenRun containerized apps"
---

OpenRun builds the image and manages the container lifecycle for containerized apps. OpenRun fetches the source code, creates the image, starts the container, proxies the API calls, does health checks on the container and stops the container when idle. Appspecs allow existing source code to be used with OpenRun with no code changes required. OpenRun supports both `Dockerfile` and `Containerfile` as the file name for the container specification file.

For single node installations, OpenRun works with a local container manager (Docker/Podman/Orbstack etc). For multi-node installation on Kubernetes, OpenRun uses Kubernetes deployments to run each app.

<picture  class="responsive-picture" style="display: block; margin-left: auto; margin-right: auto;">
  <img alt="OpenRun Components" src="/d2/container_overview.svg">
</picture>

Containers are initialized lazily, when the app API is accessed. The request flow is:
<picture  class="responsive-picture" style="display: block; margin-left: auto; margin-right: auto;">
<img alt="OpenRun Request Flow" src="/d2/container_sequence.svg">
</picture>

## App Environment Params

For containerized apps, all params specified for the app (including ones specified in `params.star` spec) are passed to the container at runtime as environment parameters. `CL_APP_PATH` is a special param passed to the container with the app installation path (without the domain name). `PORT` is also set with the value of the port number the app is expected to bind to within the container.

For example, the command

```sh
openrun app create --approve --spec python-fasthtml \
  --param APP_MODULE=basic_ws:app \
  https://github.com/AnswerDotAI/fasthtml/examples fasthtmlapp.localhost:/
```

creates a FastHTML based app. The `APP_MODULE` env param is passed to the Container and passed to the startup command line in the [Containerfile](https://github.com/openrundev/appspecs/blob/a06a59a91d99520e271c6f3df68b6fb8292dbf50/python-fasthtml/Containerfile#L41).

To update params, run

```sh
openrun param update APP_MODULE basic_app:app fasthtmlapp.localhost:/
```

Param updates are staged, they can be promoted after verification. To delete a param, pass `-` as the value to the update. Use `openrun param list` to view app params.

Params can be set to secrets, by setting the value as `{{secret "vault_prod" "MY_KEY_NAME"}}`. The secret is resolved when the container is started and the value is passed to the container in its env.

{{<callout type="info" >}}
**Note:** Staged param updates are a powerful mechanism to ensure that config changes do not break your apps. For example, if BUCKET_NAME is a param pointing to a S3 bucket, the param change can be staged. The staging app can be tested to ensure that the new bucket is functional and there are no IAM/key related errors. Once the staging app is working, the app can be promoted. Code changes are easy to test, but config changes can cause env specific errors. Configuration related issues are a common cause of outages during deployment. OpenRun enables you to avoid such errors.
{{</callout>}}

## Container Build Args

If the Containerfile has an argument, the arg can be passed during the app create. Most python specs have the python version as an argument, For example, https://github.com/openrundev/appspecs/blob/a06a59a91d99520e271c6f3df68b6fb8292dbf50/python-fasthtml/Containerfile#L2 sets

```
ARG PYTHON_VERSION=3.12.5-slim
```

To change this during app creation, pass `--carg PYTHON_VERSION=3.11.1`. For example,

```sh
openrun app create --approve --spec python-fasthtml \
  --param APP_MODULE=basic_ws:app \
  --carg PYTHON_VERSION=3.11.1 \
  https://github.com/AnswerDotAI/fasthtml/examples fasthtmlapp.localhost:/
```

To update args, run

```sh
openrun app update carg PYTHON_VERSION=3.11.2 fasthtmlapp.localhost:/
```

Like all metadata updates, arg updates are staged. Pass `--promote` to promote immediately or run `app promote` to promote from stage to prod.

{{<callout type="info" >}}
**Note:** The slim images are smaller, but they lack some debugging tools. The regular image can be used during development.
{{</callout>}}

## Container Options

To set CPU and memory limits and other options for the container, pass `--copt optkey[=optvalue]` to the app create command. For example, `--copt cpu-shares=1000`

```sh
openrun app create --approve --spec python-fasthtml \
  --param APP_MODULE=basic_ws:app \
  --copt cpu=2 \
  https://github.com/AnswerDotAI/fasthtml/examples fasthtmlapp.localhost:/
```

sets the CPU request for the container to 2.

To update container options, run

```sh
openrun app update copt cpu=3 fasthtmlapp.localhost:/
```

Like all metadata updates, option updates are staged. Pass `--promote` to promote immediately or run `app promote` to promote from stage to prod.

{{<callout type="info" >}}
**Note:** By default there are no limits set for the containers. That allows for full utilization of system resources. To avoid individual apps from utilizing too much of the system resources, CPU/memory limits can be set.
{{</callout>}}

## Volumes

OpenRun automatically manages volumes for containers. Volumes definitions are picked from:

- The `Dockerfile`/`Containerfile` in the source or spec
- The container config in the app definition `app.star`
- The app metadata, `container-volume`/`cvol`

For named and unnamed volumes, OpenRun creates a unique named volume for each app. This volume is mounted across app updates.

Bind mounts are supported for mounting secrets into the container. If the source has a template file `secret.tmpl` which needs to be loaded into the container at `/app/secret.ini`, a volume can be defined like `cl_secret:secret.tmpl:/app/secret.ini`. The template file is passed the environment params and the generated file is bound into the container. For example, if the template file contains

```{filename="secret.tmpl"}
[DEFAULT]
{{range $k, $v := .params}}
{{- $k -}} = {{- $v }}
{{end}}
```

the params are generated in the ini file format. See [streamlit spec](https://github.com/openrundev/appspecs/blob/main/python-streamlit/app.star#L10) for an example of using this.

To define the volume in the app config, add

```{filename="secret.tmpl"}
    container=container.config(container.AUTO, port=param.port, volumes=[
        "cl_secret:secret.tmpl:/app/secret.ini",
    ]),
```

To set the volume info in the app metadata, run

```sh
openrun app update cvol --promote "cl_secret:secret.tmpl:/app/secret.ini" /APPPATH
```

multiple values are supported for `cvol`.
