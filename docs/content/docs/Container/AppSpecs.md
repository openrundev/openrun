---
title: "App Specs"
weight: 500
summary: "App specifications which predefine container and routing config for common frameworks"
---

## App Specs

OpenRun app specs are defined at https://github.com/openrundev/appspecs.

The `image` spec specifies the image to use. for example

```shell
openrun app create --spec image --approve --param image=nginx \
  --param port=80 - nginxapp.localhost:/
```

downloads the nginx image, starts it and proxies any request to `https://nginxapp.localhost:25223` to the nginx container's port 80. The container is started on the first API call, and it is stopped automatically when there are no API calls for 180 seconds.

For most other specs, the `Containerfile` is defined in the spec. For example, for the `python-streamlit` spec, the Containerfile is [here](https://github.com/openrundev/appspecs/blob/main/python-streamlit/Containerfile). Running

```shell
openrun app create --spec python-streamlit --branch master \
  --approve github.com/streamlit/streamlit-example /streamlit_app
```

will create an app at `https://localhost:25223/streamlit_app`. On the first API call to the app, the image is built from the defined spec and the container is started. The `python-gradio` spec does the same for gradio apps.

The `container` spec is a generic spec which can be used when there is a `Dockerfile` defined in tha app source code.

The `static` specs serve files from the app source. The `static` and `static_single` specs load source files into the metadata database like other non-dev disk apps. The `static_disk` spec is for local-disk sources only: OpenRun stores the spec metadata, but static files are served directly from the source directory on disk and are not copied into the metadata database. Updating a served file on disk takes effect on the next request. App reload is still required when app metadata or app definition behavior changes, such as changing the selected spec, `app.star`, `params.star`, `index`, or `single_file`.

```shell
openrun app create --spec static_disk --approve \
  --param index=index.html /srv/sites/my-static-site /site
```

On Kubernetes, a network mounted disk path should be used for the `static_disk` source path so that files are visible from all pods.

By default, staging and production apps generated from the same source share the same generated container image when the build inputs match. App specs should keep app path and domain values out of image builds when possible, and read runtime values such as `CL_APP_PATH` and `CL_APP_URL` from the container environment instead. If a spec must embed staging or production URL information into the image during build, set `container.separate_stage_prod_images` in the spec's `app.star`:

```python {filename="app.star"}
app = ace.app("My App",
    settings={
        "container": {"separate_stage_prod_images": True},
    },
    # routes and container config omitted
)
```

## App Specs Listing

The specs defined currently are:

| Spec Name               | Required Params                                                                                                            | Optional Params                                                                                                                                                         | Supports Path Routing | Notes                                                                 | Example                                                                                                                                                         |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------- | :-------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| container               |                                                                                                                            | <ul><li><b>port</b> : The port number within container, optional if EXPOSE directive is present</li></ul>                                                               | Depends on app        | Requires app code to have a Containerfile/Dockerfile                  |
| image                   | <ul><li><b>image</b>: The image to use for the container</li> <li><b>port</b> : The port number within container</li></ul> |                                                                                                                                                                         | Depends on app        | No source url required when creating app, use - as url                | `openrun app create --spec image --approve --param image=nginx --param port=80 - nginxapp.localhost:/`                                                          |
| proxy                   | <ul><li><b>url</b>: The url to which requests should be proxied</li> </ul>                                                 |                                                                                                                                                                         | No                    | No source url required when creating app, use - as url                | `openrun app create --spec proxy --approve -param url=https://openrun.dev - proxyapp.localhost:/`                                                               |
| static                  |                                                                                                                            | <ul><li><b>index</b>: The index file to serve</li><li><b>single_file</b>: Serve only the index file</li></ul>                                                           | Yes                   | All files under source folder are served from metadata                | `openrun app create --spec static --approve --param index=index.html github.com/example/site /site`                                                             |
| static_single           |                                                                                                                            | <ul><li><b>index</b>: The index file to serve</li></ul>                                                                                                                 | Yes                   | Only the index file is served from metadata                           | `openrun app create --spec static_single --approve --param index=index.html github.com/example/site /site`                                                      |
| static_disk             |                                                                                                                            | <ul><li><b>index</b>: The index file to serve</li><li><b>single_file</b>: Serve only the index file</li></ul>                                                           | Yes                   | Local disk source only; files are served directly from disk           | `openrun app create --spec static_disk --approve --param index=index.html /srv/sites/my-static-site /site`                                                      |
| python-wsgi             |                                                                                                                            | <ul><li><b>APP_MODULE</b>: The module:app for the WSGI app. Defaults to app:app, meaning app in app.py</li> </ul>                                                       | Depends on app        | Runs Web Server Gateway Interface (WSGI) apps using gunicorn          |
| python-asgi             |                                                                                                                            | <ul><li><b>APP_MODULE</b>: The module:app for the ASGI app. Defaults to app:app, meaning app in app.py</li> </ul>                                                       | Depends on app        | Runs Asynchronous Server Gateway Interface (ASGI) apps using uvicorn  |
| python-flask            |                                                                                                                            | <ul><li><b>port</b> : The port number within container. If EXPOSE directive is present, that is used. Defaults to 5000</li></ul>                                        | Depends on app        | Runs app using flask dev server                                       |
| python-streamlit        |                                                                                                                            | <ul><li><b>app_file</b> : The file name of the streamlit app to run. Default streamlit_app.py</li></ul>                                                                 | Yes                   |                                                                       | `openrun app create --spec python-streamlit --branch master --approve github.com/streamlit/streamlit-example /streamlit_app`                                    |
| python-streamlit-poetry |                                                                                                                            | <ul><li><b>app_file</b> : The file name of the streamlit app to run. Default streamlit_app.py</li></ul>                                                                 | Yes                   | Installs packages using poetry                                        |
| python-fasthtml         |                                                                                                                            | <ul><li><b>APP_MODULE</b>: The module:app for the ASGI app. Defaults to app:app, meaning app in app.py</li> </ul>                                                       | Depends on app        | Runs app using uvicorn                                                | `openrun app create --approve --spec python-fasthtml --param APP_MODULE=basic_ws:app  https://github.com/AnswerDotAI/fasthtml/examples fasthtmlapp.localhost:/` |
| python-gradio           |                                                                                                                            | <ul><li><b>app_file</b> : The file name of the gradio app to run. Default run.py</li></ul>                                                                              | Yes                   |                                                                       | `openrun app create --spec python-gradio --approve github.com/gradio-app/gradio/demo/blocks_flag /gradio_app`                                                   |
| go                      | <ul><li><b>port</b> : The port number within container</li></ul>                                                           | <ul><li><b>MAIN_PACKAGE</b> : The go module to build, default ".". Pass as a `--carg` instead of `--param`.</li><li><b>APP_ARGS</b> : Args to pass to the app</li></ul> | Depends on app        | CGO is disabled; go.mod has to be present; app should bind to 0.0.0.0 | `openrun app create --approve --spec go --param port=8080 --param APP_ARGS="-addr 0.0.0.0:8080" --branch master github.com/golang/example/helloserver /goapp`   |
