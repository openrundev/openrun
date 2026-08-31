---
title: "Developing Apps"
weight: 330
summary: "Overview of developing OpenRun Apps"
---

## Structure

The structure of an OpenRun application is:

- One OpenRun application per folder, `static` sub-folder contains static assets
- An `app.star` Starlark file, defining the application configuration
- Predefined builtins, accessed through the `ace` namespace
- A global called `app`, created using `app = ace.app()` call
- An optional default handler function called `handler`. Other handlers are referenced in the route config
- An optional error handler function called `error_handler`. Defining the `error_handler` enables [automatic error handling]({{< ref "docs/plugins/overview#automatic-error-handling" >}})
- An html template file called `index.go.html` if using custom layout
- If not using custom layout, an html template block called `openrun_body` defined in any `*.go.html` file, for example `app.go.html`

## App Definition

The `app` global is created by calling the `ace.app` builtin. `name` is the only required argument, all other arguments are optional keyword arguments. The `ace.app` struct definition is

|      Property      | Optional |                    Type                     |  Default  |                                                                             Notes                                                                              |
| :----------------: | :------: | :-----------------------------------------: | :-------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------: |
|        name        |  False   |                   string                    |           |                                                                  The display name for the app                                                                  |
|       routes       |   True   | list of `ace.html`, `ace.api` , `ace.proxy` |    []     |                                          The [routes]({{< ref "docs/app/routing" >}}) exposed by the application                                               |
|      actions       |   True   |            list of `ace.action`             |    []     |                                     The [actions]({{< ref "actions" >}}) exposed by the app, with an auto-generated UI                                         |
|    permissions     |   True   |           list of `ace.permission`          |    []     |                          The plugin calls the app is allowed to make, see [App Permissions]({{< relref "#app-permissions" >}})                                 |
|     container      |   True   |             `container.config`              |           |                        The container configuration, for [containerized apps]({{< relref "#containerized-app" >}})                                              |
|       style        |   True   |                 `ace.style`                 |           |                                       The CSS [styling]({{< ref "docs/app/styling" >}}) configuration for the app                                              |
|     libraries      |   True   |      list of string or `ace.library`        |    []     |                                 The [JavaScript modules]({{< ref "docs/app/javascript" >}}) to import for the app                                              |
|   custom_layout    |   True   |                    bool                     |   False   | If True, the app defines the full HTML layout in `index.go.html`. If False, a layout is generated and the app defines only the `openrun_body` [template block]({{< ref "docs/app/templates" >}}) |
|      settings      |   True   |                    dict                     |    {}     |                                     Advanced app settings, see [App Settings]({{< relref "#app-settings" >}})                                                  |
|    static_only     |   True   |                    bool                     |   False   |                            If True, the app serves static files only, see [Static Apps]({{< relref "#static-apps" >}})                                         |
|       index        |   True   |                   string                    |           |            For static apps, the file served for the app root path. Defaults to `index.html` (or `index.htm`) if present in the app source                      |
|    single_file     |   True   |                    bool                     |   False   |                     For static apps, serve only the `index` file; requests for any other path return a 404 response                                            |
| redirect_bare_path |   True   |                    bool                     |   False   |              If True, requests to the bare app path (like `/myapp`) are redirected to the path with a trailing slash (`/myapp/`)                               |

For example, a minimal app definition is

```python {filename="app.star"}
app = ace.app("hello", routes=[ace.api("/", type=ace.TEXT)])
```

### Static Apps

Setting `static_only=True` makes the app serve the files in the app source folder directly, at the root level of the app path. No Starlark handlers or HTML templates are involved. The `index` property sets the file served for the app root path; if not set, `index.html` or `index.htm` from the app source is used if present. A static app cannot define HTML routes or a root level wildcard proxy route.

Setting `single_file=True` (along with `static_only=True`) serves only the `index` file; any other path returns a 404 response. The `index` property is required in this case. The `static`, `static_single` and `static_disk` [app specs]({{< ref "docs/container/appspecs" >}}) use these options, so static sites can be deployed without writing any Starlark configuration.

### Redirect Bare Path

Some containerized apps (like Gradio based apps) require the app to be accessed with a trailing slash in the path. Setting `redirect_bare_path=True` makes OpenRun redirect a request for the bare app path, like `/myapp`, to the full path with a trailing slash `/myapp/`.

### App Settings

The `settings` dict allows advanced customization of the app behavior. The supported settings, with their default values, are

```python {filename="app.star"}
app = ace.app("myapp",
    routes=[ace.html("/")],
    settings={
        "routing": {
            # Locations searched for template files
            "template_locations": ["*.go.html"],
            # Folder containing base templates for the structured template layout
            "base_templates": "base_templates",
            # Enable the server sent events (SSE) endpoint in prod mode
            "push_events": False,
            # Send HTTP 103 Early Hints for static files, for HTML routes in prod mode
            "early_hints": True,
            # Glob patterns excluded from the container content change check
            "container_exclude": ["static/**/*", "static_root/**/*", "base_templates/**/*", "*.go.html", "*.star", "config_gen.lock"],
        },
        "htmx": {
            # The HTMX library version to use
            "version": "2.0.3",
        },
        "container": {
            # Use separate container images for the stage and prod versions of the app
            "separate_stage_prod_images": False,
        },
    })
```

All settings are optional; only the entries being changed need to be specified. See [Templates]({{< ref "docs/app/templates/#template-file-location" >}}) for details on `template_locations` and `base_templates`.

In addition, an `app_config` key in the settings dict can set [app configuration]({{< ref "docs/applications/overview" >}}) options from within the app definition, the same options as set with `--conf` during app creation. For example, `settings={"app_config": {"cors": {"allow_origin": "*"}}}` sets the CORS allowed origin for the app. Values set in the app metadata using `--conf` take precedence over `app_config` values set in `app.star`.

## Sharing Files Across Apps

The app config property `star_base` can be used to set the base directory for Starlark files. This is useful when multiple apps need to share common files, like templates, static files, container spec etc. For example, if dir /mydir/ is the base directory with /mydir/app1 and /mydir/app2 as subdirectories containing two apps, creating apps using

```
openrun app create --approve --conf-str star_base=/app1 /mydir /test1
openrun app create --approve --conf-str star_base=/app2 /mydir /test2
```

will create two apps. `/mydir/app1/app.star` will be used as the app definition for test1 app, and static, static_root and template files will be read from /mydir.

## App Lifecycle

The OpenRun app development lifecycle is:

- Create a folder for the app, with the app.star file and templates.
- Start the OpenRun server. Create an app using `openrun app create --dev`. This runs the app in dev mode.
- In dev mode, some additional files are generated, with `_gen` in the file name. CSS dependencies and JavaScript modules are downloaded into the `static` folder.
- After the app development is done, the whole app folder can be checked into source control. There is no build step.
- Create a production app, `openrun app create`, without the `--dev`. The app is now live. The OpenRun server can host multiple applications, each application has a dedicated path and optionally a dedicated domain.

## Simple Text App

The hello world app for OpenRun is an `~/myapp/app.star` file containing:

```python {filename="app.star"}
def handler(req):
    return "hello world"

app = ace.app("hello",
        routes = [ace.api("/", type=ace.TEXT)]
)
```

Run `openrun app create --auth=none ~/myapp /hello`. After that, the app is available at `/hello`.

```sh
$ curl localhost:25222/hello
hello world
```

The default response type is `ace.HTML`. `ace.TEXT` and `ace.JSON` are the other options. The data returned by the handler function is converted to the type format specified in the API.

## Building Apps from Spec

A spec (specification) can be set for an app. This makes OpenRun use the spec as a template to specify the app configuration. Use `app create --spec python-flask` while creating an app or change the spec using `app update spec python-flask /myapp`. The spec brings in a set of predefined files. If a file with the same name is already present in the app code, then the spec file is ignored. So if the app code and spec both define a `Containerfile`, the file from the app code takes precedence. If the app folder contains just `app.py`

```python {filename="flaskapp/app.py"}
from flask import Flask

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"
```

Creating an app like `openrun app create --approve --spec python-flask ./flaskapp /myapp ` will do everything required to fully define the OpenRun app. If the app has additional python dependencies, add a `requirements.txt` file in the app source code. By [default](https://github.com/openrundev/appspecs/blob/main/python-flask/requirements.txt), only the flask package is installed. The file in the app source takes precedence.

See https://github.com/openrundev/appspecs for the list of specs. The OpenRun server build includes these specs by default. Additional specs can be defined by creating a folder `$OPENRUN_HOME/config/appspecs`. Any directory within that is treated as a spec. If the name matches with the predefined ones the spec in the config folder takes precedence. No server restart is required after spec changes. Setting up the server by doing

```bash
cd $OPENRUN_HOME/config
git clone https://github.com/openrundev/appspecs.git
```

ensures that the specs are updated to the latest version. Periodically doing a git pull on this folder refreshes the specs. Instead of cloning the main spec repo, a custom spec repo can also be used similarly. If no custom specs are defined, the specs as bundled in the OpenRun server build are available.

## App Parameters

Having a file `params.star` in the app source code causes OpenRun to load the parameters definitions from that file. Parameters are environment values which can be specified during app creation. A sample param definition is

```python {filename="params.star"}
param("port", type=INT,
      description="The port the flask app is listening on (inside the container)", default=5000)

param("app_name", description="The name for the app", default="Flask App")

param("preserve_host", type=BOOLEAN, description="Whether to preserve the original Host header", default=False)
```

This is defining three parameters. The type can be one of `STRING`(default), `INT`, `BOOLEAN`, `LIST` and `DICT`. The param structure definition is

|   Property   | Optional |                    Type                    |         Default         |                                                        Notes                                                        |
| :----------: | :------: | :----------------------------------------: | :---------------------: | :-----------------------------------------------------------------------------------------------------------------: |
|     name     |  False   |                   string                   |                         |                                         Has to be a valid starlark keyword                                          |
|     type     |   True   | `STRING`, `INT`, `BOOLEAN`, `LIST`or`DICT` |        `STRING`         |                                                    The data type                                                    |
|   default    |   True   |           Type as set for `type`           | Zero value for the type |                                                                                                                     |
| description  |   True   |                   string                   |                         |                                            The description for the param                                            |
|   required   |   True   |                    bool                    |          True           |                    If required is True and default value is not specified, then validation fails                    |
| display_type |   True   |                   string                   |                         | How this param should be displayed in the UI. Options are `FILE`, `PASSWORD` and `TEXTAREA`, default is text input. |

The parameters are available in the app Starlark code, through the `param` namespace. For example, `param.port`, `param.app_name` etc. See https://github.com/openrundev/appspecs/blob/main/python-flask/app.star for an example of how this can be used.

Params are set during app creation using `app create --param port=9000` or using `param update port 9000 /myapp`. Set value to `-` to delete the param. Use `param list /myapp` to list the params.

For containerized apps, all params specified for the app (including ones not specified in `params.star` spec) are passed to the container at runtime as environment parameters. `CL_APP_PATH` is a special param passed to the container with the app installation path (without the domain name). `PORT` is also set with the value of the port number the app is expected to bind to within the container.

## Action Apps

For use cases where an existing CLI application or API needs to be exposed as a web app, actions provide an easy solution. First, define the parameters to be exposed in the form UI. Create a `params.star` file with the params. For example,

```python {filename="params.star"}
param("repo", description="The GitHub repository to look up", default="openrundev/openrun")
```

The app defines a run handler which calls the GitHub API for the specified repository, using the [http plugin]({{< ref "docs/plugins/overview" >}}), and returns the stats as text.

```python {filename="app.star"}
load ("http.in", "http")

def run(dry_run, args):
   repo = http.get("https://api.github.com/repos/" + args.repo).value.json()
   out = ["Stars: %d" % repo["stargazers_count"], "Forks: %d" % repo["forks_count"],
          "Open Issues: %d" % repo["open_issues_count"]]
   return ace.result("Repo info for " + args.repo, out)

app = ace.app("Repo Info",
   actions=[ace.action("Repo Info", "/", run, description="Show the GitHub stats for the specified repository")],
   permissions=[
     ace.permission("http.in", "get", ["regex:^https://api\\.github\\.com/.*"]),
   ],
)
```

The app, when accessed, shows a form for the params, with the action output displayed below it:

<picture  class="responsive-picture" style="display: block; margin-left: auto; margin-right: auto;">
  <source media="(prefers-color-scheme: dark)" srcset="/images/action_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="/images/action_light.png">
  <img alt="Repo info action app" src="/images/action_light.png">
</picture>

See list files [code](https://github.com/openrundev/apps/tree/main/system/list_files):[demo](https://utils.demo.clace.io/list_files) for an actions app which lists files (using the exec plugin). See dictionary [code](https://github.com/openrundev/apps/tree/main/misc/dictionary):[demo](https://utils.demo.clace.io/dict) for another actions example app which shows different type of reports. [Actions]({{< ref "actions" >}}) has more details on building app actions.

## Containerized App

A containerized app needs to have a `Containerfile` (or `Dockerfile`) to define how the image is built. The app definition can have

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

<!-- prettier-ignore-end -->

which completely specifies the app. This is saying that the app is using the container plugin to configure the container and the proxy plugin to proxy all API calls (`/` route) to the container URL. On the first API call to the app, OpenRun will build the image, start the container and proxy the API traffic to the appropriate port. No other configuration is required in Starlark. If the container spec does not define the port being exposed, then the container config needs to specify the port number to use. The port number can be parameterized.

With the default server config, `proxy.config(container.URL, ...)` and `container.config(...)` are already approved implicitly, so no explicit `ace.permission(...)` entries are required for this standard containerized app flow. That default approval does not allow `container.config(...)` to resolve secrets; apps that pass secrets to containers must request and receive approval for the required `secrets=[...]` allowlist.

[Containerized Apps]({{< ref "/docs/container" >}}) has more details on building containerized apps.

## App Permissions

For plugin calls made by the app, the plugin permissions normally have to be specified in the app permissions and approved in the app metadata. Server config can also define globally allowed calls under `permissions.allow`, in which case no explicit app approval is required for those calls. The `ace.permission` struct definition is

| Property  | Optional |          Type          |  Default  |                                                  Notes                                                  |
| :-------: | :------: | :--------------------: | :-------: | :-----------------------------------------------------------------------------------------------------: |
|  plugin   |  False   |         string         |           |                                             The plugin name                                             |
|  method   |  False   |         string         |           |                                             The method name                                             |
| arguments |   True   |      list string       |           |                                   The arguments allowed for the call                                    |
|   type    |   True   |         string         | ace.WRITE |                                The call type, `ace.READ` or `ace.WRITE`                                 |
|  secrets  |   True   | list of list of string |           |                                 The secrets the plugin call can access                                  |
|  permit   |   True   |      list string       |    []     | Custom RBAC permissions, any one of which is required to make the call when RBAC is enabled for the app |

For example `ace.permission("proxy.in", "config", [container.URL])` is a plugin call to `config` method in `proxy.in` plugin. The first argument has to be `container.URL`. Additional arguments are allowed. If no arguments are specified in the permission, then there is no restriction on arguments passed at runtime. If the value specified starts with `regex:`, then the value passed is checked against the specified regex at runtime.

The default server config already allows `proxy.config(container.URL, ...)` and `container.config(...)`, so these two calls do not need an explicit permission entry unless the app wants to narrow the default access or allow specific secrets for `container.config(...)`.

If `permit` is set, the plugin call is available only to users who have at least one of those custom RBAC permissions when RBAC is enabled for the app. If RBAC is not enabled or `permit` is empty, plugin calls is allowed.

See [secrets]({{< ref "/docs/configuration/secrets/#plugin-access-to-secrets" >}}) for details on specifying the secrets which can be accessed by the plugin call.

## More examples

There is a disk_usage example [here](https://github.com/openrundev/openrun/tree/main/examples) and many in the [apps repo](https://github.com/openrundev/apps). The disk_usage example shows a basic hypermedia flow. The cowbull game has multiple [pages](https://github.com/openrundev/apps/blob/f5566cea6061ec85ea59495efc7b8700f06a4e70/misc/cowbull/app.star#L107), each page with some dynamic behavior. For styling, it uses the [DaisyUI](https://daisyui.com/) component library with Tailwind CSS. These two examples work fine with JavaScript disabled in the browser, falling back to basic HTML without any HTMX extensions.

The memory_usage example uses the [d3](https://d3js.org/) library to show an interactive display of the memory usage for processes on the machine. The plot library is [automatically imported](https://github.com/openrundev/apps/blob/f5566cea6061ec85ea59495efc7b8700f06a4e70/system/memory_usage/app.star#L103) as an ECMAScript module and the custom [JavaScript code](https://github.com/openrundev/apps/blob/main/system/memory_usage/static/js/app.js) works with a [JSON API](https://github.com/openrundev/apps/blob/f5566cea6061ec85ea59495efc7b8700f06a4e70/system/memory_usage/app.star#L98) on the backend. The default in OpenRun is hypermedia exchange, JSON can be used for data APIs.
