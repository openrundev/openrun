---
title: "Python as a Configuration Language Using Starlark"
summary: "Experience with using Starlark (which has a Pythonic syntax) for most configuration needs in OpenRun."
date: 2025-10-14
---

{{< openrun-intro >}}

## Background

OpenRun implements a platform for deploying web apps declaratively. The specific focus is on enabling teams to build and deploy internal tools, but it works as a general-purpose web app deployment service. For most end users, using OpenRun is as simple as starting the service and using imperative CLI commands to manage apps.

For teams, a declarative interface works better than imperative commands. GitOps enables you to do code reviews and version management for your config, same as done for code. OpenRun implements a declarative interface using [Starlark](https://starlark-lang.org/) for deploying web apps.

Starlark, a dialect of Python, is designed to be embedded in other applications for configuration or scripting abilities. Starlark was initially developed in Google for build tools like Blaze/Bazel, but it is now being used for other [use-cases](https://github.com/laurentlb/awesome-starlark?tab=readme-ov-file#users). There have been many discussions about the issues with YAML and other config languages. This post looks at the experience with using Starlark as the configuration language in OpenRun.

## How OpenRun Uses Starlark

OpenRun uses Starlark for these configurations:

- [**App declaration**]({{< ref "/docs/applications/overview/#declarative-app-management" >}}): Configure app source code and install path, with all required settings
- [**App definition**]({{< ref "/docs/develop/" >}}): Define app behavior, including proxying of requests, URL routing, static files, container config and API handler definitions.
- [**Parameter definition**]({{< ref "/docs/develop/#app-parameters" >}}): Specify configurable parameters for apps
- [**Schema definition**]({{< ref "/docs/plugins/store/#schema-definition" >}}): Table schema definition for apps that persist data

App definition enables all features of Starlark, including allowing external calls using plugins. All other use cases use the more restrictive variant of Starlark where features like recursive function calls are disabled.

## What does this look like?

### Simple App Declaration

Looking at the app declaration scenario, example declaration files are at https://github.com/openrundev/openrun/blob/main/examples/utils.star and https://github.com/openrundev/openrun/blob/main/examples/streamlit.star. Each app is one or two lines of config, like:

```python
# Install a couple of Hypermedia based apps
app("/utils/bookmarks", "github.com/openrundev/apps/utils/bookmarks")
app("/utils/disk_usage", "github.com/openrundev/apps/system/disk_usage")

# Install a proxy app and a static file app
app("openrun.:", "-", spec="proxy", params={"url": "https://openrun.dev"}) # Installs on openrun.localhost domain
app("/misc/event_planner", "github.com/simonw/tools", spec="static_single", params={"index": "event-planner.html"})

# Install container-based apps
limits = {"cpus": "2", "memory": "512m"} # Container limits
app("/misc/streamlit_example", "github.com/streamlit/streamlit-example", git_branch="master",
    spec="python-streamlit", container_opts=limits)
app("fasthtml.:", "github.com/AnswerDotAI/fasthtml/examples",
    spec="python-fasthtml",  params={"APP_MODULE":"basic_ws:app"}, container_opts=limits)
```

Each call to `app` declares an app, specifying its install path (URL) and source code path (from git or from disk) and other options. It is easy to avoid duplication. For example, the container `limits` are set once and used for multiple apps.

Considering that this is declaring the CI/CD build config, the web server routing config and the container runtime settings, the config is very simple. For equivalent declarative config in Kubernetes, there would be hundreds of lines of YAML just for the infrastructure config. Plus ArgoCD config. Plus OAuth/SAML config, all of which are automatically handled by OpenRun.

### App Declaration with Path Customization

For a scenario with a little bit more customization, consider the app declaration at https://github.com/openrundev/apps/blob/main/tools.star. A utility function `create_app` is used to customize the path, based on the git branch being used.

```python
def create_app(app_path, source_path):
  path_split = app_path.split(":") # split out the domain name
  path = path_split[1] if len(path_split) == 2 else path_split[0]

  branch = config("_branch", "")
  if branch:
     # Add branch name to app path
     path = "/" + branch + path
  if config("_dev", False):
     path = "/dev" + path

  if len(path_split) == 2:
     # Add the domain name back
     path = path_split[0] + ":" + path

  app(path, "github.com/openrundev/apps" + source_path, git_branch=branch)

create_app("/monitor/disk", "/system/disk_usage")
create_app("/monitor/memory", "/system/memory_usage")
create_app("/admin/audit", "/openrun/audit_viewer")
create_app("/admin/list", "/openrun/list_apps")
```

This is not purely config, there is some logic involved. It is easy to understand, while being deterministic and hermetic (properties of Starlark, meaning executions will behave the same each time, without having any side-effects). Values like `_dev` are properly typed, instead of everything being stringly-typed. Regular config approaches would have required maintaining multiple copies of this config or performing templating tricks to achieve the same flexibility.

## Experience with Starlark

### Pros

- Config in Starlark can be much more concise than YAML and JSON
- Easy to use utility methods to avoid repetition
- Easy to use programming constructs and perform conditional logic
- Config can use IDE features like auto-formatters, lint checks and type checkers
- While programming-language-like features are available, you get safety features which limit what the config can do

### Cons

- Reading Starlark based config is not as easy as doing a `json.load` or `yaml.load`. For Starlark, each new builtin needs to have a [Unpacker](https://github.com/openrundev/openrun/blob/main/internal/app/apptype/builtins.go) defined. How this is done depends on the host language. Only [Java, Go and Rust](https://github.com/laurentlb/awesome-starlark?tab=readme-ov-file#getting-started) are supported.
- Programmatically updating a Starlark config is not possible, there is no `dump` or `marshal` to Starlark. **EDIT**: I was informed that the Bazel team has a build file specific tool called [Buildozer](https://github.com/bazelbuild/buildtools/tree/main/buildozer) which can do limited updates to properly formatted buildfiles. HT: Jade Lovelace

Overall, if the use case does not require reading the config from multiple host languages, Starlark is a great option to consider for allowing end-users to write configuration files.

## Does Starlark work for all Config Scenarios?

In addition to Starlark, OpenRun uses TOML for the static config file. See [use-cases]({{< ref "/docs/use-cases/team/" >}}) for a full config scenario. TOML works great when the config has to be kept simple and there is no need to allow any custom logic in the configuration.

For API interaction and data serialization, OpenRun uses JSON. For example, the dynamic config uses JSON since there are API calls which can update the values dynamically. JSON works well for that scenario. Its limitations like not being able to add comments do not matter when the user is expected to use a UI to update the dynamic values.

For scenarios where configuration flexibility is good to have, Starlark is a great option.

{{<callout emoji="💬" >}}
Discussion thread on [lobste.rs](https://lobste.rs/s/knnz1l/python_as_configuration_language_via)
{{</callout>}}
