---
title: "Reference"
weight: 550
summary: "Reference index of all OpenRun Starlark functions and constants, grouped by where they are used"
---

This page is an index of all the Starlark functions and constants available in OpenRun, with links to the documentation for each. Entries are grouped by where they can be used:

- [App declaration (`apps.star`)]({{< relref "#app-declaration-appsstar" >}}) : declarative app management files, used with `openrun apply` and sync
- [App definition (`app.star`)]({{< relref "#app-definition-appstar" >}}) : the application definition and handler code
- [App parameters (`params.star`)]({{< relref "#app-parameters-paramsstar" >}}) : parameter definitions for an app
- [Store schema (`schema.star`)]({{< relref "#store-schema-schemastar" >}}) : type definitions for the document store

## App Declaration (`apps.star`)

App declaration files (any name, `apps.star` or `apps.ace` by convention) declare the apps and service bindings to deploy. They are used with the [`openrun apply`]({{< ref "docs/applications/overview/#declarative-app-management" >}}) and [`openrun sync`]({{< ref "docs/applications/overview/#automated-sync" >}}) commands. The functions available are:

|  Function   |                                 Description                                  |                                       Documentation                                       |
| :---------: | :--------------------------------------------------------------------------: | :---------------------------------------------------------------------------------------: |
|   `app`     |      Declares one app: install path, source url, params, config, bindings    |     [App Configuration]({{< ref "docs/applications/overview/#app-configuration" >}})      |
|  `binding`  |            Declares one service binding: path, source, grants, config        |   [Declarative Apply]({{< ref "docs/applications/servicebindings/#declarative-apply" >}}) |
|  `config`   | Reads a value from the server `[node_config]` in `openrun.toml`, with a default | [Config Access from Code]({{< ref "docs/configuration/overview/#config-access-from-code" >}}) |

The `config` function supports the special keys `_branch` (the git branch the declaration file was loaded from) and `_dev` (whether the apply is running in dev mode).

## App Definition (`app.star`)

The `app.star` file defines the app and its handler functions. The predefined builtins are available under the `ace` namespace. See [Developing Apps]({{< ref "docs/develop" >}}) for the app structure.

### Functions

|     Function     |                              Description                               |                                     Documentation                                      |
| :--------------: | :--------------------------------------------------------------------: | :------------------------------------------------------------------------------------: |
|    `ace.app`     |        Creates the app definition, assigned to the `app` global        |            [App Definition]({{< ref "docs/develop/#app-definition" >}})                |
|    `ace.html`    |               Defines an HTML page route with fragments                |              [HTML Route]({{< ref "docs/app/routing/#html-route" >}})                  |
|  `ace.fragment`  |        Defines a partial page interaction within an HTML route         |                [Fragment]({{< ref "docs/app/routing/#fragment" >}})                    |
|    `ace.api`     |                  Defines a JSON or plain text route                    |               [API Route]({{< ref "docs/app/routing/#api-route" >}})                   |
|   `ace.proxy`    |          Defines a route which proxies to another URL or container    |             [Proxy Route]({{< ref "docs/app/routing/#proxy-route" >}})                 |
|  `ace.redirect`  |             Returns a redirect response from a handler                 |        [Redirect Response]({{< ref "docs/app/response/#redirect-response" >}})         |
|  `ace.response`  | Returns a custom response: template, status code, HTMX retarget/reswap |          [Custom Response]({{< ref "docs/app/response/#custom-response" >}})           |
| `ace.permission` |            Declares a plugin call the app needs approval for           |           [App Permissions]({{< ref "docs/develop/#app-permissions" >}})               |
|   `ace.style`    |         Configures the CSS library and themes for the app              |                    [Styling]({{< ref "docs/app/styling" >}})                           |
|  `ace.library`   |           Imports a JavaScript library as an ECMAScript module         |       [JavaScript Modules]({{< ref "docs/app/javascript/#javascript-modules" >}})      |
|   `ace.action`   |            Defines an action with an auto-generated form UI            |         [Action Definition]({{< ref "docs/actions/#action-definition" >}})             |
|   `ace.result`   |              Returns the result from an action run handler             |             [Action Result]({{< ref "docs/actions/#action-result" >}})                 |
|   `ace.audit`    |            Sets the audit event details from a handler                 |         [Custom Events]({{< ref "docs/applications/audit/#custom-events" >}})          |
|   `ace.output`   |          Wraps a value or error returned by a Starlark function        | [Returning Errors]({{< ref "docs/plugins/overview/#returning-errors-from-functions" >}}) |
|   `ace.config`   |     Reads a value from the server `[node_config]`, with a default      | [Config Access from Code]({{< ref "docs/configuration/overview/#config-access-from-code" >}}) |

In `app.star`, `ace.config` supports the special key `_app_url`, which resolves to the url the app is served at.

### Handler Functions

Handler functions are plain Starlark functions defined in `app.star` (or in files it loads). Two global function names are special, the OpenRun runtime looks them up by name:

|     Function      |                                              Description                                               |                                    Documentation                                     |
| :---------------: | :----------------------------------------------------------------------------------------------------: | :----------------------------------------------------------------------------------: |
|   `handler(req)`  |                    The default request handler, used when a route defines no handler                   |               [Structure]({{< ref "docs/develop/#structure" >}})                     |
| `error_handler(req, ret)` |       Defining this enables automatic error handling for plugin calls                          | [Automatic Error Handling]({{< ref "docs/plugins/overview/#automatic-error-handling" >}}) |

All other handlers are regular functions with no special name, referenced from the definition: route handlers through the `handler` property of [`ace.html`/`ace.api`/`ace.fragment`]({{< ref "docs/app/routing" >}}), the action run handler (called as `run(dry_run, args)`) through the `run` property of [`ace.action`]({{< ref "docs/actions/#action-definition" >}}), and the action [suggest handler]({{< ref "docs/actions/#suggest-handler" >}}) through its `suggest` property.

### Plugins

Plugins are loaded with `load("<plugin>.in", "<plugin>")` and called from handler functions. Plugin calls need [permissions]({{< ref "docs/develop/#app-permissions" >}}) approved for the app. The builtin plugins are:

|     Plugin     |                        Description                        |                            Documentation                             |
| :------------: | :-------------------------------------------------------: | :------------------------------------------------------------------: |
|   `store.in`   |   Document store APIs, using the types defined in `schema.star`  |         [Store Plugin]({{< ref "docs/plugins/store" >}})             |
|   `http.in`    |          HTTP client APIs: get, post, put, delete etc.    |     [HTTP Plugin]({{< ref "docs/plugins/catalog/#http-plugin" >}})   |
|   `exec.in`    |               Runs external commands as processes         |     [Exec Plugin]({{< ref "docs/plugins/catalog/#exec-plugin" >}})   |
|    `fs.in`     |                  Local file system access                 |       [FS Plugin]({{< ref "docs/plugins/catalog/#fs-plugin" >}})     |
| `container.in` |  Configures the app container, sidecars and runs commands |        [Container Plugin]({{< ref "docs/plugins/container" >}})      |
|   `proxy.in`   |             Configures proxying for proxy routes          |            [Proxy Plugin]({{< ref "docs/plugins/proxy" >}})          |

Additional plugins can be added as [external plugins]({{< ref "docs/plugins/external-plugins" >}}). App parameters are available in `app.star` through the `param` namespace, like `param.port`, as defined in [`params.star`]({{< ref "docs/develop/#app-parameters" >}}).

### Constants

The `ace` namespace also defines the following constants:

|                    Constant                     |                                             Usage                                             |
| :---------------------------------------------: | :-------------------------------------------------------------------------------------------: |
| `ace.GET`, `ace.POST`, `ace.PUT`, `ace.DELETE`  |  HTTP method for [routes]({{< ref "docs/app/routing" >}}), like `ace.html(method=ace.POST)`   |
|       `ace.HTML`, `ace.JSON`, `ace.TEXT`        | Response type for [`ace.api` and `ace.response`]({{< ref "docs/app/routing/#api-route" >}})   |
|            `ace.READ`, `ace.WRITE`              |    Call type for [`ace.permission`]({{< ref "docs/develop/#app-permissions" >}})              |
| `ace.AUTO`, `ace.TABLE`, `ace.DOWNLOAD`, `ace.IMAGE` | [Report types]({{< ref "docs/actions/#report-types" >}}) for action results             |
|              `ace.CONTAINER_URL`                | The app container URL placeholder, same as [`container.URL`]({{< ref "docs/plugins/container" >}}) |

## App Parameters (`params.star`)

The `params.star` file defines the [parameters]({{< ref "docs/develop/#app-parameters" >}}) for an app, set during app creation with `--param` and shown as form fields for [actions]({{< ref "docs/actions" >}}). The functions available are:

| Function |                            Description                             |                                       Documentation                                       |
| :------: | :----------------------------------------------------------------: | :---------------------------------------------------------------------------------------: |
| `param`  | Defines one parameter: name, type, default, description, display type |             [App Parameters]({{< ref "docs/develop/#app-parameters" >}})               |
| `config` | Reads a value from the server `[node_config]`, with a default      | [Config Access from Code]({{< ref "docs/configuration/overview/#config-access-from-code" >}}) |

`options_` is a special param name prefix: a `LIST` param named `options_<name>` holds the dropdown options for the param `<name>` in the action form UI, and is itself hidden from the form. See [Param Value Selector]({{< ref "docs/actions/#param-value-selector" >}}).

The constants available in `params.star` are:

|                 Constant                  |                                       Usage                                        |
| :---------------------------------------: | :--------------------------------------------------------------------------------: |
| `STRING`, `INT`, `BOOLEAN`, `LIST`, `DICT` |                     The `type` property for a param, `STRING` is the default      |
| `FILE`, `PASSWORD`, `TEXTAREA`, `COMBO`   | The `display_type` property for string params, see [Display Types]({{< ref "docs/actions/#display-types" >}}) |

## Store Schema (`schema.star`)

The `schema.star` file defines the types for the [store plugin]({{< ref "docs/plugins/store" >}}), the document store backed by SQLite or PostgreSQL. The functions available are:

| Function |                       Description                       |                              Documentation                              |
| :------: | :-----------------------------------------------------: | :---------------------------------------------------------------------: |
|  `type`  |        Defines one document type: name, fields, indexes |  [Schema Definition]({{< ref "docs/plugins/store/#schema-definition" >}}) |
| `field`  |            Defines one field: name, type, default       |  [Schema Definition]({{< ref "docs/plugins/store/#schema-definition" >}}) |
| `index`  |     Defines an index on a list of fields, optionally unique |  [Schema Definition]({{< ref "docs/plugins/store/#schema-definition" >}}) |

The constants available in `schema.star` are `STRING`, `INT`, `BOOLEAN`, `LIST` and `DICT`, used as the field types.
