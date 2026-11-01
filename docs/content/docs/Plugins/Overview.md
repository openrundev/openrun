---
title: "Plugin Overview"
weight: 100
summary: "Overview of how plugins work, how to use them"
---

Plugins provide an API for OpenRun Starlark code to call out to external systems. Plugins are implemented in Go. Every plugin API call must be approved before it is permitted, either in the app metadata or through server level defaults in `openrun.toml`. See [security]({{< ref "appsecurity#sample-application" >}}) for an overview of the security model.

Each plugin is identified by a unique name, like `store.in` or `exec.in`. Apps always load plugins with the `.in` suffix: resolution prefers a plugin compiled into the OpenRun binary and falls back to an installed [external plugin provider]({{< ref "docs/plugins/external-plugins" >}}) serving that module, so apps do not change when a plugin moves between the two. The `.ex` suffix explicitly requires the external build. Both run the same plugin implementation, built with the OpenRun plugin SDK.

This page covers:

- [Plugin Usage](#plugin-usage): loading a plugin and declaring permissions
- [Response Handling](#response-handling) and [Automatic Error Handling](#automatic-error-handling)
- [Returning Errors from Functions](#returning-errors-from-functions) with `ace.output`
- [Plugin Accounts](#plugin-accounts): per-plugin config, account linking and named accounts

## Plugin Usage

To use a plugin, load it using

```python {filename="app.star"}
load("http.in", "http")
```

This adds `http` to the namespace for the app. To make a call to the plugin, first add the permissions to the app config unless the server config already allows that call by default.

```python {filename="app.star"}
permissions=[
    ace.permission("http.in", "get"),
    ace.permission("http.in", "post")
],
```

Run `openrun app approve /myapp` to authorize the app to call the `get` and `post` methods on the http plugin. Approval also records the plugins the app is allowed to load: a `load("x.in", ...)` for a plugin which is neither approved nor listed in a server config `[[permissions.allow]]` entry fails when the app is initialized.

The `ace.permission` arguments are:

| Property | Optional | Type | Notes |
| :--- | :--- | :--- | :--- |
| plugin | false | string | The plugin name, like `http.in` |
| method | false | string | The plugin function name |
| arguments | true | list of strings | Approved values for the leading positional arguments, exact or `regex:` patterns. A call passing more positional arguments than listed is allowed; arguments which are checked cannot be passed as kwargs |
| type | true | string | `READ` or `WRITE`, overrides the read/write type defined by the plugin. Write calls are blocked for staging and preview apps when [write access]({{< ref "docs/applications/lifecycle/#write-mode-access" >}}) is disabled |
| secrets | true | list of lists | The [secrets]({{< ref "docs/configuration/secrets" >}}) the call is allowed to resolve, each entry a list of name patterns |
| permit | true | list of strings | Custom [RBAC permissions]({{< ref "docs/configuration/rbac" >}}), the call is allowed only if the user has any one of them |

Server config `[[permissions.allow]]` entries use the same fields and approve a call for all apps without an explicit approval; `[[permissions.disallow]]` entries block a call for all apps. See [default plugin permissions]({{< ref "docs/configuration/security/#default-plugin-permissions" >}}) for the defaults.

In the app handler code, do

```python {filename="app.star"}
ret = http.get(SERVICE_URL + "/api/challenge/" + challenge_id)
if not ret:
    return ace.response(ret.error, "invalid_challenge_id", code=404)
```

At runtime, OpenRun checks if the `get` call is authorized. If so, the call to the plugin is performed.

## Response Handling

All plugin API calls return a `plugin_response` structure with these fields:

| Field | Type | Notes |
| :--- | :--- | :--- |
| `error` | string | The error message, empty string if no error |
| `error_code` | int | The error code, zero if no error |
| `value` | any | The actual return value for the plugin API call. The datatype depends on the API, check the API documentation for details |
| `is_stream` | bool | True when the value is a stream (like `exec.run(stream=True)`) which has to be returned from the handler instead of being read in the handler code |

To check the error status of an API call:

- Check the boolean value of the return. If false, that indicates an error which can be returned.
- If no error, get the `value` property and continue with processing.

For example,

```python {filename="app.star"}
ret = http.get("https://localhost:9999/test")
if not ret:
    # error condition
    return ace.response(ret, "error_block")

# success
print(ret.value.json()) # ret.value is the return value. The http plugin response has a json() function
```

An alternate way to write the error check is

```python {filename="app.star"}
ret = http.get("https://localhost:9999/test")
if ret.error:
    # error condition
    return ace.response(ret, "error_block")

# Success
print(ret.value.json())
```

## Automatic Error Handling

OpenRun supports automatic error handling, so that handler functions do not have to check the error status of every plugin API call. If a handler does no explicit error handling for a call, automatic error handling kicks in; if explicit error handling is done, it is not. See [bookmarks app](https://github.com/openrundev/apps/blob/main/utils/bookmarks/app.star) for an example of how the automatic error handling can be used.

If the `error_handler` function is defined, the OpenRun platform calls it with the error when no manual error checking is done. The `error_handler` could be defined as:

```python {filename="app.star"}
def error_handler(req, ret):
    if req.IsPartial:
        return ace.response(ret, "error", retarget="#error_div", reswap="innerHTML")
    else:
        return ace.response(ret, "error.go.html")
```

When no explicit error checks are done, the automatic error handling happens in these three cases:

| Case | When the error is raised |
| :--- | :--- |
| [Value Access](#value-access) | When the response `value` is accessed |
| [Next API call](#next-api-call) | When the next plugin API call happens (to any plugin function) |
| [Handler Return](#handler-return) | When the handler function returns |

### Value Access

If the handler code is

```python {filename="app.star"}
ret = http.get("https://localhost:9999/test")
print(ret.value.json())
```

If the `get` API had succeeded, the `value` property access works as usual. If the `get` API had failed, the `value` access fails and the `error_handler` is called with the original request and the error response.

### Next API Call

If the `value` is not being accessed, then the next plugin call raises the error. For example, if the handler code is

```python {filename="app.star"}
store.begin()
bookmark = store.select_one(table.bookmark, {"url": url}).value
```

The response of the `begin` API is not checked. When the next `select_one` API is called, if the previous `begin` had failed, the `select_one` API raises the previous API call's error; the `select_one` does not run.

### Handler Return

If the handler code is

```python {filename="app.star"}
def insert(req):
    store.begin()
    book = doc.bookmark("abc", [])
    store.insert(table.bookmark, book)
    store.commit()
```

Assume all the API calls had succeeded and then the `commit` fails. Since the `value` is not accessed and there is no plugin API call after the `commit` call, the OpenRun platform raises the error after the handler completes.

### Overriding Automatic Error Handling

Automatic error handling is for the unusual error scenarios. For error scenarios which are common, like a database uniqueness check failure, handle the error explicitly in the handler code. Checking `ret.error` disables the automatic error handling for that call:

```python {filename="app.star"}
ret = store.insert(table.bookmark, new_bookmark)
if ret.error:
    return ace.response(ret, "error.go.html")
```

Checking the truth status of `ret` also disables the automatic error handling:

```python {filename="app.star"}
ret = store.insert(table.bookmark, new_bookmark)
if not ret:
    return ace.response(ret, "error.go.html")
```

{{<callout type="info" >}}
**Note:** When developing a new app, first define the `error_handler` and test it for the partial and full page scenarios. All subsequent handler code does not need to handle errors unless specific handling is required. If no `error_handler` is defined, a generic error message screen is returned. It is recommended to define a custom `error_handler`.
{{</callout>}}

## Returning Errors from Functions

For returning error values within Starlark code, a convenience `ace.output` struct is available. If you have a function in Starlark which can return success or an error, use `ace.output`.

The fields in the `ace.output` structure are:

| Property | Optional | Type | Default | Notes |
| :--- | :--- | :--- | :--- | :--- |
| value | true | any | | The return value |
| error | true | string | | The error message |

If a function `f1` returns an error value, using `return ace.output(error="mymessage")`, the caller will automatically fail when it tries to access the return value using `f1().value`. To do custom error handling, do

```
ret = f1()
if not ret:
    return "Call failed: " + ret.error
```

## Plugin Accounts

Some plugins like `exec.in` do not require any account information. Others like `store.in` need some account information. The account configuration for a plugin is loaded from the OpenRun config file `openrun.toml`. For example, the default configuration for `store.in` is [here](https://github.com/openrundev/openrun/blob/4fa05f6ea642ad8b4b7fdd55c1f96b13a72e64d8/internal/system/openrun.default.toml#L78), which contains:

```toml {filename="openrun.toml"}
[plugin."store.in"]
db_connection = "sqlite:$OPENRUN_HOME/metadata/clace_app_store.db"
```

Any application using the `store.in` plugin will by default use the `$OPENRUN_HOME/metadata/clace_app_store.db` sqlite database. To change the default account config used by apps, update `openrun.toml` and restart the OpenRun server. For example, adding the below overwrites the default `store.in` config for all apps.

```toml {filename="openrun.toml"}
[plugin."store.in"]
db_connection = "sqlite:/tmp/openrun_app.db"
```

String values in the plugin config can be [secret references]({{< ref "docs/configuration/secrets" >}}) like `{{secret_from "env" "STORE_DB_URL"}}`, which are resolved when the server starts.

### Account Linking

If specific account config is required for an app, the app can be linked to a specific account config.

{{% steps %}}

### Add the account config

Add a new account config in `openrun.toml`:

```toml {filename="openrun.toml"}
[plugin."store.in#tmpaccount"]
db_connection = "sqlite:/tmp/openrun_app.db"
```

### Link the app to the account

For an app `/myapp` using `store.in`, run `openrun account link --promote store.in tmpaccount /myapp`

This links the `myapp` app to use the `tmpaccount` account.

{{% /steps %}}

- The link is staged like other metadata changes, `--promote` applies it to the prod app.
- Use `-` as the account name to remove the link.
- Use `openrun account list /myapp` to list the links of an app.

### Named Account

In addition to using account linking, the plugin code itself can point to specific accounts. For example, if the app code has

```python {filename="app.star"}
load("http.in#google", googlehttp="http")
```

then the app will use the `http.in#google` account config by default. This also can be overridden using account links, by
running `openrun account link --promote http.in#google myaccount /myapp`

This approach is useful if an app has to access multiple accounts for the same plugin. The account linking approach is recommended for normal scenarios.

OpenRun apps aim to be portable across installations, without requiring code changes. Using account config allows the app code to be independent of the installation specific account config.
