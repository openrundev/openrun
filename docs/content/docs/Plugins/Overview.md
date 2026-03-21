---
title: "Plugin Overview"
weight: 100
summary: "Overview of how plugins work, how to use them"
---

Plugins provide an API for OpenRun Starlark code to call out to external systems. Plugins are implemented in Go. Every plugin API calls needs to be in the approved list for it to be permitted. See [security]({{< ref "appsecurity#sample-application" >}}/) for an overview of the security model.

Each plugin is identified by a unique name, like `store.in` or `exec.in`. Plugins ending with `.in` are internal plugins, built into the OpenRun binary. Support for external plugins which are loaded dynamically is planned.

## Plugin Usage

To use a plugin, load it using

```python {filename="app.star"}
load("http.in", "http")
```

This adds `http` to the namespace for the app. To make a call to the plugin, first add the permissions to the app config.

```python {filename="app.star"}
    permissions=[
        ace.permission("http.in", "get"),
        ace.permission("http.in", "post")
    ],
```

Run `openrun app approve /myapp` to authorize the app to call the `get` and `post` methods on the http plugin.

In the app handler code, do

```python {filename="app.star"}
    ret = http.get(SERVICE_URL + "/api/challenge/" + challenge_id)
    if not ret:
        return ace.response(ret.error, "invalid_challenge_id", code=404)
```

At runtime, OpenRun will check if the `get` call is authorized. If so, the call to the plugin will be performed.

## Response Handling

All plugin API calls return a `plugin_response` structure. The fields in this are

- `error` The error message string, empty string if no error
- `error_code` The error code integer, zero if no error
- `value` The actual return value for the plugin API call. The datatype for this depends on the API, check the API documentation for details.

To check the error status of an API call:

- Check boolean value for the return. If false, that indicates an error which can be returned.
- If no error, get the `value` property and continue with processing

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

OpenRun supports automatic error handling, so that the handler functions do not have to check the error status of every plugin API call. The way this is implemented is such that if no explicit error handling is done, then the automatic error handling kicks in. If explicit error handling is done, then automatic error handling is not done. See [bookmarks app](https://github.com/openrundev/apps/blob/main/utils/bookmarks/app.star) for an example of how the automatic error handling can be used.

If the `error_handler` function is defined, then that is called with the error. The manual error checking works the same as mentioned above. But if no manual error checking is done, then the OpenRun platform will automatically call the `error_handler` function in case of an error. The `error_handler` could be defined as:

```python {filename="app.star"}
def error_handler(req, ret):
    if req.IsPartial:
        return ace.response(ret, "error", retarget="#error_div", reswap="innerHTML")
    else:
        return ace.response(ret, "error.go.html")
```

When no explicit error checks are done, the automatic error handling happens in these three cases:

- **Value Access** When the response `value` is accessed
- **Next API call** When the next plugin API call happens (to any plugin function)
- **Handler Return** When the handler function returns

### Value Access

If the handler code is

```python {filename="app.star"}
    ret = http.get("https://localhost:9999/test")
    print(ret.value.json())
```

If the `get` API had succeeded, then the `value` property access will work as usual. But if the `get` API had failed, then the `value` access will fail and the `error_handler` will be called with the original request and the error response.

### Next API Call

If the `value` is not being accessed, then the next plugin call will raise the error. For example, if the handler code is

```python {filename="app.star"}
    store.begin()
    bookmark = store.select_one(table.bookmark, {"url": url}).value
```

The response of the `begin` API is not checked. When the next `select_one` API is called, if the previous `begin` had failed, the `select_one` API will raise the previous API call's error, the `select_one` will not run.

### Handler Return

If the handler code is

```python {filename="app.star"}
    def insert(req):
        store.begin()
        book = doc.bookmark("abc", [])
        store.insert(table.bookmark, book)
        store.commit()
```

Assume all the API calls had succeeded and then the `commit` fails. Since the `value` is not accessed and there is no plugin API call after the `commit` call, the OpenRun platform will raise the error after the handler completes since the `commit` had failed.

### Overriding Automatic Error Handling

The automatic error handling is great for handling the unusual error scenarios. For the error scenarios which are common, like a database uniqueness check failure, the error handing can be done explicitly in the handler code. If the handler code is

```python {filename="app.star"}
ret = store.insert(table.bookmark, new_bookmark)
if ret.error:
    return ace.response(ret, "error.go.html")
```

The automatic error handling will not be invoked in this case since the `ret.error` is being checked. Checking the truth status of `ret` also will disable the automatic error handling:

```python {filename="app.star"}
ret = store.insert(table.bookmark, new_bookmark)
if not ret:
    return ace.response(ret, "error.go.html")
```

{{<callout type="info" >}}
**Note:** When developing a new app, first define the `error_handler` and test it for the partial and full page scenarios. All subsequent handler code does not need to handle errors unless specific handling is required. If no `error_handler` is defined, a generic error message screen is returned. If is recommended to define a custom `error_handler`.
{{</callout>}}

## Returning Errors from Functions

For returning error values within Starlark code, a convenience `ace.output` struct is available. If you have a function in Starlark which can return success or an error, use `ace.output`.

The fields in the `ace.output` structure are:

| Property | Optional |  Type  | Default |       Notes       |
| :------: | :------: | :----: | :-----: | :---------------: |
|  value   |   true   |  any   |         | The return value  |
|  error   |   true   | string |         | The error message |

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
db_connection = "sqlite:$OPENRUN_HOME/clace_app_store.db"
```

Any application using the `store.in` plugin will by default use the `$OPENRUN_HOME/openrun_app.db` sqlite database. To change the default account config used by apps, update `openrun.toml` and restart the OpenRun server. For example, adding the below will overwrite the default `store.in` config for all apps.

```toml {filename="openrun.toml"}
[plugin."store.in"]
db_connection = "sqlite:/tmp/openrun_app.db"
```

### Account Linking

If specific account config is required for an app, then the app can be linked to a specific account config. First add a new account config by adding in `openrun.toml`

```toml {filename="openrun.toml"}
[plugin."store.in#tmpaccount"]
db_connection = "sqlite:/tmp/openrun_app.db"
```

For an app `/myapp` using `store.in`, run `openrun account link --promote /myapp store.in tmpaccount`

This links the `myapp` app to use the `tmpaccount` account.

### Named Account

In addition to using account linking, the plugin code itself can point to specific accounts. For example, if the app code has

```python {filename="app.star"}
load("http.in#google", "googlehttp")
```

then the app will use the `http.in#google` account config by default. This also can be overridden using account links, by
running `openrun account link --promote /myapp http.in#google myaccount`

This approach is useful if an app has to access multiple accounts for the same plugin. The account linking approach is recommended for normal scenarios.

OpenRun apps aim to be portable across installations, without requiring code changes. Using account config allows the app code to be independent of the installation specific account config.
