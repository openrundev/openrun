---
title: "Plugin Catalog"
weight: 200
summary: "Catalog of OpenRun Plugins"
---

The page lists the available plugins and their API details.

## Database Storage

The `store.in` plugin supports a document store interface for writing data to SQLite or PostgreSQL. See [store]({{< ref "store" >}}) for details.

## Container Config

The `container.in` plugin supports configuring for using a container for deploying backend APIs. See [container]({{< ref "container" >}}) for details.

## Proxy Config

The `proxy.in` plugin supports proxying API calls to deploying backend APIs. See [proxy]({{< ref "proxy" >}}) for details.

## HTTP Plugin

### get,head,options,post,put,delete,patch

The `http.in` plugin supports making HTTP API calls. The APIs available are:

|     API     | Type  |        Notes         |
| :---------: | :---: | :------------------: |
|   **get**   | Read  |   HTTP Get request   |
|  **head**   | Read  |  HTTP Head request   |
| **options** | Read  | HTTP Options request |
|  **post**   | Write |  HTTP Post request   |
|   **put**   | Write |   HTTP Put request   |
| **delete**  | Write | HTTP Delete request  |
|  **patch**  | Write |  HTTP Patch request  |

All the APIs support the following parameters:

- **url** (string, required) : the url to send the request to. A url starting with `container.URL` (from the `container.in` plugin) is sent to the app's own container, like `http.get(container.URL + "/api/items")`; the default server config allows these calls without an explicit permission
- **params** (dict, optional) : url params to send, string values
- **headers** (dict, optional) : HTTP headers to send, string values
- **body** (string, optional) : body to send
- **form_body** (dict, optional) : form body to send
- **form_encoding** (string, optional) : the form encoding to use, `application/x-www-form-urlencoded` (default) or `multipart/form-data`
- **json_body** (object, optional) : the object to send as json encoded body
- **auth_basic** (tuple(string, string), optional): HTTP basic auth username and password
- **auth_signature** (dict, optional): signature based auth. The dict keys are `type` (only `SL` is supported), `user` (the key id) and `api_key`; a signed `Authorization` header (and a `date` header if not already set) is added to the request
- **error_on_fail** (bool, optional): Whether to fail on non-2xx status code, default true
- **timeout** (int, optional): Request timeout in seconds, default 300

The response for all APIs (`value` within `plugin_response`) contains the following properties:

- **url** (string): the url the response is for
- **status_code** (int): the HTTP status code
- **headers** (dict): the output headers, multiple values for a header are joined with `,`
- **encoding** (string): the transfer encoding header
- **body()** (string) : the response body as a string
- **json()** (object) : the response body un-marshalled as a json

If the API calls fails to go through then the plugin response `error` property will be set. If the API returns non 2xx status code (1xx and 3xx included), error is set (unless `error_on_fail` is False). The `status_code` will indicate whether the API succeeded on the server. The response body is read only when `body()` or `json()` is called, an unread body is closed at the end of the request. To make an API call and parse the response as JSON, do

```python {filename="app.star"}
ret = http.get("http://localhost:9999/test").value.json()
```

## Exec Plugin

### run

The `exec.in` plugin allows running external commands, starting a new process for the specified command. The command runs on the server host as the server user, so two approvals apply: the app's `exec.in` permission for the command, and the server's `security.allowed_exec_commands` allowlist of executables (empty by default), which is matched on the resolved file. The OpenRun binary itself cannot be run. See [host commands]({{< ref "docs/configuration/security/#host-commands-exec-plugin" >}}). The APIs available are:

|   API   |    Type    |               Notes               |
| :-----: | :--------: | :-------------------------------: |
| **run** | Read/Write | Runs the command as a new process |

The API supports the following parameters:

- **path** (string, required) : the command to run
- **args** (list of strings, optional) : arguments to pass to the cmd
- **env** (list of strings, optional) : the env to pass to the cmd, in the form `key=value`. The command gets exactly these variables, never the server's environment. Each name must be in the server's `security.allowed_exec_env` list (empty by default), or the call is refused
- **process_partial** (bool, optional) : whether to process the output when there is a failure
- **stdout_file** (bool, optional) : whether to send the stdout for the process to a temporary file on disk. Not supported with `stream`
- **parse** (string, optional) : Whether to parse the stdout. Supported options are `json` (the whole output is one JSON object, returned as a list with that one dict) and `jsonlines` (each output line is a JSON object, returned as a list of dicts)
- **stream** (bool, optional) : return the output as a stream which is read as the response is generated, instead of buffering the full output. The output is delivered in chunks of complete lines as the command produces it (lines of any length), and a non-zero exit ends the stream with an error after the output. Return the response from a route handler to stream it as the HTTP response, or from an action handler in `ace.result(stream=...)` to show it live in the action UI (see [streaming output]({{< ref "docs/actions/#streaming-output" >}})). Not supported with `parse="json"`
- **include_stderr** (bool, optional, default True) : whether to include the stderr output in the command output. If False, stderr is reported only in the error message when the command fails
- **cwd** (string, optional) : the working directory to run the command in

The default response (when `stdout_file` is `False`) for the `exec` API (`value` within `plugin_response`) is of type list of strings. The stdout is scanned and split on newlines. The list of lines is returned. For example

```python {filename="app.star"}
ret = exec.run("ls", ["-l", "/"], process_partial=True).value
for line in ret:
    print(line)
```

{{<callout type="warning" >}}
**Note:** Only first 100MB of the command stdout output is scanned currently, the rest is discarded.
{{</callout>}}

If `stdout_file` is `True`, then the plugin output `value` is the name for the temp file to which the output was written. There is no size limit on this file output. The user is responsible for deleting this file.

## FS Plugin

The `fs.in` allows working with local file system. The metadata for `serve_tmp_file` is saved in the database configured in the `[plugin."fs.in"]` section of `openrun.toml` (`db_connection`, by default `sqlite:$OPENRUN_HOME/metadata/clace_fs.db`). The APIs available are

|        API         | Type |                                   Notes                                   |
| :----------------: | :--: | :-----------------------------------------------------------------------: |
|      **abs**       | Read |             Returns the absolute path for given relative path             |
|      **list**      | Read |                     List files in specified directory                     |
|      **find**      | Read |          Find files under specified directory matching criteria           |
| **serve_tmp_file** | Read | Load file metadata to the OpenRun database and make available through API |

### abs

The `abs` API supports the following parameter:

- **path** (string, required) : the file path

The response for the API (`value` within `plugin_response`) is of type string, the absolute path for given path.

### list

The `list` API supports the following parameters:

- **path** (string, required) : the directory path
- **recursive_size** (bool, optional, default false) : whether to include the recursive size of sub-directories
- **ignore_errors** (bool, optional, default false) : whether to ignore errors when accessing entries

The response for the API is a list of type `FileInfo`, one entry per directory entry plus a final entry for the directory itself (`path` as the name, `is_dir` true) whose size is the total size of the listed entries. The `FileInfo` struct contains the fields:

- **name** (string) : the file path, the directory path joined with the entry name
- **size** (int) : the file size in bytes, rounded up to 4K. For directories, the recursive size when `recursive_size` is set
- **is_dir** (bool) : is it a directory
- **mode** (int) : file mode info

### find

The `find` API supports the following parameters:

- **path** (string, required) : the directory path
- **name** (string, optional) : the file name glob pattern to match
- **limit** (int, optional, default 10K, max 100K) : the limit on number of entries to return
- **min_size** (int, optional) : the minimum file size in bytes to look for
- **ignore_errors** (bool, optional, default false) : whether to ignore errors when accessing entries

The response for the `find` API is a list of type `FileInfo`, same as returned by `list` (files only, no entry is added for the directory itself). Sub-directories are searched recursively. When more than `limit` files match, the largest files are kept.

### serve_tmp_file

The `serve_tmp_file` API supports the following parameters:

- **path** (string, required) : the file path to serve
- **name** (string, optional, default basename of path) : the file name to use (when serving the API)
- **visibility** (string, optional, default `fs.USER`) : the API access level for the file: `fs.USER` serves it to the user who registered it only (anyone, for an app without authentication), `fs.APP` to anyone who has access to the app. The file is served by the app that registered it
- **mime_type** (string, optional, default `application/octet-stream`) : the mime type to use when serving the file
- **expiry_minutes** (int, optional, default 60 minutes) : how long to keep the file metadata, set to zero for no deletion
- **single_access** (bool, optional, default `True`) : whether to serve the file just once and then automatically delete it

The response for the `serve_tmp_file` API is a dict with the fields:

- **id** (string) : the id of the metadata entry
- **url** (string) : the url path (without domain) for downloading the file
- **name** (string) : the file name

The `serve_tmp_file` API creates a metadata entry in the OpenRun database. The file has to be under one of the directories listed in the `fs.file_access` [app config]({{< ref "docs/actions/#file-handling" >}}) setting, by default `["$TEMPDIR", "/tmp"]`, otherwise the call fails with a `file access denied` error. The file can be served through an API using this entry, the download `url` returned has the form `<app_path>/_openrun_app/file/<id>`. The default behavior is the file is accessible only to the user who created it. First download of the file will serve the file and automatically deletes the file. The file is deleted after 60 minutes in case there is no API access before that. Deleting the metadata entry removes the database entry and **also deletes the file from disk**. If the file should not be deleted, do:

`ret = fs.serve_tmp_file("/tmp/myfile", single_access=False, expiry_minutes=0)`

See number_lines app [code](https://github.com/openrundev/apps/blob/main/misc/num_lines/app.star):[demo](https://utils.demo.clace.io/num_lines) for an example of using this API. Setting `visibility` to `fs.APP` will make the API available to anyone who has access to the app.

## System Plugins

Three plugins expose the OpenRun management APIs to apps, for use by the management console and by apps automating server operations. Their functions mirror the `openrun` CLI commands and the management REST API, with the same arguments (see the `openrun <command> --help` output for the semantics), and are subject to the caller's [RBAC]({{< ref "docs/configuration/rbac" >}}) permissions. `openrun_admin.in` and `build.in` require an authenticated (non-anonymous) caller, see [system plugin access]({{< ref "docs/configuration/security/#system-plugin-access" >}}).

- **openrun.in** : read-only server information. `list_apps`, `list_all_apps`, `get_app`, `audit_app`, `list_specs`, `list_versions`, `list_version_files`, `get_version_file`, `get_version_zip`, `export_app`, `export_app_diff`, `get_permissions`, `list_audit_events`, `list_operations`, `analytics_summary`, `list_sync`, `list_jobs`, `list_job_runs`, `job_logs`, `list_actions`, `get_action`, `list_action_runs`, `get_action_run`, `list_bindings`, `binding_health`, `list_services`, `service_health`, `replication_status`, `list_containers`, `get_container`, `container_logs`, `container_logs_stream`, `container_kubernetes_status`, `kubernetes_stats`, `get_rbac_config`, `list_rbac_permissions`, `list_api_operations`, `get_config_entries`, `get_config_values`, `list_config_history`, `get_config_version`, `list_auths`, `list_git_auths`, `server_info` and `system_plugins_allowed`.
- **openrun_admin.in** : management operations. Apps: `create_app`, `delete_apps`, `reload_apps`, `approve_apps`, `promote_apps`, `switch_version`, `update_params`, `update_auth`, `update_bindings`, `update_mcp`. Sync and jobs: `create_sync`, `run_sync`, `delete_sync`, `run_job`, `cancel_job`, `cancel_action_run`. RBAC: `set_rbac_group`, `delete_rbac_group`, `set_rbac_role`, `delete_rbac_role`, `add_rbac_grant`, `update_rbac_grant`, `delete_rbac_grant`, `publish_rbac_config`, `discard_rbac_draft`. Config: `set_config_entry`, `delete_config_entry`, `set_config_value`, `delete_config_value`, `restore_config`. Services, bindings and containers: `create_service`, `delete_service`, `create_binding`, `update_binding`, `delete_binding`, `start_container`, `stop_container`. Secrets: `create_secret`, `delete_secret`, `list_secrets`, `get_secret`, `rekey_secrets` and `secret_reveal` (see [revealing secrets]({{< ref "docs/configuration/secrets/#revealing-secrets-to-html-templates" >}})). Most write functions accept `dry_run=True` and, for staged changes, `promote` (default True).
- **build.in** : the [AI app builder]({{< ref "docs/appbuilder" >}}) sessions. `list_sessions`, `get_session`, `get_messages`, `session_events`, `list_files`, `read_file`, `get_source_zip`, `get_publish_config`, `list_activity`, `create_session`, `send_message`, `cancel_turn`, `stop_session`, `resume_session`, `delete_session`, `check_publish_path`, `publish_app`, `unpublish_app` and `verify_config`.
