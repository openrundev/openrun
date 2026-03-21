---
title: "Plugin Catalog"
weight: 200
summary: "Catalog of OpenRun Plugins"
---

The page lists the available plugins and their API details.

## Database Storage

The `store.in` plugin supports a document store interface for writing data to SQLite. See [store]({{< ref "store" >}}) for details.

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

- **url** (string, required) : the url to send the request to
- **params** (dict, optional) : url params to send
- **headers** (dict, optional) : HTTP headers to send
- **body** (string, optional) : body to send
- **form_body** (dict, optional) : form body to send
- **form_encoding** (string, optional) : the form encoding to use, `application/x-www-form-urlencoded` (default) or `multipart/form-data`
- **json_body** (object, optional) : the object to send as json encoded body
- **auth_basic** (tuple(string, string), optional): HTTP basic auth username and password
- **auth_signature** (string, optional): Signature auth type
- **error_on_fail** (bool, optional): Whether to fail on non-2xx status code, default true

The response for all APIs (`value` within `plugin_response`) contains the following properties:

- **url** (string): the url the response is for
- **status_code** (int): the HTTP status code
- **headers** (dict): the output headers
- **encoding** (string): the transfer encoding header
- **body()** (string) : the response body as a string
- **json()** (object) : the response body un-marshalled as a json

If the API calls fails to go through then the plugin response `error` property will be set. If the API returns non 2xx status code, error is set (unless `error_on_fail` is False). The `status_code` will indicate whether the API succeeded on the server. To make an API call and parse the response as JSON, do

```python {filename="app.star"}
ret = http.get("http://localhost:9999/test").value.json()
```

## Exec Plugin

### run

The `exec.in` plugin allows running external commands, starting a new process for the specified command. The APIs available are:

|   API   |    Type    |               Notes               |
| :-----: | :--------: | :-------------------------------: |
| **run** | Read/Write | Runs the command as a new process |

The API supports the following parameters:

- **path** (string, required) : the command to run
- **args** (list of strings, optional) : arguments to pass to the cmd
- **env** (list of strings, optional) : the env to pass to the cmd, in the form `key=value`
- **process_partial** (bool, optional) : whether to process the output when there is a failure
- **stdout_file** (bool, optional) : whether to send the stdout for the process to a temporary file on disk
- **parse** (string, optional) : Whether to parse the stdout. Supported options are `json` and `jsonlines`

The default response (when `stdout_file` is `False`) for the `exec` API (`value` within `plugin_response`) is of type list of strings. The stdout is scanned and split on newlines. The list of lines is returned. For example

```python {filename="app.star"}
   ret = exec.run("ls", ["-l", "/"], process_partial=True).value
   for line in ret:
       # Process lines
```

{{<callout type="warning" >}}
**Note:** Only first 100MB of the command stdout output is scanned currently, the rest is discarded.
{{</callout>}}

If `stdout_file` is `True`, then the plugin output `value` is the name for the temp file to which the output was written. There is no size limit on this file output. The user is responsible for deleting this file.

## FS Plugin

The `fs.in` allows working with local file system. The APIs available are

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

The response for the API is a list of type `FileInfo`. The `FileInfo` struct contains the fields:

- **name** (string) : the file name
- **size** (int) : the file size in bytes, rounded up to 4K
- **is_dir** (bool) : is it a directory
- **mode** (int) : file mode info

### find

The `find` API supports the following parameters:

- **path** (string, required) : the directory path
- **name** (string, optional) : the file name glob pattern to match
- **limit** (int, optional, default 10K, max 100K) : the limit on number of entries to return
- **min_size** (int, optional) : the minimum file size in bytes to look for
- **ignore_errors** (bool, optional, default false) : whether to ignore errors when accessing entries

The response for the `find` API is a list of type `FileInfo`, same as returned by `list`.

### serve_tmp_file

The `serve_tmp_file` API supports the following parameters:

- **path** (string, required) : the file path to serve
- **name** (string, optional, default basename of path) : the file name to use (when serving the API)
- **visibility** (string, optional, default `fs.USER`) : the API access level for the file (`fs.USER` or `fs.APP`)
- **mime_type** (string, optional, default `application/octet-stream`) : the mime type to use when serving the file
- **expiry_minutes** (int, optional, default 60 minutes) : how long to keep the file metadata, set to zero for no deletion
- **single_access** (bool, optional, default `True`) : whether to serve the file just once and then automatically delete it

The response for the `serve_tmp_file` API is a dict with the fields:

- **id** (string) : the id of the metadata entry
- **url** (string) : the url path (without domain) for downloading the file
- **name** (string) : the file name

The `serve_tmp_file` API creates a metadata entry in the OpenRun database. The file can be served through an API using this entry. The default behavior is the file is accessible only to the user who created it. First download of the file will serve the file and automatically deletes the file. The file is deleted after 60 minutes in case there is no API access before that. Deleting the metadata entry removes the database entry and **also deletes the file from disk**. If the file should not be deleted, do:

`ret = fs.serve_tmp_file("/tmp/myfile", single_access=False, expiry_minutes=0)`

See number_lines app [code](https://github.com/openrundev/apps/blob/main/misc/num_lines/app.star):[demo](https://utils.demo.clace.io/num_lines) for an example of using this API. Setting `visibility` to `fs.APP` will make the API available to anyone who has access to the app.
