---
title: "JavaScript"
weight: 700
summary: "JavaScript dependency handling, esbuild config"
---

OpenRun supports importing JavaScript libraries as [JavaScript Modules](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules). To use this feature, add

```python {filename="app.star"}
    libraries=[ace.library("d3", "7.8.5")]
```

in the app definition. The fields in the `ace.library` structure are:

| Property | Optional |   Type   | Default |               Notes               |
| :------: | :------: | :------: | :-----: | :-------------------------------: |
|   name   |  false   |  string  |         | The name of the library to import |
| version  |  false   |  string  |         |    The version of the library     |
|   args   |   true   | string[] |   []    |   Arguments to pass to esbuild    |

The args array uses the [esbuild cli syntax](https://pkg.go.dev/github.com/evanw/esbuild/pkg/cli). For example, passing args as `["--minify"]` will enable minification for the imported module.

To directly download a library from a CDN to the static folder, add the URL directly. For example,

```python {filename="app.star"}
    libraries=["https://unpkg.com/jquery@3.3.1/dist/jquery.min.js"]
```

The HTMX library and its SSE extension are automatically downloaded.

## JavaScript Modules

JavaScript modules (also called ESM or ECMAScript Modules) are a way to import JavaScript libraries dynamically, providing a unique namespace for all functions. Modules, once imported, can be used in the client code without requiring any build steps. See [jvns.ca](https://jvns.ca/blog/2023/02/16/writing-javascript-without-a-build-system/) and [simonwillison.net](https://simonwillison.net/2023/May/2/download-esm/) for notes about this approach. OpenRun tries to provide an easy interface to modules, converting npm packages to module format so that subsequent code changes do not require any build steps.

## Workflow

The workflow when using modules in OpenRun for an app in dev mode is:

- Ensure [Node.js](https://nodejs.org/en/download) is installed
- Using npm, install the package you want to use as a module. For example, `npm install d3`
- Add the ace.library entry in the app config. OpenRun will automatically run esbuild and import the package as a module into `static/gen/esm`
- Add an importmap in the head section of the html. Like [here](https://github.com/openrundev/openrun/blob/8b7f0d7d0c692e0ca3c6a74e97d1913031b954a1/examples/memory_usage/index.go.html#L10).
  ```html
  <script type="importmap">
    {
      "imports": {
          "d3": "{{ static "gen/esm/d3-7.8.5.js"}}"
      }
    }
  </script>
  ```
- Use the library as required in your client. Like [here](https://github.com/openrundev/openrun/blob/8b7f0d7d0c692e0ca3c6a74e97d1913031b954a1/examples/memory_usage/static/js/app.js#L4)

```javascript
import * as d3 from "d3";
```

Creating the module is a one-time step. The generated module can be checked into source code. On a new machine, to make code changes to the app, you do not need Node.js or npm to be installed.

For production deployment, no changes are required. Check out the git repo containing the source code and create an OpenRun app. OpenRun will serve the static assets over HTTP/2 with content-hash-based caching. The assets are compressed for serving, there is usually no need for minifying the modules.

## Esbuild Config

OpenRun includes esbuild, there is no need to install esbuild manually. The OpenRun server config has the entry

```toml {filename="openrun.toml"}
[system]
node_path = ""
```

The node_path property is used by esbuild, these paths are searched for packages in addition to the node_modules directories in all parent directories. See [esbuild docs](https://esbuild.github.io/api/#node-paths) for details. Paths should be separated with : on Unix and ; on Windows.

If you install the npm packages in your home directory, esbuild will pick up those without any additional configuration. Since each OpenRun project is importing the npm package as a module, you do not need to maintain separate node_modules for each OpenRun project.

If you do not want esbuild to create modules, set the node_path property in the server config to `disable`. You will have to manually download the module file into the static folder.

## Notes

- The version number specified in the `ace.library` is used to create the file name under `static/gen/esm`. The actual package version depends on what was installed using npm. Ensure that the same version is installed by npm as specified in the library config.
- Only the `minify` option for esbuild has been tested with OpenRun. Other options like chunking the files might not work currently.
- The JavaScript support is for running JS in the browser. There is no support for running JavaScript on the OpenRun server, the server runs only Go code and Starlark applications.
- If a library URL is specified, that is downloaded directly. There is no need for an npm package in that case.
