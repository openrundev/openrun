---
title: "Templates"
weight: 500
summary: "HTML templates functions, static file handling and customizations"
---

OpenRun uses [Go HTML templates](https://pkg.go.dev/html/template@go1.21.2) for returning data to the client. See [template](https://pkg.go.dev/text/template@go1.21.2) for an overview of the template syntax. [Hugo docs](https://gohugo.io/templates/introduction/) are a good source for an overview of using go templates.

The [Sprig template library functions](http://masterminds.github.io/sprig/) are included automatically. Two functions from Sprig which are excluded for security considerations are `env` and `expandenv`.

Two extra functions `static` and `fileNonEmpty` are added for handling static file paths.

## static function

This function takes a file name and returns the url for a file in the static folder with a sha256 hash included in the file name. This approach is similar to the [hashfs library](https://github.com/benbjohnson/hashfs). If the `static` folder contains a file `file1` with the content `file1data`, then a call to `static "file"` will return `/test/static/file1-ca9e40772ef9119c13100a8258bc38a665a0a1976bf81c96e69a353b6605f5a7`, assuming the app is installed at `/test`.

The returned file name has a hash based on the file contents. The file server used by OpenRun will serve aggressive cache headers `Cache-Control: public, max-age=31536000` when this file is referenced by the browser. When the file contents change, the content hash will change and the file name will change. The files on disk are not renamed, only the filesystem used by the OpenRun server in memory sees the hashed file names.

This approach allows for a build-less system with aggressive static asset caching. The usual approach for this requires the static file to be renamed to have the hash value in the file name on disk. This require a build step to do the file renaming. The hashfs approach can avoid the build step. The file hash computation and compression are done once, during app installation in prod mode. There is no runtime penalty for this. In dev mode, the file hashing is done during the api serving.

## fileNonEmpty function

The fileNonEmpty function returns a bool, indicating whether a static file with that non-hashed name is present and is not empty. This can be used to conditionally include style files if present.

For example

<!-- prettier-ignore -->
```html
{{ if fileNonEmpty "css/style.css" }}
   <link rel="stylesheet" href="{{ static "css/style.css" }}" />
{{ end }}
```

<!-- prettier-ignore-end -->

checks if the "css/style.css" file is present and not empty. If so, it is linked using the `static` function, which returns a hashed file name which can be cached aggressively.

{{<callout type="warning" >}}
The path passed to `static` and `fileNonEmpty` functions should not include static, it is automatically added. So use `{{ static "css/style.css" }}`, not `{{ static "static/css/style.css" }}`
{{</callout>}}

## Template File Location

Templates are loaded once on app initialization. In dev mode, they are automatically reload on file updates. By default, the app source home directory is searched for template files. This can be changed by adding this directive in the `ace.app` config.

```json
settings={
    "routing": {"template_locations": ["*.go.html", "templates/*.go.html"]}
}
```

the default is `["*.go.html"]`. If additional directories are added, `"*.go.html"` still needs to present in the list since generated files are created in the app home directory. Also, all folders in the list need to contains at least one template file. File names have to be unique across folders. Files are referenced by their name, without the folder name, when used in template import directives.

## Structured Template Layout

The default in OpenRun is to load all the templates in one parse operation. This is easy to get started with but can result in challenges when the same template block needs to be duplicated in different files. OpenRun also supports a structured template layout. See [this blog](https://philipptanlak.com/web-frontends-in-go/#how-i-structure-my-templates) for an explanation about the differences between the two layouts. The default in OpenRun is the WordPress layout, all template files are loaded in one go. To use the second, Django layout, use the structured format.

If there is a `base_templates` folder in the app main folder with one or more `*.go.html` files, the structured template layout is used. In the structured layout format, all the base template files are loaded in one parse operation. Each of the files in the app main folder is then individually loaded. Each top level file has access to its own template blocks plus the base templates.

This has the advantage that the main templates can have duplicate templates, with no conflicts because they are loaded individually. For example, if there is a `base_templates/base.go.html` file with

```html
<html>
  <head></head>
  {{block "body" .}} {{end}}
  <footer></footer>
</html>
{{end}}
```

and a `index.go.html` file with

```html
{{define "body"}} My Index Body {{end}} {{- template "full" . -}}
```

and a `help.go.html` file with

```html
{{define "body"}} My Help Body {{end}} {{- template "full" . -}}
```

then a route using `index.go.html` will get the HTML for the index page and route using `help.go.html` with get HTML help page. Although the `body` is defined in two template files, there is no conflict since the root level template files are loaded independently.

Without structured template layout, if a duplicate block is found, the one to be used depends on the order in which the files are loaded. To change the folders used for base templates, set:

```json
settings={
    "routing": {"base_templates": ["base_templates", "template_helpers"]}
}
```

## App Layout

When using custom layout with `custom_layout=True`, the app developer has to create the `index.go.html` file. Add a directive like:

```html
{{ template "openrun_gen_import" . }}
```

in the head section to ensure that the auto generated `openrun_gen_import` directives are loaded in the . This will include the style files, HTMX library and the live reload functionality in dev mode.

In the default layout mode, the auto generated `index_gen.go.html` file is used. The app developer has to provide a `openrun_body` block. It can be in any template file, the convention is to use `app.go.html`. For example:

<!-- prettier-ignore -->
```html
{{block "openrun_body" .}}
   Data is {{.Data}}
{{end}}
```

<!-- prettier-ignore-end -->

The `.Data` binding has the data as returned by the handler function for the route.

shared across both apps.

## Static Root Files

The `static` folder is used for file which are served under the `/static` path. Content based hashing is supported for these files.

For files which need to be served under the root level, the `static_root` folder is used. Files in this folder are served at the root path. For example, if an app is installed at `example.com:` and a robots.txt file needs to be served, a file `static_root/robots.txt` can be added to the app. This will be automatically served at `example.com/robots.txt`. Note that the static folder path is stripped from the route name. The file name should not conflict with any of the API routes defined in the app. Nested folders are looked up in the static root folder.

Content based hashing is not supported for static root files. These files are expected to be used for well known files like `favicon.ico`. Most regular static file serving use cases should use the `static` folder, not the `static_root` folder.
