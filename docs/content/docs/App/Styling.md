---
title: "Styling"
weight: 600
summary: "CSS Styling, TailwindCSS, DaisyUI"
---

OpenRun supports working with Classless CSS libraries and also with TailwindCSS and DaisyUI. To use this, add the directive

```python {filename="app.star"}
    style=ace.style("daisyui")
```

in the app definition. The fields in the `ace.style` structure are:

|    Property     | Optional |   Type   | Default |                                  Notes                                   |
| :-------------: | :------: | :------: | :-----: | :----------------------------------------------------------------------: |
|     library     |  false   |  string  |         | The library to use, url to classless library, "tailwindcss" or "daisyui" |
|     themes      |   true   | string[] |   []    |                      The daisyui themes to include                       |
| disable_watcher |   true   |   bool   |  false  |   Whether to disable the tailwind watcher process startup in dev mode    |
|      light      |   true   |  string  | emerald |            The DaisyUI theme to use in light mode for Actions            |
|      dark       |   true   |  string  |  night  |            The DaisyUI theme to use in dark mode for Actions             |

## Classless CSS

If the library property is a url, it should point to a publicly accessible style file. The style file is downloaded into the `static/gen/css/style.css` file. The file is automatically included as part of the `openrun_gen_import` template.

For example,

```python {filename="app.star"}
    style=ace.style("https://unpkg.com/mvp.css@1.14.0/mvp.css"),
```

imports the [MVP.css](https://andybrewer.github.io/mvp/) library. Since this is classless, no changes are required in the HTML templates.

## TailwindCSS

To use TailwindCSS, in app settings, add

```python {filename="app.star"}
    style=ace.style("tailwindcss")
```

Tailwind CSS works by scanning the HTML files for class names, generating the corresponding styles and then writing them to a static CSS file. A watcher process is started when an app using Tailwind is loaded in dev mode. The output of the watcher is written to `static/gen/css/style.css` file. This file is automatically included as part of the `openrun_gen_import` template.

To ensure that the tailwind watcher is started, the tailwind CLI needs to be installed manually. The [standalone CLI](https://tailwindcss.com/blog/standalone-cli) can be used. If using DaisyUI, use this [custom build](https://github.com/dobicinaitis/tailwind-cli-extra) of the standalone CLI with DaisyUI included.

The OpenRun server config file has the following entries:

```toml {filename="openrun.toml"}
[system]
tailwindcss_command = "npx tailwindcss"
file_watcher_debounce_millis = 300
```

`tailwindcss_command` is the command use to start the watcher. If the standalone version is being used change to

```toml {filename="openrun.toml"}
[system]
tailwindcss_command = "/path/to/tailwindcss"
```

`file_watcher_debounce_millis` is used to prevent repeated reloads of the application files during dev mode. On slower machine, this value might have to be increased, but setting it too high will cause the reload to be slower.

## DaisyUI

To use [DaisyUI](https://daisyui.com/), in app settings, add

```python {filename="app.star"}
    style=ace.style("daisyui", themes=["dark"])
```

Change to the preferred [theme](https://daisyui.com/docs/themes/). DaisyUI is a good option to use to get great default styling for components, with the full flexibility of Tailwind. To use DaisyUI, use the npm version of Tailwind or use this [custom version](https://github.com/dobicinaitis/tailwind-cli-extra) of the standalone CLI with DaisyUI included. OpenRun takes care of creating the config files. Using the CDN version of DaisyUI or Tailwind is not recommended since that will cause the style files to be large.

If using [Actions]({{< ref "/docs/actions/" >}}), DaisyUI styles are automatically included. The themes can be customized using the `light` and `dark` property.
