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

To ensure that the tailwind watcher is started, the tailwind CLI needs to be installed manually. The [standalone CLI](https://tailwindcss.com/blog/standalone-cli) is the easiest option: no npm or node_modules setup is required. The npm packages (`npm install -D tailwindcss @tailwindcss/cli daisyui`, with `npx tailwindcss` as the command) also work.

The OpenRun server config file has the following entries:

```toml {filename="openrun.toml"}
[system]
tailwindcss_command = "npx tailwindcss"
tailwind_version = 4
file_watcher_debounce_millis = 300
```

`tailwindcss_command` is the command use to start the watcher. If the standalone version is being used change to

```toml {filename="openrun.toml"}
[system]
tailwindcss_command = "/path/to/tailwindcss"
```

`tailwind_version` controls the generated config format. The default is `4`, which generates Tailwind 4/daisyUI 5 CSS-first config in `style/input.css`. Set it to `3` to use the legacy Tailwind 3/daisyUI 4 `tailwind.config.js` config format. Values below `3` are rejected.

`file_watcher_debounce_millis` is used to prevent repeated reloads of the application files during dev mode. On slower machine, this value might have to be increased, but setting it too high will cause the reload to be slower.

## DaisyUI

To use [DaisyUI](https://daisyui.com/), in app settings, add

```python {filename="app.star"}
    style=ace.style("daisyui", themes=["dark"])
```

Change to the preferred [theme](https://daisyui.com/docs/themes/). DaisyUI is a good option to use to get great default styling for components, with the full flexibility of Tailwind. OpenRun takes care of creating the config files. With `tailwind_version = 4`, OpenRun writes the daisyUI plugin and theme list into `style/input.css` using the daisyUI 5 `@plugin` syntax. Using the CDN version of DaisyUI or Tailwind is not recommended since that will cause the style files to be large.

The standalone tailwind CLI does not bundle daisyUI. Since a `tailwindcss_command` is configured, OpenRun automatically downloads the prebundled daisyUI plugin (a single `daisyui.js` file, no node_modules required) into the app's work directory and references it from the generated `style/input.css`. The download happens once and is cached across server restarts. The download location can be overridden (for example to an internal mirror) with:

```toml {filename="openrun.toml"}
[system]
daisyui_url = "https://internal.example.com/daisyui.js"
```

If the download fails (for example, no network access), OpenRun falls back to the `@plugin "daisyui"` node_modules based reference, which requires `npm install daisyui` such that daisyui is resolvable from the app work directory.

If using [Actions]({{< ref "/docs/actions/" >}}), DaisyUI styles are automatically included. The themes can be customized using the `light` and `dark` property.

### Custom Themes

With `tailwind_version = 4`, fully custom [daisyUI themes](https://daisyui.com/docs/themes/#how-to-add-a-new-custom-theme) can be defined with the `custom_themes` property: a dict of theme name to the theme's CSS properties. Setting `light`/`dark` to a custom theme name makes it the default for that color scheme:

```python {filename="app.star"}
    style=ace.style("daisyui",
                    light="mybrand-light",
                    dark="mybrand-dark",
                    custom_themes={
                        "mybrand-light": {
                            "color-scheme": "light",
                            "--color-base-100": "#ffffff",
                            "--color-primary": "#007700",
                            # ... other daisyUI theme variables
                        },
                        "mybrand-dark": {
                            "color-scheme": "dark",
                            "--color-base-100": "#17221a",
                            "--color-primary": "#00c200",
                        },
                    })
```

OpenRun generates a daisyUI theme plugin block per custom theme in `style/input.css` (using the prebundled daisyUI theme plugin, downloaded automatically like the main plugin; `daisyui_theme_url` overrides the download location). Custom themes can be mixed with the bundled theme names in `themes`. When only custom themes are used, the bundled themes are disabled, keeping the generated CSS small.
