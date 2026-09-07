# OpenRun Documentation

This folder has the public documentation for OpenRun.

Documentation is hosted at [OpenRun](https://openrun.dev) using GitHub Pages.

The docs are generated using [Hugo](https://gohugo.io/) with the [Hextra](https://github.com/imfing/hextra) theme.

The icons are from [Tabler Icons](https://tabler-icons.io/).

## Preview and validate

Edit Markdown in `content/`, site settings in `hugo.toml`, and shared templates in `layouts/`. The generated `public/` directory is not a documentation source.

From the repository root, run:

```sh
hugo server --source docs
hugo --source docs --destination /tmp/openrun-docs --panicOnWarning
```

Use the Hugo version specified in `.github/workflows/docs.yml` when checking publishing compatibility. Check command examples against `openrun <command> --help` and config defaults against `internal/system/openrun.default.toml`. Prefer Hugo `ref` links for documentation pages so builds catch missing targets.
