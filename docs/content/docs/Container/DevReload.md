---
title: "Fast Dev Reload"
weight: 250
summary: "Fast reload for containerized apps in dev mode: dev settings, the dev stage convention and auto-inference"
---

In dev mode (`openrun app create --dev`), OpenRun watches the app source and reloads the app on changes. For containerized apps, with **Fast dev reload**, the dev image is built once, the app source directory is bind mounted into the container and a source change just restarts the container (or does nothing, for frameworks with built-in hot reload). Reload times become independent of the image build time.

## How it works

- The dev image is built with `docker build --target <stage>`, so the build stops at the _dev stage_ — the stage that still has the toolchain — instead of the final runtime stage.
- The image is rebuilt only when its identity changes: the Containerfile contents, build args, target stage or the contents of the configured `env_files` (dependency manifests like `requirements.txt`). Ordinary source changes never rebuild the image.
- The app source is bind mounted over the configured directory inside the container, shadowing the copy baked into the image.
- On a source change, the container is restarted with no grace period (`reload: restart`), recreated (`reload: recreate`) or left alone (`reload: none`, for frameworks like Flask/uvicorn that watch for changes themselves).

All app specs shipped with OpenRun configure this per framework, so spec-based apps get fast reload automatically. For apps that bring their own Containerfile, OpenRun infers the settings as described below.

## The dev stage convention

The recommended way to enable fast reload for a custom Containerfile is to add one stage named `dev`, anywhere **except last**, whose `CMD` is the command that runs the app from source:

```dockerfile
FROM golang:1.24 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o app ./cmd/app

FROM builder AS dev
CMD go run ./cmd/app

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/app .
ENTRYPOINT ["/app/app"]
```

Nothing else is needed — no changes in `app.star`. In dev mode, OpenRun builds the `dev` stage, mounts the source at the stage's `WORKDIR` (`/app` here, inherited from `builder`) and runs the stage's `CMD`. Editing a source file restarts the container and `go run` picks up the change.

The `dev` stage costs production builds nothing: builds without `--target` build the last stage, and BuildKit/buildah skip stages that the last stage does not depend on.

Notes:

- The dev stage must define `CMD` (or `ENTRYPOINT`); otherwise the app load fails, since the base image's default command would not run the app.
- If the stage's base image defines its own `ENTRYPOINT`, the `CMD` becomes its arguments; add `ENTRYPOINT []` in the dev stage to reset it.
- The dev stage must **not** be the last stage. Since the production image build builds the last stage, a `dev` stage placed last would silently become the production image; OpenRun rejects prod deployments of such a Containerfile and warns in dev mode.

## Auto-inference

When the Containerfile has no `dev` stage, OpenRun attempts to infer the dev settings (this is enabled by default; set `disable` to opt out):

- **Multi-stage builds**: the penultimate stage (typically the builder stage, which has the toolchain) is built as the dev image, and the _final_ stage's `ENTRYPOINT`/`CMD` is run in it, with the source mounted at the penultimate stage's `WORKDIR`. `ENV` values declared in the final stage (with build arg defaults applied) are passed to the dev container, since the built dev image does not include them. If the penultimate stage defines its own `CMD`/`ENTRYPOINT`, that runs instead.
- **Compiled apps — build replay**: when the entry command runs a _build artifact_ (a file the final stage takes from the build stage with `COPY --from`, like a Go binary or a jar), running it directly would fail — the artifact was produced under the source directory during the image build, and the source mount shadows it. OpenRun instead replays the build: the dev command becomes the build stage's `RUN` instructions after the source `COPY`, followed by the entry command, e.g.

  ```sh
  go build -o app ./cmd/app && exec /app/app -flag value
  ```

  Artifact paths that the final stage renamed are rewritten to their build stage locations (`app.jar` → `/build/target/app-1.0.jar`), including references inside `sh -c` command strings and files provided by directory copies; files the final stage copies from the build context (like an entrypoint script) are used from the mounted source. Dependency steps that run before the source `COPY` (`go mod download`, `mvn dependency:go-offline`) are not repeated — they are baked into the dev image. `RUN --mount=type=cache` cache directories are automatically turned into named volumes so builds stay incremental across reloads. Each reload re-runs the build step, which is exactly what a compiled language needs; note the build writes its artifacts into the mounted source directory on the host (the same paths the image build produces).

- **Single-stage builds**: the full image is built once and its own entry command runs, with the source mounted at the `WORKDIR`. Since a single-stage image typically has the full toolchain, this gives interpreted apps (Python, Node) fast reload with zero configuration.

Anything that cannot be inferred or safely replayed (no named build stage, no entry command, no `WORKDIR`, artifact built by steps that cannot be replayed) makes the app fall back to the rebuild-on-change flow. When an auto-inferred command fails to start or fails its health check, the error shows the inferred command and how to override it.

Auto-inference can still be semantically wrong — for example when the image build does codegen whose outputs live under the source directory, or the final stage installs runtime packages the build stage lacks. The dev stage convention is the explicit answer for those cases (or `disable: True` to opt out).

## Configuring dev settings

Everything inferred can also be set explicitly via `dev_settings` in `container.config` in `app.star`. Explicit values always win over inferred ones:

```python
container=container.config(container.AUTO, port=8000,
    dev_settings={
        "target": "builder",          # Containerfile stage to build for dev
        "command": "go run ./cmd/app",# command to run the app from source
        "dir": "/app",                # where the source is mounted (default: the stage's WORKDIR)
        "reload": "restart",          # restart (default) | none | recreate
        "env_files": ["go.mod", "go.sum"],  # changes to these rebuild the dev image
        "additional_mounts": ["go-mod-cache:/go/pkg/mod", "go-build-cache:/root/.cache/go-build"],
        "port": 8000,                 # dev command port, if different from the image port
        "dev_stage": "dev",           # stage name for the dev stage convention (default "dev")
        "disable": False,             # True switches back to the rebuild-on-change flow
    })
```

- `target`: the Containerfile stage built for dev mode (`docker build --target`). Defaults to the `dev_stage` stage if present, else the penultimate stage.
- `command`: the app start command, run with `sh -c`, overriding the image entrypoint. Defaults to the dev stage's `CMD`, or the final stage's entry command under auto-inference.
- `dir`: absolute path where the app source is bind mounted, also the working directory. Defaults to the effective `WORKDIR` of the dev stage.
- `reload`: what a source change does. `restart` (default) restarts the container; `none` leaves it running, for dev servers with built-in hot reload; `recreate` removes and recreates the container.
- `env_files`: files whose content changes trigger a dev image rebuild and container recreate — dependency manifests like `requirements.txt`, `pyproject.toml`, `pom.xml`.
- `additional_mounts`: extra named volume mounts, typically toolchain caches (Go module cache, Maven `~/.m2`) so restarts stay fast.
- `port`: the port the dev command listens on, when different from the port the built image uses.
- `dev_stage`: the stage name used by the dev stage convention. Setting it to a name that does not exist in the Containerfile fails the app load.
- `disable`: `True` disables fast dev reload and returns to rebuilding the image on every change.

## Toolchain caches

Compiled languages benefit from persisting the toolchain caches across container recreates, using named volumes in `additional_mounts`. For the Go example above:

```python
"additional_mounts": ["go-mod-cache:/go/pkg/mod", "go-build-cache:/root/.cache/go-build"]
```

With the mod and build caches on named volumes, a `go run` after a restart recompiles only the changed packages.
