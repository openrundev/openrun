---
title: "External Plugins"
weight: 600
summary: "How to build external plugin providers and use .ex plugins in apps"
---

External plugins extend OpenRun with new Starlark APIs **without changing the OpenRun binary**. A plugin is written once against the OpenRun plugin SDK (`pkg/plugin`) and the same implementation can run two ways:

- **internal**: compiled into the OpenRun binary and called in-process — no gRPC, no serialization. All of OpenRun's builtin plugins (`store`, `http`, `exec`, `fs`, ...) are SDK plugins running this way, and custom builds can compile additional plugins in for performance.
- **external**: built as a standalone _plugin provider_ executable that the server runs as a separate process per app and talks to over gRPC — for distributing plugins without rebuilding OpenRun.

Apps always load plugins with the `.in` suffix (`load("myplugin.in", "myplugin")`). Resolution prefers a compiled-in module of that name and falls back to an installed external provider serving it, so **an app does not change when a plugin moves between internal and external**. The `.ex` suffix remains available to explicitly require the external build.

The store plugin ships in both forms as the reference implementation: the module in `internal/app/store` is compiled in as `store.in`, and `internal/app/store/storeprovider` in the OpenRun repo is the same module built as an external provider, passing the same test suite. Use it as a working example for everything on this page.

## Using a plugin in an app

Load the module; the name bound in the app is the module name without the suffix:

```python {filename="app.star"}
load("myplugin.in", "myplugin")
```

Whether `myplugin` is compiled in or served by an external provider makes no difference to the app. To force the external build, or to load an internal and an external build of the same module side by side, use `.ex` and rename one:

```python {filename="app.star"}
load("store.in", "store")
load("store.ex", store_ex="store")
```

Declare permissions like any plugin call, and approve them with `openrun app approve`:

```python {filename="app.star"}
app = ace.app("myapp",
    routes=[ace.api("/")],
    permissions=[
        ace.permission("myplugin.in", "query"),
        ace.permission("myplugin.in", "submit"),
    ],
)
```

Everything in the [plugin overview]({{< ref "docs/plugins/overview" >}}) applies unchanged to `.ex` plugins:

- Calls return the same `plugin_response` (`value` / `error` / `error_code`), and **automatic error handling** works identically — an unchecked error fails the value access, the next plugin call (to _any_ plugin, builtin or external), or the handler return.
- The security model is identical: the server checks approvals, `permissions.disallow` rules, RBAC `permit` lists, and stage/preview write access **before** the call reaches the provider, and expands approved secrets in arguments. A provider never sees a call that policy would have blocked.
- Account linking works the same: `load("myplugin.in#staging", "myplugin")` selects the `[plugin."myplugin.in#staging"]` settings block from `openrun.toml`.
- Deferred cleanup works the same: resources a plugin leaves open (an uncommitted transaction, an unread result cursor) are released at the end of the request, and strictly-tracked resources that were never consumed fail the request with a `resource has not be closed` error.

Plugin settings are configured in `openrun.toml` under the full module path the app loads (an app loading `myplugin.ex` explicitly uses `[plugin."myplugin.ex"]` blocks instead):

```toml {filename="openrun.toml"}
[plugin."myplugin.in"]
api_url = "https://example.com/api"

[plugin."myplugin.in#staging"]
api_url = "https://staging.example.com/api"
```

## Building a plugin provider

A provider is a Go `main` package that depends only on the plugin SDK module `github.com/openrundev/openrun/pkg/plugin`. The SDK has a small dependency tree (go-plugin, gRPC, zerolog) and **no Starlark dependency**: plugin functions are plain Go functions over plain Go values; the server converts Starlark values at the process boundary with full fidelity (big ints stay exact, int and float stay distinct, dict order is preserved).

```go {filename="main.go"}
package main

import (
	"context"

	plugin "github.com/openrundev/openrun/pkg/plugin"
)

var version = "dev" // set with -ldflags "-X main.version=v0.x.y"

func main() {
	plugin.Serve(&plugin.ServeConfig{
		ProviderVersion: version,
		Modules: map[string]plugin.ModuleDef{
			// loaded by apps as "notes.in" (or explicitly "notes.ex")
			"notes": {
				Builder: NewNotesModule,
				Functions: []plugin.FuncDef{
					{Name: "add", Type: plugin.WRITE, Method: "Add"},
					{Name: "list", Type: plugin.READ, Method: "List"},
				},
				Constants: map[string]any{"MAX_NOTE_LEN": 1024},
			},
		},
	})
}
```

Each module has a builder returning a `plugin.Module`, which carries per-app initialization and shutdown:

```go {filename="module.go"}
type NotesModule struct {
	apiURL string
	logger *plugin.Logger
}

func NewNotesModule() plugin.Module { return &NotesModule{} }

func (m *NotesModule) InitModule(ctx context.Context, init plugin.ModuleInit) error {
	// init.Settings come from [plugin."notes.ex"] (or the linked account
	// block) in openrun.toml, with approved secrets already expanded.
	url, _ := init.Settings["api_url"].(string)
	if url == "" {
		return fmt.Errorf("api_url must be set in the notes.ex plugin config")
	}
	m.apiURL = url
	m.logger = init.Logger
	// init.AppId / init.AppPath identify the app; init.AppSchema holds the
	// raw contents of the app's schema.star (nil if the app has none), for
	// plugins that are schema-aware like the store.
	return nil
}

func (m *NotesModule) Close(ctx context.Context) error { return nil }
```

### Plugin functions

Every function declared in `FuncDef` must be an exported method with this exact signature (validated when the provider starts, so a typo fails immediately, not on a user request):

```go
func (m *NotesModule) Add(ctx context.Context, call *plugin.Call) (any, error)
```

`plugin.UnpackArgs` binds positional and keyword arguments with the same rules Starlark apps expect — alternating name/pointer pairs, a trailing `?` marks a parameter optional:

```go {filename="module.go"}
func (m *NotesModule) Add(ctx context.Context, call *plugin.Call) (any, error) {
	var text string
	var tags []string
	if err := plugin.UnpackArgs("add", call, "text", &text, "tags?", &tags); err != nil {
		return nil, err
	}
	// call.Thread has request-scoped info: UserId, UserEmail, Groups,
	// RequestId, AppUrl
	id, err := m.addNote(ctx, call.Thread.UserId, text, tags)
	if err != nil {
		return nil, err // becomes response.error in the app
	}
	return id, nil // becomes response.value
}
```

The return value maps to Starlark automatically:

| Go value returned                 | Starlark value in the app                       |
| --------------------------------- | ----------------------------------------------- |
| `nil`                             | `None`                                          |
| `bool`, `string`, int/uint widths | `bool`, `string`, `int`                         |
| `*big.Int`                        | `int` (arbitrary precision)                     |
| `float32/64`                      | `float`                                         |
| `[]byte`                          | `bytes`                                         |
| `[]any`, `[]string`, `[]int`, ... | `list`                                          |
| `map[string]any`                  | `dict`                                          |
| `plugin.Tuple` / `plugin.Set`     | `tuple` / `set`                                 |
| `plugin.Dict`                     | `dict` with controlled entry order              |
| `*plugin.Struct`                  | typed record with attribute access (`row.name`) |
| `time.Time`                       | `time.time`                                     |
| `*plugin.Cursor`                  | lazy iterable (see below)                       |

Arguments arrive through the same mapping in reverse: typed records passed by the app arrive as `*plugin.Struct`, string-keyed dicts as `map[string]any`, and so on.

Errors: returning a plain `error` produces `response.error` with `error_code` 1; `plugin.ErrorWithCode(429, err)` sets an explicit code. Both feed OpenRun's normal response and automatic error handling flow.

### Sessions: state across calls in one request

All calls made during one app request share a `call.Session`. Use it for state that spans calls — the canonical example is a transaction:

```go {filename="module.go"}
func (m *NotesModule) Begin(ctx context.Context, call *plugin.Call) (any, error) {
	// Resources that outlive this one call MUST be created on the session
	// context: the per-call ctx is cancelled when the call returns, which
	// would roll back a sql.Tx or close sql.Rows immediately.
	tx, err := m.db.BeginTx(call.Session.Context(), nil)
	if err != nil {
		return nil, err
	}
	call.Session.Set("transaction", tx)
	// If the app never commits, roll back automatically at request end
	call.Session.Defer("transaction", false, func(ctx context.Context) error {
		return tx.Rollback()
	})
	return true, nil
}
```

`Session.Defer` registers cleanup that runs when the request ends (in reverse registration order), unless removed first with `ClearDefer` — e.g. after a successful commit. This is the external equivalent of the deferred-cleanup mechanism builtin plugins use, and it drains at the same point in the request lifecycle. The `strict` argument controls leak reporting: a strict entry still registered when the request ends does not just get cleaned up — it **fails the request** as a leaked resource (`resource has not be closed ...`), so use `strict=true` for resources the app is required to consume or release explicitly, and `strict=false` for silent safety nets like an automatic rollback.

`Module.Close` is called on every initialized module instance when the app is closed or reloaded, before the provider process exits — release long-lived resources (connection pools, flush buffers) there.

### Cursors: lazy result iteration

For results that should stream lazily instead of being materialized in one response, return a `*plugin.Cursor`. The app receives an iterable; each batch is fetched from the provider on demand:

```go {filename="module.go"}
return &plugin.Cursor{
	TypeName: "notes",                                  // Starlark type is "notes iterator"
	LeakKey:  fmt.Sprintf("notes_cursor_%p", rows),     // names the leak-check entry
	Next: func(ctx context.Context, max int) ([]any, bool, error) {
		// return up to max items, and done=true when exhausted
	},
	Close: func(ctx context.Context) error { return rows.Close() },
}, nil
```

Cursor semantics match builtin plugins exactly: iterating the value (a `for` loop, even with `break`) closes the cursor; a cursor the app never touches is closed at request end **and fails the request** with `resource has not be closed, check handler code: myplugin.in:<LeakKey>`. As with sessions, back the cursor's query with `call.Session.Context()`, not the per-call context.

A cursor with `Stream: true` is instead returned by the app handler as a **streaming HTTP response** (`response.is_stream`): the server pulls batches and writes them to the client as they arrive, after the request's plugin cleanup has run. `plugin.PushCursor` adapts a push-style (yield-based) producer into a cursor. Stream cursors are supported for in-process modules only.

### Callable members: Thunk and FuncRef

A returned `*plugin.Struct` can carry members the app calls as functions:

- `plugin.Thunk{Name, Value}` materializes as a zero-argument callable returning the pre-computed value (`Thunk{Error: "..."}` makes the call fail instead).
- `plugin.FuncRef{Function, Args}` materializes as a zero-argument callable that dispatches the named plugin function with those arguments, in the same module, account, and session — for members computed lazily against live plugin state. Function names starting with `_` are internal: declared in `Functions` (so the binding is validated) but not exposed as module attributes, callable only through a FuncRef.

The http plugin's `response.body()` and `response.json()` are FuncRefs into an internal `_read_body` function, reading a response held open in the session; an unread body is closed by the session cleanup at request end.

### Building and testing

```bash
CGO_ENABLED=0 go build -o openrun-plugin-notes .
```

Providers are conventionally named `openrun-plugin-<name>`. Test the provider end to end the way the store provider tests do (`internal/app/tests/store_test.go`): build the binary in the test, register it, and run app requests against a test app that loads the `.ex` module.

### Compiling a plugin into OpenRun

The same module runs in-process — no gRPC, no serialization — when compiled into an OpenRun binary. Move the `ServeConfig` into an importable package that registers it from `init`:

```go {filename="notes.go"}
package notes

import plugin "github.com/openrundev/openrun/pkg/plugin"

func init() {
	plugin.RegisterEmbedded("notes", Config())
}

func Config() *plugin.ServeConfig { return &plugin.ServeConfig{ ... } }
```

The provider executable's `main` shrinks to `plugin.Serve(notes.Config())`, and a custom OpenRun build just blank-imports the package:

```go
import _ "example.com/notes"
```

The server picks up embedded providers at startup and serves their modules in-process under the same `<module>.in` names, taking precedence over an external provider serving the same module — apps do not change. This is the recommended workflow: develop and test the plugin compiled in, distribute it as an external provider.

## How it works: the complete flow

1. **Registration**: the server launches the provider binary briefly, performs the go-plugin handshake (a magic cookie distinguishes plugin providers from binding providers), and calls `Describe`. The provider reports its version and a **manifest** per module: function names, read/write classification, and constants. The manifest is registered under both the `<module>.in` and `<module>.ex` paths — after this, no provider process is needed for loading or auditing.
2. **Load and audit**: `load("notes.in", "notes")` resolves the module from the registered manifest (unless a compiled-in module of that name takes precedence), binding one hooked function per manifest entry (plus constants). `openrun app audit`/`approve` work from the manifest alone, without launching anything.
3. **First call**: the server lazily launches **one provider process per app** — mutual-TLS gRPC over a unix socket, with the binary's sha256 verified at every launch when a checksum is registered. `InitApp` sends the app identity and the raw `schema.star` bytes once; `InitModule` then initializes each (module, account) instance with its settings.
4. **Per call**: the hook runs the standard checks (approval, disallow rules, RBAC, write gating, secret expansion), encodes the Starlark arguments to the wire format, and sends `Call` with the request's thread state and a session id. The provider decodes to Go values, dispatches to your method, and the result flows back and is rewrapped as a normal `plugin_response`.
5. **Request end**: the server ends the session; remaining session defers run (transactions roll back, cursors close), and strictly-tracked leaks fail the request.
6. **Lifecycle**: the provider process is stopped when the app is closed, deleted, or reloaded (so schema and settings changes take effect), and respawns on the next call. If a provider crashes, in-flight calls fail like any plugin error, session state is lost, and the next request gets a fresh process — calls are never retried automatically.

Two error channels keep failures unambiguous: an error _returned by your function_ travels inside the response and becomes `response.error` in the app; a _transport_ error (process crash, protocol mismatch) kills the provider process and fails the request server-side.

## Installing a provider

Plugin providers share the provider install machinery with [binding providers]({{< ref "docs/applications/servicebindings/#binding-providers-sql-server-oracle-mongodb-snowflake-clickhouse" >}}): the binary is fetched, verified, registered in the metadata database (the source of truth, propagated to all server replicas) and materialized into a local cache directory. The provider **type is carried in the name**: `plugin/<name>` installs a plugin provider, a bare name (or `binding/<name>`) a binding provider.

```bash
openrun provider install plugin/pdftool --version v0.1.0
openrun provider install plugin/pdftool --source-url /path/to/openrun-plugin-pdftool
openrun provider list
openrun provider uninstall plugin/pdftool
```

The module manifest captured at install time is stored with the provider record, so module loading and app audit work on every replica without launching the provider — a provider process only runs when an app actually calls one of its modules. Checksums are pinned per platform at install and verified at every process launch.

For config-managed deployments, declare installs in `openrun.toml` (these providers cannot be modified with the CLI):

```toml {filename="openrun.toml"}
[plugin_providers.install]
pdftool = "v0.1.0"
# with pinned digests, one per platform:
# pdftool = "v0.1.0@sha256:8f4e...,a1b2..."
```

`plugin_providers` also supports `release_url_template` (mirror downloads), `cache_dir`, `unsafe_allow_http` and `disable_install`, mirroring the `bindings` config section.

On Kubernetes without egress, use the OCI image path instead: provider images are `FROM scratch` with the provider binary as the entrypoint, and an init container per provider runs `<provider> export <dir>` to copy the binary into a shared volume that the server scans at startup (`plugin_providers.preinstalled_dir`). The OpenRun Helm chart wires this up from values:

```yaml {filename="values.yaml"}
pluginProviders:
  images:
    pdftool: ghcr.io/openrundev/openrun-plugin-pdftool@sha256:8f4e...
  # or the download path:
  # install:
  #   pdftool: v0.1.0
```

For development, register a provider executable directly from a local path — no database registration, no checksum verification (a startup log warns about this):

```toml {filename="openrun.toml"}
[plugin_providers.dev_providers.notes]
path = "/path/to/openrun-plugin-notes"
```
