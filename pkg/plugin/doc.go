// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// Package plugin is the OpenRun Starlark plugin provider SDK.
//
// An OpenRun plugin provider is a standalone executable that serves one or
// more Starlark plugin modules to the OpenRun server over gRPC
// (hashicorp/go-plugin). Apps load provider-served modules with the .ex
// suffix — load("notes.ex", "notes") — and use them exactly like builtin .in
// plugins: the same permission approvals, the same plugin_response error
// handling, and the same request-end resource cleanup apply. The SDK has no
// Starlark dependency; plugin functions are plain Go methods over plain Go
// values, and the server converts Starlark values at the process boundary
// with full fidelity (exact big ints, int/float distinction, dict order,
// tuples, sets, bytes, typed records).
//
// # Writing a provider
//
// A provider's main function calls [Serve] with a [ServeConfig] declaring its
// modules. Each [ModuleDef] names a builder and the module's functions:
//
//	func main() {
//		plugin.Serve(&plugin.ServeConfig{
//			ProviderVersion: version,
//			Modules: map[string]plugin.ModuleDef{
//				"notes": { // served to apps as "notes.ex"
//					Builder: NewNotesModule,
//					Functions: []plugin.FuncDef{
//						{Name: "add", Type: plugin.WRITE, Method: "Add"},
//						{Name: "list", Type: plugin.READ, Method: "List"},
//					},
//				},
//			},
//		})
//	}
//
// The builder returns a [Module]; one instance is created per (module,
// account) pair in each provider process. [Module.InitModule] receives a
// [ModuleInit] with the app identity, the per-account settings from
// openrun.toml (secrets already expanded by the server), and the raw
// schema.star bytes for schema-aware plugins.
//
// Every declared function must be an exported method with the [Func]
// signature; Serve validates this at startup:
//
//	func (m *NotesModule) Add(ctx context.Context, call *plugin.Call) (any, error) {
//		var text string
//		if err := plugin.UnpackArgs("add", call, "text", &text); err != nil {
//			return nil, err
//		}
//		...
//		return id, nil
//	}
//
// [UnpackArgs] binds positional and keyword arguments with
// starlark.UnpackArgs semantics. The returned value becomes response.value
// in the app; a returned error becomes response.error (use [ErrorWithCode]
// for an explicit error_code) and feeds OpenRun's automatic error handling.
//
// # Sessions, cursors, and resource lifetimes
//
// All calls made during one app request share [Call.Session]. Session state
// ([Session.Set], [Session.Get]) and deferred cleanup ([Session.Defer],
// [Session.ClearDefer]) scope cross-call resources such as transactions to
// the request; remaining defers run when the request ends.
//
// A function may return a [*Cursor] to stream results lazily: the app
// receives an iterable, batches are fetched on demand, and a cursor the app
// never consumes is closed at request end and reported as a leaked resource,
// failing the request under the cursor's LeakKey.
//
// The one rule stateful providers must follow: resources that outlive a
// single call — a sql.Tx, the sql.Rows behind a Cursor — must be created on
// [Session.Context], not the per-call context. The per-call gRPC context is
// cancelled when the call returns, which would roll back the transaction or
// close the rows before the next call arrives.
//
// # How the server runs providers
//
// At registration time the server launches the provider briefly and calls
// Describe; the returned module manifests (functions, read/write flags,
// constants) are what app loading and permission auditing use, so no
// provider process runs until an app actually calls the plugin. At runtime
// the server keeps one provider process per app (mutual-TLS gRPC over a unix
// socket, binary checksum verified at launch), initializes it once via
// InitApp/InitModule, and stops it when the app is closed or reloaded. All
// permission checks and secret expansion happen server-side before a call is
// dispatched.
//
// Application errors travel inside responses; a gRPC transport error means
// the provider process failed, its sessions are lost, and calls are never
// retried automatically.
//
// The out-of-process build of the OpenRun store plugin
// (internal/app/store/storeprovider in the OpenRun repository) is the
// reference provider implementation, covering settings, schema access,
// transactions, and cursors.
package plugin
