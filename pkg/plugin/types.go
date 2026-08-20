// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// FunctionType classifies a plugin function as a read or a write operation.
// Writes are blocked for stage/preview apps without write access.
type FunctionType int

const (
	READ FunctionType = iota
	WRITE
)

// Func is the signature every plugin function method must have.
type Func = func(ctx context.Context, call *Call) (any, error)

// ModuleDef declares one Starlark module served by a provider. A module named
// "store" is loaded by apps as load("store.ex", "store").
type ModuleDef struct {
	// Builder returns a new module instance. One instance is created per
	// (module, account) pair in each provider process (one process per app).
	Builder func() Module

	// Functions declares the module's plugin functions.
	Functions []FuncDef

	// Constants are exported as module constants, e.g. store.MAX_LIMIT.
	Constants map[string]any
}

// FuncDef declares one plugin function: its Starlark name, read/write
// classification, and the Go method (on the Module implementation) that
// handles it. The method must have the Func signature.
type FuncDef struct {
	Name   string
	Type   FunctionType
	Method string
}

// Module is a plugin module instance, scoped to one (module, account) pair
// within one app's provider process.
type Module interface {
	// InitModule initializes the instance before its first call.
	InitModule(ctx context.Context, init ModuleInit) error

	// Close releases the instance's resources. Called at process shutdown.
	Close(ctx context.Context) error
}

// ModuleInit carries the app and account context for a module instance.
type ModuleInit struct {
	AppId   string
	AppPath string
	Account string // "" for the default account
	IsDev   bool

	// AppSchema is the raw contents of the app's schema.star, nil if the app
	// has none.
	AppSchema []byte

	// Settings are the per-account plugin settings from the server config
	// (e.g. [plugin."store.ex#myaccount"]), with secrets already expanded.
	Settings map[string]any

	Logger *Logger
}

// ThreadState snapshots the request-scoped state a plugin function may read.
type ThreadState struct {
	RequestId   string
	UserId      string
	UserSubject string
	UserEmail   string
	Groups      []string
	AppUrl      string
}

// Kwarg is one keyword argument, in call-site order.
type Kwarg struct {
	Name  string
	Value any
}

// HostServices exposes host-process services to a module running in-process
// (compiled into the OpenRun binary). It is nil when the module runs in an
// external provider process, so a module using it is host-bound: it works
// internal-only and must fail gracefully when Host is nil.
type HostServices interface {
	// Value returns a host-scoped value by key, nil if not set. Keys are
	// host-defined (e.g. the container plugin's request container handler).
	Value(key string) any
}

// Call carries one plugin function invocation.
type Call struct {
	Function string
	Args     []any
	Kwargs   []Kwarg
	Thread   ThreadState
	Session  *Session

	// Host is non-nil only when the module runs in-process. See HostServices.
	Host HostServices
}

// Tuple is a Starlark tuple argument or return value.
type Tuple []any

// Set is a Starlark set argument or return value.
type Set []any

// DictEntry is one entry of an order-preserving Dict.
type DictEntry struct {
	Key   any
	Value any
}

// Dict is an order-preserving Starlark dict. Incoming dicts whose keys are
// all strings arrive as map[string]any instead; Dict is used for dicts with
// non-string keys, and may be returned by a function that needs to control
// the entry order of a returned dict.
type Dict struct {
	Entries []DictEntry
}

// Struct is a schema-typed record. The server materializes returned Structs
// as typed Starlark values with attribute access (row.field), matching what
// builtin plugins return; typed values passed as arguments arrive as Structs.
type Struct struct {
	TypeName string
	Fields   map[string]any
}

// Thunk is a value the server materializes as a zero-argument callable in
// the app: calling it returns Value, or fails with Error if set. Use it as a
// Struct field to return a record with callable members over pre-computed
// data. The value must be transportable (EncodeValue rules); Name names the
// callable in error messages.
type Thunk struct {
	Name  string
	Value any
	Error string
}

// Download is a file download whose content is produced at response-write
// time: the app passes it to ace.response(content, download=name) and the
// producer writes the bytes directly to the HTTP response, after the
// request's plugin cleanup has run. Supported for in-process modules only;
// an external provider returning a Download fails the call.
type Download struct {
	Name     string
	Producer func(w io.Writer) error
}

// FuncRef is a value the server materializes as a zero-argument callable in
// the app: calling it invokes the named plugin function with Args, in the
// same module, account, and session as the call that returned it. Use it as
// a Struct field for members whose result is computed lazily against live
// plugin state, e.g. the http plugin's response.body() reading a response
// held open in the session. Function names starting with "_" are internal:
// they are declared in the module's Functions list (so the method binding is
// validated) but are not exposed as module attributes, and are callable only
// through a FuncRef.
type FuncRef struct {
	Function string
	Args     []any
}

// Cursor is a lazy result iterator that stays in the provider process,
// scoped to the session of the Call that returned it. The server wraps it in
// a Starlark iterable; an unconsumed cursor fails the request through the
// strict deferred-cleanup mechanism, under the name LeakKey.
type Cursor struct {
	// TypeName names the iterable's Starlark type ("<TypeName> iterator").
	TypeName string

	// Stream marks a cursor that the app returns from its handler as a
	// streaming HTTP response (response.is_stream), instead of iterating it
	// in Starlark. A stream cursor is detached from its session when the
	// call returns — it is consumed after the request's plugin cleanup runs —
	// and no leak entry is registered for it. Supported for in-process
	// modules only; an external provider returning a stream cursor fails
	// the call.
	Stream bool

	// LeakKey names the strict cleanup entry the server registers for this
	// cursor, e.g. "rows_cursor_<table>_0x...". If the app never consumes or
	// closes the cursor, the request fails citing this key.
	LeakKey string

	// Next returns up to max items and whether iteration is complete. The
	// provider closes the cursor itself when it reports done.
	Next func(ctx context.Context, max int) ([]any, bool, error)

	// Close releases the cursor before exhaustion.
	Close func(ctx context.Context) error
}

// ErrorWithCode returns an error that carries a plugin error code, surfaced
// to Starlark as response.error_code.
func ErrorWithCode(code int64, err error) error {
	return &ProviderError{Message: err.Error(), Code: code}
}

// Session groups the plugin calls of one app request. Cross-call state
// (transactions, handles) and deferred cleanup are scoped to it; the server
// ends the session when the request handler finishes.
type Session struct {
	id     string
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	state   map[string]any
	defers  []*deferEntry
	cursors map[string]*cursorState
}

type deferEntry struct {
	key    string
	strict bool
	fn     func(ctx context.Context) error
}

type cursorState struct {
	cursor *Cursor
}

// NewSession creates a standalone session, for unit tests of plugin modules.
// In a provider the host creates and ends sessions itself.
func NewSession(id string) *Session {
	return newSession(id)
}

// End runs the session's remaining deferred cleanups, for unit tests of
// plugin modules. In a provider the host ends sessions itself.
func (s *Session) End(ctx context.Context) error {
	return s.end(ctx)
}

func newSession(id string) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		id:      id,
		ctx:     ctx,
		cancel:  cancel,
		state:   map[string]any{},
		cursors: map[string]*cursorState{},
	}
}

// Id returns the session id assigned by the server.
func (s *Session) Id() string {
	return s.id
}

// Context returns a context that stays alive until the session ends. Use it
// (not the per-call context) for resources that outlive one call, such as
// the query backing a returned Cursor: the per-call gRPC context is
// cancelled when the call returns, which would invalidate the resource
// before the next CursorNext arrives.
func (s *Session) Context() context.Context {
	return s.ctx
}

// Set stores a session-scoped value.
func (s *Session) Set(key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state[key] = value
}

// Get returns a session-scoped value, or nil if not set.
func (s *Session) Get(key string) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state[key]
}

// Defer registers a cleanup function run when the session ends (unless
// cleared first). Cleanups run in reverse registration order. Strict entries
// are mirrored to the server after every call: a strict entry still
// registered when the request ends fails the request as a leaked resource,
// matching the strict cleanup contract of builtin plugins. Use strict for
// resources the app is required to consume or release explicitly, and
// ClearDefer when it does.
func (s *Session) Defer(key string, strict bool, fn func(ctx context.Context) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.defers {
		if d.key == key {
			d.strict = strict
			d.fn = fn
			return
		}
	}
	s.defers = append(s.defers, &deferEntry{key: key, strict: strict, fn: fn})
}

// ClearDefer removes a previously registered cleanup, typically after the
// resource was released explicitly (e.g. a transaction was committed).
func (s *Session) ClearDefer(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, d := range s.defers {
		if d.key == key {
			s.defers = append(s.defers[:i], s.defers[i+1:]...)
			return
		}
	}
}

// strictKeys returns the keys of the currently registered strict deferred
// cleanups, in registration order. Reported to the server after every call.
func (s *Session) strictKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []string
	for _, d := range s.defers {
		if d.strict {
			keys = append(keys, d.key)
		}
	}
	return keys
}

// end runs the remaining deferred cleanups in reverse registration order and
// reports any failures and strict leaks.
func (s *Session) end(ctx context.Context) error {
	s.mu.Lock()
	defers := s.defers
	s.defers = nil
	s.mu.Unlock()
	defer s.cancel()

	var failures []string
	for i := len(defers) - 1; i >= 0; i-- {
		d := defers[i]
		if err := d.fn(ctx); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", d.key, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("session cleanup errors: %v", failures)
	}
	return nil
}
