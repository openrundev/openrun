// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
)

// Host runs a provider's modules for one app, on plain Go values, with no
// transport involved. It owns the module instances (one per (module, account)
// pair), the sessions with their deferred cleanups, and the cursors returned
// by calls. Both plugin transports are thin layers over it: the gRPC
// providerServer (external providers) decodes wire values at its edges, and
// the OpenRun server embeds one Host per (app, provider) for internal
// plugins, converting Starlark values with the direct bridge. Keeping the
// semantics here — lazy module init, session-scoped state, strict-leak
// reporting, cursor batching, module Close on shutdown — is what guarantees a
// plugin behaves identically internal and external.
type Host struct {
	config *ServeConfig
	logger *Logger

	mu        sync.Mutex
	appInited bool
	appId     string
	appPath   string
	isDev     bool
	appSchema []byte
	modules   map[string]*moduleInstance // "module\x00account"
	initing   map[string]*moduleIniting  // first-time inits in flight
	sessions  map[string]*Session

	// retired marks a host being replaced (app reload): it closes once the
	// last session ends, so in-flight requests finish on the old instances
	retired bool

	cursorCounter atomic.Uint64
}

// moduleIniting tracks one in-flight first-time module initialization, so a
// concurrent first call waits for it instead of building a second instance
// (which would overwrite the first without Close, leaking its resources).
type moduleIniting struct {
	done chan struct{}
	err  error
}

// Typed errors the gRPC shim maps to protocol-level status errors; every
// other error is an application-level failure carried in response fields.
var (
	ErrAppAlreadyInited = errors.New("app already initialized in this provider process")
	ErrAppNotInited     = errors.New("app not initialized")
	ErrUnknownModule    = errors.New("unknown module")
	ErrModuleNotInited  = errors.New("module not initialized")
	ErrUnknownFunction  = errors.New("unknown function")
	errUnknownSession   = errors.New("unknown session")
	errUnknownCursor    = errors.New("unknown cursor")
)

// AppInfo identifies the app a Host serves.
type AppInfo struct {
	AppId     string
	AppPath   string
	IsDev     bool
	AppSchema []byte // raw schema.star contents, nil if the app has none
}

// HostCall is one plugin function invocation at the Host level.
type HostCall struct {
	Module    string
	Account   string
	Function  string
	Args      []any
	Kwargs    []Kwarg
	Thread    ThreadState
	SessionId string

	// Host provides host-process services to in-process modules; nil for
	// external provider processes.
	Host HostServices
}

// CursorInfo is the handle for a cursor returned by a call, to be drained
// with CursorNext / released with CursorClose in the same session (or, for
// a stream cursor, detached with DetachCursor and consumed directly).
type CursorInfo struct {
	CursorId string
	TypeName string
	LeakKey  string
	Stream   bool
}

// HostResult is the outcome of one call. StrictKeys is always populated
// (even alongside an error) so the caller can mirror strict deferred-cleanup
// entries after every call.
type HostResult struct {
	Value      any
	Cursor     *CursorInfo // set instead of Value when the function returned a *Cursor
	StrictKeys []string
}

// NewHost validates the config and returns a Host. The logger may be nil.
func NewHost(config *ServeConfig, logger *Logger) (*Host, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = newServeLogger("")
	}
	return &Host{
		config:   config,
		logger:   logger,
		modules:  map[string]*moduleInstance{},
		initing:  map[string]*moduleIniting{},
		sessions: map[string]*Session{},
	}, nil
}

// Config returns the provider config the Host serves.
func (h *Host) Config() *ServeConfig {
	return h.config
}

// InitApp establishes the app identity. Called once, before any InitModule.
func (h *Host) InitApp(info AppInfo) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.appInited {
		return ErrAppAlreadyInited
	}
	h.appInited = true
	h.appId = info.AppId
	h.appPath = info.AppPath
	h.isDev = info.IsDev
	h.appSchema = info.AppSchema
	return nil
}

// InitModule initializes one (module, account) instance, if not already
// initialized. Settings are the per-account plugin settings with secrets
// expanded. An error returned by the module's InitModule is returned as-is.
// Concurrent first calls for the same (module, account) are serialized: one
// runs the initialization, the others wait for its outcome, so exactly one
// instance is ever built (a failed init is forgotten, so a later call
// retries fresh).
func (h *Host) InitModule(ctx context.Context, module, account string, settings map[string]any) error {
	def, ok := h.config.Modules[module]
	if !ok {
		return fmt.Errorf("%w: provider does not serve module %q", ErrUnknownModule, module)
	}
	key := instanceKey(module, account)

	h.mu.Lock()
	if !h.appInited {
		h.mu.Unlock()
		return ErrAppNotInited
	}
	if _, exists := h.modules[key]; exists {
		h.mu.Unlock()
		return nil
	}
	if inflight, ok := h.initing[key]; ok {
		h.mu.Unlock()
		<-inflight.done
		return inflight.err
	}
	inflight := &moduleIniting{done: make(chan struct{})}
	h.initing[key] = inflight
	appId, appPath, isDev, appSchema := h.appId, h.appPath, h.isDev, h.appSchema
	h.mu.Unlock()

	instance := def.Builder()
	initErr := instance.InitModule(ctx, ModuleInit{
		AppId:     appId,
		AppPath:   appPath,
		Account:   account,
		IsDev:     isDev,
		AppSchema: appSchema,
		Settings:  settings,
		Logger:    h.logger,
	})

	var functions map[string]Func
	if initErr == nil {
		functions = make(map[string]Func, len(def.Functions))
		for _, fn := range def.Functions {
			functions[fn.Name] = reflect.ValueOf(instance).MethodByName(fn.Method).Interface().(Func)
		}
	}

	h.mu.Lock()
	delete(h.initing, key)
	if initErr == nil {
		h.modules[key] = &moduleInstance{module: instance, functions: functions}
	}
	h.mu.Unlock()

	inflight.err = initErr
	close(inflight.done)
	return initErr
}

func (h *Host) getSession(sessionId string) *Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	session, ok := h.sessions[sessionId]
	if !ok {
		session = newSession(sessionId)
		h.sessions[sessionId] = session
	}
	return session
}

// StartSession registers a request session before its first call. Callers
// register the session at host-acquisition time so a concurrent Retire (app
// reload) counts the request as active and keeps the host open until the
// matching EndSession, instead of closing the modules mid-request.
func (h *Host) StartSession(sessionId string) {
	h.getSession(sessionId)
}

// Call invokes one plugin function. An error returned by the function is
// returned as-is (possibly a *ProviderError carrying an error code), with
// the result's StrictKeys still valid; ErrModuleNotInited / ErrUnknownFunction
// signal caller bugs.
func (h *Host) Call(ctx context.Context, call *HostCall) (*HostResult, error) {
	h.mu.Lock()
	instance, ok := h.modules[instanceKey(call.Module, call.Account)]
	h.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: module %q account %q", ErrModuleNotInited, call.Module, call.Account)
	}
	fn, ok := instance.functions[call.Function]
	if !ok {
		return nil, fmt.Errorf("%w: module %q has no function %q", ErrUnknownFunction, call.Module, call.Function)
	}

	session := h.getSession(call.SessionId)
	pluginCall := &Call{
		Function: call.Function,
		Args:     call.Args,
		Kwargs:   call.Kwargs,
		Thread:   call.Thread,
		Session:  session,
		Host:     call.Host,
	}

	result, err := fn(ctx, pluginCall)
	// Report the session's strict deferred-cleanup keys so the caller can
	// mirror them as strict cleanup entries (leak detection at request end)
	hostResult := &HostResult{StrictKeys: session.strictKeys()}
	if err != nil {
		return hostResult, err
	}

	if cursor, ok := result.(*Cursor); ok {
		// An interface holding a typed-nil cursor is a nil plugin result, not a
		// cursor to register. Dereferencing it here would panic the host.
		if cursor != nil {
			hostResult.Cursor = h.registerCursor(session, cursor)
		}
	} else {
		hostResult.Value = result
	}
	return hostResult, nil
}

// registerCursor stores a cursor in the session and returns its handle. A
// session cleanup entry closes the cursor if it is never drained; the strict
// leak reporting happens on the caller side under LeakKey.
func (h *Host) registerCursor(session *Session, cursor *Cursor) *CursorInfo {
	cursorId := fmt.Sprintf("cursor-%d", h.cursorCounter.Add(1))
	session.mu.Lock()
	session.cursors[cursorId] = &cursorState{cursor: cursor}
	session.mu.Unlock()
	session.Defer("cursor_"+cursorId, false, func(ctx context.Context) error {
		return h.closeCursor(session, cursorId)
	})
	return &CursorInfo{
		CursorId: cursorId,
		TypeName: cursor.TypeName,
		LeakKey:  cursor.LeakKey,
		Stream:   cursor.Stream,
	}
}

// DetachCursor removes a cursor from its session and returns it for direct
// consumption. Used for stream cursors, which are consumed after the
// request's session has ended; the caller owns closing the cursor.
func (h *Host) DetachCursor(sessionId, cursorId string) (*Cursor, error) {
	h.mu.Lock()
	session, ok := h.sessions[sessionId]
	h.mu.Unlock()
	if !ok {
		return nil, errUnknownSession
	}
	session.mu.Lock()
	state, ok := session.cursors[cursorId]
	delete(session.cursors, cursorId)
	session.mu.Unlock()
	if !ok {
		return nil, errUnknownCursor
	}
	session.ClearDefer("cursor_" + cursorId)
	return state.cursor, nil
}

func (h *Host) closeCursor(session *Session, cursorId string) error {
	session.mu.Lock()
	state, ok := session.cursors[cursorId]
	delete(session.cursors, cursorId)
	session.mu.Unlock()
	if !ok || state.cursor.Close == nil {
		return nil
	}
	return state.cursor.Close(context.Background())
}

// CursorNext returns up to max items from a cursor and whether iteration is
// complete. When done, the cursor and its session cleanup are forgotten (the
// cursor released its own resources).
func (h *Host) CursorNext(ctx context.Context, sessionId, cursorId string, max int) ([]any, bool, error) {
	h.mu.Lock()
	session, ok := h.sessions[sessionId]
	h.mu.Unlock()
	if !ok {
		return nil, false, errUnknownSession
	}

	session.mu.Lock()
	state, ok := session.cursors[cursorId]
	session.mu.Unlock()
	if !ok {
		return nil, false, errUnknownCursor
	}

	if max <= 0 {
		max = 100
	}
	items, done, err := state.cursor.Next(ctx, max)
	if err != nil {
		return nil, false, err
	}

	if done {
		session.mu.Lock()
		delete(session.cursors, cursorId)
		session.mu.Unlock()
		session.ClearDefer("cursor_" + cursorId)
	}
	return items, done, nil
}

// CursorClose releases a cursor before exhaustion. Closing an unknown cursor
// or session is not an error.
func (h *Host) CursorClose(ctx context.Context, sessionId, cursorId string) error {
	h.mu.Lock()
	session, ok := h.sessions[sessionId]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	session.ClearDefer("cursor_" + cursorId)
	return h.closeCursor(session, cursorId)
}

// EndSession runs the session's remaining deferred cleanups and forgets it.
// On a retired host, the last session ending closes the host's modules.
func (h *Host) EndSession(ctx context.Context, sessionId string) error {
	h.mu.Lock()
	session, ok := h.sessions[sessionId]
	delete(h.sessions, sessionId)
	closeNow := h.retired && len(h.sessions) == 0
	h.mu.Unlock()
	if !ok {
		return nil
	}
	err := session.end(ctx)
	if closeNow {
		h.Close(ctx)
	}
	return err
}

// Retire marks a host that is being replaced (app reload): in-flight
// requests finish on the old module instances, and the modules are closed
// when the last active session ends (immediately when none are active).
// New requests go to the replacement host; a straggler call racing the
// retire still works — InitModule lazily rebuilds the instance and the
// session-end close runs again.
func (h *Host) Retire() {
	h.mu.Lock()
	h.retired = true
	active := len(h.sessions)
	h.mu.Unlock()
	if active == 0 {
		h.Close(context.Background())
	}
}

// Close calls Close on every initialized module instance, logging failures.
// Used at provider process shutdown and at app close/reload for in-process
// hosts.
func (h *Host) Close(ctx context.Context) {
	h.mu.Lock()
	instances := make([]*moduleInstance, 0, len(h.modules))
	for _, instance := range h.modules {
		instances = append(instances, instance)
	}
	h.modules = map[string]*moduleInstance{}
	h.mu.Unlock()

	for _, instance := range instances {
		if err := instance.module.Close(ctx); err != nil {
			h.logger.Warn().Err(err).Msg("error closing plugin module")
		}
	}
}
