// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
	"go.starlark.net/starlark"
)

// Local plugin providers serve SDK plugin modules (pkg/plugin ModuleDef, the
// same API external providers are built with) in-process: calls go through
// the direct starlark_type value bridge into a sdk.Host, with no
// gRPC and no serialization. The registry below is process-global, like
// builtInPlugins; Hosts are per app, managed by localHosts on each App, so
// module instances, sessions, and cursors have exactly the scoping an
// external provider process would give them.
//
// Module resolution for "name.in" prefers a local module over an external
// provider serving the same name (see pluginLookup), so a plugin moves
// between a compiled-in build and an external provider with no app change.

// LocalProvider is one registered in-process plugin provider and the modules
// it serves.
type LocalProvider struct {
	Name    string
	Config  *sdk.ServeConfig
	Options LocalProviderOptions

	pluginMaps map[string]plugin.PluginMap // "store.in" -> function map
}

// LocalProviderOptions carries host-side policy for an in-process provider's
// modules, beyond what the transport-neutral ServeConfig expresses.
type LocalProviderOptions struct {
	// SystemModules lists modules whose functions require an authenticated
	// caller (RegisterSystemPlugin semantics), e.g. exec, openrun_admin.
	SystemModules []string

	// SettingsHook, if set, can augment a module's settings with app-derived
	// config before the module instance is initialized (e.g. the fs module's
	// allowed directory list comes from the app config, not plugin settings).
	// It must return a new map if it adds entries; the input map may be nil.
	SettingsHook func(a *App, module string, settings map[string]any) map[string]any
}

var (
	localProviderMutex sync.RWMutex
	localProviders     = map[string]*LocalProvider{} // by provider name
	localModules       = map[string]*LocalProvider{} // "store.in" -> owner
)

// RegisterLocalProvider registers an SDK plugin provider config to be served
// in-process. Modules are loadable as "<module>.in". Re-registering the same
// provider name replaces it (server initialization can run more than once in
// a test process); a module served by a different provider panics, so a
// conflicting build fails at startup, not on a user request.
func RegisterLocalProvider(name string, config *sdk.ServeConfig, options LocalProviderOptions) {
	entry := &LocalProvider{
		Name:       name,
		Config:     config,
		Options:    options,
		pluginMaps: map[string]plugin.PluginMap{},
	}
	for moduleName, def := range config.Modules {
		pluginPath := moduleName + "." + apptype.BUILTIN_PLUGIN_SUFFIX
		requiresAuth := slices.Contains(options.SystemModules, moduleName)
		pluginMap, err := moduleDefToPluginMap(name, pluginPath, moduleName, def, requiresAuth)
		if err != nil {
			panic(fmt.Sprintf("plugin provider %s module %s: %s", name, moduleName, err))
		}
		entry.pluginMaps[pluginPath] = pluginMap
	}

	localProviderMutex.Lock()
	defer localProviderMutex.Unlock()
	for pluginPath := range entry.pluginMaps {
		if owner, ok := localModules[pluginPath]; ok && owner.Name != name {
			panic(fmt.Sprintf("plugin module %s is already served by provider %s", pluginPath, owner.Name))
		}
	}
	if prev, ok := localProviders[name]; ok {
		for pluginPath := range prev.pluginMaps {
			delete(localModules, pluginPath)
		}
	}
	localProviders[name] = entry
	for pluginPath := range entry.pluginMaps {
		localModules[pluginPath] = entry
	}
}

// RegisterEmbeddedProviders registers every provider added to the SDK's
// embedded registry (plugin.RegisterEmbedded, used by custom OpenRun builds
// that compile plugins in). Called once at server startup.
func RegisterEmbeddedProviders() {
	for name, config := range sdk.EmbeddedProviders() {
		RegisterLocalProvider(name, config, LocalProviderOptions{})
	}
}

// UnregisterLocalProvider removes a provider and its modules from the
// registry. For tests.
func UnregisterLocalProvider(name string) {
	localProviderMutex.Lock()
	defer localProviderMutex.Unlock()
	prev, ok := localProviders[name]
	if !ok {
		return
	}
	for pluginPath := range prev.pluginMaps {
		delete(localModules, pluginPath)
	}
	delete(localProviders, name)
}

func moduleDefToPluginMap(providerName, pluginPath, moduleName string, def sdk.ModuleDef, requiresAuth bool) (plugin.PluginMap, error) {
	pluginMap := make(plugin.PluginMap)
	for _, fn := range def.Functions {
		if strings.HasPrefix(fn.Name, "_") {
			// Internal function: callable only through a FuncRef, not
			// exposed as a module attribute
			continue
		}
		pluginMap[fn.Name] = &plugin.PluginInfo{
			ModuleName:   moduleName,
			PluginPath:   pluginPath,
			FuncName:     fn.Name,
			IsRead:       fn.Type == sdk.READ,
			HandlerName:  fn.Name,
			RequiresAuth: requiresAuth,

			ProviderName: providerName,
		}
	}
	for constName, constValue := range def.Constants {
		value, err := starlark_type.FromPlugin(constValue, 0, nil)
		if err != nil {
			return nil, fmt.Errorf("constant %s: %w", constName, err)
		}
		value.Freeze()
		pluginMap[constName] = &plugin.PluginInfo{
			ModuleName:    moduleName,
			PluginPath:    pluginPath,
			FuncName:      constName,
			ConstantValue: value,
			RequiresAuth:  requiresAuth,

			ProviderName: providerName,
		}
	}
	return pluginMap, nil
}

// lookupLocalPlugin resolves a "name.in" module path from the local provider
// registry.
func lookupLocalPlugin(modulePath string) (plugin.PluginMap, bool) {
	localProviderMutex.RLock()
	defer localProviderMutex.RUnlock()
	provider, ok := localModules[modulePath]
	if !ok {
		return nil, false
	}
	return provider.pluginMaps[modulePath], true
}

func getLocalProvider(name string) (*LocalProvider, bool) {
	localProviderMutex.RLock()
	defer localProviderMutex.RUnlock()
	provider, ok := localProviders[name]
	return provider, ok
}

// localPluginHosts manages one in-process sdk.Host per (app, provider) pair.
type localPluginHosts struct {
	mu     sync.Mutex
	hosts  map[string]*sdk.Host
	closed bool // terminal: no new hosts after app close
}

func newLocalPluginHosts() *localPluginHosts {
	return &localPluginHosts{hosts: map[string]*sdk.Host{}}
}

// stopAll retires every host but leaves the manager usable: the next .in
// call builds a fresh host from the reloaded schema and settings, while
// in-flight requests finish on the old hosts (each host runs its modules'
// Close callbacks once its last session ends). Used on app reload. Safe on
// a nil receiver: tests construct App literals without NewApp.
func (l *localPluginHosts) stopAll() {
	l.stop(false)
}

// shutdown closes every host immediately and prevents re-creation. Used on
// app close.
func (l *localPluginHosts) shutdown() {
	l.stop(true)
}

func (l *localPluginHosts) stop(terminal bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	hosts := l.hosts
	l.hosts = map[string]*sdk.Host{}
	if terminal {
		l.closed = true
	}
	l.mu.Unlock()
	for _, host := range hosts {
		if terminal {
			host.Close(context.Background())
		} else {
			host.Retire()
		}
	}
}

// getLocalHost returns the app's host for the provider, creating and
// app-initializing it on first use, with the request's session registered on
// it (StartSession) while the manager mutex is held — so a concurrent reload
// cannot observe zero active sessions and close the host's modules before
// the request's first call reaches it. The session is released by the
// request's deferred EndSession.
func (a *App) getLocalHost(providerName, sessionId string) (*sdk.Host, error) {
	a.localHosts.mu.Lock()
	defer a.localHosts.mu.Unlock()
	if a.localHosts.closed {
		return nil, fmt.Errorf("app %s is closed, plugin provider %s is not available", a.Path, providerName)
	}

	if host, ok := a.localHosts.hosts[providerName]; ok {
		host.StartSession(sessionId)
		return host, nil
	}

	registered, ok := getLocalProvider(providerName)
	if !ok {
		return nil, fmt.Errorf("plugin provider %s is not registered", providerName)
	}

	host, err := sdk.NewHost(registered.Config, sdk.NewLogger(a.serverConfig.Log.Level))
	if err != nil {
		return nil, fmt.Errorf("error creating plugin provider %s: %w", providerName, err)
	}

	var appSchema []byte
	if a.storeInfo != nil {
		appSchema = a.storeInfo.Bytes
	}
	if err := host.InitApp(sdk.AppInfo{
		AppId:     string(a.Id),
		AppPath:   a.Path,
		IsDev:     a.IsDev,
		AppSchema: appSchema,
	}); err != nil {
		return nil, fmt.Errorf("error initializing plugin provider %s for app %s: %w", providerName, a.Path, err)
	}

	host.StartSession(sessionId)
	a.localHosts.hosts[providerName] = host
	return host, nil
}

const localSessionLocalPrefix = "openrun_local_session_"

// localHostSession pins a request to one host: every plugin call of the
// request uses the same host and session, even when a reload retires it
// mid-request (the registered session keeps it open until request end).
// Without the pin, a call after the reload would go to the replacement host
// while the session and its cleanup stayed bound to the retired one.
type localHostSession struct {
	host      *sdk.Host
	sessionId string
}

// getLocalHostSession returns the request's pinned host and session id,
// acquiring and pinning them on first use. The session is registered on the
// host by getLocalHost before the host is visible outside the manager mutex,
// so a reload racing this call cannot close its modules; the session ends
// via the deferred cleanup at request end (transactions roll back, cursors
// close), exactly where plugin cleanup already runs for handlers and actions.
func (a *App) getLocalHostSession(thread *starlark.Thread, providerName string) (*sdk.Host, string, error) {
	localKey := localSessionLocalPrefix + providerName
	if v := thread.Local(localKey); v != nil {
		hs := v.(*localHostSession)
		return hs.host, hs.sessionId, nil
	}

	sessionId := fmt.Sprintf("%s-%d", a.Id, extSessionCounter.Add(1))
	host, err := a.getLocalHost(providerName, sessionId)
	if err != nil {
		return nil, "", err
	}
	thread.SetLocal(localKey, &localHostSession{host: host, sessionId: sessionId})
	DeferCleanup(thread, "session_"+sessionId, func() error {
		if err := host.EndSession(context.Background(), sessionId); err != nil {
			a.Warn().Err(err).Msgf("error ending plugin session %s on provider %s", sessionId, providerName)
		}
		return nil
	}, false)
	return host, sessionId, nil
}

// threadHostServices exposes the request's starlark thread locals to
// host-bound in-process modules (sdk.HostServices).
type threadHostServices struct {
	thread *starlark.Thread
}

func (t threadHostServices) Value(key string) any {
	return t.thread.Local(key)
}

// localPluginFunc builds the dispatch function for an in-process SDK plugin
// call. It runs inside pluginHook after the shared permission/secret
// prelude, so local SDK plugins get exactly the same enforcement as builtin
// and external plugins; the result flows through the same PluginResponse
// wrapping.
func (a *App) localPluginFunc(pluginInfo *plugin.PluginInfo, modulePath, accountName, functionName string) StarlarkFunction {
	return func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		ctx := GetContext(thread)
		if ctx == nil {
			ctx = context.Background()
		}

		// Acquire (or reuse) the request's pinned host and session first: the
		// registered session keeps the host open through module init and the
		// call itself, even when a reload retires the host concurrently
		host, sessionId, err := a.getLocalHostSession(thread, pluginInfo.ProviderName)
		if err != nil {
			return nil, err
		}

		settings := map[string]any(a.plugins.GetPluginSettings(pluginInfo.PluginPath, accountName))
		if provider, ok := getLocalProvider(pluginInfo.ProviderName); ok && provider.Options.SettingsHook != nil {
			settings = provider.Options.SettingsHook(a, pluginInfo.ModuleName, settings)
		}
		if err := host.InitModule(ctx, pluginInfo.ModuleName, accountName, settings); err != nil {
			return nil, fmt.Errorf("error initializing plugin %s: %w", modulePath, err)
		}

		goArgs := make([]any, len(args))
		for i, arg := range args {
			dec, err := starlark_type.ToPlugin(arg, 0)
			if err != nil {
				return nil, fmt.Errorf("%s.%s argument %d: %w", modulePath, functionName, i, err)
			}
			goArgs[i] = dec
		}
		goKwargs := make([]sdk.Kwarg, len(kwargs))
		for i, kwarg := range kwargs {
			name, ok := kwarg[0].(starlark.String)
			if !ok {
				return nil, fmt.Errorf("%s.%s: invalid keyword argument name", modulePath, functionName)
			}
			dec, err := starlark_type.ToPlugin(kwarg[1], 0)
			if err != nil {
				return nil, fmt.Errorf("%s.%s keyword argument %s: %w", modulePath, functionName, name, err)
			}
			goKwargs[i] = sdk.Kwarg{Name: string(name), Value: dec}
		}

		funcRefFn := a.localFuncRefFn(host, pluginInfo, accountName, sessionId, thread)
		result, err := host.Call(ctx, &sdk.HostCall{
			Module:    pluginInfo.ModuleName,
			Account:   accountName,
			Function:  functionName,
			Args:      goArgs,
			Kwargs:    goKwargs,
			Thread:    a.buildSDKThreadState(thread),
			SessionId: sessionId,
			Host:      threadHostServices{thread: thread},
		})
		if result != nil {
			// Mirror the session's strict deferred-cleanup keys as strict
			// host-side entries, so a strict resource (e.g. a result set the
			// app must consume) still registered at request end fails the
			// request as a leak, like builtin plugins
			syncExtStrictDefers(thread, "local:"+pluginInfo.ProviderName, pluginInfo.PluginPath, result.StrictKeys)
		}
		if err != nil {
			if perr, ok := err.(*sdk.ProviderError); ok && perr.Code > 1 {
				// The thread must be attached so an explicit error check by
				// the app clears the thread-local failure state
				return NewErrorCodeResponseThread(int(perr.Code), perr, nil, thread), nil
			}
			return nil, err
		}

		if result.Cursor != nil && result.Cursor.Stream {
			// Stream cursor: the app returns it from the handler as a
			// streaming HTTP response, consumed after the request's plugin
			// cleanup has run. Detach it from the session so session end does
			// not close it; the range function owns closing it.
			cursor, err := host.DetachCursor(sessionId, result.Cursor.CursorId)
			if err != nil {
				return nil, err
			}
			return NewStreamResponse(cursorRangeFunc(cursor)), nil
		}

		if result.Cursor != nil {
			// Register the strict cleanup entry under the provider-supplied
			// leak key: an unconsumed cursor fails the request the same way
			// an unconsumed builtin cursor does
			cursorId := result.Cursor.CursorId
			DeferCleanup(thread, result.Cursor.LeakKey, func() error {
				return host.CursorClose(context.Background(), sessionId, cursorId)
			}, true)
			return &localIterable{
				app:       a,
				host:      host,
				thread:    thread,
				sessionId: sessionId,
				cursorId:  cursorId,
				typeName:  result.Cursor.TypeName,
				leakKey:   result.Cursor.LeakKey,
				// The cleanup entry is cleared when iteration completes,
				// which may run while another plugin is the current module;
				// remember the registering module so the right map is cleared
				modulePath: pluginInfo.PluginPath,
				funcRefFn:  funcRefFn,
			}, nil
		}
		return starlark_type.FromPlugin(result.Value, 0, funcRefFn)
	}
}

// localFuncRefFn builds the materializer for sdk.FuncRef values returned by
// an in-process module: the ref becomes a zero-argument callable that
// dispatches the referenced plugin function in the same module, account, and
// session. Unlike top-level plugin calls, a func ref call's error propagates
// as a starlark error (matching the previous behavior of member callables
// like response.body()), not as a PluginResponse.
func (a *App) localFuncRefFn(host *sdk.Host, pluginInfo *plugin.PluginInfo, accountName, sessionId string, thread *starlark.Thread) starlark_type.FuncRefValueFunc {
	var funcRefFn starlark_type.FuncRefValueFunc
	funcRefFn = func(ref *sdk.FuncRef) (starlark.Value, error) {
		function := ref.Function
		args := ref.Args
		return starlark.NewBuiltin(function, func(t *starlark.Thread, b *starlark.Builtin, callArgs starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(function, callArgs, kwargs); err != nil {
				return nil, err
			}
			ctx := GetContext(thread)
			if ctx == nil {
				ctx = context.Background()
			}
			result, err := host.Call(ctx, &sdk.HostCall{
				Module:    pluginInfo.ModuleName,
				Account:   accountName,
				Function:  function,
				Args:      args,
				Thread:    a.buildSDKThreadState(thread),
				SessionId: sessionId,
				Host:      threadHostServices{thread: thread},
			})
			if result != nil {
				syncExtStrictDefers(thread, "local:"+pluginInfo.ProviderName, pluginInfo.PluginPath, result.StrictKeys)
			}
			if err != nil {
				return nil, err
			}
			if result.Cursor != nil {
				return nil, fmt.Errorf("%s: a func ref call cannot return a cursor", function)
			}
			return starlark_type.FromPlugin(result.Value, 0, funcRefFn)
		}), nil
	}
	return funcRefFn
}

// cursorRangeFunc adapts a detached stream cursor to the range function
// shape handleStreamResponse consumes: items are yielded as plain Go values
// and the cursor is closed when the consumer stops early or a batch fails.
// A cursor that reports done has already closed itself.
func cursorRangeFunc(cursor *sdk.Cursor) func(yield func(any, error) bool) {
	return func(yield func(any, error) bool) {
		closed := false
		defer func() {
			if !closed && cursor.Close != nil {
				cursor.Close(context.Background()) //nolint:errcheck
			}
		}()
		for {
			items, done, err := cursor.Next(context.Background(), cursorBatchSize)
			if err != nil {
				yield(nil, err)
				return
			}
			for _, item := range items {
				if !yield(item, nil) {
					return
				}
			}
			if done {
				closed = true
				return
			}
		}
	}
}

func (a *App) buildSDKThreadState(thread *starlark.Thread) sdk.ThreadState {
	state := sdk.ThreadState{
		AppUrl: system.GetThreadLocalKey(thread, types.TL_APP_URL),
	}
	ctx := GetContext(thread)
	if ctx != nil {
		state.RequestId = system.GetContextRequestId(ctx)
		state.UserId = system.GetContextUserId(ctx)
		state.UserSubject = system.GetContextUserSubject(ctx)
		state.UserEmail = system.GetContextUserEmail(ctx)
		state.Groups = system.GetContextGroups(ctx)
	}
	return state
}

// localIterable wraps an in-process host cursor as a starlark iterable,
// batching CursorNext calls. It mirrors remoteIterable: the strict cleanup
// entry is cleared in Done (run by the interpreter when a for loop over the
// iterable finishes), and a cursor the app never iterates is reported as a
// leaked resource at request end.
type localIterable struct {
	app        *App
	host       *sdk.Host
	thread     *starlark.Thread
	sessionId  string
	cursorId   string
	typeName   string
	leakKey    string
	modulePath string // module the leak-key cleanup entry is registered under
	funcRefFn  starlark_type.FuncRefValueFunc
}

var _ starlark.Iterable = (*localIterable)(nil)

func (r *localIterable) Iterate() starlark.Iterator {
	return &localIterator{r: r}
}

func (r *localIterable) String() string {
	return r.Type()
}

func (r *localIterable) Type() string {
	return r.typeName + " iterator"
}

func (r *localIterable) Freeze() {
	// Not supported
}

func (r *localIterable) Truth() starlark.Bool {
	return true
}

func (r *localIterable) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: %s", r.Type())
}

type localIterator struct {
	r    *localIterable
	buf  []starlark.Value
	done bool
}

var _ starlark.Iterator = (*localIterator)(nil)

func (i *localIterator) Next(value *starlark.Value) bool {
	if len(i.buf) == 0 && !i.done {
		ctx := GetContext(i.r.thread)
		if ctx == nil {
			ctx = context.Background()
		}
		goItems, done, err := i.r.host.CursorNext(ctx, i.r.sessionId, i.r.cursorId, cursorBatchSize)
		if err != nil {
			// starlark.Iterator.Next cannot return an error; the builtin
			// store iterator panics on row errors, and the handler's panic
			// recovery turns it into a request failure
			panic(err)
		}
		items := make([]starlark.Value, len(goItems))
		for idx, item := range goItems {
			dec, decErr := starlark_type.FromPlugin(item, 0, i.r.funcRefFn)
			if decErr != nil {
				panic(decErr)
			}
			items[idx] = dec
		}
		i.buf = items
		i.done = done
	}

	if len(i.buf) == 0 {
		return false
	}
	*value = i.buf[0]
	i.buf = i.buf[1:]
	return true
}

func (i *localIterator) Done() {
	// Clear the strict cleanup entry and release the host-side cursor; both
	// are no-ops if the cursor was already drained. The entry is cleared
	// under its registering module: Done can run while another plugin is the
	// current module (calls to other plugins between select and iteration)
	ClearCleanupModule(i.r.thread, i.r.modulePath, i.r.leakKey)
	if err := i.r.host.CursorClose(context.Background(), i.r.sessionId, i.r.cursorId); err != nil {
		i.r.app.Warn().Err(err).Msgf("error closing plugin cursor %s", i.r.cursorId)
	}
}
