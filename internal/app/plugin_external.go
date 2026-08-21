// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	goplugin "github.com/hashicorp/go-plugin"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
	pb "github.com/openrundev/openrun/pkg/plugin/proto"
	"go.starlark.net/starlark"
	"google.golang.org/protobuf/encoding/protojson"
)

// External plugin providers serve Starlark plugin modules (loaded as
// "name.ex") from separate provider processes, over the gRPC protocol in
// pkg/plugin. The registry below is process-global, like builtInPlugins: it
// records which provider executable serves which modules, along with the
// function manifests captured from Describe at registration time, so module
// loading and audit never launch a provider process. Provider processes are
// per app, managed by extPluginProcs on each App.

// ExternalProvider is one registered plugin provider executable and the
// modules it serves.
type ExternalProvider struct {
	Name     string
	ExecPath string
	Sha256   string // hex sha256 of the executable, "" skips verification (dev)
	Version  string

	pluginMaps map[string]plugin.PluginMap // "store.ex" -> function map
}

var (
	extProviderMutex sync.RWMutex
	extProviders     = map[string]*ExternalProvider{} // by provider name
	extModules       = map[string]*ExternalProvider{} // "store.ex" -> owner
)

// RegisterExternalProvider launches the provider executable briefly to
// Describe its modules and registers them for loading as "<module>.ex".
// A provider registered under the same name is replaced; a module served by
// a different provider is a conflict.
func RegisterExternalProvider(name, execPath, sha256Hex string) error {
	version, _, manifest, err := DescribeExternalProviderManifest(context.Background(), execPath, sha256Hex)
	if err != nil {
		return fmt.Errorf("plugin provider %s: %w", name, err)
	}
	return registerExternalProvider(name, execPath, sha256Hex, version, manifest)
}

// DescribeExternalProviderManifest launches a plugin provider executable
// briefly and returns its version, the served module names, and the module
// manifest serialized as JSON. The manifest can be persisted (it is stored in
// the provider database row at install time) and later registered with
// RegisterExternalProviderManifest without launching the provider again.
func DescribeExternalProviderManifest(ctx context.Context, execPath, sha256Hex string) (string, []string, string, error) {
	provider, err := launchProviderProcess(execPath, sha256Hex, "WARN")
	if err != nil {
		return "", nil, "", fmt.Errorf("error launching plugin provider: %w", err)
	}
	defer provider.Kill()

	describe, err := provider.Describe(ctx)
	if err != nil {
		return "", nil, "", fmt.Errorf("error describing plugin provider: %w", err)
	}
	if len(describe.GetModules()) == 0 {
		return "", nil, "", fmt.Errorf("plugin provider serves no modules")
	}

	moduleNames := make([]string, 0, len(describe.GetModules()))
	for _, manifest := range describe.GetModules() {
		moduleNames = append(moduleNames, manifest.GetName())
	}
	manifestJson, err := protojson.Marshal(describe)
	if err != nil {
		return "", nil, "", fmt.Errorf("error serializing plugin provider manifest: %w", err)
	}
	return describe.GetProviderVersion(), moduleNames, string(manifestJson), nil
}

// RegisterExternalProviderManifest registers a plugin provider from a
// previously captured manifest (see DescribeExternalProviderManifest),
// without launching the provider executable. This is the database-backed
// install path: replicas register modules from the stored manifest, and the
// provider process is only launched when an app calls one of its modules.
func RegisterExternalProviderManifest(name, execPath, sha256Hex, manifestJson string) error {
	describe := &pb.DescribeResponse{}
	if err := protojson.Unmarshal([]byte(manifestJson), describe); err != nil {
		return fmt.Errorf("plugin provider %s: invalid stored manifest: %w", name, err)
	}
	if len(describe.GetModules()) == 0 {
		return fmt.Errorf("plugin provider %s: stored manifest has no modules", name)
	}
	return registerExternalProvider(name, execPath, sha256Hex, describe.GetProviderVersion(), manifestJson)
}

func registerExternalProvider(name, execPath, sha256Hex, version, manifestJson string) error {
	describe := &pb.DescribeResponse{}
	if err := protojson.Unmarshal([]byte(manifestJson), describe); err != nil {
		return fmt.Errorf("plugin provider %s: invalid manifest: %w", name, err)
	}

	entry := &ExternalProvider{
		Name:       name,
		ExecPath:   execPath,
		Sha256:     sha256Hex,
		Version:    version,
		pluginMaps: map[string]plugin.PluginMap{},
	}
	for _, manifest := range describe.GetModules() {
		// Each module is registered under both suffixes: "name.ex" (explicit
		// external load) and "name.in" (used when no internal module of that
		// name exists; pluginLookup gives internal modules precedence). The
		// maps are built per path so permissions and settings match the path
		// the app loaded.
		for _, suffix := range []string{apptype.EXTERNAL_PLUGIN_SUFFIX, apptype.BUILTIN_PLUGIN_SUFFIX} {
			pluginPath := manifest.GetName() + "." + suffix
			pluginMap, err := manifestToPluginMap(name, pluginPath, manifest)
			if err != nil {
				return fmt.Errorf("plugin provider %s module %s: %w", name, manifest.GetName(), err)
			}
			entry.pluginMaps[pluginPath] = pluginMap
		}
	}

	extProviderMutex.Lock()
	defer extProviderMutex.Unlock()
	for pluginPath := range entry.pluginMaps {
		if owner, ok := extModules[pluginPath]; ok && owner.Name != name {
			return fmt.Errorf("plugin module %s is already served by provider %s", pluginPath, owner.Name)
		}
	}
	if prev, ok := extProviders[name]; ok {
		for pluginPath := range prev.pluginMaps {
			delete(extModules, pluginPath)
		}
	}
	extProviders[name] = entry
	for pluginPath := range entry.pluginMaps {
		extModules[pluginPath] = entry
	}
	return nil
}

// GetExternalProviderInfo returns a registered provider's executable path
// and served module paths (e.g. "store.ex"), for tests and diagnostics.
func GetExternalProviderInfo(name string) (string, []string, bool) {
	extProviderMutex.RLock()
	defer extProviderMutex.RUnlock()
	provider, ok := extProviders[name]
	if !ok {
		return "", nil, false
	}
	modules := make([]string, 0, len(provider.pluginMaps))
	for pluginPath := range provider.pluginMaps {
		modules = append(modules, pluginPath)
	}
	slices.Sort(modules)
	return provider.ExecPath, modules, true
}

// UnregisterExternalProvider removes a provider and its modules from the
// registry. Running per-app provider processes are not affected; they are
// torn down with their apps.
func UnregisterExternalProvider(name string) {
	extProviderMutex.Lock()
	defer extProviderMutex.Unlock()
	prev, ok := extProviders[name]
	if !ok {
		return
	}
	for pluginPath := range prev.pluginMaps {
		delete(extModules, pluginPath)
	}
	delete(extProviders, name)
}

func manifestToPluginMap(providerName, pluginPath string, manifest *pb.ModuleManifest) (plugin.PluginMap, error) {
	pluginMap := make(plugin.PluginMap)
	for _, fn := range manifest.GetFunctions() {
		if strings.HasPrefix(fn.GetName(), "_") {
			// Internal function: callable only through a FuncRef, not
			// exposed as a module attribute
			continue
		}
		pluginMap[fn.GetName()] = &plugin.PluginInfo{
			ModuleName:   manifest.GetName(),
			PluginPath:   pluginPath,
			FuncName:     fn.GetName(),
			IsRead:       fn.GetIsRead(),
			HandlerName:  fn.GetName(),
			Remote:       true,
			ProviderName: providerName,
		}
	}
	for constName, constValue := range manifest.GetConstants() {
		value, err := starlark_type.FromWire(constValue, nil, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("constant %s: %w", constName, err)
		}
		pluginMap[constName] = &plugin.PluginInfo{
			ModuleName:    manifest.GetName(),
			PluginPath:    pluginPath,
			FuncName:      constName,
			ConstantValue: value,
			Remote:        true,
			ProviderName:  providerName,
		}
	}
	return pluginMap, nil
}

// lookupExternalPlugin resolves a "name.ex" module path from the registry.
func lookupExternalPlugin(modulePath string) (plugin.PluginMap, error) {
	extProviderMutex.RLock()
	defer extProviderMutex.RUnlock()
	provider, ok := extModules[modulePath]
	if !ok {
		return nil, fmt.Errorf("module %s not found: no plugin provider serves it", modulePath)
	}
	return provider.pluginMaps[modulePath], nil
}

func getExternalProvider(name string) (*ExternalProvider, bool) {
	extProviderMutex.RLock()
	defer extProviderMutex.RUnlock()
	provider, ok := extProviders[name]
	return provider, ok
}

func launchProviderProcess(execPath, sha256Hex, logLevel string) (*sdk.Provider, error) {
	var secureConfig *goplugin.SecureConfig
	if sha256Hex != "" {
		checksum, err := hex.DecodeString(sha256Hex)
		if err != nil {
			return nil, fmt.Errorf("invalid provider checksum: %w", err)
		}
		secureConfig = &goplugin.SecureConfig{Checksum: checksum, Hash: sha256.New()}
	}
	return sdk.LaunchProvider(sdk.LaunchConfig{
		ExecPath:     execPath,
		LogLevel:     logLevel,
		SecureConfig: secureConfig,
	})
}

// extPluginProcs manages one provider process per (app, provider) pair.
type extPluginProcs struct {
	mu     sync.Mutex
	procs  map[string]*extProc
	closed bool // terminal: no relaunch after app close
}

type extProc struct {
	providerName string
	provider     *sdk.Provider

	mu            sync.Mutex
	initedModules map[string]bool // "module\x00account"
	dead          bool
	// retiring marks a process being replaced (app reload): in-flight
	// requests finish on it, and it is killed when its last active session
	// ends. activeSessions counts the request sessions opened on it
	retiring       bool
	activeSessions int
}

func newExtPluginProcs() *extPluginProcs {
	return &extPluginProcs{procs: map[string]*extProc{}}
}

// stopAll retires every provider process but leaves the manager usable: the
// next .ex call relaunches a fresh process from the reloaded schema and
// settings, while in-flight requests finish on the old processes (each is
// killed once its last active session ends). Used on app reload. Safe on a
// nil receiver: tests construct App literals without NewApp.
func (e *extPluginProcs) stopAll() {
	e.stop(false)
}

// shutdown kills every provider process immediately and prevents any
// relaunch: a concurrent request that races app close cannot leave a
// provider process running after Close returns. Used on app close.
func (e *extPluginProcs) shutdown() {
	e.stop(true)
}

func (e *extPluginProcs) stop(terminal bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	procs := e.procs
	e.procs = map[string]*extProc{}
	if terminal {
		e.closed = true
	}
	e.mu.Unlock()
	for _, proc := range procs {
		if terminal {
			proc.markDead()
		} else {
			proc.retire()
		}
	}
}

// getExtProc returns the app's provider process, launching and app-
// initializing it on first use or after a crash. The returned process
// carries a session lease (sessionStarted), taken while holding the manager
// mutex so a concurrent reload cannot observe zero active sessions and kill
// the process before the caller registers its request session; the caller
// owes a matching sessionEnded.
func (a *App) getExtProc(providerName string) (*extProc, error) {
	a.extProcs.mu.Lock()
	defer a.extProcs.mu.Unlock()
	if a.extProcs.closed {
		return nil, fmt.Errorf("app %s is closed, plugin provider %s is not available", a.Path, providerName)
	}

	registered, ok := getExternalProvider(providerName)
	if !ok {
		return nil, fmt.Errorf("plugin provider %s is not registered", providerName)
	}

	if proc, ok := a.extProcs.procs[providerName]; ok && !proc.isDead() {
		proc.sessionStarted()
		return proc, nil
	}

	provider, err := launchProviderProcess(registered.ExecPath, registered.Sha256, "WARN")
	if err != nil {
		return nil, fmt.Errorf("error launching plugin provider %s: %w", providerName, err)
	}

	var appSchema []byte
	if a.storeInfo != nil {
		appSchema = a.storeInfo.Bytes
	}
	initErr := provider.InitApp(context.Background(), &pb.InitAppRequest{
		AppId:     string(a.Id),
		AppPath:   a.Path,
		IsDev:     a.IsDev,
		AppSchema: appSchema,
	})
	if initErr != nil {
		provider.Kill()
		return nil, fmt.Errorf("error initializing plugin provider %s for app %s: %w", providerName, a.Path, initErr)
	}

	proc := &extProc{
		providerName:  providerName,
		provider:      provider,
		initedModules: map[string]bool{},
	}
	proc.sessionStarted()
	a.extProcs.procs[providerName] = proc
	return proc, nil
}

func (p *extProc) isDead() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dead || p.provider.Exited()
}

// markDead records a transport failure: the process is killed and the next
// call launches a fresh one. In-flight sessions are lost; plugin calls are
// never retried automatically.
func (p *extProc) markDead() {
	p.mu.Lock()
	alreadyDead := p.dead
	p.dead = true
	p.mu.Unlock()
	if !alreadyDead {
		p.provider.Kill()
	}
}

// retire marks a process being replaced (app reload): it is killed once its
// last active session ends, or immediately when none are active, so requests
// in flight during the reload finish instead of failing mid-call.
func (p *extProc) retire() {
	p.mu.Lock()
	if p.dead {
		p.mu.Unlock()
		return
	}
	p.retiring = true
	kill := p.activeSessions <= 0
	if kill {
		p.dead = true
	}
	p.mu.Unlock()
	if kill {
		p.provider.Kill()
	}
}

// sessionStarted counts a request session opened on this process.
func (p *extProc) sessionStarted() {
	p.mu.Lock()
	p.activeSessions++
	p.mu.Unlock()
}

// sessionEnded is the drain trigger for a retiring process: the last active
// session ending kills it.
func (p *extProc) sessionEnded() {
	p.mu.Lock()
	p.activeSessions--
	kill := p.retiring && p.activeSessions <= 0 && !p.dead
	if kill {
		p.dead = true
	}
	p.mu.Unlock()
	if kill {
		p.provider.Kill()
	}
}

// ensureModule lazily initializes the (module, account) instance in the
// provider process, mirroring AppPlugins.GetPlugin instance caching.
func (p *extProc) ensureModule(ctx context.Context, moduleName, accountName string, settings types.PluginSettings) error {
	key := moduleName + "\x00" + accountName
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.initedModules[key] {
		return nil
	}

	settingsWire, err := sdk.EncodeValueMap(settings)
	if err != nil {
		return fmt.Errorf("plugin settings for %s are not transportable: %w", moduleName, err)
	}
	if err := p.provider.InitModule(ctx, &pb.InitModuleRequest{
		Module:   moduleName,
		Account:  accountName,
		Settings: settingsWire,
	}); err != nil {
		return err
	}
	p.initedModules[key] = true
	return nil
}

var extSessionCounter atomic.Uint64

const extSessionLocalPrefix = "openrun_ex_session_"

// extProcSession pins a request to one provider process: every plugin call
// of the request uses the same process and session, even when a reload
// retires it mid-request (the session lease keeps it alive until request
// end). Without the pin, a call after the reload would go to the replacement
// process while the session and its cleanup stayed bound to the retired one.
type extProcSession struct {
	proc      *extProc
	sessionId string
}

// getExtProcSession returns the request's pinned provider process and
// session id, acquiring and pinning them on first use. The process is leased
// by getExtProc before it is visible outside the manager mutex, so a reload
// racing this call cannot kill it; the lease is released by the session's
// deferred cleanup at request end. Session end (provider-side transactions
// roll back, cursors close) rides the existing deferred-cleanup mechanism,
// so it runs exactly where plugin cleanup already runs for handlers and
// actions.
func (a *App) getExtProcSession(thread *starlark.Thread, providerName string) (*extProc, string, error) {
	localKey := extSessionLocalPrefix + providerName
	if v := thread.Local(localKey); v != nil {
		ps := v.(*extProcSession)
		return ps.proc, ps.sessionId, nil
	}

	proc, err := a.getExtProc(providerName)
	if err != nil {
		return nil, "", err
	}
	sessionId := fmt.Sprintf("%s-%d", a.Id, extSessionCounter.Add(1))
	thread.SetLocal(localKey, &extProcSession{proc: proc, sessionId: sessionId})
	DeferCleanup(thread, "session_"+sessionId, func() error {
		// sessionEnded after EndSession: a retiring process (replaced by an
		// app reload) is killed when its last active session ends, so this
		// request's provider-side cleanup still ran
		defer proc.sessionEnded()
		if proc.isDead() {
			return nil // session state died with the process
		}
		if err := proc.provider.EndSession(context.Background(), &pb.EndSessionRequest{SessionId: sessionId}); err != nil {
			a.Warn().Err(err).Msgf("error ending plugin session %s on provider %s", sessionId, proc.providerName)
		}
		return nil
	}, false)
	return proc, sessionId, nil
}

// remotePluginFunc builds the dispatch function for an external plugin call.
// It runs inside pluginHook after the shared permission/secret prelude, so
// external plugins get exactly the same enforcement as builtin plugins; the
// result flows through the same PluginResponse wrapping.
func (a *App) remotePluginFunc(pluginInfo *plugin.PluginInfo, modulePath, accountName, functionName string) StarlarkFunction {
	return func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		ctx := GetContext(thread)
		if ctx == nil {
			ctx = context.Background()
		}

		// Acquire (or reuse) the request's pinned process and session first:
		// the pin's session lease keeps the process alive through module
		// init, argument conversion, and the call itself, even when a reload
		// retires the process concurrently
		proc, sessionId, err := a.getExtProcSession(thread, pluginInfo.ProviderName)
		if err != nil {
			return nil, err
		}

		settings := a.plugins.GetPluginSettings(pluginInfo.PluginPath, accountName)
		if err := proc.ensureModule(ctx, pluginInfo.ModuleName, accountName, settings); err != nil {
			if _, ok := err.(*sdk.ProviderError); !ok {
				proc.markDead()
			}
			return nil, fmt.Errorf("error initializing plugin %s: %w", modulePath, err)
		}

		wireArgs := make([]*pb.StarValue, len(args))
		for i, arg := range args {
			enc, err := starlark_type.ToWire(arg, 0)
			if err != nil {
				return nil, fmt.Errorf("%s.%s argument %d: %w", modulePath, functionName, i, err)
			}
			wireArgs[i] = enc
		}
		wireKwargs := make([]*pb.Kwarg, len(kwargs))
		for i, kwarg := range kwargs {
			name, ok := kwarg[0].(starlark.String)
			if !ok {
				return nil, fmt.Errorf("%s.%s: invalid keyword argument name", modulePath, functionName)
			}
			enc, err := starlark_type.ToWire(kwarg[1], 0)
			if err != nil {
				return nil, fmt.Errorf("%s.%s keyword argument %s: %w", modulePath, functionName, name, err)
			}
			wireKwargs[i] = &pb.Kwarg{Name: string(name), Value: enc}
		}

		resp, err := proc.provider.Call(ctx, &pb.CallRequest{
			Module:    pluginInfo.ModuleName,
			Account:   accountName,
			Function:  functionName,
			Args:      wireArgs,
			Kwargs:    wireKwargs,
			Thread:    a.buildThreadState(thread),
			SessionId: sessionId,
		})
		if resp != nil {
			// Mirror the session's strict deferred-cleanup keys as strict
			// host-side entries, so a strict provider resource (e.g. a
			// result set the app must consume) still registered at request
			// end fails the request as a leak, like builtin plugins
			syncExtStrictDefers(thread, proc.providerName, pluginInfo.PluginPath, resp.GetStrictKeys())
		}
		if err != nil {
			perr, ok := err.(*sdk.ProviderError)
			if !ok {
				// Transport failure: the process (and its sessions) are gone
				proc.markDead()
				return nil, fmt.Errorf("plugin provider %s failed: %w", pluginInfo.ProviderName, err)
			}
			if perr.Code > 1 {
				// The thread must be attached so an explicit error check by
				// the app clears the thread-local failure state
				return NewErrorCodeResponseThread(int(perr.Code), perr, nil, thread), nil
			}
			return nil, perr
		}

		// funcRefFn materializes a returned func ref as a zero-argument
		// callable dispatching the referenced function over the same
		// provider session. Errors propagate as starlark errors (matching
		// member callables like response.body()), not as a PluginResponse
		var funcRefFn starlark_type.WireFuncRefFunc
		funcRefFn = func(ref *pb.FuncRef) (starlark.Value, error) {
			function := ref.GetFunction()
			refArgs := ref.GetArgs()
			return starlark.NewBuiltin(function, func(t *starlark.Thread, b *starlark.Builtin, callArgs starlark.Tuple, callKwargs []starlark.Tuple) (starlark.Value, error) {
				if err := starlark.UnpackArgs(function, callArgs, callKwargs); err != nil {
					return nil, err
				}
				refCtx := GetContext(thread)
				if refCtx == nil {
					refCtx = context.Background()
				}
				resp, err := proc.provider.Call(refCtx, &pb.CallRequest{
					Module:    pluginInfo.ModuleName,
					Account:   accountName,
					Function:  function,
					Args:      refArgs,
					Thread:    a.buildThreadState(thread),
					SessionId: sessionId,
				})
				if resp != nil {
					syncExtStrictDefers(thread, proc.providerName, pluginInfo.PluginPath, resp.GetStrictKeys())
				}
				if err != nil {
					if _, ok := err.(*sdk.ProviderError); !ok {
						proc.markDead()
						return nil, fmt.Errorf("plugin provider %s failed: %w", pluginInfo.ProviderName, err)
					}
					return nil, err
				}
				return starlark_type.FromWire(resp.GetValue(), nil, funcRefFn, 0)
			}), nil
		}

		cursorFn := func(cursor *pb.Cursor) (starlark.Value, error) {
			if cursor.GetStream() {
				return nil, fmt.Errorf("%s.%s: streaming responses are not supported for external plugins", modulePath, functionName)
			}
			// Register the strict cleanup entry under the provider-supplied
			// leak key: an unconsumed cursor fails the request the same way
			// an unconsumed builtin cursor does
			cursorId := cursor.GetCursorId()
			DeferCleanup(thread, cursor.GetLeakKey(), func() error {
				if proc.isDead() {
					return nil
				}
				return proc.provider.CursorClose(context.Background(), &pb.CursorCloseRequest{
					SessionId: sessionId,
					CursorId:  cursorId,
				})
			}, true)
			return &remoteIterable{
				app:       a,
				proc:      proc,
				thread:    thread,
				sessionId: sessionId,
				cursorId:  cursorId,
				typeName:  cursor.GetTypeName(),
				leakKey:   cursor.GetLeakKey(),
				// The cleanup entry is cleared when iteration completes,
				// which may run while another plugin is the current module;
				// remember the registering module so the right map is cleared
				modulePath: pluginInfo.PluginPath,
			}, nil
		}
		return starlark_type.FromWire(resp.GetValue(), cursorFn, funcRefFn, 0)
	}
}

const extStrictLocalPrefix = "openrun_ex_strict_"

// syncExtStrictDefers reconciles the host-side strict cleanup entries with
// the provider session's strict deferred-cleanup keys, reported after every
// call. New keys register a strict entry (its presence at request end fails
// the request; the resource itself is released by EndSession); keys the
// provider has cleared (e.g. a committed transaction) remove their entry.
func syncExtStrictDefers(thread *starlark.Thread, providerName, modulePath string, strictKeys []string) {
	localKey := extStrictLocalPrefix + providerName
	mirrored, _ := thread.Local(localKey).(map[string]string) // key -> registering module path
	if mirrored == nil {
		if len(strictKeys) == 0 {
			return
		}
		mirrored = map[string]string{}
		thread.SetLocal(localKey, mirrored)
	}

	current := make(map[string]bool, len(strictKeys))
	for _, key := range strictKeys {
		current[key] = true
		if _, ok := mirrored[key]; !ok {
			// The resource is released by EndSession at request end; the
			// entry exists for its strict leak reporting
			DeferCleanupModule(thread, modulePath, key, func() error { return nil }, true)
			mirrored[key] = modulePath
		}
	}
	for key, owner := range mirrored {
		if !current[key] {
			ClearCleanupModule(thread, owner, key)
			delete(mirrored, key)
		}
	}
}

func (a *App) buildThreadState(thread *starlark.Thread) *pb.ThreadState {
	state := &pb.ThreadState{
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

// remoteIterable wraps a provider-side cursor as a starlark iterable,
// batching CursorNext calls. It mirrors the in-process cursor iterable
// contract: the strict cleanup entry is cleared in Done (run by the
// interpreter when a for loop over the iterable finishes), and a cursor the
// app never iterates is reported as a leaked resource at request end.
type remoteIterable struct {
	app        *App
	proc       *extProc
	thread     *starlark.Thread
	sessionId  string
	cursorId   string
	typeName   string
	leakKey    string
	modulePath string // module the leak-key cleanup entry is registered under
}

var _ starlark.Iterable = (*remoteIterable)(nil)

func (r *remoteIterable) Iterate() starlark.Iterator {
	return &remoteIterator{r: r}
}

func (r *remoteIterable) String() string {
	return r.Type()
}

func (r *remoteIterable) Type() string {
	return r.typeName + " iterator"
}

func (r *remoteIterable) Freeze() {
	// Not supported
}

func (r *remoteIterable) Truth() starlark.Bool {
	return true
}

func (r *remoteIterable) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: %s", r.Type())
}

const cursorBatchSize = 100

type remoteIterator struct {
	r    *remoteIterable
	buf  []starlark.Value
	done bool
}

var _ starlark.Iterator = (*remoteIterator)(nil)

func (i *remoteIterator) Next(value *starlark.Value) bool {
	if len(i.buf) == 0 && !i.done {
		ctx := GetContext(i.r.thread)
		if ctx == nil {
			ctx = context.Background()
		}
		resp, err := i.r.proc.provider.CursorNext(ctx, &pb.CursorNextRequest{
			SessionId: i.r.sessionId,
			CursorId:  i.r.cursorId,
			MaxItems:  cursorBatchSize,
		})
		if err != nil {
			if _, ok := err.(*sdk.ProviderError); !ok {
				i.r.proc.markDead()
			}
			// starlark.Iterator.Next cannot return an error; the builtin
			// store iterator panics on row errors, and the handler's panic
			// recovery turns it into a request failure
			panic(err)
		}
		items := make([]starlark.Value, len(resp.GetItems()))
		for idx, item := range resp.GetItems() {
			dec, decErr := starlark_type.FromWire(item, nil, nil, 0)
			if decErr != nil {
				panic(decErr)
			}
			items[idx] = dec
		}
		i.buf = items
		i.done = resp.GetDone()
	}

	if len(i.buf) == 0 {
		return false
	}
	*value = i.buf[0]
	i.buf = i.buf[1:]
	return true
}

func (i *remoteIterator) Done() {
	// Clear the strict cleanup entry and release the provider-side cursor;
	// both are no-ops if the cursor was already drained. The entry is cleared
	// under its registering module: Done can run while another plugin is the
	// current module (calls to other plugins between select and iteration)
	ClearCleanupModule(i.r.thread, i.r.modulePath, i.r.leakKey)
	if i.r.proc.isDead() {
		return
	}
	if err := i.r.proc.provider.CursorClose(context.Background(), &pb.CursorCloseRequest{
		SessionId: i.r.sessionId,
		CursorId:  i.r.cursorId,
	}); err != nil {
		i.r.app.Warn().Err(err).Msgf("error closing plugin cursor %s", i.r.cursorId)
	}
}

// externalSuffixed reports whether the module path names an external plugin.
func externalSuffixed(modulePath string) bool {
	return strings.HasSuffix(modulePath, "."+apptype.EXTERNAL_PLUGIN_SUFFIX)
}
