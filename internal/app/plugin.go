// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/telemetry"
	"github.com/openrundev/openrun/internal/types"
	"go.opentelemetry.io/otel/attribute"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func init() {
	initFS()
}

type StarlarkFunction func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error)

// pluginErrorWrapper wraps the plugin function call with error handling code. If the plugin function returns an error,
// it is wrapped in a PluginResponse. If the starlark function returns a PluginResponse, it is returned as is. Returning
// a error causes the starlark interpreter to panic, so this wrapper is needed to handle the error and return a value which
// the starlark code can handle
func pluginErrorWrapper(f StarlarkFunction, errorHandler starlark.Callable) StarlarkFunction {
	return func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		// Wrap the plugin function call with error handling
		val, err := f(thread, fn, args, kwargs)

		// If the return value is already of type PluginResponse, return it without wrapping it
		resp, ok := val.(*PluginResponse)
		if ok {
			thread.SetLocal(types.TL_PLUGIN_API_FAILED_ERROR, resp.err)
			return val, err
		}

		// Update the thread local error state
		thread.SetLocal(types.TL_PLUGIN_API_FAILED_ERROR, err)

		if err != nil {
			// Error response wrapped in a PluginResponse
			return NewErrorResponse(err, thread), nil
		}

		// Success response, wrapped in a PluginResponse
		return NewResponse(val), nil
	}
}

func GetContext(thread *starlark.Thread) context.Context {
	c := thread.Local(types.TL_CONTEXT)
	if c == nil {
		return nil
	}
	return c.(context.Context)
}

// DeferCleanup defers a close function to call when the API handler is done
func DeferCleanup(thread *starlark.Thread, key string, deferFunc apptype.DeferFunc, strict bool) {
	pluginName := thread.Local(types.TL_CURRENT_MODULE_FULL_PATH)
	if pluginName == nil {
		panic(fmt.Errorf("plugin name not found in thread local"))
	}
	DeferCleanupModule(thread, pluginName.(string), key, deferFunc, strict)
}

// DeferCleanupModule is DeferCleanup with the owning module path passed
// explicitly instead of read from TL_CURRENT_MODULE_FULL_PATH. Use it when
// the entry may be registered outside the owning module's own call
func DeferCleanupModule(thread *starlark.Thread, modulePath, key string, deferFunc apptype.DeferFunc, strict bool) {
	deferMap := thread.Local(types.TL_DEFER_MAP)
	if deferMap == nil {
		deferMap = map[string]map[string]apptype.DeferEntry{}
	}

	pluginMap := deferMap.(map[string]map[string]apptype.DeferEntry)[modulePath]
	if pluginMap == nil {
		pluginMap = map[string]apptype.DeferEntry{}
	}

	pluginMap[key] = apptype.DeferEntry{Func: deferFunc, Strict: strict}
	deferMap.(map[string]map[string]apptype.DeferEntry)[modulePath] = pluginMap
	thread.SetLocal(types.TL_DEFER_MAP, deferMap)
}

// ClearCleanup clears a defer function from the thread local
func ClearCleanup(thread *starlark.Thread, key string) {
	pluginName := thread.Local(types.TL_CURRENT_MODULE_FULL_PATH)
	if pluginName == nil {
		panic(fmt.Errorf("plugin name not found in thread local"))
	}
	ClearCleanupModule(thread, pluginName.(string), key)
}

// ClearCleanupModule clears a defer entry registered under the given module
// path. Cleanup code can run when TL_CURRENT_MODULE_FULL_PATH points at a
// different plugin — a result cursor is often iterated after calls to other
// plugins — so code clearing an entry outside the owning module's own call
// must name the module explicitly or the wrong plugin's map is searched,
// leaving the entry registered and failing the request as a resource leak
func ClearCleanupModule(thread *starlark.Thread, modulePath, key string) {
	deferMap := thread.Local(types.TL_DEFER_MAP)
	if deferMap == nil {
		return
	}

	pluginMap := deferMap.(map[string]map[string]apptype.DeferEntry)[modulePath]
	if pluginMap == nil {
		return
	}

	delete(pluginMap, key)
	deferMap.(map[string]map[string]apptype.DeferEntry)[modulePath] = pluginMap
	thread.SetLocal(types.TL_DEFER_MAP, deferMap)
}

// loader is the starlark loader function
func (a *App) loader(thread *starlark.Thread, moduleFullPath string) (starlark.StringDict, error) {
	if strings.HasSuffix(moduleFullPath, apptype.STARLARK_FILE_SUFFIX) {
		// Load the starlark file rather than the plugin
		return a.loadStarlark(thread, moduleFullPath, a.starlarkCache)
	}

	allowedModules := append([]string{}, a.Metadata.Loads...)
	for _, p := range a.serverConfig.Permissions.Allow {
		allowedModules = append(allowedModules, p.Plugin)
	}

	if !slices.Contains(allowedModules, moduleFullPath) {
		return nil, fmt.Errorf("app %s is not permitted to load plugin %s. Audit the app and approve permissions", a.Path, moduleFullPath)
	}

	modulePath, moduleName, accountName := parseModulePath(moduleFullPath)
	plugin, err := a.pluginLookup(thread, modulePath)
	if err != nil {
		return nil, err
	}

	// Add calls to the hook function, which will do the permission checks at invocation time to
	// verify if the application has approval to call the specified function.
	// The audit loader will replace the builtins with dummy methods, so the hook is not added for the audit loader
	hookedDict := make(starlark.StringDict)
	for funcName, pluginInfo := range plugin {
		if pluginInfo.HandlerName == "" {
			hookedDict[funcName] = pluginInfo.ConstantValue
		} else {
			hookedDict[funcName] = a.pluginHook(a.AppPathDomain().String(), moduleFullPath, accountName, funcName, pluginInfo)
		}
	}

	ret := make(starlark.StringDict)
	ret[moduleName] = starlarkstruct.FromStringDict(starlarkstruct.Default, hookedDict)
	return ret, nil

}

func parseModulePath(moduleFullPath string) (string, string, string) {
	parts := strings.Split(moduleFullPath, apptype.ACCOUNT_SEPARATOR)
	modulePath := parts[0]
	moduleName := strings.TrimSuffix(modulePath, "."+apptype.BUILTIN_PLUGIN_SUFFIX)
	moduleName = strings.TrimSuffix(moduleName, "."+apptype.EXTERNAL_PLUGIN_SUFFIX)
	accountName := ""
	if len(parts) > 1 {
		accountName = parts[1]
	}
	return modulePath, moduleName, accountName
}

// pluginLookup looks up the plugin. Audit checks need to be done by the
// caller. Resolution order for "name.in": an in-process SDK plugin provider
// module (compiled into the binary), then an external provider module of the
// same name — so an app moves between a compiled-in and an external build of
// a plugin with no app change. "name.ex" always resolves to an external
// provider.
func (a *App) pluginLookup(_ *starlark.Thread, module string) (plugin.PluginMap, error) {
	if externalSuffixed(module) {
		// .ex modules are served by out-of-process plugin providers; the
		// function manifest was captured at provider registration, so lookup
		// does not launch a provider process
		return lookupExternalPlugin(module)
	}

	if pluginMap, ok := lookupLocalPlugin(module); ok {
		return pluginMap, nil
	}
	// No internal module: fall back to an external provider serving this
	// module name (registered under the .in path as well as .ex)
	if pluginMap, err := lookupExternalPlugin(module); err == nil {
		return pluginMap, nil
	}
	return nil, fmt.Errorf("module %s not found", module)
}

// SystemPluginsAllowed reports whether userId may invoke the privileged system
// plugins (openrun_admin, build): an authenticated (non-anonymous) caller, or
// any caller when security.unsafe_allow_system_plugins_anon is set. Shared by
// the pluginHook gate and the openrun plugin's system_plugins_allowed report,
// so the two cannot drift
func SystemPluginsAllowed(serverConfig *types.ServerConfig, userId string) bool {
	if serverConfig.Security.UnsafeAllowSystemPluginsAnon {
		return true
	}
	return userId != "" && userId != types.ANONYMOUS_USER
}

func (a *App) pluginHook(appPath, modulePath, accountName, functionName string, pluginInfo *plugin.PluginInfo) *starlark.Builtin {
	hook := func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		a.Trace().Msgf("Plugin called: %s.%s", modulePath, functionName)

		// Privileged system plugins (openrun_admin, build) require an
		// authenticated caller regardless of RBAC status, so a console app
		// accidentally served with none auth cannot run admin/builder ops. The
		// read-only openrun plugin is not marked and stays reachable.
		if pluginInfo.RequiresAuth &&
			!SystemPluginsAllowed(a.serverConfig, system.GetContextUserId(system.GetRequestContext(thread))) {
			return nil, fmt.Errorf("plugin %s requires an authenticated user", modulePath)
		}

		// Server config disallow list: a matching entry blocks the call for
		// every app, even when the app's approved permissions or the server
		// config allow list would permit it
		disallowed, err := matchesDisallowed(a.serverConfig.Permissions.Disallow, modulePath, functionName, args)
		if err != nil {
			return nil, err
		}
		if disallowed {
			return nil, fmt.Errorf("app %s is not permitted to call %s.%s: the call is disallowed by the server config (permissions.disallow)", a.Path, modulePath, functionName)
		}

		permsList := append([]types.Permission(nil), a.Metadata.Permissions...)
		if len(a.serverConfig.Permissions.Allow) > 0 {
			// Add the server config allowed permissions to the list
			permsList = append(permsList, a.serverConfig.Permissions.Allow...)
		}
		lastError, secrets, approved, err := checkPermissions(GetContext(thread), a, modulePath, functionName, args, pluginInfo, permsList)
		if err != nil {
			return nil, err
		}

		if !approved {
			if lastError != nil {
				return nil, lastError
			} else {
				return nil, fmt.Errorf("app %s is not permitted to call %s.%s. Audit the app and approve permissions", a.Path, modulePath, functionName)
			}
		}

		var builtinFunc StarlarkFunction
		if pluginInfo.Remote {
			// External plugin: dispatch over gRPC to the provider process.
			// Everything before this point (auth gate, disallow list,
			// permissions, secrets) and after it (PluginResponse wrapping)
			// is shared with in-process plugins
			builtinFunc = a.remotePluginFunc(pluginInfo, modulePath, accountName, functionName)
		} else {
			// In-process SDK plugin: dispatch through the direct value
			// bridge to the app's host, with the same enforcement and
			// response wrapping as the remote path
			builtinFunc = a.localPluginFunc(pluginInfo, modulePath, accountName, functionName)
		}

		prevPluginError := thread.Local(types.TL_PLUGIN_API_FAILED_ERROR)
		if prevPluginError != nil {
			return nil, fmt.Errorf("previous plugin call failed: %s", prevPluginError)
		}
		thread.SetLocal(types.TL_PLUGIN_API_FAILED_ERROR, nil)

		// Wrap the plugin function call with error handling
		errorHandlingWrapper := pluginErrorWrapper(builtinFunc, a.errorHandler)

		// Pass the module full path as a thread local
		thread.SetLocal(types.TL_CURRENT_MODULE_FULL_PATH, modulePath)

		// Evaluate secrets passed as arguments
		if a.secretEvalFunc != nil {
			for i, arg := range args {
				switch v := arg.(type) {
				case starlark.String:
					evalString, err := a.secretEvalFunc(secrets, a.AppConfig.Security.DefaultSecretsProvider, v.GoString())
					if err != nil {
						return nil, err
					}
					args[i] = starlark.String(evalString)
				case *starlark.List:
					for i := 0; i < v.Len(); i++ {
						switch sv := v.Index(i).(type) {
						case starlark.String:
							evalString, err := a.secretEvalFunc(secrets, a.AppConfig.Security.DefaultSecretsProvider, sv.GoString())
							if err != nil {
								return nil, err
							}
							v.SetIndex(i, starlark.String(evalString)) //nolint:errcheck
						}
					}
				case *starlark.Dict:
					for _, key := range v.Keys() {
						value, _, err := v.Get(key)
						if err != nil {
							return nil, err
						}
						switch sv := value.(type) {
						case starlark.String:
							evalString, err := a.secretEvalFunc(secrets, a.AppConfig.Security.DefaultSecretsProvider, sv.GoString())
							if err != nil {
								return nil, err
							}
							v.SetKey(key, starlark.String(evalString)) //nolint:errcheck
						}
					}
				}
			}

			// Evaluate secrets passed as keyword arguments
			for i, kwarg := range kwargs {
				switch v := kwarg[1].(type) {
				case starlark.String:
					evalString, err := a.secretEvalFunc(secrets, a.AppConfig.Security.DefaultSecretsProvider, v.GoString())
					if err != nil {
						return nil, err

					}
					kwargs[i][1] = starlark.String(evalString)
				case *starlark.List:
					for i := 0; i < v.Len(); i++ {
						switch sv := v.Index(i).(type) {
						case starlark.String:
							evalString, err := a.secretEvalFunc(secrets, a.AppConfig.Security.DefaultSecretsProvider, sv.GoString())
							if err != nil {
								return nil, err
							}
							v.SetIndex(i, starlark.String(evalString)) //nolint:errcheck
						}
					}
				case *starlark.Dict:
					for _, key := range v.Keys() {
						value, _, err := v.Get(key)
						if err != nil {
							return nil, err
						}
						switch sv := value.(type) {
						case starlark.String:
							evalString, err := a.secretEvalFunc(secrets, a.AppConfig.Security.DefaultSecretsProvider, sv.GoString())
							if err != nil {
								return nil, err
							}
							v.SetKey(key, starlark.String(evalString)) //nolint:errcheck
						}
					}
				}
			}
		}

		// Call the builtin function
		newBuiltin := starlark.NewBuiltin(functionName, errorHandlingWrapper)
		// Plugin spans are gated separately because data-heavy apps may issue
		// many plugin calls per request; we also require an existing parent
		// context (set by the surrounding handler) so a missing TL_CONTEXT
		// surfaces as no span rather than a silently-detached root span.
		parentCtx := GetContext(thread)
		if telemetry.PluginSpansEnabled() && parentCtx != nil && pluginInfo != nil {
			ctx, span := telemetry.StartSpan(parentCtx, "openrun.plugin.call",
				attribute.String("openrun.app.id", string(a.Id)),
				attribute.String("openrun.app.path", appPath),
				attribute.String("openrun.plugin.module", modulePath),
				attribute.String("openrun.plugin.function", functionName),
				attribute.Bool("openrun.plugin.read", pluginInfo.IsRead),
			)
			defer span.End()
			defer pushThreadContext(thread, ctx, parentCtx)()

			val, err := newBuiltin.CallInternal(thread, args, kwargs)
			telemetry.RecordError(span, err)
			return val, err
		}
		val, err := newBuiltin.CallInternal(thread, args, kwargs)
		return val, err
	}

	return starlark.NewBuiltin(functionName, hook)
}

// matchesDisallowed reports whether the plugin call matches a server config
// permissions.disallow entry. Matching mirrors the allow/approval options in
// checkPermissions: the plugin name must match, an empty method matches every
// method of the plugin, and argument patterns (exact or regex:, positional
// prefix) narrow the block to matching calls. A call with fewer arguments than
// the entry's patterns does not match. Permit/is_read/secrets have no meaning
// on a deny rule and are ignored
func matchesDisallowed(disallowList []types.Permission, modulePath, functionName string, args starlark.Tuple) (bool, error) {
	for _, p := range disallowList {
		if p.Plugin != modulePath {
			continue
		}
		if p.Method != "" && p.Method != functionName {
			continue
		}
		if len(p.Arguments) > len(args) {
			continue
		}
		argMismatch := false
		for i, arg := range p.Arguments {
			funcInput := types.StripQuotes(args[i].String())
			if funcInput == arg {
				continue
			}
			match, err := types.RegexMatch(arg, funcInput)
			if err != nil {
				return false, err
			}
			if !match {
				argMismatch = true
				break
			}
		}
		if !argMismatch {
			return true, nil
		}
	}
	return false, nil
}

func checkPermissions(ctx context.Context, a *App, modulePath string, functionName string, args starlark.Tuple, pluginInfo *plugin.PluginInfo, permsList []types.Permission) (error, [][]string, bool, error) {
	var lastError error
	secrets := [][]string{}
	approved := false
	for _, p := range permsList {
		a.Trace().Msgf("Checking permission %s.%s call %s.%s", p.Plugin, p.Method, modulePath, functionName)
		if p.Plugin == modulePath && p.Method == functionName {
			if len(p.Arguments) > 0 {
				if len(p.Arguments) > len(args) {
					lastError = fmt.Errorf("app %s is not permitted to call %s.%s with %d arguments, %d or more positional arguments are required (permissions checks are not supported for kwargs). Audit the app and approve permissions", a.Path, modulePath, functionName, len(args), len(p.Arguments))
					continue
				}
				argMismatch := false
				for i, arg := range p.Arguments {
					funcInput := types.StripQuotes(args[i].String())
					if funcInput != arg {
						match, err := types.RegexMatch(arg, funcInput)
						if err != nil {
							return nil, nil, false, err
						}
						if !match {
							lastError = fmt.Errorf("app %s is not permitted to call %s.%s with argument %d having value \"%s\", expected \"%s\". Update the app or audit and approve permissions", a.Path, modulePath, functionName, i, funcInput, arg)
							argMismatch = true
							break
						}
					}
					// More arguments than approved are permitted. Also, using kwargs is not allowed for args which are approved
				}
				if argMismatch {
					// This permission is not approved, but there may be others which are
					continue
				}
			}

			if a.MainApp != "" {
				var isRead bool
				if p.IsRead != nil {
					// Permission defines isRead, use that
					isRead = *p.IsRead
				} else {
					// Use the plugin defined isRead value
					isRead = pluginInfo.IsRead
				}

				if !isRead {
					// Write API, check if stage/preview has write access
					if strings.HasPrefix(string(a.Id), types.ID_PREFIX_APP_STAGE) && !a.Settings.StageWriteAccess {
						return nil, nil, false, fmt.Errorf("stage app %s is not permitted to call %s.%s args %v. Stage app does not have access to write operations", a.Path, modulePath, functionName, p.Arguments)
					}

					if strings.HasPrefix(string(a.Id), types.ID_PREFIX_APP_PREVIEW) && !a.Settings.PreviewWriteAccess {
						return nil, nil, false, fmt.Errorf("preview app %s is not permitted to call %s.%s args %v. Preview app does not have access to write operations", a.Path, modulePath, functionName, p.Arguments)
					}
				}
			}

			// Permit checks also apply under _cl_perm test URL directives (RBAC is
			// inactive for the app then; the simulated set replaces allow-all)
			if a.rbacApi != nil && ctx != nil && len(p.Permit) > 0 && rbac.AppRBACActive(ctx) {
				authorized, err := a.rbacApi.AuthorizeAny(ctx, p.Permit)
				if err != nil {
					return nil, nil, false, err
				}
				if !authorized {
					userId := system.GetContextUserId(ctx)
					lastError = fmt.Errorf("app %s is not permitted to call %s.%s: user %s does not have any required permission %v", a.Path, modulePath, functionName, userId, p.Permit)
					return lastError, secrets, false, nil
				}
			}

			secrets = p.Secrets // the secrets this plugin call is allowed access to
			approved = true
			break
		}
	}
	return lastError, secrets, approved, nil
}
