// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/telemetry"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
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
		if err := a.checkDisallowed(modulePath, functionName, args, kwargs, "the call"); err != nil {
			return nil, err
		}

		permsList := append([]types.Permission(nil), a.Metadata.Permissions...)
		if len(a.serverConfig.Permissions.Allow) > 0 {
			// Add the server config allowed permissions to the list
			permsList = append(permsList, a.serverConfig.Permissions.Allow...)
		}
		lastError, secrets, matched, err := checkPermissions(GetContext(thread), a, modulePath, functionName, args, pluginInfo, permsList, false, nil)
		if err != nil {
			return nil, err
		}

		if matched == nil {
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

		// Resolve the template values (ace.eval, app level param values)
		// passed as arguments and keyword arguments. Plain strings are never
		// template evaluated, so request data an app forwards to a plugin
		// cannot resolve the app's secrets
		// The secrets the templates resolved, as the key lists of the
		// secret/secret_from calls, for the checks on derived targets
		var usedSecrets [][]string
		recordSecret := func(keys []string) {
			if !slices.ContainsFunc(usedSecrets, func(used []string) bool { return slices.Equal(used, keys) }) {
				usedSecrets = append(usedSecrets, slices.Clone(keys))
			}
		}
		if a.secretEvalFunc != nil {
			changed := false
			for i, arg := range args {
				evalValue, argChanged, err := a.evalArgSecrets(secrets, arg, recordSecret)
				if err != nil {
					return nil, err
				}
				args[i] = evalValue
				changed = changed || argChanged
			}
			for i, kwarg := range kwargs {
				evalValue, argChanged, err := a.evalArgSecrets(secrets, kwarg[1], recordSecret)
				if err != nil {
					return nil, err
				}
				kwargs[i][1] = evalValue
				changed = changed || argChanged
			}

			if changed {
				// The checks above saw the raw argument text. A template
				// (any string with a {{secret}} reference, including one in a
				// branch that never runs) can resolve to a value the raw text
				// did not show, so the disallow list and the argument
				// patterns of the permission that approved the call are
				// checked again on what the plugin will actually receive
				if err := a.checkDisallowed(modulePath, functionName, args, kwargs, "the template-resolved argument value"); err != nil {
					return nil, err
				}
				if err := a.checkMatchedArgs(modulePath, functionName, args, matched); err != nil {
					return nil, err
				}
			}
		}

		// Plugins which derive further targets from the call (the http
		// plugin following a redirect) check each one as if it were the
		// first argument of a fresh call, through this thread local. The
		// plugin names the function the derived call corresponds to (a 303
		// turns a post into a get), empty for the current one. The secrets
		// the call resolved (in headers, body) go along to the derived
		// target, so the permission approving the target must grant each of
		// them: a redirect cannot carry a secret to a host the app may only
		// call without it
		argCheck := types.PluginArgCheckFunc(func(checkFunction, arg string) error {
			if checkFunction == "" {
				checkFunction = functionName
			}
			checkArgs := starlark.Tuple{starlark.String(arg)}
			if len(args) > 1 {
				checkArgs = append(checkArgs, args[1:]...)
			}
			if err := a.checkDisallowed(modulePath, checkFunction, checkArgs, kwargs, "the target"); err != nil {
				return err
			}
			// The remaining positionals are template-resolved by now and
			// may hold secrets, so the errors leave argument values out
			lastError, _, matched, err := checkPermissions(GetContext(thread), a, modulePath, checkFunction, checkArgs, pluginInfo, permsList, true, usedSecrets)
			if err != nil {
				return err
			}
			if matched == nil {
				if lastError != nil {
					return lastError
				}
				return fmt.Errorf("app %s is not permitted to call %s.%s with the target. Audit the app and approve permissions", a.Path, modulePath, checkFunction)
			}
			return nil
		})
		thread.SetLocal(types.TL_PLUGIN_ARG_CHECK, argCheck)
		defer thread.SetLocal(types.TL_PLUGIN_ARG_CHECK, nil)

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
			markPluginSource(val, modulePath, functionName)
			return val, err
		}
		val, err := newBuiltin.CallInternal(thread, args, kwargs)
		markPluginSource(val, modulePath, functionName)
		return val, err
	}

	return starlark.NewBuiltin(functionName, hook)
}

// evalArgSecrets resolves the template values (ace.eval, app level param
// values) in a plugin argument, at any depth inside lists, tuples and dicts,
// with the secrets the plugin call is allowed. Every other value, including
// plain strings, is returned as is. A container holding templates is
// replaced by a resolved copy: the original may be a frozen module level
// value, and must not end up holding the resolved secret. It reports whether
// any value was resolved
func (a *App) evalArgSecrets(secrets [][]string, value starlark.Value, record func(secretKeys []string)) (starlark.Value, bool, error) {
	return a.evalArgSecretsDepth(secrets, value, record, 0)
}

// evalArgSecretsDepth is evalArgSecrets with the nesting depth, bounded by
// the plugin value depth limit so a cyclic collection is an argument error
// rather than unbounded recursion
func (a *App) evalArgSecretsDepth(secrets [][]string, value starlark.Value, record func(secretKeys []string), depth int) (starlark.Value, bool, error) {
	if depth > sdk.MaxValueDepth {
		return nil, false, fmt.Errorf("plugin argument nesting exceeds max depth %d (cyclic value?)", sdk.MaxValueDepth)
	}
	depth++
	if t, ok := starlark_type.TemplateValue(value); ok {
		s, err := t.Resolve(func(text string, strict bool) (string, error) {
			return a.secretEvalFunc(secrets, a.AppConfig.Security.DefaultSecretsProvider, text, strict, record)
		})
		if err != nil {
			return nil, false, err
		}
		return starlark.String(s), true, nil
	}
	switch arg := value.(type) {
	case *starlark.List:
		elems, changed, err := a.evalElemSecrets(secrets, slices.Collect(arg.Elements()), record, depth)
		if err != nil {
			return nil, false, err
		}
		if changed {
			return starlark.NewList(elems), true, nil
		}
	case starlark.Tuple:
		elems, changed, err := a.evalElemSecrets(secrets, arg, record, depth)
		if err != nil {
			return nil, false, err
		}
		if changed {
			return starlark.Tuple(elems), true, nil
		}
	case *starlark.Dict:
		var resolved *starlark.Dict
		items := arg.Items()
		for i, item := range items {
			entry, changed, err := a.evalArgSecretsDepth(secrets, item[1], record, depth)
			if err != nil {
				return nil, false, err
			}
			if !changed {
				if resolved != nil {
					if err := resolved.SetKey(item[0], item[1]); err != nil {
						return nil, false, err
					}
				}
				continue
			}
			if resolved == nil {
				resolved = starlark.NewDict(len(items))
				for _, orig := range items[:i] {
					if err := resolved.SetKey(orig[0], orig[1]); err != nil {
						return nil, false, err
					}
				}
			}
			if err := resolved.SetKey(item[0], entry); err != nil {
				return nil, false, err
			}
		}
		if resolved != nil {
			return resolved, true, nil
		}
	}
	return value, false, nil
}

// evalElemSecrets resolves the templates in a list or tuple's elements,
// returning the resolved elements and whether any changed
func (a *App) evalElemSecrets(secrets [][]string, elems []starlark.Value, record func(secretKeys []string), depth int) ([]starlark.Value, bool, error) {
	var resolved []starlark.Value
	for i, elem := range elems {
		value, changed, err := a.evalArgSecretsDepth(secrets, elem, record, depth)
		if err != nil {
			return nil, false, err
		}
		if !changed {
			if resolved != nil {
				resolved[i] = elem
			}
			continue
		}
		if resolved == nil {
			resolved = make([]starlark.Value, len(elems))
			copy(resolved, elems[:i])
		}
		resolved[i] = value
	}
	return resolved, resolved != nil, nil
}

// methodMatches reports whether a permission entry's method covers the
// called function: the exact name, or a regex: pattern (the http.in default
// in the server config covers every method of the plugin that way)
func methodMatches(pattern, functionName string) (bool, error) {
	if pattern == functionName {
		return true, nil
	}
	return types.RegexMatch(pattern, functionName)
}

// matchArgPatterns matches the positional args against the patterns position
// by position (exact or regex:). It returns the index and value of the first
// argument that does not match, or -1 when every pattern matches. The caller
// ensures the call has at least as many positional args as there are patterns
func matchArgPatterns(patterns []string, args starlark.Tuple) (int, string, error) {
	for i, pattern := range patterns {
		funcInput := types.StripQuotes(args[i].String())
		if funcInput == pattern {
			continue
		}
		match, err := types.RegexMatch(pattern, funcInput)
		if err != nil {
			return i, funcInput, err
		}
		if !match {
			return i, funcInput, nil
		}
	}
	return -1, "", nil
}

// checkDisallowed returns an error when the plugin call matches a server
// config permissions.disallow entry. Matching mirrors the allow/approval
// options in checkPermissions: the plugin name must match, an empty method
// matches every method of the plugin (a regex: method matches by pattern),
// and argument patterns (exact or regex:, positional prefix) narrow the block
// to matching calls. A call with fewer positional arguments than the entry
// has patterns does not match, unless it passes keyword arguments: those may
// carry the argument the entry restricts, and the positional patterns cannot
// see them, so the entry blocks the call. Permit/is_read/secrets have no
// meaning on a deny rule and are ignored. what names the value being checked
// in the error ("the call", a resolved argument, a redirect target)
func (a *App) checkDisallowed(modulePath, functionName string, args starlark.Tuple, kwargs []starlark.Tuple, what string) error {
	// The module path of a call can carry an account suffix (http.in#acct).
	// An entry without an account blocks the plugin for every account, an
	// entry with an account blocks that account only
	basePath, _, _ := parseModulePath(modulePath)
	for _, p := range a.serverConfig.Permissions.Disallow {
		if p.Plugin != modulePath && p.Plugin != basePath {
			continue
		}
		if p.Method != "" {
			match, err := methodMatches(p.Method, functionName)
			if err != nil {
				return err
			}
			if !match {
				continue
			}
		}
		if len(p.Arguments) > len(args) {
			if len(kwargs) > 0 {
				return fmt.Errorf("app %s is not permitted to call %s.%s: %s is disallowed by the server config (permissions.disallow), keyword arguments cannot be checked against the entry's argument patterns, pass the arguments positionally", a.Path, modulePath, functionName, what)
			}
			continue
		}
		mismatch, _, err := matchArgPatterns(p.Arguments, args)
		if err != nil {
			return err
		}
		if mismatch < 0 {
			return fmt.Errorf("app %s is not permitted to call %s.%s: %s is disallowed by the server config (permissions.disallow)", a.Path, modulePath, functionName, what)
		}
	}
	return nil
}

// checkMatchedArgs re-runs the argument patterns of the permission that
// approved the call against the template-resolved argument values. The
// permission's secrets were granted for calls matching its patterns, so the
// resolved values (which may carry those secrets) must match them too. The
// error names the argument and the pattern but not the resolved value: it
// may hold a secret, and the error reaches the app's response and logs
func (a *App) checkMatchedArgs(modulePath, functionName string, args starlark.Tuple, p *types.Permission) error {
	if len(p.Arguments) == 0 {
		return nil
	}
	if len(p.Arguments) > len(args) {
		return fmt.Errorf("app %s is not permitted to call %s.%s with %d arguments, %d or more positional arguments are required", a.Path, modulePath, functionName, len(args), len(p.Arguments))
	}
	mismatch, _, err := matchArgPatterns(p.Arguments, args)
	if err != nil {
		return err
	}
	if mismatch >= 0 {
		return fmt.Errorf("app %s is not permitted to call %s.%s: template-resolved argument %d does not match the approved pattern \"%s\". Update the app or audit and approve permissions", a.Path, modulePath, functionName, mismatch, p.Arguments[mismatch])
	}
	return nil
}

// checkPermissions looks for a permission in permsList that approves the
// call. It returns the matched permission (nil when none approves), the
// secrets that permission grants, and the last reason a candidate was
// rejected. Argument patterns match the positional args only: a call that
// passes a restricted argument by keyword is not approved by a patterned
// entry. With redactValues the rejection reasons name the argument and the
// pattern but not the argument's value, for args that may hold resolved
// secrets (the errors reach the app's response and logs). A candidate that
// does not grant every secret in requiredSecrets (the key lists of the
// secrets a derived call carries from the call that was approved) is
// rejected like one whose argument patterns do not match
func checkPermissions(ctx context.Context, a *App, modulePath string, functionName string, args starlark.Tuple, pluginInfo *plugin.PluginInfo, permsList []types.Permission, redactValues bool, requiredSecrets [][]string) (error, [][]string, *types.Permission, error) {
	var lastError error
	secrets := [][]string{}
	var matched *types.Permission
	for idx := range permsList {
		p := permsList[idx]
		a.Trace().Msgf("Checking permission %s.%s call %s.%s", p.Plugin, p.Method, modulePath, functionName)
		if p.Plugin != modulePath {
			continue
		}
		methodMatch, err := methodMatches(p.Method, functionName)
		if err != nil {
			return nil, nil, nil, err
		}
		if methodMatch {
			if len(p.Arguments) > 0 {
				if len(p.Arguments) > len(args) {
					lastError = fmt.Errorf("app %s is not permitted to call %s.%s with %d arguments, %d or more positional arguments are required (permissions checks are not supported for kwargs). Audit the app and approve permissions", a.Path, modulePath, functionName, len(args), len(p.Arguments))
					continue
				}
				// More arguments than approved are permitted
				mismatch, value, err := matchArgPatterns(p.Arguments, args)
				if err != nil {
					return nil, nil, nil, err
				}
				if mismatch >= 0 {
					// This permission is not approved, but there may be others which are
					if redactValues {
						lastError = fmt.Errorf("app %s is not permitted to call %s.%s: argument %d does not match the approved pattern \"%s\". Update the app or audit and approve permissions", a.Path, modulePath, functionName, mismatch, p.Arguments[mismatch])
					} else {
						lastError = fmt.Errorf("app %s is not permitted to call %s.%s with argument %d having value \"%s\", expected \"%s\". Update the app or audit and approve permissions", a.Path, modulePath, functionName, mismatch, value, p.Arguments[mismatch])
					}
					continue
				}
			}

			if !secretsCovered(requiredSecrets, p.Secrets) {
				lastError = fmt.Errorf("app %s is not permitted to call %s.%s: the matching permission does not allow the secrets the call resolved (%s). Update the app or audit and approve permissions", a.Path, modulePath, functionName, types.Permission{Secrets: requiredSecrets}.SecretsString())
				continue
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
						return nil, nil, nil, fmt.Errorf("stage app %s is not permitted to call %s.%s args %v. Stage app does not have access to write operations", a.Path, modulePath, functionName, p.Arguments)
					}

					if strings.HasPrefix(string(a.Id), types.ID_PREFIX_APP_PREVIEW) && !a.Settings.PreviewWriteAccess {
						return nil, nil, nil, fmt.Errorf("preview app %s is not permitted to call %s.%s args %v. Preview app does not have access to write operations", a.Path, modulePath, functionName, p.Arguments)
					}
				}
			}

			// Permit checks also apply under _cl_perm test URL directives (RBAC is
			// inactive for the app then; the simulated set replaces allow-all)
			if a.rbacApi != nil && ctx != nil && len(p.Permit) > 0 && rbac.AppRBACActive(ctx) {
				authorized, err := a.rbacApi.AuthorizeAny(ctx, p.Permit)
				if err != nil {
					return nil, nil, nil, err
				}
				if !authorized {
					userId := system.GetContextUserId(ctx)
					lastError = fmt.Errorf("app %s is not permitted to call %s.%s: user %s does not have any required permission %v", a.Path, modulePath, functionName, userId, p.Permit)
					return lastError, secrets, nil, nil
				}
			}

			secrets = p.Secrets // the secrets this plugin call is allowed access to
			matched = &permsList[idx]
			break
		}
	}
	return lastError, secrets, matched, nil
}
