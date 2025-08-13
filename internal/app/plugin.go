// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

type PluginFunctionType int

const (
	READ PluginFunctionType = iota
	WRITE
	READ_WRITE
)

var (
	loaderInitMutex sync.Mutex
	builtInPlugins  map[string]plugin.PluginMap
)

func init() {
	builtInPlugins = make(map[string]plugin.PluginMap)
	initFS()
}

// RegisterPlugin registers a plugin with OpenRun
func RegisterPlugin(name string, builder plugin.NewPluginFunc, funcs []plugin.PluginFunc) {
	loaderInitMutex.Lock()
	defer loaderInitMutex.Unlock()

	pluginPath := fmt.Sprintf("%s.%s", name, apptype.BUILTIN_PLUGIN_SUFFIX)
	pluginMap := make(plugin.PluginMap)
	for _, f := range funcs {
		info := plugin.PluginInfo{
			ModuleName:    name,
			PluginPath:    pluginPath,
			FuncName:      f.Name,
			IsRead:        f.IsRead,
			HandlerName:   f.FunctionName,
			Builder:       builder,
			ConstantValue: f.Constant,
		}

		pluginMap[f.Name] = &info
	}

	builtInPlugins[pluginPath] = pluginMap
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

func CreatePluginConstant(name string, value starlark.Value) plugin.PluginFunc {
	return plugin.PluginFunc{
		Name:     name,
		Constant: value,
	}
}

func CreatePluginApi(f StarlarkFunction, opType PluginFunctionType) plugin.PluginFunc {
	funcVal := runtime.FuncForPC(reflect.ValueOf(f).Pointer())
	if funcVal == nil {
		panic(fmt.Errorf("function not found during plugin register"))
	}

	parts := strings.Split(funcVal.Name(), "/")
	nameParts := strings.Split(parts[len(parts)-1], ".")
	funcName := strings.TrimSuffix(nameParts[len(nameParts)-1], "-fm") // -fm denotes function value

	return CreatePluginApiName(f, opType, strings.ToLower(funcName))
}

// CreatePluginApiName creates a OpenRun plugin function
func CreatePluginApiName(
	f func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error),
	opType PluginFunctionType,
	name string) plugin.PluginFunc {
	funcVal := runtime.FuncForPC(reflect.ValueOf(f).Pointer())
	if funcVal == nil {
		panic(fmt.Errorf("function %s not found during plugin register", name))
	}

	parts := strings.Split(funcVal.Name(), "/")
	nameParts := strings.Split(parts[len(parts)-1], ".")
	funcName := strings.TrimSuffix(nameParts[len(nameParts)-1], "-fm") // -fm denotes function value

	if len(funcName) == 0 {
		panic(fmt.Errorf("function %s not found during plugin register", name))
	}
	rune, _ := utf8.DecodeRuneInString(funcName)
	if !unicode.IsUpper(rune) {
		panic(fmt.Errorf("function %s is not an exported method during plugin register", funcName))
	}

	return plugin.PluginFunc{
		Name:         name,
		IsRead:       opType == READ,
		FunctionName: funcName,
	}
}

func GetContext(thread *starlark.Thread) context.Context {
	c := thread.Local(types.TL_CONTEXT)
	if c == nil {
		return nil
	}
	return c.(context.Context)
}

// SavePluginState saves a value in the thread local for the plugin
func SavePluginState(thread *starlark.Thread, key string, value any) {
	pluginName := thread.Local(types.TL_CURRENT_MODULE_FULL_PATH)
	if pluginName == nil {
		panic(fmt.Errorf("plugin name not found in thread local"))
	}

	keyName := fmt.Sprintf("%s_%s", pluginName, key)
	thread.SetLocal(keyName, value)
}

// FetchPluginState fetches a value from the thread local for the plugin
func FetchPluginState(thread *starlark.Thread, key string) any {
	pluginName := thread.Local(types.TL_CURRENT_MODULE_FULL_PATH)
	if pluginName == nil {
		panic(fmt.Errorf("plugin name not found in thread local"))
	}

	keyName := fmt.Sprintf("%s_%s", pluginName, key)
	return thread.Local(keyName)
}

// DeferCleanup defers a close function to call when the API handler is done
func DeferCleanup(thread *starlark.Thread, key string, deferFunc apptype.DeferFunc, strict bool) {
	pluginName := thread.Local(types.TL_CURRENT_MODULE_FULL_PATH)
	if pluginName == nil {
		panic(fmt.Errorf("plugin name not found in thread local"))
	}

	deferMap := thread.Local(types.TL_DEFER_MAP)
	if deferMap == nil {
		deferMap = map[string]map[string]apptype.DeferEntry{}
	}

	pluginMap := deferMap.(map[string]map[string]apptype.DeferEntry)[pluginName.(string)]
	if pluginMap == nil {
		pluginMap = map[string]apptype.DeferEntry{}
	}

	pluginMap[key] = apptype.DeferEntry{Func: deferFunc, Strict: strict}
	deferMap.(map[string]map[string]apptype.DeferEntry)[pluginName.(string)] = pluginMap
	thread.SetLocal(types.TL_DEFER_MAP, deferMap)
}

// ClearCleanup clears a defer function from the thread local
func ClearCleanup(thread *starlark.Thread, key string) {
	pluginName := thread.Local(types.TL_CURRENT_MODULE_FULL_PATH)
	if pluginName == nil {
		panic(fmt.Errorf("plugin name not found in thread local"))
	}

	deferMap := thread.Local(types.TL_DEFER_MAP)
	if deferMap == nil {
		return
	}

	pluginMap := deferMap.(map[string]map[string]apptype.DeferEntry)[pluginName.(string)]
	if pluginMap == nil {
		return
	}

	delete(pluginMap, key)
	deferMap.(map[string]map[string]apptype.DeferEntry)[pluginName.(string)] = pluginMap
	thread.SetLocal(types.TL_DEFER_MAP, deferMap)
}

// loader is the starlark loader function
func (a *App) loader(thread *starlark.Thread, moduleFullPath string) (starlark.StringDict, error) {
	if strings.HasSuffix(moduleFullPath, apptype.STARLARK_FILE_SUFFIX) {
		// Load the starlark file rather than the plugin
		return a.loadStarlark(thread, moduleFullPath, a.starlarkCache)
	}

	if a.Metadata.Loads == nil || !slices.Contains(a.Metadata.Loads, moduleFullPath) {
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
			hookedDict[funcName] = a.pluginHook(moduleFullPath, accountName, funcName, pluginInfo)
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
	accountName := ""
	if len(parts) > 1 {
		accountName = parts[1]
	}
	return modulePath, moduleName, accountName
}

// pluginLookup looks up the plugin. Audit checks need to be done by the caller
func (a *App) pluginLookup(_ *starlark.Thread, module string) (plugin.PluginMap, error) {
	pluginDict, ok := builtInPlugins[module]
	if !ok {
		return nil, fmt.Errorf("module %s not found", module) // TODO extend loading
	}

	return pluginDict, nil
}

func (a *App) pluginHook(modulePath, accountName, functionName string, pluginInfo *plugin.PluginInfo) *starlark.Builtin {
	hook := func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		a.Trace().Msgf("Plugin called: %s.%s", modulePath, functionName)

		if a.Metadata.Permissions == nil {
			return nil, fmt.Errorf("app %s has no permissions configured, plugin call %s.%s is blocked. Audit the app and approve permissions", a.Path, modulePath, functionName)
		}

		approved := false
		var lastError error
		var secrets [][]string
		for _, p := range a.Metadata.Permissions {
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
								return nil, err
							}
							if !match {
								lastError = fmt.Errorf("app %s is not permitted to call %s.%s with argument %d having value \"%s\", expected \"%s\". Update the app or audit and approve permissions", a.Path, modulePath, functionName, i, funcInput, arg)
								argMismatch = true
								break
							}
						}
						// More arguments than approved are permitted. Also, using kwargs is not allowed for args which are approved
						// Regex support is not implemented, the arguments have to match exactly as approved
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
							return nil, fmt.Errorf("stage app %s is not permitted to call %s.%s args %v. Stage app does not have access to write operations", a.Path, modulePath, functionName, p.Arguments)
						}

						if strings.HasPrefix(string(a.Id), types.ID_PREFIX_APP_PREVIEW) && !a.Settings.PreviewWriteAccess {
							return nil, fmt.Errorf("preview app %s is not permitted to call %s.%s args %v. Preview app does not have access to write operations", a.Path, modulePath, functionName, p.Arguments)
						}
					}
				}

				secrets = p.Secrets // the secrets this plugin call is allowed access to
				approved = true
				break
			}
		}

		if !approved {
			if lastError != nil {
				return nil, lastError
			} else {
				return nil, fmt.Errorf("app %s is not permitted to call %s.%s. Audit the app and approve permissions", a.Path, modulePath, functionName)
			}
		}

		// Get the plugin from the app config
		plugin, err := a.plugins.GetPlugin(pluginInfo, accountName)
		if err != nil {
			return nil, err
		}

		// Get the plugin function using reflection
		pluginValue := reflect.ValueOf(plugin).MethodByName(pluginInfo.HandlerName)
		if pluginValue.IsNil() {
			return nil, fmt.Errorf("plugin func %s.%s cannot be resolved", modulePath, functionName)
		}

		builtinFunc, ok := pluginValue.Interface().(func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error))
		if !ok {
			return nil, fmt.Errorf("plugin %s.%s is not a starlark function", modulePath, functionName)
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
							v.SetIndex(i, starlark.String(evalString))
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
							v.SetKey(key, starlark.String(evalString))
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
							v.SetIndex(i, starlark.String(evalString))
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
							v.SetKey(key, starlark.String(evalString))
						}
					}
				}
			}
		}

		// Call the builtin function
		newBuiltin := starlark.NewBuiltin(functionName, errorHandlingWrapper)
		val, err := newBuiltin.CallInternal(thread, args, kwargs)
		return val, err
	}

	return starlark.NewBuiltin(functionName, hook)
}
