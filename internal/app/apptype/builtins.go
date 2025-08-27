// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package apptype

import (
	"cmp"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

const (
	DEFAULT_MODULE        = "ace"
	DOC_MODULE            = "doc"
	TABLE_MODULE          = "table"
	PARAM_MODULE          = "param"
	APP                   = "app"
	HTML                  = "html"
	API                   = "api"
	PROXY                 = "proxy"
	FRAGMENT              = "fragment"
	STYLE                 = "style"
	REDIRECT              = "redirect"
	PERMISSION            = "permission"
	RESPONSE              = "response"
	CONFIG                = "config"
	LIBRARY               = "library"
	ACTION                = "action"
	RESULT                = "result"
	AUDIT                 = "audit"
	OUTPUT                = "output"
	CONTAINER_URL         = "<CONTAINER_URL>" // special url to use for proxying to the container
	DEFAULT_REDIRECT_CODE = 303
)

const (
	DEFAULT_DAISYUI_LIGHT_THEME = "emerald"
	DEFAULT_DAISYUI_DARK_THEME  = "night"
)

const (
	// Constants included in the ace builtin module
	GET       = "GET"
	POST      = "POST"
	PUT       = "PUT"
	DELETE    = "DELETE"
	HTML_TYPE = "HTML"
	JSON      = "JSON"
	TEXT      = "TEXT"
	READ      = "READ"
	WRITE     = "WRITE"

	AUTO     = "AUTO"
	TABLE    = "TABLE"
	DOWNLOAD = "DOWNLOAD"
	IMAGE    = "IMAGE"
)

var (
	once    sync.Once
	builtin starlark.StringDict
)

func createAppBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var customLayout, staticOnly, singleFile starlark.Bool
	var name, index starlark.String
	var routes, actions *starlark.List
	var settings *starlark.Dict
	var permissions, libraries *starlark.List
	var style *starlarkstruct.Struct
	var containerConfig starlark.Value
	if err := starlark.UnpackArgs(APP, args, kwargs, "name", &name,
		"routes?", &routes, "style?", &style, "permissions?", &permissions, "libraries?", &libraries, "settings?",
		&settings, "custom_layout?", &customLayout, "container?", &containerConfig, "actions?", &actions,
		"static_only?", &staticOnly, "index?", &index, "single_file?", &singleFile); err != nil {
		return nil, fmt.Errorf("error unpacking app args: %w", err)
	}

	if routes == nil {
		routes = starlark.NewList([]starlark.Value{})
	}
	if actions == nil {
		actions = starlark.NewList([]starlark.Value{})
	}
	if libraries == nil {
		libraries = starlark.NewList([]starlark.Value{})
	}
	if settings == nil {
		settings = starlark.NewDict(0)
	}

	if permissions == nil {
		permissions = starlark.NewList([]starlark.Value{})
	}

	fields := starlark.StringDict{
		"name":          name,
		"custom_layout": customLayout,
		"routes":        routes,
		"settings":      settings,
		"permissions":   permissions,
		"libraries":     libraries,
		"actions":       actions,
		"static_only":   staticOnly,
		"index":         index,
		"single_file":   singleFile,
	}

	if style != nil {
		fields["style"] = style
	}

	if containerConfig != nil {
		fields["container"] = containerConfig
	}

	return starlarkstruct.FromStringDict(starlark.String(APP), fields), nil
}

func createHtmlBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, html, block starlark.String
	var handler starlark.Callable
	var fragments *starlark.List
	var method starlark.String
	if err := starlark.UnpackArgs(HTML, args, kwargs, "path", &path, "full?", &html,
		"partial?", &block, "handler?", &handler, "fragments?", &fragments, "method?", &method); err != nil {
		return nil, fmt.Errorf("error unpacking html args: %w", err)
	}

	if method == "" {
		method = "GET"
	}
	if fragments == nil {
		fragments = starlark.NewList([]starlark.Value{})
	}

	fields := starlark.StringDict{
		"path":      path,
		"full":      html,
		"partial":   block,
		"fragments": fragments,
		"method":    method,
	}
	if handler != nil {
		fields["handler"] = handler
	}
	return starlarkstruct.FromStringDict(starlark.String(HTML), fields), nil
}

func createFragmentBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, block starlark.String
	var handler starlark.Callable
	var method starlark.String
	if err := starlark.UnpackArgs(FRAGMENT, args, kwargs, "path", &path, "partial?", &block,
		"handler?", &handler, "method?", &method); err != nil {
		return nil, fmt.Errorf("error unpacking fragment args: %w", err)
	}

	if method == "" {
		method = "GET"
	}

	fields := starlark.StringDict{
		"path":    path,
		"partial": block,
		"method":  method,
	}
	if handler != nil {
		fields["handler"] = handler
	}
	return starlarkstruct.FromStringDict(starlark.String(FRAGMENT), fields), nil
}

func createStyleBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var library, light, dark starlark.String
	var themes *starlark.List
	var disableWatcher starlark.Bool
	if err := starlark.UnpackArgs(FRAGMENT, args, kwargs, "library", &library, "themes?", &themes, "disable_watcher?", &disableWatcher, "light?", &light, "dark?", &dark); err != nil {
		return nil, fmt.Errorf("error unpacking style args: %w", err)
	}

	if themes == nil {
		themes = starlark.NewList([]starlark.Value{})
	}

	fields := starlark.StringDict{
		"library":         library,
		"themes":          themes,
		"disable_watcher": disableWatcher,
		"light":           cmp.Or(light, DEFAULT_DAISYUI_LIGHT_THEME),
		"dark":            cmp.Or(dark, DEFAULT_DAISYUI_DARK_THEME),
	}
	return starlarkstruct.FromStringDict(starlark.String(STYLE), fields), nil
}

func createRedirectBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url starlark.String
	var code starlark.Int
	var refresh starlark.Bool
	if err := starlark.UnpackArgs(REDIRECT, args, kwargs, "url", &url, "code?", &code, "refresh?", &refresh); err != nil {
		return nil, fmt.Errorf("error unpacking redirect args: %w", err)
	}

	codeValue, _ := code.Int64()
	if codeValue == 0 {
		code = starlark.MakeInt(DEFAULT_REDIRECT_CODE)
	}

	fields := starlark.StringDict{
		"url":     url,
		"code":    code,
		"refresh": refresh,
	}
	return starlarkstruct.FromStringDict(starlark.String(REDIRECT), fields), nil
}

func createResponseBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var block, retarget, reswap, redirect, rtype starlark.String
	var data starlark.Value
	var code starlark.Int
	if err := starlark.UnpackArgs(RESPONSE, args, kwargs, "data", &data, "block?", &block, "type?", &rtype, "code?", &code, "retarget?", &retarget, "reswap?", &reswap, "redirect?", &redirect); err != nil {
		return nil, fmt.Errorf("error unpacking response args: %w", err)
	}

	codeValue, _ := code.Int64()
	if codeValue == 0 {
		code = starlark.MakeInt(http.StatusOK)
	}

	rtypeStr := strings.ToUpper(rtype.GoString())
	if rtypeStr != "" && rtypeStr != HTML_TYPE && rtypeStr != JSON && rtypeStr != TEXT {
		return nil, fmt.Errorf("invalid type specified : %s", rtypeStr)
	}

	fields := starlark.StringDict{
		"data":     data,
		"block":    block,
		"type":     rtype,
		"code":     code,
		"retarget": retarget,
		"reswap":   reswap,
		"redirect": redirect,
	}
	return starlarkstruct.FromStringDict(starlark.String(RESPONSE), fields), nil
}

func createPermissionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var plugin, method starlark.String
	var arguments *starlark.List
	var secrets *starlark.List
	var rtype starlark.String
	if err := starlark.UnpackArgs(PERMISSION, args, kwargs, "plugin", &plugin, "method", &method,
		"arguments?", &arguments, "type?", &rtype, "secrets?", &secrets); err != nil {
		return nil, fmt.Errorf("error unpacking permission args: %w", err)
	}

	if arguments == nil {
		arguments = starlark.NewList([]starlark.Value{})
	}
	if secrets == nil {
		secrets = starlark.NewList([]starlark.Value{})
	}

	fields := starlark.StringDict{
		"plugin":    plugin,
		"method":    method,
		"arguments": arguments,
		"secrets":   secrets,
	}

	if rtype == "READ" {
		fields["is_read"] = starlark.True
	} else if rtype == "WRITE" {
		fields["is_read"] = starlark.False
	} else if rtype != "" {
		return nil, fmt.Errorf("invalid permission type specified : %s", rtype)
	}

	return starlarkstruct.FromStringDict(starlark.String(PERMISSION), fields), nil
}

func createLibraryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, version starlark.String
	var esbuildArgs *starlark.List
	if err := starlark.UnpackArgs(LIBRARY, args, kwargs, "name", &name, "version", &version,
		"args?", &esbuildArgs); err != nil {
		return nil, fmt.Errorf("error unpacking library args: %w", err)
	}

	if esbuildArgs == nil {
		esbuildArgs = starlark.NewList([]starlark.Value{})
	}

	fields := starlark.StringDict{
		"name":    name,
		"version": version,
		"args":    esbuildArgs,
	}
	return starlarkstruct.FromStringDict(starlark.String(LIBRARY), fields), nil
}

func createActionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, desc, path starlark.String
	var suggest, executor starlark.Callable
	var hidden *starlark.List
	var showValidate starlark.Bool
	if err := starlark.UnpackArgs(ACTION, args, kwargs, "name", &name, "path", &path,
		"run", &executor, "suggest?", &suggest, "description?", &desc, "hidden?", &hidden,
		"show_validate?", &showValidate); err != nil {
		return nil, fmt.Errorf("error unpacking action args: %w", err)
	}

	if hidden == nil {
		hidden = starlark.NewList([]starlark.Value{})
	}

	fields := starlark.StringDict{
		"name":          name,
		"description":   desc,
		"path":          path,
		"run":           executor,
		"hidden":        hidden,
		"show_validate": showValidate,
	}

	if suggest != nil {
		fields["suggest"] = suggest
	}
	return starlarkstruct.FromStringDict(starlark.String(ACTION), fields), nil
}

func createResultBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var status, report starlark.String
	var values *starlark.List
	var paramErrors *starlark.Dict
	if err := starlark.UnpackArgs(RESULT, args, kwargs, "status?", &status, "values?", &values,
		"report?", &report, "param_errors?", &paramErrors); err != nil {
		return nil, fmt.Errorf("error unpacking result args: %w", err)
	}

	if report == "" {
		report = AUTO
	}

	if values == nil {
		values = starlark.NewList([]starlark.Value{})
	}

	if paramErrors == nil {
		paramErrors = starlark.NewDict(0)
	}

	fields := starlark.StringDict{
		"status":       status,
		"values":       values,
		"report":       report,
		"param_errors": paramErrors,
	}
	return starlarkstruct.FromStringDict(starlark.String(RESULT), fields), nil
}

func createAuditBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var operation, target, detail starlark.String
	if err := starlark.UnpackArgs(AUDIT, args, kwargs, "operation", &operation, "target", &target, "detail?", &detail); err != nil {
		return nil, fmt.Errorf("error unpacking audit args: %w", err)
	}

	// Set the audit values in the thread local, that last call to audit from a handler takes effect
	thread.SetLocal(types.TL_AUDIT_OPERATION, operation.GoString())
	thread.SetLocal(types.TL_AUDIT_TARGET, target.GoString())
	thread.SetLocal(types.TL_AUDIT_DETAIL, detail.GoString())
	return starlark.None, nil
}

func createOutputBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var errValue starlark.String
	if err := starlark.UnpackArgs(OUTPUT, args, kwargs, "value?", &value, "error?", &errValue); err != nil {
		return nil, fmt.Errorf("error unpacking output args: %w", err)
	}

	if value == nil {
		value = starlark.None
	}

	output := starlark_type.Output{
		Value: value,
		Err:   errValue.GoString(),
	}
	return output, nil
}

func createProxyBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path starlark.String
	var config starlark.Value
	if err := starlark.UnpackArgs(PROXY, args, kwargs, "path", &path, "config", &config); err != nil {
		return nil, fmt.Errorf("error unpacking proxy args: %w", err)
	}

	fields := starlark.StringDict{
		"path":   path,
		"config": config,
	}
	return starlarkstruct.FromStringDict(starlark.String(PROXY), fields), nil
}

func createAPIBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, rtype starlark.String
	var handler starlark.Callable
	var method starlark.String
	if err := starlark.UnpackArgs(API, args, kwargs, "path", &path, "handler?", &handler, "method?", &method, "type?", &rtype); err != nil {
		return nil, fmt.Errorf("error unpacking api args: %w", err)
	}

	if method == "" {
		method = "GET"
	}

	rtypeStr := strings.ToUpper(rtype.GoString())
	if rtypeStr == "" {
		rtypeStr = JSON
	}
	if rtypeStr != JSON && rtypeStr != TEXT {
		return nil, fmt.Errorf("invalid API type specified : %s", rtypeStr)
	}

	fields := starlark.StringDict{
		"path":   path,
		"method": method,
		"type":   starlark.String(rtypeStr),
	}
	if handler != nil {
		fields["handler"] = handler
	}
	return starlarkstruct.FromStringDict(starlark.String(API), fields), nil
}

func CreateConfigBuiltin(nodeConfig types.NodeConfig, allowedEnv []string) func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var key starlark.String
		var defaultVal starlark.Value
		if err := starlark.UnpackArgs(CONFIG, args, kwargs, "key", &key, "default", &defaultVal); err != nil {
			return nil, fmt.Errorf("error unpacking config args: %w", err)
		}
		var err error
		var outVal starlark.Value = defaultVal

		if key == "_branch" {
			// _branch is a special input that returns the current branch name
			branch := thread.Local(types.TL_BRANCH)
			if branch == nil {
				return defaultVal, nil
			}
			branchStr, ok := branch.(string)
			if !ok {
				return nil, fmt.Errorf("branch is not a string %v", branch)
			}
			if branchStr == "" {
				return defaultVal, nil
			}
			return starlark.String(branchStr), nil
		} else if key == "_dev" {
			// _dev is a special input that returns the current dev status
			dev := thread.Local(types.TL_DEV)
			if dev == nil {
				return defaultVal, nil
			}

			devBool, ok := dev.(bool)
			if !ok {
				return nil, fmt.Errorf("dev is not a boolean %v", dev)
			}
			return starlark.Bool(devBool), nil
		}

		localVal, ok := nodeConfig[string(key)]
		if ok {
			outVal, err = starlark_type.MarshalStarlark(localVal)
			if err != nil {
				return nil, fmt.Errorf("error marshalling config value for %s: %w", key, err)
			}
		}
		if strVal, ok := outVal.(starlark.String); ok {
			for _, env := range allowedEnv {
				envVal := os.Getenv(env)
				strVal = starlark.String(strings.ReplaceAll(string(strVal), fmt.Sprintf("$%s", env), envVal))
			}
			outVal = strVal
		}

		if outVal == nil {
			outVal = starlark.None
		}

		return outVal, nil
	}
}

func CreateBuiltin(nodeConfig types.NodeConfig, allowedEnv []string) starlark.StringDict {
	once.Do(func() {
		builtin = starlark.StringDict{
			DEFAULT_MODULE: &starlarkstruct.Module{
				Name: DEFAULT_MODULE,
				Members: starlark.StringDict{
					APP:        starlark.NewBuiltin(APP, createAppBuiltin),
					HTML:       starlark.NewBuiltin(HTML, createHtmlBuiltin),
					PROXY:      starlark.NewBuiltin(PROXY, createProxyBuiltin),
					API:        starlark.NewBuiltin(API, createAPIBuiltin),
					FRAGMENT:   starlark.NewBuiltin(FRAGMENT, createFragmentBuiltin),
					REDIRECT:   starlark.NewBuiltin(REDIRECT, createRedirectBuiltin),
					PERMISSION: starlark.NewBuiltin(PERMISSION, createPermissionBuiltin),
					STYLE:      starlark.NewBuiltin(STYLE, createStyleBuiltin),
					RESPONSE:   starlark.NewBuiltin(RESPONSE, createResponseBuiltin),
					LIBRARY:    starlark.NewBuiltin(LIBRARY, createLibraryBuiltin),
					ACTION:     starlark.NewBuiltin(ACTION, createActionBuiltin),
					RESULT:     starlark.NewBuiltin(RESULT, createResultBuiltin),
					AUDIT:      starlark.NewBuiltin(AUDIT, createAuditBuiltin),
					OUTPUT:     starlark.NewBuiltin(OUTPUT, createOutputBuiltin),
					CONFIG:     starlark.NewBuiltin(CONFIG, CreateConfigBuiltin(nodeConfig, allowedEnv)),

					GET:             starlark.String(GET),
					POST:            starlark.String(POST),
					PUT:             starlark.String(PUT),
					DELETE:          starlark.String(DELETE),
					JSON:            starlark.String(JSON),
					TEXT:            starlark.String(TEXT),
					READ:            starlark.String(READ),
					WRITE:           starlark.String(WRITE),
					AUTO:            starlark.String(AUTO),
					TABLE:           starlark.String(TABLE),
					DOWNLOAD:        starlark.String(DOWNLOAD),
					IMAGE:           starlark.String(IMAGE),
					"CONTAINER_URL": starlark.String(CONTAINER_URL),
				},
			},
		}
	})

	return builtin
}
