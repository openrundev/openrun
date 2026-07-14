// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

type NewPluginFunc func(pluginContext *types.PluginContext) (any, error)

// PluginMap is the plugin function mapping to PluginFuncs
type PluginMap map[string]*PluginInfo

// PluginFunc is the OpenRun plugin function mapping to starlark function
type PluginFunc struct {
	Name         string
	IsRead       bool
	FunctionName string
	Constant     starlark.Value
}

// PluginFuncInfo is the OpenRun plugin function info for the starlark function
type PluginInfo struct {
	ModuleName    string // exec
	PluginPath    string // exec.in
	FuncName      string // run
	IsRead        bool
	HandlerName   string
	Builder       NewPluginFunc
	ConstantValue starlark.Value
	// RequiresAuth marks a privileged system plugin that anonymous callers may
	// not invoke unless security.unsafe_allow_system_plugins_anon is set
	RequiresAuth bool
}
