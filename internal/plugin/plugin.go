// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"go.starlark.net/starlark"
)

// PluginMap is the plugin function mapping to PluginFuncs
type PluginMap map[string]*PluginInfo

// PluginInfo is the info for one plugin module function (or constant), used
// to build the hooked Starlark module at load time. All plugins are SDK
// plugins (pkg/plugin ModuleDef); Remote selects the dispatch transport.
type PluginInfo struct {
	ModuleName    string // store
	PluginPath    string // store.in
	FuncName      string // run
	IsRead        bool
	HandlerName   string // "" marks a module constant
	ConstantValue starlark.Value
	// RequiresAuth marks a privileged system plugin that anonymous callers may
	// not invoke unless security.unsafe_allow_system_plugins_anon is set
	RequiresAuth bool
	// Remote marks a function served by an out-of-process plugin provider;
	// the call is dispatched over gRPC to the provider named by ProviderName.
	// Otherwise the function is served by the in-process provider of that
	// name, through the direct value bridge
	Remote       bool
	ProviderName string
}
