// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

const MAX_BYTES_STDOUT = 100 * 1024 * 1024 // 100MB

func init() {
	e := &ExecPlugin{}
	// exec runs arbitrary commands on the host: registered as a system plugin
	// (anonymous callers are blocked unless security.unsafe_allow_system_plugins_anon
	// is set), and additionally disallowed for all apps by the default
	// permissions.disallow config entry
	app.RegisterSystemPlugin("exec", NewExecPlugin, []plugin.PluginFunc{
		app.CreatePluginApi(e.Run, app.READ_WRITE),
	})
}

type ExecPlugin struct {
}

func NewExecPlugin(_ *types.PluginContext) (any, error) {
	return &ExecPlugin{}, nil
}

func (e *ExecPlugin) Run(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return execCommand(nil, thread, builtin, args, kwargs)
}
