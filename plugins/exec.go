// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"

	"github.com/openrundev/openrun/internal/app"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

const MAX_BYTES_STDOUT = 100 * 1024 * 1024 // 100MB

func init() {
	// exec runs arbitrary commands on the host: registered as a system plugin
	// (anonymous callers are blocked unless security.unsafe_allow_system_plugins_anon
	// is set), and additionally disallowed for all apps by the default
	// permissions.disallow config entry
	app.RegisterLocalProvider("exec", &sdk.ServeConfig{
		ProviderVersion: "builtin",
		Modules: map[string]sdk.ModuleDef{
			"exec": {
				Builder: NewExecModule,
				Functions: []sdk.FuncDef{
					{Name: "run", Type: sdk.WRITE, Method: "Run"},
				},
			},
		},
	}, app.LocalProviderOptions{SystemModules: []string{"exec"}})
}

type execModule struct{}

func NewExecModule() sdk.Module {
	return &execModule{}
}

func (e *execModule) InitModule(ctx context.Context, init sdk.ModuleInit) error {
	return nil
}

func (e *execModule) Close(ctx context.Context) error {
	return nil
}

func (e *execModule) Run(ctx context.Context, call *sdk.Call) (any, error) {
	return execCommand(ctx, call, nil)
}
