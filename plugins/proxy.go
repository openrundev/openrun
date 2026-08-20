// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"

	"github.com/openrundev/openrun/internal/app"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

func init() {
	app.RegisterLocalProvider("proxy", &sdk.ServeConfig{
		ProviderVersion: "builtin",
		Modules: map[string]sdk.ModuleDef{
			"proxy": {
				Builder: NewProxyModule,
				Functions: []sdk.FuncDef{
					// config API, preview/stage permission checks happen in the reverse proxy wrapper
					{Name: "config", Type: sdk.READ, Method: "Config"},
				},
			},
		},
	}, app.LocalProviderOptions{})
}

type proxyModule struct{}

func NewProxyModule() sdk.Module {
	return &proxyModule{}
}

func (h *proxyModule) InitModule(ctx context.Context, init sdk.ModuleInit) error {
	return nil
}

func (h *proxyModule) Close(ctx context.Context) error {
	return nil
}

func (h *proxyModule) Config(ctx context.Context, call *sdk.Call) (any, error) {
	var url, stripPath string
	var preserveHost bool
	stripApp := true
	var responseHeaders map[string]any
	if err := sdk.UnpackArgs("config", call, "url", &url, "strip_path?", &stripPath,
		"preserve_host?", &preserveHost, "strip_app?", &stripApp, "response_headers?", &responseHeaders); err != nil {
		return nil, err
	}

	if responseHeaders == nil {
		responseHeaders = map[string]any{}
	}

	return &sdk.Struct{TypeName: "ProxyConfig", Fields: map[string]any{
		"url":              url,
		"strip_path":       stripPath,
		"preserve_host":    preserveHost,
		"strip_app":        stripApp,
		"response_headers": responseHeaders,
	}}, nil
}
