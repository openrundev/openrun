// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func init() {
	h := &proxyPlugin{}
	pluginFuncs := []plugin.PluginFunc{
		app.CreatePluginApi(h.Config, app.READ), // config API, preview/stage permission checks happen in the reverse proxy wrapper
	}
	app.RegisterPlugin("proxy", NewProxyPlugin, pluginFuncs)
}

type proxyPlugin struct {
}

func NewProxyPlugin(pluginContext *types.PluginContext) (any, error) {
	return &proxyPlugin{}, nil
}

func (h *proxyPlugin) Config(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url, stripPath starlark.String
	var preserveHost starlark.Bool
	var stripApp starlark.Bool = starlark.True
	var responseHeaders *starlark.Dict = &starlark.Dict{}
	if err := starlark.UnpackArgs("config", args, kwargs, "url", &url, "strip_path?",
		&stripPath, "preserve_host?", &preserveHost, "strip_app?", &stripApp, "response_headers", &responseHeaders); err != nil {
		return nil, err
	}

	fields := starlark.StringDict{
		"url":              url,
		"strip_path":       stripPath,
		"preserve_host":    preserveHost,
		"strip_app":        stripApp,
		"response_headers": responseHeaders,
	}
	return starlarkstruct.FromStringDict(starlark.String("ProxyConfig"), fields), nil
}
