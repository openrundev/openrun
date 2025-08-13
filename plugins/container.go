// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"cmp"
	"errors"
	"fmt"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func init() {
	h := &containerPlugin{}
	pluginFuncs := []plugin.PluginFunc{
		app.CreatePluginApi(h.Config, app.READ), // config API
		app.CreatePluginApi(h.Run, app.READ_WRITE),
		app.CreatePluginConstant("URL", starlark.String(apptype.CONTAINER_URL)),
		app.CreatePluginConstant("AUTO", starlark.String(types.CONTAINER_SOURCE_AUTO)),
		app.CreatePluginConstant("NIXPACKS", starlark.String(types.CONTAINER_SOURCE_NIXPACKS)),
		app.CreatePluginConstant("IMAGE_PREFIX", starlark.String(types.CONTAINER_SOURCE_IMAGE_PREFIX)),
		app.CreatePluginConstant("COMMAND", starlark.String(types.CONTAINER_LIFETIME_COMMAND)),
	}
	app.RegisterPlugin("container", NewContainerPlugin, pluginFuncs)
}

type containerPlugin struct {
	pluginContext *types.PluginContext
}

func NewContainerPlugin(pluginContext *types.PluginContext) (any, error) {
	return &containerPlugin{pluginContext: pluginContext}, nil
}

func (c *containerPlugin) Run(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	cm := thread.Local(types.TL_CONTAINER_MANAGER)
	if cm == nil {
		panic(errors.New("container config not initialized"))
	}
	manager, ok := cm.(*app.ContainerManager)
	if !ok {
		return nil, fmt.Errorf("expected container manager, got %T", cm)
	}
	return execCommand(manager, thread, builtin, args, kwargs)
}

func (c *containerPlugin) Config(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var src, lifetime, scheme, health, buildDir starlark.String
	var port starlark.Int
	var cargs *starlark.Dict
	var volumes *starlark.List
	if err := starlark.UnpackArgs("config", args, kwargs, "src?", &src, "port?", &port, "scheme?", &scheme,
		"health?", &health, "lifetime?", &lifetime, "build_dir?", &buildDir, "volumes?", &volumes, "cargs", &cargs); err != nil {
		return nil, err
	}

	if cargs == nil {
		cargs = starlark.NewDict(0)
	}
	portInt, ok := port.Int64()
	if !ok || portInt < 0 {
		return nil, fmt.Errorf("port must be an integer higher than or equal to zero")
	}

	volumes = cmp.Or(volumes, starlark.NewList([]starlark.Value{}))

	fields := starlark.StringDict{
		"source":    starlark.String(cmp.Or(string(src), "auto")),
		"lifetime":  starlark.String(cmp.Or(string(lifetime), "app")),
		"port":      port,
		"scheme":    starlark.String(cmp.Or(string(scheme), "http")),
		"health":    starlark.String(cmp.Or(string(health), "/")),
		"build_dir": buildDir,
		"volumes":   volumes,
		"cargs":     cargs,
	}

	return starlarkstruct.FromStringDict(starlark.String("container_config"), fields), nil
}
