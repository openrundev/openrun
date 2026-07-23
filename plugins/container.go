// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

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
	ch := thread.Local(types.TL_CONTAINER_HANDLER)
	if ch == nil {
		panic(errors.New("container config not initialized"))
	}
	handler, ok := ch.(*app.ContainerHandler)
	if !ok {
		return nil, fmt.Errorf("expected container manager, got %T", ch)
	}
	return execCommand(handler, thread, builtin, args, kwargs)
}

func (c *containerPlugin) Config(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var src, lifetime, scheme, health, buildDir starlark.String
	var port starlark.Int
	var cargs, devSettings *starlark.Dict
	var volumes *starlark.List
	if err := starlark.UnpackArgs("config", args, kwargs, "src?", &src, "port?", &port, "scheme?", &scheme,
		"health?", &health, "lifetime?", &lifetime, "build_dir?", &buildDir, "volumes?", &volumes, "cargs", &cargs,
		"dev_settings?", &devSettings); err != nil {
		return nil, err
	}

	if cargs == nil {
		cargs = starlark.NewDict(0)
	}
	portInt, ok := port.Int64()
	if !ok || portInt < 0 {
		return nil, fmt.Errorf("port must be an integer higher than or equal to zero")
	}

	if devSettings == nil {
		devSettings = starlark.NewDict(0)
	} else {
		if err := validateDevSettings(devSettings); err != nil {
			return nil, err
		}
	}

	volumes = cmp.Or(volumes, starlark.NewList([]starlark.Value{}))

	fields := starlark.StringDict{
		"source":       starlark.String(cmp.Or(string(src), "auto")),
		"lifetime":     starlark.String(cmp.Or(string(lifetime), "app")),
		"port":         port,
		"scheme":       starlark.String(cmp.Or(string(scheme), "http")),
		"health":       starlark.String(cmp.Or(string(health), "/")),
		"build_dir":    buildDir,
		"volumes":      volumes,
		"cargs":        cargs,
		"dev_settings": devSettings,
	}

	return starlarkstruct.FromStringDict(starlark.String("container_config"), fields), nil
}

// validateDevSettings checks the dev_settings dict keys at config eval time so
// that typos fail the app load with a clear error instead of being ignored.
func validateDevSettings(devSettings *starlark.Dict) error {
	for _, k := range devSettings.Keys() {
		keyStr, ok := k.(starlark.String)
		if !ok {
			return fmt.Errorf("dev_settings keys must be strings, got %s", k.Type())
		}
		if !slices.Contains(types.DevSettingsKeys, string(keyStr)) {
			return fmt.Errorf("invalid dev_settings key %q, allowed keys are %s", string(keyStr), strings.Join(types.DevSettingsKeys, ", "))
		}
	}
	return nil
}
