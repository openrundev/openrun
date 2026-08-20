// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

func init() {
	app.RegisterLocalProvider("container", &sdk.ServeConfig{
		ProviderVersion: "builtin",
		Modules: map[string]sdk.ModuleDef{
			"container": {
				Builder: NewContainerModule,
				Functions: []sdk.FuncDef{
					{Name: "config", Type: sdk.READ, Method: "Config"}, // config API
					{Name: "run", Type: sdk.WRITE, Method: "Run"},
				},
				Constants: map[string]any{
					"URL":          apptype.CONTAINER_URL,
					"AUTO":         types.CONTAINER_SOURCE_AUTO,
					"NIXPACKS":     types.CONTAINER_SOURCE_NIXPACKS,
					"IMAGE_PREFIX": types.CONTAINER_SOURCE_IMAGE_PREFIX,
					"COMMAND":      types.CONTAINER_LIFETIME_COMMAND,
				},
			},
		},
	}, app.LocalProviderOptions{})
}

type containerModule struct{}

func NewContainerModule() sdk.Module {
	return &containerModule{}
}

func (c *containerModule) InitModule(ctx context.Context, init sdk.ModuleInit) error {
	return nil
}

func (c *containerModule) Close(ctx context.Context) error {
	return nil
}

// Run executes a command inside the app's container. It needs the request's
// container handler from the host process, so the container module is
// host-bound: it only works compiled into the OpenRun binary.
func (c *containerModule) Run(ctx context.Context, call *sdk.Call) (any, error) {
	if call.Host == nil {
		return nil, errors.New("container.run requires the compiled-in container plugin")
	}
	ch := call.Host.Value(types.TL_CONTAINER_HANDLER)
	if ch == nil {
		return nil, errors.New("container config not initialized")
	}
	handler, ok := ch.(*app.ContainerHandler)
	if !ok {
		return nil, fmt.Errorf("expected container manager, got %T", ch)
	}
	return execCommand(ctx, call, handler)
}

func (c *containerModule) Config(ctx context.Context, call *sdk.Call) (any, error) {
	var src, lifetime, scheme, health, buildDir string
	var port int64
	var cargs, devSettings map[string]any
	var volumes []string
	if err := sdk.UnpackArgs("config", call, "src?", &src, "port?", &port, "scheme?", &scheme,
		"health?", &health, "lifetime?", &lifetime, "build_dir?", &buildDir, "volumes?", &volumes,
		"cargs?", &cargs, "dev_settings?", &devSettings); err != nil {
		return nil, err
	}

	if port < 0 {
		return nil, fmt.Errorf("port must be an integer higher than or equal to zero")
	}

	if cargs == nil {
		cargs = map[string]any{}
	}
	if devSettings == nil {
		devSettings = map[string]any{}
	} else {
		if err := validateDevSettings(devSettings); err != nil {
			return nil, err
		}
	}
	if volumes == nil {
		volumes = []string{}
	}

	return &sdk.Struct{TypeName: "container_config", Fields: map[string]any{
		"source":       cmp.Or(src, "auto"),
		"lifetime":     cmp.Or(lifetime, "app"),
		"port":         port,
		"scheme":       cmp.Or(scheme, "http"),
		"health":       cmp.Or(health, "/"),
		"build_dir":    buildDir,
		"volumes":      volumes,
		"cargs":        cargs,
		"dev_settings": devSettings,
	}}, nil
}

// validateDevSettings checks the dev_settings dict keys at config eval time so
// that typos fail the app load with a clear error instead of being ignored.
func validateDevSettings(devSettings map[string]any) error {
	for key := range devSettings {
		if !slices.Contains(types.DevSettingsKeys, key) {
			return fmt.Errorf("invalid dev_settings key %q, allowed keys are %s", key, strings.Join(types.DevSettingsKeys, ", "))
		}
	}
	return nil
}
