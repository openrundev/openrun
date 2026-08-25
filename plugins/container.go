// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"cmp"
	"context"
	"encoding/json/v2"
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
					{Name: "sidecar", Type: sdk.READ, Method: "Sidecar"},
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

const sidecarTypeName = "container_sidecar"

// Sidecar declares one sidecar container of the app: a worker running the
// app image with its own command, or a companion service from a foreign
// image. The result is passed in container.config(sidecars=[...]). Going
// through this call gives each sidecar its own permission entry
// (container.in sidecar, with the name and image as positional arguments),
// so foreign images show up in the app approval, and lets secret references
// in env resolve through the permission's secrets list.
func (c *containerModule) Sidecar(ctx context.Context, call *sdk.Call) (any, error) {
	var name, image, health string
	var port int64
	var command, args, volumes []string
	var env, options map[string]any
	var inheritEnv, alwaysOn any
	if err := sdk.UnpackArgs("sidecar", call, "name", &name, "image?", &image, "command?", &command,
		"args?", &args, "env?", &env, "inherit_env?", &inheritEnv, "port?", &port, "health?", &health,
		"volumes?", &volumes, "always_on?", &alwaysOn, "options?", &options); err != nil {
		return nil, err
	}

	spec := types.SidecarSpec{
		Name:    name,
		Image:   image,
		Command: command,
		Args:    args,
		Port:    int32(port),
		Health:  health,
		Volumes: volumes,
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("sidecar %s: port must be between 0 and 65535", name)
	}
	if image != "" && !strings.HasPrefix(image, types.CONTAINER_SOURCE_IMAGE_PREFIX) {
		// Accept a bare reference too: the prefix is what the spec stores
		spec.Image = types.CONTAINER_SOURCE_IMAGE_PREFIX + image
	}
	var err error
	if spec.Env, err = stringMap("env", env); err != nil {
		return nil, err
	}
	if spec.Options, err = stringMap("options", options); err != nil {
		return nil, err
	}
	if spec.InheritEnv, err = optionalBool("inherit_env", inheritEnv); err != nil {
		return nil, err
	}
	if spec.AlwaysOn, err = optionalBool("always_on", alwaysOn); err != nil {
		return nil, err
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}

	// Round trip through the JSON form so the struct fields are exactly the
	// spec's JSON members (omitted optionals stay omitted)
	var fields map[string]any
	if err := json.Unmarshal([]byte(spec.String()), &fields); err != nil {
		return nil, fmt.Errorf("error encoding sidecar %s: %w", name, err)
	}
	return &sdk.Struct{TypeName: sidecarTypeName, Fields: fields}, nil
}

func stringMap(argName string, in map[string]any) (map[string]string, error) {
	if in == nil {
		return nil, nil
	}
	ret := make(map[string]string, len(in))
	for k, v := range in {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: value for %s must be a string, got %T", argName, k, v)
		}
		ret[k] = s
	}
	return ret, nil
}

func optionalBool(argName string, v any) (*bool, error) {
	if v == nil {
		return nil, nil
	}
	b, ok := v.(bool)
	if !ok {
		return nil, fmt.Errorf("%s must be a bool, got %T", argName, v)
	}
	return &b, nil
}

func (c *containerModule) Config(ctx context.Context, call *sdk.Call) (any, error) {
	var src, lifetime, scheme, health, buildDir string
	var port int64
	var cargs, devSettings map[string]any
	var volumes []string
	var sidecars []any
	if err := sdk.UnpackArgs("config", call, "src?", &src, "port?", &port, "scheme?", &scheme,
		"health?", &health, "lifetime?", &lifetime, "build_dir?", &buildDir, "volumes?", &volumes,
		"cargs?", &cargs, "dev_settings?", &devSettings, "sidecars?", &sidecars); err != nil {
		return nil, err
	}

	// Only container.sidecar() results are accepted, so every sidecar went
	// through its own permission check (a dict literal would bypass it)
	sidecarList := make([]any, 0, len(sidecars))
	names := map[string]bool{}
	for i, entry := range sidecars {
		st, ok := entry.(*sdk.Struct)
		if !ok || st.TypeName != sidecarTypeName {
			return nil, fmt.Errorf("sidecars entry %d must be created with container.sidecar(), got %T", i, entry)
		}
		name, _ := st.Fields["name"].(string)
		if names[name] {
			return nil, fmt.Errorf("duplicate sidecar name %q", name)
		}
		names[name] = true
		sidecarList = append(sidecarList, st.Fields)
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
		"sidecars":     sidecarList,
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
