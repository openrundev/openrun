// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

func initAdminPlugin(server *Server) {
	c := &openrunAdminPlugin{}
	pluginFuncs := []plugin.PluginFunc{
		app.CreatePluginApiName(c.CreateSync, app.WRITE, "create_sync"),
		app.CreatePluginApiName(c.RunSync, app.WRITE, "run_sync"),
		app.CreatePluginApiName(c.DeleteSync, app.WRITE, "delete_sync"),
	}

	adminPlugin := func(pluginContext *types.PluginContext) (any, error) {
		return &openrunAdminPlugin{server: server}, nil
	}

	app.RegisterPlugin("openrun_admin", adminPlugin, pluginFuncs)
}

type openrunAdminPlugin struct {
	server *Server
}

func (c *openrunAdminPlugin) CreateSync(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, gitBranch, gitAuth starlark.String
	var dryRun, promote, approve starlark.Bool
	var minutes starlark.Int
	if err := starlark.UnpackArgs("create_sync", args, kwargs, "path", &path, "git_branch?", &gitBranch,
		"git_auth?", &gitAuth, "minutes?", &minutes, "dry_run?", &dryRun, "promote?", &promote, "approve?", &approve); err != nil {
		return nil, err
	}

	minutesInt, ok := minutes.Int64()
	if !ok {
		return nil, fmt.Errorf("minutes must be an integer")
	}

	sync := types.SyncMetadata{
		GitBranch:         gitBranch.GoString(),
		GitAuth:           gitAuth.GoString(),
		Promote:           bool(promote),
		Approve:           bool(approve),
		ScheduleFrequency: int(minutesInt),
	}

	createResponse, err := c.server.CreateSyncEntry(system.GetRequestContext(thread), path.GoString(), true, bool(dryRun), &sync)
	if err != nil {
		return nil, err
	}

	ret, err := starlark_type.ConvertToStarlark(createResponse)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *openrunAdminPlugin) RunSync(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var syncId starlark.String
	var dryRun starlark.Bool
	if err := starlark.UnpackArgs("run_sync", args, kwargs, "sync_id", &syncId, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	runResponse, err := c.server.RunSync(system.GetRequestContext(thread), syncId.GoString(), bool(dryRun))
	if err != nil {
		return nil, err
	}

	ret, err := starlark_type.ConvertToStarlark(runResponse)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *openrunAdminPlugin) DeleteSync(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var syncId starlark.String
	var dryRun starlark.Bool
	if err := starlark.UnpackArgs("delete_sync", args, kwargs, "sync_id", &syncId, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	delResponse, err := c.server.DeleteSyncEntry(system.GetRequestContext(thread), syncId.GoString(), bool(dryRun))
	if err != nil {
		return nil, err
	}

	ret, err := starlark_type.ConvertToStarlark(delResponse)
	if err != nil {
		return nil, err
	}

	return ret, nil
}
