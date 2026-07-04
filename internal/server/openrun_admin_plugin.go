// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"strings"

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
		app.CreatePluginApiName(c.CreateApp, app.WRITE, "create_app"),
		app.CreatePluginApiName(c.DeleteApps, app.WRITE, "delete_apps"),
		app.CreatePluginApiName(c.ReloadApps, app.WRITE, "reload_apps"),
		app.CreatePluginApiName(c.ApproveApps, app.WRITE, "approve_apps"),
		app.CreatePluginApiName(c.SwitchVersion, app.WRITE, "switch_version"),
		app.CreatePluginApiName(c.PromoteApps, app.WRITE, "promote_apps"),
		app.CreatePluginApiName(c.UpdateParams, app.WRITE, "update_params"),
		app.CreatePluginApiName(c.UpdateAuth, app.WRITE, "update_auth"),
		app.CreatePluginApiName(c.CreateSync, app.WRITE, "create_sync"),
		app.CreatePluginApiName(c.RunSync, app.WRITE, "run_sync"),
		app.CreatePluginApiName(c.DeleteSync, app.WRITE, "delete_sync"),
		app.CreatePluginApiName(c.CreateService, app.WRITE, "create_service"),
		app.CreatePluginApiName(c.DeleteService, app.WRITE, "delete_service"),
		app.CreatePluginApiName(c.StartContainer, app.WRITE, "start_container"),
		app.CreatePluginApiName(c.StopContainer, app.WRITE, "stop_container"),
		app.CreatePluginApiName(c.CreateBinding, app.WRITE, "create_binding"),
		app.CreatePluginApiName(c.UpdateBinding, app.WRITE, "update_binding"),
		app.CreatePluginApiName(c.DeleteBinding, app.WRITE, "delete_binding"),
	}

	adminPlugin := func(pluginContext *types.PluginContext) (any, error) {
		return &openrunAdminPlugin{server: server}, nil
	}

	app.RegisterPlugin("openrun_admin", adminPlugin, pluginFuncs)
}

type openrunAdminPlugin struct {
	server *Server
}

// CreateApp creates a new app (imperative create). With dry_run, the create
// is validated and the requested permissions are returned without committing
func (c *openrunAdminPlugin) CreateApp(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var appPath, sourceUrl, auth, spec, gitBranch, gitAuth starlark.String
	var params *starlark.Dict
	var dryRun, approve starlark.Bool
	if err := starlark.UnpackArgs("create_app", args, kwargs, "path", &appPath, "source_url", &sourceUrl,
		"approve?", &approve, "auth?", &auth, "spec?", &spec, "git_branch?", &gitBranch,
		"git_auth?", &gitAuth, "params?", &params, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	paramValues, err := dictToStringMap(params, "params")
	if err != nil {
		return nil, err
	}

	appRequest := &types.CreateAppRequest{
		Path:        appPath.GoString(),
		SourceUrl:   sourceUrl.GoString(),
		AppAuthn:    types.AppAuthnType(auth.GoString()),
		Spec:        types.AppSpec(spec.GoString()),
		GitBranch:   gitBranch.GoString(),
		GitAuthName: gitAuth.GoString(),
		ParamValues: paramValues,
	}

	result, err := c.server.CreateApp(system.GetRequestContext(thread), appPath.GoString(), bool(approve), bool(dryRun), appRequest)
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

// DeleteApps deletes the apps matching the glob (with their staging/preview apps)
func (c *openrunAdminPlugin) DeleteApps(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pathGlob starlark.String
	var dryRun starlark.Bool
	if err := starlark.UnpackArgs("delete_apps", args, kwargs, "path_glob", &pathGlob, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	result, err := c.server.DeleteApps(system.GetRequestContext(thread), pathGlob.GoString(), bool(dryRun))
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

// ReloadApps reloads apps matching the glob from their source (git or disk)
func (c *openrunAdminPlugin) ReloadApps(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pathGlob starlark.String
	var dryRun, forceReload starlark.Bool
	approve := starlark.Bool(true)
	promote := starlark.Bool(true)
	if err := starlark.UnpackArgs("reload_apps", args, kwargs, "path_glob", &pathGlob,
		"approve?", &approve, "promote?", &promote, "force_reload?", &forceReload, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	result, err := c.server.ReloadApps(system.GetRequestContext(thread), pathGlob.GoString(), bool(approve), bool(dryRun), bool(promote),
		"", "", "", bool(forceReload), false)
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

// ApproveApps approves the plugin and permission usage for apps matching the
// glob. With dry_run, the pending permissions are returned without approving
func (c *openrunAdminPlugin) ApproveApps(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pathGlob starlark.String
	var dryRun starlark.Bool
	promote := starlark.Bool(true)
	if err := starlark.UnpackArgs("approve_apps", args, kwargs, "path_glob", &pathGlob, "promote?", &promote, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	result, err := c.server.ApproveApps(system.GetRequestContext(thread), pathGlob.GoString(), bool(dryRun), bool(promote))
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

// UpdateParams replaces the param values for apps matching the glob. The
// change applies to staging and is promoted to prod when promote is true
func (c *openrunAdminPlugin) UpdateParams(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pathGlob starlark.String
	var params *starlark.Dict
	var dryRun starlark.Bool
	promote := starlark.Bool(true)
	if err := starlark.UnpackArgs("update_params", args, kwargs, "path_glob", &pathGlob, "params", &params,
		"promote?", &promote, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	paramValues, err := dictToStringMap(params, "params")
	if err != nil {
		return nil, err
	}

	result, err := c.server.ReplaceAppParams(system.GetRequestContext(thread), pathGlob.GoString(), bool(dryRun), bool(promote), paramValues)
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

// SwitchVersion switches the app at path (use the staging app's path for
// staging) to the given version. version can be a number, "previous", "next"
// or "revert"
func (c *openrunAdminPlugin) SwitchVersion(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, version starlark.String
	var dryRun starlark.Bool
	if err := starlark.UnpackArgs("switch_version", args, kwargs, "path", &path, "version", &version, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	result, err := c.server.VersionSwitch(system.GetRequestContext(thread), path.GoString(), bool(dryRun), version.GoString())
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

// PromoteApps promotes staged changes to prod for apps matching the glob
func (c *openrunAdminPlugin) PromoteApps(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pathGlob starlark.String
	var dryRun starlark.Bool
	if err := starlark.UnpackArgs("promote_apps", args, kwargs, "path_glob", &pathGlob, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	result, err := c.server.PromoteApps(system.GetRequestContext(thread), pathGlob.GoString(), bool(dryRun))
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

// UpdateAuth updates the authentication type for apps matching the glob
func (c *openrunAdminPlugin) UpdateAuth(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pathGlob, auth starlark.String
	var dryRun starlark.Bool
	if err := starlark.UnpackArgs("update_auth", args, kwargs, "path_glob", &pathGlob, "auth", &auth, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	updateRequest := types.CreateUpdateAppRequest()
	updateRequest.AuthnType = types.StringValue(auth.GoString())

	result, err := c.server.UpdateAppSettings(system.GetRequestContext(thread), pathGlob.GoString(), bool(dryRun), updateRequest)
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

func parseServiceId(id string) (serviceType, name string, err error) {
	parts := strings.Split(id, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid service id %q: expected <service_type>/<service_name>", id)
	}
	return parts[0], parts[1], nil
}

// CreateService creates a new service entry. id is <service_type>/<name>
func (c *openrunAdminPlugin) CreateService(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, staging starlark.String
	var config *starlark.Dict
	var isDefault, dryRun starlark.Bool
	if err := starlark.UnpackArgs("create_service", args, kwargs, "id", &id,
		"config?", &config, "is_default?", &isDefault, "staging?", &staging, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	serviceType, name, err := parseServiceId(id.GoString())
	if err != nil {
		return nil, err
	}
	configMap, err := dictToStringMap(config, "config")
	if err != nil {
		return nil, err
	}

	service := types.Service{
		Name:        name,
		ServiceType: serviceType,
		IsDefault:   bool(isDefault),
		Staging:     staging.GoString(),
		Config:      configMap,
	}
	if err := c.server.CreateService(system.GetRequestContext(thread), &service, bool(dryRun)); err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(map[string]any{"id": service.Id, "dry_run": bool(dryRun)})
}

// DeleteService deletes a service entry. id is <service_type>/<name>
func (c *openrunAdminPlugin) DeleteService(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id starlark.String
	var dryRun starlark.Bool
	if err := starlark.UnpackArgs("delete_service", args, kwargs, "id", &id, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	serviceType, name, err := parseServiceId(id.GoString())
	if err != nil {
		return nil, err
	}
	if err := c.server.DeleteService(system.GetRequestContext(thread), name, serviceType, bool(dryRun)); err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(map[string]any{"id": id.GoString(), "dry_run": bool(dryRun)})
}

// StartContainer starts a stopped OpenRun managed container
func (c *openrunAdminPlugin) StartContainer(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return c.containerLifecycle(thread, args, kwargs, "start_container")
}

// StopContainer stops a running OpenRun managed container
func (c *openrunAdminPlugin) StopContainer(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return c.containerLifecycle(thread, args, kwargs, "stop_container")
}

func (c *openrunAdminPlugin) containerLifecycle(thread *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple, op string) (starlark.Value, error) {
	var id starlark.String
	if err := starlark.UnpackArgs(op, args, kwargs, "id", &id); err != nil {
		return nil, err
	}

	ctx := system.GetRequestContext(thread)
	var err error
	if op == "start_container" {
		err = c.server.StartManagedContainer(ctx, id.GoString())
	} else {
		err = c.server.StopManagedContainer(ctx, id.GoString())
	}
	if err != nil {
		return nil, err
	}
	ret := starlark.Dict{}
	ret.SetKey(starlark.String("id"), id) //nolint:errcheck
	return &ret, nil
}

// CreateBinding creates a new binding. source is a service id
// (serviceType/name) or a base binding path
func (c *openrunAdminPlugin) CreateBinding(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, source starlark.String
	var grants *starlark.List
	var config *starlark.Dict
	var dryRun starlark.Bool
	if err := starlark.UnpackArgs("create_binding", args, kwargs, "path", &path, "source", &source,
		"grants?", &grants, "config?", &config, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	grantList, err := listToStringSlice(grants, "grants")
	if err != nil {
		return nil, err
	}
	configValues, err := dictToStringMap(config, "config")
	if err != nil {
		return nil, err
	}

	createRequest := &types.CreateBindingRequest{
		Path:   path.GoString(),
		Source: source.GoString(),
		Grants: grantList,
		Config: configValues,
	}

	binding, err := c.server.CreateBinding(system.GetRequestContext(thread), createRequest, bool(dryRun))
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(redactBindingAccount(binding))
}

// UpdateBinding updates the grants on a derived binding. The change applies
// to staging and is promoted to prod when promote is true
func (c *openrunAdminPlugin) UpdateBinding(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path starlark.String
	var addGrants, deleteGrants *starlark.List
	var dryRun starlark.Bool
	promote := starlark.Bool(true)
	if err := starlark.UnpackArgs("update_binding", args, kwargs, "path", &path,
		"add_grants?", &addGrants, "delete_grants?", &deleteGrants, "promote?", &promote, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	addList, err := listToStringSlice(addGrants, "add_grants")
	if err != nil {
		return nil, err
	}
	deleteList, err := listToStringSlice(deleteGrants, "delete_grants")
	if err != nil {
		return nil, err
	}

	updateRequest := types.UpdateBindingRequest{
		Path:         path.GoString(),
		AddGrants:    addList,
		DeleteGrants: deleteList,
	}

	binding, err := c.server.UpdateBinding(system.GetRequestContext(thread), updateRequest, bool(dryRun), bool(promote), false)
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(redactBindingAccount(binding))
}

// DeleteBinding deletes the binding at the given path
func (c *openrunAdminPlugin) DeleteBinding(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path starlark.String
	var dryRun starlark.Bool
	if err := starlark.UnpackArgs("delete_binding", args, kwargs, "path", &path, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	if err := c.server.DeleteBinding(system.GetRequestContext(thread), path.GoString(), bool(dryRun)); err != nil {
		return nil, err
	}
	ret := starlark.Dict{}
	ret.SetKey(starlark.String("path"), path) //nolint:errcheck
	return &ret, nil
}

func listToStringSlice(list *starlark.List, name string) ([]string, error) {
	if list == nil {
		return nil, nil
	}
	values := make([]string, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		value, ok := list.Index(i).(starlark.String)
		if !ok {
			return nil, fmt.Errorf("%s values must be strings", name)
		}
		values = append(values, value.GoString())
	}
	return values, nil
}

func dictToStringMap(dict *starlark.Dict, name string) (map[string]string, error) {
	values := map[string]string{}
	if dict == nil {
		return values, nil
	}
	for _, item := range dict.Items() {
		key, ok := item[0].(starlark.String)
		if !ok {
			return nil, fmt.Errorf("%s keys must be strings", name)
		}
		value, ok := item[1].(starlark.String)
		if !ok {
			return nil, fmt.Errorf("%s values must be strings", name)
		}
		values[key.GoString()] = value.GoString()
	}
	return values, nil
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
