// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

func initAdminPlugin(server *Server) {
	app.RegisterLocalProvider("openrun_admin", &sdk.ServeConfig{
		ProviderVersion: "builtin",
		Modules: map[string]sdk.ModuleDef{
			"openrun_admin": {
				Builder: func() sdk.Module { return &openrunAdminPlugin{server: server} },
				Functions: []sdk.FuncDef{
					{Name: "create_app", Type: sdk.WRITE, Method: "CreateApp"},
					{Name: "delete_apps", Type: sdk.WRITE, Method: "DeleteApps"},
					{Name: "reload_apps", Type: sdk.WRITE, Method: "ReloadApps"},
					{Name: "approve_apps", Type: sdk.WRITE, Method: "ApproveApps"},
					{Name: "switch_version", Type: sdk.WRITE, Method: "SwitchVersion"},
					{Name: "promote_apps", Type: sdk.WRITE, Method: "PromoteApps"},
					{Name: "update_params", Type: sdk.WRITE, Method: "UpdateParams"},
					{Name: "update_auth", Type: sdk.WRITE, Method: "UpdateAuth"},
					{Name: "update_bindings", Type: sdk.WRITE, Method: "UpdateBindings"},
					{Name: "create_sync", Type: sdk.WRITE, Method: "CreateSync"},
					{Name: "run_sync", Type: sdk.WRITE, Method: "RunSync"},
					{Name: "delete_sync", Type: sdk.WRITE, Method: "DeleteSync"},
					{Name: "update_rbac_enabled", Type: sdk.WRITE, Method: "UpdateRBACEnabled"},
					{Name: "set_rbac_group", Type: sdk.WRITE, Method: "SetRBACGroup"},
					{Name: "delete_rbac_group", Type: sdk.WRITE, Method: "DeleteRBACGroup"},
					{Name: "set_rbac_role", Type: sdk.WRITE, Method: "SetRBACRole"},
					{Name: "delete_rbac_role", Type: sdk.WRITE, Method: "DeleteRBACRole"},
					{Name: "add_rbac_grant", Type: sdk.WRITE, Method: "AddRBACGrant"},
					{Name: "update_rbac_grant", Type: sdk.WRITE, Method: "UpdateRBACGrant"},
					{Name: "delete_rbac_grant", Type: sdk.WRITE, Method: "DeleteRBACGrant"},
					{Name: "publish_rbac_config", Type: sdk.WRITE, Method: "PublishRBACConfig"},
					{Name: "discard_rbac_draft", Type: sdk.WRITE, Method: "DiscardRBACDraft"},
					{Name: "restore_config", Type: sdk.WRITE, Method: "RestoreConfig"},
					{Name: "set_config_entry", Type: sdk.WRITE, Method: "SetConfigEntry"},
					{Name: "delete_config_entry", Type: sdk.WRITE, Method: "DeleteConfigEntry"},
					{Name: "set_config_value", Type: sdk.WRITE, Method: "SetConfigValue"},
					{Name: "delete_config_value", Type: sdk.WRITE, Method: "DeleteConfigValue"},
					{Name: "create_service", Type: sdk.WRITE, Method: "CreateService"},
					{Name: "delete_service", Type: sdk.WRITE, Method: "DeleteService"},
					{Name: "start_container", Type: sdk.WRITE, Method: "StartContainer"},
					{Name: "stop_container", Type: sdk.WRITE, Method: "StopContainer"},
					{Name: "create_binding", Type: sdk.WRITE, Method: "CreateBinding"},
					{Name: "update_binding", Type: sdk.WRITE, Method: "UpdateBinding"},
					{Name: "delete_binding", Type: sdk.WRITE, Method: "DeleteBinding"},
					{Name: "create_secret", Type: sdk.WRITE, Method: "CreateSecret"},
					{Name: "delete_secret", Type: sdk.WRITE, Method: "DeleteSecret"},
					{Name: "list_secrets", Type: sdk.READ, Method: "ListSecrets"},
					{Name: "get_secret", Type: sdk.READ, Method: "GetSecret"},
					{Name: "secret_reveal", Type: sdk.READ, Method: "SecretReveal"},
					{Name: "rekey_secrets", Type: sdk.WRITE, Method: "RekeySecrets"},
				},
			},
		},
	}, app.LocalProviderOptions{SystemModules: []string{"openrun_admin"}})
}

type openrunAdminPlugin struct {
	server *Server
}

func (c *openrunAdminPlugin) InitModule(ctx context.Context, init sdk.ModuleInit) error {
	return nil
}

func (c *openrunAdminPlugin) Close(ctx context.Context) error {
	return nil
}

// CreateApp creates a new app (imperative create). With dry_run, the create
// is validated and the requested permissions are returned without committing.
// bindings entries are binding paths or service sources (serviceType or
// serviceType/name), for which an auto binding is created
func (c *openrunAdminPlugin) CreateApp(ctx context.Context, call *sdk.Call) (any, error) {
	var appPath, sourceUrl, auth, spec, gitBranch, gitAuth string
	var params map[string]any
	var bindings []string
	var dryRun, approve bool
	if err := sdk.UnpackArgs("create_app", call, "path", &appPath, "source_url", &sourceUrl,
		"approve?", &approve, "auth?", &auth, "spec?", &spec, "git_branch?", &gitBranch,
		"git_auth?", &gitAuth, "params?", &params, "bindings?", &bindings, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	paramValues, err := dictToStringMap(params, "params")
	if err != nil {
		return nil, err
	}

	appRequest := &types.CreateAppRequest{
		Path:        appPath,
		SourceUrl:   sourceUrl,
		AppAuthn:    types.AppAuthnType(auth),
		Spec:        types.AppSpec(spec),
		GitBranch:   gitBranch,
		GitAuthName: gitAuth,
		ParamValues: paramValues,
		Bindings:    bindings,
	}

	result, err := c.server.CreateApp(ctx, appPath, approve, dryRun, appRequest)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// DeleteApps deletes the apps matching the glob (with their staging/preview apps)
func (c *openrunAdminPlugin) DeleteApps(ctx context.Context, call *sdk.Call) (any, error) {
	var pathGlob string
	var dryRun bool
	if err := sdk.UnpackArgs("delete_apps", call, "path_glob", &pathGlob, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	result, err := c.server.DeleteApps(ctx, pathGlob, dryRun)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// ReloadApps reloads apps matching the glob from their source (git or disk)
func (c *openrunAdminPlugin) ReloadApps(ctx context.Context, call *sdk.Call) (any, error) {
	var pathGlob string
	var dryRun, forceReload, verify bool
	approve := true
	promote := true
	if err := sdk.UnpackArgs("reload_apps", call, "path_glob", &pathGlob,
		"approve?", &approve, "promote?", &promote, "force_reload?", &forceReload, "verify?", &verify, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	result, err := c.server.ReloadApps(ctx, pathGlob, approve, dryRun, promote,
		"", "", "", forceReload, verify)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// ApproveApps approves the plugin and permission usage for apps matching the
// glob. With dry_run, the pending permissions are returned without approving
func (c *openrunAdminPlugin) ApproveApps(ctx context.Context, call *sdk.Call) (any, error) {
	var pathGlob string
	var dryRun bool
	promote := true
	if err := sdk.UnpackArgs("approve_apps", call, "path_glob", &pathGlob, "promote?", &promote, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	result, err := c.server.ApproveApps(ctx, pathGlob, dryRun, promote)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// UpdateParams replaces the param values for apps matching the glob. The
// change applies to staging and is promoted to prod when promote is true
func (c *openrunAdminPlugin) UpdateParams(ctx context.Context, call *sdk.Call) (any, error) {
	var pathGlob string
	var params map[string]any
	var dryRun bool
	promote := true
	if err := sdk.UnpackArgs("update_params", call, "path_glob", &pathGlob, "params", &params,
		"promote?", &promote, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	paramValues, err := dictToStringMap(params, "params")
	if err != nil {
		return nil, err
	}

	result, err := c.server.ReplaceAppParams(ctx, pathGlob, dryRun, promote, paramValues)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// SwitchVersion switches the app at path (use the staging app's path for
// staging) to the given version. version can be a number, "previous", "next"
// or "revert"
func (c *openrunAdminPlugin) SwitchVersion(ctx context.Context, call *sdk.Call) (any, error) {
	var path, version string
	var dryRun bool
	if err := sdk.UnpackArgs("switch_version", call, "path", &path, "version", &version, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	result, err := c.server.VersionSwitch(ctx, path, dryRun, version)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// PromoteApps promotes staged changes to prod for apps matching the glob
func (c *openrunAdminPlugin) PromoteApps(ctx context.Context, call *sdk.Call) (any, error) {
	var pathGlob string
	var dryRun bool
	if err := sdk.UnpackArgs("promote_apps", call, "path_glob", &pathGlob, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	result, err := c.server.PromoteApps(ctx, pathGlob, dryRun)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// UpdateAuth updates the authentication type for apps matching the glob
func (c *openrunAdminPlugin) UpdateAuth(ctx context.Context, call *sdk.Call) (any, error) {
	var pathGlob, auth string
	var dryRun bool
	if err := sdk.UnpackArgs("update_auth", call, "path_glob", &pathGlob, "auth", &auth, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	updateRequest := types.CreateUpdateAppRequest()
	updateRequest.AuthnType = types.StringValue(auth)

	result, err := c.server.UpdateAppSettings(ctx, pathGlob, dryRun, updateRequest)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// UpdateBindings replaces the binding references on apps matching the glob.
// Entries are binding paths or service sources (serviceType or
// serviceType/name), for which an auto binding is created; a single "-" entry
// clears all bindings. The change applies to staging and is promoted to prod
// when promote is true
func (c *openrunAdminPlugin) UpdateBindings(ctx context.Context, call *sdk.Call) (any, error) {
	var pathGlob string
	var bindings []string
	var dryRun bool
	promote := true
	if err := sdk.UnpackArgs("update_bindings", call, "path_glob", &pathGlob, "bindings", &bindings,
		"promote?", &promote, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	updateMetadata := types.CreateUpdateAppMetadataRequest()
	updateMetadata.ConfigType = types.AppMetadataBindings
	updateMetadata.ConfigEntries = bindings

	metadataArgs := map[string]any{
		"metadata": updateMetadata,
		"dryRun":   dryRun,
	}
	result, err := c.server.StagedUpdate(ctx, pathGlob, dryRun, promote,
		c.server.updateMetadataHandler, metadataArgs, "update_metadata")
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

func parseServiceId(id string) (serviceType, name string, err error) {
	parts := strings.Split(id, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid service id %q: expected <service_type>/<service_name>", id)
	}
	return parts[0], parts[1], nil
}

// CreateService creates a new service entry. id is <service_type>/<name>
func (c *openrunAdminPlugin) CreateService(ctx context.Context, call *sdk.Call) (any, error) {
	var id, staging string
	var config map[string]any
	var isDefault, dryRun bool
	if err := sdk.UnpackArgs("create_service", call, "id", &id,
		"config?", &config, "is_default?", &isDefault, "staging?", &staging, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	serviceType, name, err := parseServiceId(id)
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
		IsDefault:   isDefault,
		Staging:     staging,
		Config:      configMap,
	}
	if err := c.server.CreateService(ctx, &service, dryRun); err != nil {
		return nil, err
	}
	return map[string]any{"id": service.Id, "dry_run": dryRun}, nil
}

// DeleteService deletes a service entry. id is <service_type>/<name>
func (c *openrunAdminPlugin) DeleteService(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	var dryRun bool
	if err := sdk.UnpackArgs("delete_service", call, "id", &id, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	serviceType, name, err := parseServiceId(id)
	if err != nil {
		return nil, err
	}
	if err := c.server.DeleteService(ctx, name, serviceType, dryRun); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "dry_run": dryRun}, nil
}

// StartContainer starts a stopped OpenRun managed container
func (c *openrunAdminPlugin) StartContainer(ctx context.Context, call *sdk.Call) (any, error) {
	return c.containerLifecycle(ctx, call, "start_container")
}

// StopContainer stops a running OpenRun managed container
func (c *openrunAdminPlugin) StopContainer(ctx context.Context, call *sdk.Call) (any, error) {
	return c.containerLifecycle(ctx, call, "stop_container")
}

func (c *openrunAdminPlugin) containerLifecycle(ctx context.Context, call *sdk.Call, op string) (any, error) {
	var id string
	if err := sdk.UnpackArgs(op, call, "id", &id); err != nil {
		return nil, err
	}

	var err error
	if op == "start_container" {
		err = c.server.StartManagedContainer(ctx, id)
	} else {
		err = c.server.StopManagedContainer(ctx, id)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id}, nil
}

// CreateBinding creates a new binding. source is a service id
// (serviceType/name) or a base binding path
func (c *openrunAdminPlugin) CreateBinding(ctx context.Context, call *sdk.Call) (any, error) {
	var path, source string
	var grants []string
	var config map[string]any
	var dryRun bool
	if err := sdk.UnpackArgs("create_binding", call, "path", &path, "source", &source,
		"grants?", &grants, "config?", &config, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	configValues, err := dictToStringMap(config, "config")
	if err != nil {
		return nil, err
	}

	createRequest := &types.CreateBindingRequest{
		Path:   path,
		Source: source,
		Grants: grants,
		Config: configValues,
	}

	binding, err := c.server.CreateBinding(ctx, createRequest, dryRun)
	if err != nil {
		return nil, err
	}
	return structValue(redactBindingAccount(binding))
}

// UpdateBinding updates the grants on a derived binding. The change applies
// to staging and is promoted to prod when promote is true
func (c *openrunAdminPlugin) UpdateBinding(ctx context.Context, call *sdk.Call) (any, error) {
	var path string
	var addGrants, deleteGrants []string
	var dryRun bool
	promote := true
	if err := sdk.UnpackArgs("update_binding", call, "path", &path,
		"add_grants?", &addGrants, "delete_grants?", &deleteGrants, "promote?", &promote, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	updateRequest := types.UpdateBindingRequest{
		Path:         path,
		AddGrants:    addGrants,
		DeleteGrants: deleteGrants,
	}

	binding, err := c.server.UpdateBinding(ctx, updateRequest, dryRun, promote, false)
	if err != nil {
		return nil, err
	}
	return structValue(redactBindingAccount(binding))
}

// DeleteBinding deletes the binding at the given path
func (c *openrunAdminPlugin) DeleteBinding(ctx context.Context, call *sdk.Call) (any, error) {
	var path string
	var dryRun bool
	if err := sdk.UnpackArgs("delete_binding", call, "path", &path, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	if err := c.server.DeleteBinding(ctx, path, dryRun); err != nil {
		return nil, err
	}
	return map[string]any{"path": path}, nil
}

func listToStringSlice(list []any, name string) ([]string, error) {
	if list == nil {
		return nil, nil
	}
	values := make([]string, 0, len(list))
	for _, item := range list {
		value, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s values must be strings", name)
		}
		values = append(values, value)
	}
	return values, nil
}

func dictToStringMap(dict map[string]any, name string) (map[string]string, error) {
	values := map[string]string{}
	for key, item := range dict {
		value, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s values must be strings", name)
		}
		values[key] = value
	}
	return values, nil
}

// CreateSecret stores a secret value in a writable secret provider (default
// "db"). Either name (explicit) or prefix (a unique name is generated) must
// be set. Returns the name and the {{secret}} template reference to use
func (c *openrunAdminPlugin) CreateSecret(ctx context.Context, call *sdk.Call) (any, error) {
	var name, prefix, value, encoding, description, provider, sourceFile string
	var update bool
	if err := sdk.UnpackArgs("create_secret", call, "value", &value, "prefix?", &prefix,
		"name?", &name, "encoding?", &encoding, "description?", &description, "provider?", &provider,
		"update?", &update, "source_file?", &sourceFile); err != nil {
		return nil, err
	}

	createRequest := &types.CreateSecretRequest{
		Name:        name,
		Prefix:      prefix,
		Value:       value,
		Encoding:    encoding,
		Description: description,
		Provider:    provider,
		SourceFile:  sourceFile,
	}

	result, err := c.server.CreateSecret(ctx, createRequest, update)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// DeleteSecret deletes a stored secret
func (c *openrunAdminPlugin) DeleteSecret(ctx context.Context, call *sdk.Call) (any, error) {
	var name, provider string
	if err := sdk.UnpackArgs("delete_secret", call, "name", &name, "provider?", &provider); err != nil {
		return nil, err
	}

	if err := c.server.DeleteSecret(ctx, provider, name); err != nil {
		return nil, err
	}
	return structValue(types.SecretDeleteResponse{Name: name})
}

// ListSecrets returns info about stored secrets (never values), optionally
// filtered by a glob pattern on the name
func (c *openrunAdminPlugin) ListSecrets(ctx context.Context, call *sdk.Call) (any, error) {
	var glob, provider string
	if err := sdk.UnpackArgs("list_secrets", call, "glob?", &glob, "provider?", &provider); err != nil {
		return nil, err
	}

	results, err := c.server.ListSecrets(ctx, provider, glob)
	if err != nil {
		return nil, err
	}
	return structValue(types.SecretListResponse{Secrets: results})
}

// GetSecret returns info about one stored secret. reveal=True additionally
// returns the value and requires the secret:reveal RBAC permission
func (c *openrunAdminPlugin) GetSecret(ctx context.Context, call *sdk.Call) (any, error) {
	var name, provider string
	var reveal bool
	if err := sdk.UnpackArgs("get_secret", call, "name", &name, "provider?", &provider, "reveal?", &reveal); err != nil {
		return nil, err
	}

	result, err := c.server.GetSecret(ctx, provider, name, reveal)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// SecretReveal returns the clear text value of a secret reference, for the app
// to pass into an HTML template explicitly. The value argument is a
// `{{secret_from "provider" "name"}}` reference (typically from an app param);
// the plugin framework resolves secret references in call arguments before the
// method runs, gated by the secrets patterns of the app's approved permission
// for this call, so the method body only has to echo the argument back.
// Unlike GetSecret with reveal=True, authority comes from the app's approved
// `ace.permission("openrun_admin.in", "secret_reveal", secrets=[[...]])` entry
// (the audit/approve flow), not from the request caller's RBAC permissions,
// so this deliberately does not call a server API gated by enforceGlobalPerm.
// The caller must still be an authenticated user (system plugin auth check)
func (c *openrunAdminPlugin) SecretReveal(ctx context.Context, call *sdk.Call) (any, error) {
	var value string
	if err := sdk.UnpackArgs("secret_reveal", call, "value", &value); err != nil {
		return nil, err
	}

	// A well formed reference matching the approved secrets patterns has been
	// replaced with the clear text value by now. A leftover reference means the
	// reference was malformed (unparseable templates pass through as-is), so
	// fail with a pointer instead of serving the reference text to the page
	if strings.Contains(value, "{{") && strings.Contains(value, "secret") {
		return nil, fmt.Errorf("secret_reveal value still contains an unresolved secret reference; " +
			"check the {{secret_from ...}} syntax and that the app permission for openrun_admin.in " +
			"secret_reveal has matching secrets patterns")
	}
	return value, nil
}

// RekeySecrets re-encrypts stored secrets with the active master key
func (c *openrunAdminPlugin) RekeySecrets(ctx context.Context, call *sdk.Call) (any, error) {
	var provider string
	if err := sdk.UnpackArgs("rekey_secrets", call, "provider?", &provider); err != nil {
		return nil, err
	}

	result, err := c.server.RekeySecrets(ctx, provider)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

func (c *openrunAdminPlugin) CreateSync(ctx context.Context, call *sdk.Call) (any, error) {
	var path, gitBranch, gitAuth string
	var dryRun, promote, approve, verify bool
	var minutes int64
	if err := sdk.UnpackArgs("create_sync", call, "path", &path, "git_branch?", &gitBranch,
		"git_auth?", &gitAuth, "minutes?", &minutes, "dry_run?", &dryRun, "promote?", &promote, "approve?", &approve,
		"verify?", &verify); err != nil {
		return nil, err
	}

	sync := types.SyncMetadata{
		GitBranch:         gitBranch,
		GitAuth:           gitAuth,
		Promote:           promote,
		Approve:           approve,
		Verify:            verify,
		ScheduleFrequency: int(minutes),
	}

	createResponse, err := c.server.CreateSyncEntry(ctx, path, true, dryRun, &sync)
	if err != nil {
		return nil, err
	}

	ret, err := structValue(createResponse)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *openrunAdminPlugin) RunSync(ctx context.Context, call *sdk.Call) (any, error) {
	var syncId string
	var dryRun bool
	if err := sdk.UnpackArgs("run_sync", call, "sync_id", &syncId, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	runResponse, err := c.server.RunSync(ctx, syncId, dryRun)
	if err != nil {
		return nil, err
	}

	ret, err := structValue(runResponse)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *openrunAdminPlugin) DeleteSync(ctx context.Context, call *sdk.Call) (any, error) {
	var syncId string
	var dryRun bool
	if err := sdk.UnpackArgs("delete_sync", call, "sync_id", &syncId, "dry_run?", &dryRun); err != nil {
		return nil, err
	}

	delResponse, err := c.server.DeleteSyncEntry(ctx, syncId, dryRun)
	if err != nil {
		return nil, err
	}

	ret, err := structValue(delResponse)
	if err != nil {
		return nil, err
	}

	return ret, nil
}
