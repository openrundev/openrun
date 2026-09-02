// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"slices"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

// Plugin methods for the dynamic config (RBAC section). Reads live on
// openrun.in, mutations on openrun_admin.in. Mutations edit the staged draft;
// publish_rbac_config validates and swaps the draft live atomically.

// GetRBACConfig returns the live RBAC config, the staged draft (if any) and
// the config version id used for optimistic concurrency
func (c *openrunPlugin) GetRBACConfig(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("get_rbac_config", call); err != nil {
		return nil, err
	}

	config, draft, err := c.server.GetRBACDynamicConfig(ctx)
	if err != nil {
		return nil, err
	}

	ret := map[string]any{
		"version_id": config.VersionId,
		"rbac":       config.RBAC,
		"has_staged": draft != nil,
		// Built-in roles (admin + predefined openrun-*) are always available
		// but not part of the config's roles map; surface them so the grant
		// editor can offer them for selection
		"builtin_roles": rbac.BuiltinRoleNames(),
	}
	if draft != nil {
		ret["staged"] = draft.RBAC
		ret["draft"] = map[string]any{
			"base_version":  draft.BaseVersion,
			"draft_version": draft.DraftVersion,
			"created_by":    draft.CreatedBy,
			"create_time":   draft.CreateTime.UTC(),
			"updated_by":    draft.UpdatedBy,
			"update_time":   draft.UpdateTime.UTC(),
		}
	}
	return structValue(ret)
}

// GetConfigVersion returns one config history snapshot as formatted JSON.
// Secret values in dynamic config entries are redacted
func (c *openrunPlugin) GetConfigVersion(ctx context.Context, call *sdk.Call) (any, error) {
	var versionId string
	if err := sdk.UnpackArgs("get_config_version", call, "version_id", &versionId); err != nil {
		return nil, err
	}

	snapshot, err := c.server.GetConfigVersion(ctx, versionId)
	if err != nil {
		return nil, err
	}
	if len(snapshot.Entries) > 0 || len(snapshot.Settings) > 0 {
		redacted, err := copyDynamicConfig(snapshot)
		if err != nil {
			return nil, err
		}
		for section, sectionEntries := range redacted.Entries {
			for name, values := range sectionEntries {
				redacted.Entries[section][name] = redactEntryValues(values)
			}
		}
		for section, values := range redacted.Settings {
			redacted.Settings[section] = redactEntryValues(values)
		}
		snapshot = redacted
	}
	formatted, err := json.Marshal(snapshot, jsontext.WithIndent("  "))
	if err != nil {
		return nil, err
	}
	return structValue(map[string]any{
		"version_id": snapshot.VersionId,
		"json":       string(formatted),
	})
}

// ListApiOperations returns the management API operation registry (the
// audit operation vocabulary), sorted by name, with the per-surface policy
// facts a config UI needs: read_only/destructive hints, whether the op is
// disabled for MCP by default (a candidate for api.mcp enable_apis) and
// whether it has no MCP tool at all (mcp_excluded reason). Gated on
// config:basic_read like the other config pickers
func (c *openrunPlugin) ListApiOperations(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("list_api_operations", call); err != nil {
		return nil, err
	}

	if err := c.server.enforceGlobalPerm(ctx, types.PermissionConfigBasicRead, ""); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(apiRegistry))
	for name := range apiRegistry {
		names = append(names, string(name))
	}
	slices.Sort(names)
	ret := make([]any, 0, len(names))
	for _, name := range names {
		entry := apiRegistry[API_NAME(name)]
		value, err := structValue(map[string]any{
			"name":         name,
			"description":  entry.Description,
			"read_only":    entry.ReadOnly,
			"destructive":  entry.Destructive,
			"mcp_disabled": entry.MCPDisabled,
			"mcp_excluded": entry.MCPExcluded,
		})
		if err != nil {
			return nil, err
		}
		ret = append(ret, value)
	}
	return ret, nil
}

// ListRBACPermissions returns the canonical RBAC permissions grouped by
// resource type, as defined in types.RBACPermissionGroups. Used by UIs to
// build permission pickers without hardcoding the permission names
func (c *openrunPlugin) ListRBACPermissions(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("list_rbac_permissions", call); err != nil {
		return nil, err
	}

	if err := c.server.enforceGlobalPerm(ctx, types.PermissionConfigBasicRead, ""); err != nil {
		return nil, err
	}

	ret := []any{}
	for _, group := range types.RBACPermissionGroups {
		perms := make([]string, 0, len(group.Permissions))
		for _, perm := range group.Permissions {
			perms = append(perms, string(perm))
		}
		value, err := structValue(map[string]any{
			"resource":    group.Resource,
			"permissions": perms,
		})
		if err != nil {
			return nil, err
		}
		ret = append(ret, value)
	}
	return ret, nil
}

// GetConfigEntries returns the static and dynamic entries for the requested
// config sections (all dynamically settable sections when the list is
// empty), values redacted. Sections are the named-entry map sections of
// openrun.toml: git_auth, auth, saml, ...
func (c *openrunPlugin) GetConfigEntries(ctx context.Context, call *sdk.Call) (any, error) {
	var sections []any
	if err := sdk.UnpackArgs("get_config_entries", call, "sections?", &sections); err != nil {
		return nil, err
	}
	sectionNames, err := listToStringSlice(sections, "sections")
	if err != nil {
		return nil, err
	}

	entries, err := c.server.GetConfigEntries(ctx, sectionNames)
	if err != nil {
		return nil, err
	}

	config := c.server.GetDynamicConfig()
	ret := map[string]any{"version_id": config.VersionId, "sections": map[string]any{}}
	retSections := ret["sections"].(map[string]any)
	for section, sectionEntries := range entries {
		list := make([]any, 0, len(sectionEntries))
		for _, entry := range sectionEntries {
			list = append(list, map[string]any{
				"name":       entry.Name,
				"values":     entry.Values,
				"source":     entry.Source,
				"overridden": entry.Overridden,
			})
		}
		retSections[section] = list
	}
	return structValue(ret)
}

// GetConfigValues returns the static and dynamic field values for the
// requested struct config sections (security, system, logging, ...), values
// redacted. Static values are flattened to dotted keys
func (c *openrunPlugin) GetConfigValues(ctx context.Context, call *sdk.Call) (any, error) {
	var sections []any
	if err := sdk.UnpackArgs("get_config_values", call, "sections?", &sections); err != nil {
		return nil, err
	}
	sectionNames, err := listToStringSlice(sections, "sections")
	if err != nil {
		return nil, err
	}

	values, err := c.server.GetConfigValues(ctx, sectionNames)
	if err != nil {
		return nil, err
	}

	config := c.server.GetDynamicConfig()
	ret := map[string]any{"version_id": config.VersionId, "sections": map[string]any{}}
	retSections := ret["sections"].(map[string]any)
	for section, sectionValues := range values {
		retSections[section] = map[string]any{
			"static":  sectionValues.Static,
			"dynamic": sectionValues.Dynamic,
		}
	}
	return structValue(ret)
}

// SetConfigValue sets one dynamic config field (section + dotted key). The
// change is validated against the config schema and takes effect immediately
// (settings updates are not staged, unlike RBAC). version_id is the CAS token
func (c *openrunAdminPlugin) SetConfigValue(ctx context.Context, call *sdk.Call) (any, error) {
	var section, key, versionId string
	var value any
	if err := sdk.UnpackArgs("set_config_value", call, "section", &section,
		"key", &key, "value", &value, "version_id?", &versionId); err != nil {
		return nil, err
	}

	return configVersionResult(c.server.SetConfigValue(ctx, section, key, value, versionId))
}

// DeleteConfigValue removes one dynamic config field, immediately reverting
// to the static openrun.toml value
func (c *openrunAdminPlugin) DeleteConfigValue(ctx context.Context, call *sdk.Call) (any, error) {
	var section, key, versionId string
	if err := sdk.UnpackArgs("delete_config_value", call, "section", &section,
		"key", &key, "version_id?", &versionId); err != nil {
		return nil, err
	}

	return configVersionResult(c.server.DeleteConfigValue(ctx, section, key, versionId))
}

// SetConfigEntry creates or replaces one dynamic config entry. The change is
// validated against the config schema and takes effect immediately (entry
// updates are not staged, unlike RBAC). version_id is the CAS token
func (c *openrunAdminPlugin) SetConfigEntry(ctx context.Context, call *sdk.Call) (any, error) {
	var section, name, versionId string
	var values map[string]any
	if err := sdk.UnpackArgs("set_config_entry", call, "section", &section,
		"name", &name, "values", &values, "version_id?", &versionId); err != nil {
		return nil, err
	}

	return configVersionResult(c.server.SetConfigEntry(ctx, section, name, values, versionId))
}

// DeleteConfigEntry removes one dynamic config entry, immediately reverting
// to the static entry of the same name if one exists
func (c *openrunAdminPlugin) DeleteConfigEntry(ctx context.Context, call *sdk.Call) (any, error) {
	var section, name, versionId string
	if err := sdk.UnpackArgs("delete_config_entry", call, "section", &section,
		"name", &name, "version_id?", &versionId); err != nil {
		return nil, err
	}

	return configVersionResult(c.server.DeleteConfigEntry(ctx, section, name, versionId))
}

// ListConfigHistory lists the dynamic config snapshots, newest first
func (c *openrunPlugin) ListConfigHistory(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("list_config_history", call); err != nil {
		return nil, err
	}

	entries, err := c.server.ListConfigHistory(ctx)
	if err != nil {
		return nil, err
	}

	ret := []any{}
	for _, entry := range entries {
		value, err := structValue(map[string]any{
			"version_id":  entry.VersionId,
			"user_id":     entry.UserId,
			"update_time": entry.UpdateTime.UTC(),
		})
		if err != nil {
			return nil, err
		}
		ret = append(ret, value)
	}
	return ret, nil
}

// configVersionResult returns the standard {version_id} result for config mutations
func configVersionResult(config *types.DynamicConfig, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return structValue(map[string]any{"version_id": config.VersionId})
}

// draftVersionResult returns the standard {draft_version} result for draft mutations
func draftVersionResult(draft *types.ConfigDraft, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return structValue(map[string]any{"draft_version": draft.DraftVersion})
}

// SetRBACGroup creates or replaces one group in the draft config
func (c *openrunAdminPlugin) SetRBACGroup(ctx context.Context, call *sdk.Call) (any, error) {
	var name, versionId string
	var users []any
	if err := sdk.UnpackArgs("set_rbac_group", call, "name", &name, "users", &users, "draft_version", &versionId); err != nil {
		return nil, err
	}

	userList, err := listToStringSlice(users, "users")
	if err != nil {
		return nil, err
	}
	groupName := name
	if groupName == "" {
		return nil, fmt.Errorf("group name cannot be empty")
	}

	return draftVersionResult(c.server.UpdateRBACDraft(ctx, versionId,
		func(config *types.RBACConfig) error {
			if config.Groups == nil {
				config.Groups = map[string][]string{}
			}
			config.Groups[groupName] = userList
			return nil
		}))
}

// DeleteRBACGroup removes one group from the draft config
func (c *openrunAdminPlugin) DeleteRBACGroup(ctx context.Context, call *sdk.Call) (any, error) {
	var name, versionId string
	if err := sdk.UnpackArgs("delete_rbac_group", call, "name", &name, "draft_version", &versionId); err != nil {
		return nil, err
	}

	return draftVersionResult(c.server.UpdateRBACDraft(ctx, versionId,
		func(config *types.RBACConfig) error {
			if _, ok := config.Groups[name]; !ok {
				return fmt.Errorf("group %s not found", name)
			}
			delete(config.Groups, name)
			return nil
		}))
}

// SetRBACRole creates or replaces one role in the draft config
func (c *openrunAdminPlugin) SetRBACRole(ctx context.Context, call *sdk.Call) (any, error) {
	var name, versionId string
	var permissions []any
	if err := sdk.UnpackArgs("set_rbac_role", call, "name", &name, "permissions", &permissions, "draft_version", &versionId); err != nil {
		return nil, err
	}

	permList, err := listToStringSlice(permissions, "permissions")
	if err != nil {
		return nil, err
	}
	roleName := name
	if roleName == "" {
		return nil, fmt.Errorf("role name cannot be empty")
	}

	perms := make([]types.RBACPermission, 0, len(permList))
	for _, perm := range permList {
		rbacPerm := types.RBACPermission(perm)
		if err := rbac.ValidatePermissionName(rbacPerm); err != nil {
			return nil, err
		}
		perms = append(perms, rbacPerm)
	}

	return draftVersionResult(c.server.UpdateRBACDraft(ctx, versionId,
		func(config *types.RBACConfig) error {
			if config.Roles == nil {
				config.Roles = map[string][]types.RBACPermission{}
			}
			config.Roles[roleName] = perms
			return nil
		}))
}

// DeleteRBACRole removes one role from the draft config. Dangling grant
// references are allowed in the draft and rejected at publish
func (c *openrunAdminPlugin) DeleteRBACRole(ctx context.Context, call *sdk.Call) (any, error) {
	var name, versionId string
	if err := sdk.UnpackArgs("delete_rbac_role", call, "name", &name, "draft_version", &versionId); err != nil {
		return nil, err
	}

	return draftVersionResult(c.server.UpdateRBACDraft(ctx, versionId,
		func(config *types.RBACConfig) error {
			if _, ok := config.Roles[name]; !ok {
				return fmt.Errorf("role %s not found", name)
			}
			delete(config.Roles, name)
			return nil
		}))
}

func unpackGrantArgs(apiName string, call *sdk.Call,
	index *int64, withIndex bool) (*types.RBACGrant, string, error) {
	var description, versionId string
	var users, roles, targets []any

	unpackArgs := []any{"description", &description, "users", &users, "roles", &roles,
		"targets", &targets, "draft_version", &versionId}
	if withIndex {
		unpackArgs = append([]any{"index", index}, unpackArgs...)
	}
	if err := sdk.UnpackArgs(apiName, call, unpackArgs...); err != nil {
		return nil, "", err
	}

	userList, err := listToStringSlice(users, "users")
	if err != nil {
		return nil, "", err
	}
	roleList, err := listToStringSlice(roles, "roles")
	if err != nil {
		return nil, "", err
	}
	targetList, err := listToStringSlice(targets, "targets")
	if err != nil {
		return nil, "", err
	}
	// Malformed target globs are rejected when the grant is staged, matching
	// the stage-time permission name validation on roles, so the error
	// surfaces in the grant form instead of at publish
	for _, target := range targetList {
		if err := rbac.ValidateGlob(target); err != nil {
			return nil, "", fmt.Errorf("invalid target %q: %w", target, err)
		}
	}

	grant := types.RBACGrant{
		Description: description,
		Users:       userList,
		Roles:       roleList,
		Targets:     targetList,
	}
	return &grant, versionId, nil
}

// AddRBACGrant appends one grant to the draft config
func (c *openrunAdminPlugin) AddRBACGrant(ctx context.Context, call *sdk.Call) (any, error) {
	grant, versionId, err := unpackGrantArgs("add_rbac_grant", call, nil, false)
	if err != nil {
		return nil, err
	}

	return draftVersionResult(c.server.UpdateRBACDraft(ctx, versionId,
		func(config *types.RBACConfig) error {
			config.Grants = append(config.Grants, *grant)
			return nil
		}))
}

// UpdateRBACGrant replaces the grant at index in the draft config
func (c *openrunAdminPlugin) UpdateRBACGrant(ctx context.Context, call *sdk.Call) (any, error) {
	var index int64
	grant, versionId, err := unpackGrantArgs("update_rbac_grant", call, &index, true)
	if err != nil {
		return nil, err
	}
	idx := index

	return draftVersionResult(c.server.UpdateRBACDraft(ctx, versionId,
		func(config *types.RBACConfig) error {
			if idx < 0 || int(idx) >= len(config.Grants) {
				return fmt.Errorf("grant index %d out of range", idx)
			}
			config.Grants[idx] = *grant
			return nil
		}))
}

// DeleteRBACGrant removes the grant at index from the draft config
func (c *openrunAdminPlugin) DeleteRBACGrant(ctx context.Context, call *sdk.Call) (any, error) {
	var index int64
	var versionId string
	if err := sdk.UnpackArgs("delete_rbac_grant", call, "index", &index, "draft_version", &versionId); err != nil {
		return nil, err
	}
	idx := index

	return draftVersionResult(c.server.UpdateRBACDraft(ctx, versionId,
		func(config *types.RBACConfig) error {
			if idx < 0 || int(idx) >= len(config.Grants) {
				return fmt.Errorf("grant index %d out of range", idx)
			}
			config.Grants = append(config.Grants[:idx], config.Grants[idx+1:]...)
			return nil
		}))
}

// PublishRBACConfig validates the draft and swaps it live atomically
func (c *openrunAdminPlugin) PublishRBACConfig(ctx context.Context, call *sdk.Call) (any, error) {
	var versionId string
	var force bool
	if err := sdk.UnpackArgs("publish_rbac_config", call, "version_id", &versionId, "force?", &force); err != nil {
		return nil, err
	}

	return configVersionResult(c.server.PublishRBACConfig(ctx, versionId, force))
}

// DiscardRBACDraft drops the staged RBAC changes
func (c *openrunAdminPlugin) DiscardRBACDraft(ctx context.Context, call *sdk.Call) (any, error) {
	var versionId string
	if err := sdk.UnpackArgs("discard_rbac_draft", call, "draft_version", &versionId); err != nil {
		return nil, err
	}

	if err := c.server.DiscardRBACDraft(ctx, versionId); err != nil {
		return nil, err
	}
	return structValue(map[string]any{"discarded": true})
}

// RestoreConfig restores the full dynamic config from a history snapshot
func (c *openrunAdminPlugin) RestoreConfig(ctx context.Context, call *sdk.Call) (any, error) {
	var versionId string
	var force bool
	if err := sdk.UnpackArgs("restore_config", call, "version_id", &versionId, "force?", &force); err != nil {
		return nil, err
	}

	return configVersionResult(c.server.RestoreConfig(ctx, versionId, force))
}
