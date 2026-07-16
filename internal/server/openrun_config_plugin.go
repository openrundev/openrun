// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

// Plugin methods for the dynamic config (RBAC section). Reads live on
// openrun.in, mutations on openrun_admin.in. Mutations edit the staged draft;
// publish_rbac_config validates and swaps the draft live atomically.

// GetRBACConfig returns the live RBAC config, the staged draft (if any) and
// the config version id used for optimistic concurrency
func (c *openrunPlugin) GetRBACConfig(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("get_rbac_config", args, kwargs); err != nil {
		return nil, err
	}

	config, draft, err := c.server.GetRBACDynamicConfig(system.GetRequestContext(thread))
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
			"create_time":   draft.CreateTime.UTC().Format(time.RFC3339),
			"updated_by":    draft.UpdatedBy,
			"update_time":   draft.UpdateTime.UTC().Format(time.RFC3339),
		}
	}
	return starlark_type.ConvertToStarlark(ret)
}

// GetConfigVersion returns one config history snapshot as formatted JSON.
// Secret values in dynamic config entries are redacted
func (c *openrunPlugin) GetConfigVersion(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var versionId starlark.String
	if err := starlark.UnpackArgs("get_config_version", args, kwargs, "version_id", &versionId); err != nil {
		return nil, err
	}

	snapshot, err := c.server.GetConfigVersion(system.GetRequestContext(thread), versionId.GoString())
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
	formatted, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(map[string]any{
		"version_id": snapshot.VersionId,
		"json":       string(formatted),
	})
}

// ListRBACPermissions returns the canonical RBAC permissions grouped by
// resource type, as defined in types.RBACPermissionGroups. Used by UIs to
// build permission pickers without hardcoding the permission names
func (c *openrunPlugin) ListRBACPermissions(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("list_rbac_permissions", args, kwargs); err != nil {
		return nil, err
	}

	ctx := system.GetRequestContext(thread)
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionConfigBasicRead, ""); err != nil {
		return nil, err
	}

	ret := starlark.List{}
	for _, group := range types.RBACPermissionGroups {
		perms := make([]string, 0, len(group.Permissions))
		for _, perm := range group.Permissions {
			perms = append(perms, string(perm))
		}
		value, err := starlark_type.ConvertToStarlark(map[string]any{
			"resource":    group.Resource,
			"permissions": perms,
		})
		if err != nil {
			return nil, err
		}
		ret.Append(value) //nolint:errcheck
	}
	return &ret, nil
}

// GetConfigEntries returns the static and dynamic entries for the requested
// config sections (all dynamically settable sections when the list is
// empty), values redacted. Sections are the named-entry map sections of
// openrun.toml: git_auth, auth, saml, ...
func (c *openrunPlugin) GetConfigEntries(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sections *starlark.List
	if err := starlark.UnpackArgs("get_config_entries", args, kwargs, "sections?", &sections); err != nil {
		return nil, err
	}
	sectionNames, err := listToStringSlice(sections, "sections")
	if err != nil {
		return nil, err
	}

	entries, err := c.server.GetConfigEntries(system.GetRequestContext(thread), sectionNames)
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
	return starlark_type.ConvertToStarlark(ret)
}

// GetConfigValues returns the static and dynamic field values for the
// requested struct config sections (security, system, logging, ...), values
// redacted. Static values are flattened to dotted keys
func (c *openrunPlugin) GetConfigValues(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sections *starlark.List
	if err := starlark.UnpackArgs("get_config_values", args, kwargs, "sections?", &sections); err != nil {
		return nil, err
	}
	sectionNames, err := listToStringSlice(sections, "sections")
	if err != nil {
		return nil, err
	}

	values, err := c.server.GetConfigValues(system.GetRequestContext(thread), sectionNames)
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
	return starlark_type.ConvertToStarlark(ret)
}

// SetConfigValue sets one dynamic config field (section + dotted key). The
// change is validated against the config schema and takes effect immediately
// (settings updates are not staged, unlike RBAC). version_id is the CAS token
func (c *openrunAdminPlugin) SetConfigValue(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var section, key, versionId starlark.String
	var value starlark.Value
	if err := starlark.UnpackArgs("set_config_value", args, kwargs, "section", &section,
		"key", &key, "value", &value, "version_id?", &versionId); err != nil {
		return nil, err
	}

	goValue, err := starlark_type.UnmarshalStarlark(value)
	if err != nil {
		return nil, err
	}

	return configVersionResult(c.server.SetConfigValue(system.GetRequestContext(thread),
		section.GoString(), key.GoString(), goValue, versionId.GoString()))
}

// DeleteConfigValue removes one dynamic config field, immediately reverting
// to the static openrun.toml value
func (c *openrunAdminPlugin) DeleteConfigValue(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var section, key, versionId starlark.String
	if err := starlark.UnpackArgs("delete_config_value", args, kwargs, "section", &section,
		"key", &key, "version_id?", &versionId); err != nil {
		return nil, err
	}

	return configVersionResult(c.server.DeleteConfigValue(system.GetRequestContext(thread),
		section.GoString(), key.GoString(), versionId.GoString()))
}

// SetConfigEntry creates or replaces one dynamic config entry. The change is
// validated against the config schema and takes effect immediately (entry
// updates are not staged, unlike RBAC). version_id is the CAS token
func (c *openrunAdminPlugin) SetConfigEntry(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var section, name, versionId starlark.String
	var values *starlark.Dict
	if err := starlark.UnpackArgs("set_config_entry", args, kwargs, "section", &section,
		"name", &name, "values", &values, "version_id?", &versionId); err != nil {
		return nil, err
	}

	goValues, err := starlark_type.UnmarshalStarlark(values)
	if err != nil {
		return nil, err
	}
	valuesMap, ok := goValues.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("values must be a dict with string keys")
	}

	return configVersionResult(c.server.SetConfigEntry(system.GetRequestContext(thread),
		section.GoString(), name.GoString(), valuesMap, versionId.GoString()))
}

// DeleteConfigEntry removes one dynamic config entry, immediately reverting
// to the static entry of the same name if one exists
func (c *openrunAdminPlugin) DeleteConfigEntry(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var section, name, versionId starlark.String
	if err := starlark.UnpackArgs("delete_config_entry", args, kwargs, "section", &section,
		"name", &name, "version_id?", &versionId); err != nil {
		return nil, err
	}

	return configVersionResult(c.server.DeleteConfigEntry(system.GetRequestContext(thread),
		section.GoString(), name.GoString(), versionId.GoString()))
}

// ListConfigHistory lists the dynamic config snapshots, newest first
func (c *openrunPlugin) ListConfigHistory(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("list_config_history", args, kwargs); err != nil {
		return nil, err
	}

	entries, err := c.server.ListConfigHistory(system.GetRequestContext(thread))
	if err != nil {
		return nil, err
	}

	ret := starlark.List{}
	for _, entry := range entries {
		value, err := starlark_type.ConvertToStarlark(map[string]any{
			"version_id":  entry.VersionId,
			"user_id":     entry.UserId,
			"update_time": entry.UpdateTime.UTC().Format(time.RFC3339),
		})
		if err != nil {
			return nil, err
		}
		ret.Append(value) //nolint:errcheck
	}
	return &ret, nil
}

// configVersionResult returns the standard {version_id} result for config mutations
func configVersionResult(config *types.DynamicConfig, err error) (starlark.Value, error) {
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(map[string]any{"version_id": config.VersionId})
}

// draftVersionResult returns the standard {draft_version} result for draft mutations
func draftVersionResult(draft *types.ConfigDraft, err error) (starlark.Value, error) {
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(map[string]any{"draft_version": draft.DraftVersion})
}

// UpdateRBACEnabled sets the rbac enabled flag in the draft config
func (c *openrunAdminPlugin) UpdateRBACEnabled(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var enabled starlark.Bool
	var versionId starlark.String
	if err := starlark.UnpackArgs("update_rbac_enabled", args, kwargs, "enabled", &enabled, "draft_version", &versionId); err != nil {
		return nil, err
	}

	return draftVersionResult(c.server.UpdateRBACDraft(system.GetRequestContext(thread), versionId.GoString(),
		func(config *types.RBACConfig) error {
			config.Enabled = bool(enabled)
			return nil
		}))
}

// SetRBACGroup creates or replaces one group in the draft config
func (c *openrunAdminPlugin) SetRBACGroup(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, versionId starlark.String
	var users *starlark.List
	if err := starlark.UnpackArgs("set_rbac_group", args, kwargs, "name", &name, "users", &users, "draft_version", &versionId); err != nil {
		return nil, err
	}

	userList, err := listToStringSlice(users, "users")
	if err != nil {
		return nil, err
	}
	groupName := name.GoString()
	if groupName == "" {
		return nil, fmt.Errorf("group name cannot be empty")
	}

	return draftVersionResult(c.server.UpdateRBACDraft(system.GetRequestContext(thread), versionId.GoString(),
		func(config *types.RBACConfig) error {
			if config.Groups == nil {
				config.Groups = map[string][]string{}
			}
			config.Groups[groupName] = userList
			return nil
		}))
}

// DeleteRBACGroup removes one group from the draft config
func (c *openrunAdminPlugin) DeleteRBACGroup(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, versionId starlark.String
	if err := starlark.UnpackArgs("delete_rbac_group", args, kwargs, "name", &name, "draft_version", &versionId); err != nil {
		return nil, err
	}

	return draftVersionResult(c.server.UpdateRBACDraft(system.GetRequestContext(thread), versionId.GoString(),
		func(config *types.RBACConfig) error {
			if _, ok := config.Groups[name.GoString()]; !ok {
				return fmt.Errorf("group %s not found", name.GoString())
			}
			delete(config.Groups, name.GoString())
			return nil
		}))
}

// SetRBACRole creates or replaces one role in the draft config
func (c *openrunAdminPlugin) SetRBACRole(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, versionId starlark.String
	var permissions *starlark.List
	if err := starlark.UnpackArgs("set_rbac_role", args, kwargs, "name", &name, "permissions", &permissions, "draft_version", &versionId); err != nil {
		return nil, err
	}

	permList, err := listToStringSlice(permissions, "permissions")
	if err != nil {
		return nil, err
	}
	roleName := name.GoString()
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

	return draftVersionResult(c.server.UpdateRBACDraft(system.GetRequestContext(thread), versionId.GoString(),
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
func (c *openrunAdminPlugin) DeleteRBACRole(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, versionId starlark.String
	if err := starlark.UnpackArgs("delete_rbac_role", args, kwargs, "name", &name, "draft_version", &versionId); err != nil {
		return nil, err
	}

	return draftVersionResult(c.server.UpdateRBACDraft(system.GetRequestContext(thread), versionId.GoString(),
		func(config *types.RBACConfig) error {
			if _, ok := config.Roles[name.GoString()]; !ok {
				return fmt.Errorf("role %s not found", name.GoString())
			}
			delete(config.Roles, name.GoString())
			return nil
		}))
}

func unpackGrantArgs(apiName string, args starlark.Tuple, kwargs []starlark.Tuple,
	index *starlark.Int, withIndex bool) (*types.RBACGrant, string, error) {
	var description, versionId starlark.String
	var users, roles, targets *starlark.List

	unpackArgs := []any{"description", &description, "users", &users, "roles", &roles,
		"targets", &targets, "draft_version", &versionId}
	if withIndex {
		unpackArgs = append([]any{"index", index}, unpackArgs...)
	}
	if err := starlark.UnpackArgs(apiName, args, kwargs, unpackArgs...); err != nil {
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
		Description: description.GoString(),
		Users:       userList,
		Roles:       roleList,
		Targets:     targetList,
	}
	return &grant, versionId.GoString(), nil
}

// AddRBACGrant appends one grant to the draft config
func (c *openrunAdminPlugin) AddRBACGrant(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	grant, versionId, err := unpackGrantArgs("add_rbac_grant", args, kwargs, nil, false)
	if err != nil {
		return nil, err
	}

	return draftVersionResult(c.server.UpdateRBACDraft(system.GetRequestContext(thread), versionId,
		func(config *types.RBACConfig) error {
			config.Grants = append(config.Grants, *grant)
			return nil
		}))
}

// UpdateRBACGrant replaces the grant at index in the draft config
func (c *openrunAdminPlugin) UpdateRBACGrant(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var index starlark.Int
	grant, versionId, err := unpackGrantArgs("update_rbac_grant", args, kwargs, &index, true)
	if err != nil {
		return nil, err
	}
	idx, _ := index.Int64()

	return draftVersionResult(c.server.UpdateRBACDraft(system.GetRequestContext(thread), versionId,
		func(config *types.RBACConfig) error {
			if idx < 0 || int(idx) >= len(config.Grants) {
				return fmt.Errorf("grant index %d out of range", idx)
			}
			config.Grants[idx] = *grant
			return nil
		}))
}

// DeleteRBACGrant removes the grant at index from the draft config
func (c *openrunAdminPlugin) DeleteRBACGrant(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var index starlark.Int
	var versionId starlark.String
	if err := starlark.UnpackArgs("delete_rbac_grant", args, kwargs, "index", &index, "draft_version", &versionId); err != nil {
		return nil, err
	}
	idx, _ := index.Int64()

	return draftVersionResult(c.server.UpdateRBACDraft(system.GetRequestContext(thread), versionId.GoString(),
		func(config *types.RBACConfig) error {
			if idx < 0 || int(idx) >= len(config.Grants) {
				return fmt.Errorf("grant index %d out of range", idx)
			}
			config.Grants = append(config.Grants[:idx], config.Grants[idx+1:]...)
			return nil
		}))
}

// PublishRBACConfig validates the draft and swaps it live atomically
func (c *openrunAdminPlugin) PublishRBACConfig(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var versionId starlark.String
	var force starlark.Bool
	if err := starlark.UnpackArgs("publish_rbac_config", args, kwargs, "version_id", &versionId, "force?", &force); err != nil {
		return nil, err
	}

	return configVersionResult(c.server.PublishRBACConfig(system.GetRequestContext(thread), versionId.GoString(), bool(force)))
}

// DiscardRBACDraft drops the staged RBAC changes
func (c *openrunAdminPlugin) DiscardRBACDraft(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var versionId starlark.String
	if err := starlark.UnpackArgs("discard_rbac_draft", args, kwargs, "draft_version", &versionId); err != nil {
		return nil, err
	}

	if err := c.server.DiscardRBACDraft(system.GetRequestContext(thread), versionId.GoString()); err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(map[string]any{"discarded": true})
}

// RestoreConfig restores the full dynamic config from a history snapshot
func (c *openrunAdminPlugin) RestoreConfig(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var versionId starlark.String
	var force starlark.Bool
	if err := starlark.UnpackArgs("restore_config", args, kwargs, "version_id", &versionId, "force?", &force); err != nil {
		return nil, err
	}

	return configVersionResult(c.server.RestoreConfig(system.GetRequestContext(thread), versionId.GoString(), bool(force)))
}
