// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/segmentio/ksuid"
)

// copyRBACConfig returns a deep copy, so draft edits never alias the live config
func copyRBACConfig(config *types.RBACConfig) (*types.RBACConfig, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("error copying rbac config: %w", err)
	}
	var copied types.RBACConfig
	if err := json.Unmarshal(data, &copied); err != nil {
		return nil, fmt.Errorf("error copying rbac config: %w", err)
	}
	return &copied, nil
}

// GetRBACDynamicConfig returns the live dynamic config and the staged draft
// (nil when there is none) for the configuration UI
func (s *Server) GetRBACDynamicConfig(ctx context.Context) (*types.DynamicConfig, *types.ConfigDraft, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigRead, ""); err != nil {
		return nil, nil, err
	}
	config := s.GetDynamicConfig()

	draft, err := s.db.GetConfigDraft(ctx)
	if err != nil && err != metadata.ErrNoConfigDraft {
		return nil, nil, err
	}
	return &config, draft, nil
}

// UpdateRBACDraft applies one mutation to the draft config. The draft is
// created from the live config on first edit; draftVersion is the CAS token
// for edits on an existing draft (two operators editing concurrently conflict
// instead of overwriting each other). Draft edits do not touch the live
// config and are not recorded in the config history
func (s *Server) UpdateRBACDraft(ctx context.Context, draftVersion string,
	mutate func(*types.RBACConfig) error) (*types.ConfigDraft, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return nil, err
	}

	user := system.GetContextUserId(ctx)
	now := time.Now().UTC()

	draft, err := s.db.GetConfigDraft(ctx)
	if err == metadata.ErrNoConfigDraft {
		// First edit forks the draft from the live config
		live := s.GetDynamicConfig()
		rbacCopy, err := copyRBACConfig(&live.RBAC)
		if err != nil {
			return nil, err
		}
		draft = &types.ConfigDraft{
			RBAC:        *rbacCopy,
			BaseVersion: live.VersionId,
			CreatedBy:   user,
			CreateTime:  now,
		}
	} else if err != nil {
		return nil, err
	} else if draft.DraftVersion != draftVersion {
		return nil, fmt.Errorf("draft was updated by %s since you loaded it, reload and retry", draft.UpdatedBy)
	}

	if err := mutate(&draft.RBAC); err != nil {
		return nil, err
	}

	draft.DraftVersion = "draft_" + ksuid.New().String()
	draft.UpdatedBy = user
	draft.UpdateTime = now
	if err := s.db.SetConfigDraft(ctx, draft); err != nil {
		return nil, err
	}
	return draft, nil
}

// copyDynamicConfig returns a deep copy of the dynamic config, so entry edits
// never alias the live config
func copyDynamicConfig(config *types.DynamicConfig) (*types.DynamicConfig, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("error copying dynamic config: %w", err)
	}
	var copied types.DynamicConfig
	if err := json.Unmarshal(data, &copied); err != nil {
		return nil, fmt.Errorf("error copying dynamic config: %w", err)
	}
	return &copied, nil
}

// ConfigEntry is one named config entry (static from openrun.toml or dynamic)
// as returned by the config read APIs. Values are redacted
type ConfigEntry struct {
	Name       string         `json:"name"`
	Values     map[string]any `json:"values"`
	Source     string         `json:"source"`     // "static" or "dynamic"
	Overridden bool           `json:"overridden"` // static entry shadowed by a dynamic entry of the same name
}

// GetConfigEntries returns the static and dynamic entries for the requested
// config sections (all dynamically settable sections when empty). Secret
// field values are redacted
func (s *Server) GetConfigEntries(ctx context.Context, sections []string) (map[string][]ConfigEntry, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigRead, ""); err != nil {
		return nil, err
	}
	if len(sections) == 0 {
		sections = listConfigSections()
	}

	config := s.GetDynamicConfig()
	ret := map[string][]ConfigEntry{}
	staticVal := reflect.ValueOf(s.staticConfig).Elem()
	structType := staticVal.Type()
	for _, section := range sections {
		if _, ok := configSectionType(section); !ok {
			return nil, fmt.Errorf("unknown config section %q, valid sections are: %s",
				section, strings.Join(listConfigSections(), ", "))
		}

		entries := []ConfigEntry{}
		dynamic := config.Entries[section]
		for i := range structType.NumField() {
			tag := strings.Split(structType.Field(i).Tag.Get("toml"), ",")[0]
			if tag != section {
				continue
			}
			iter := staticVal.Field(i).MapRange()
			for iter.Next() {
				values, err := structEntryValues(iter.Value().Interface())
				if err != nil {
					return nil, err
				}
				_, overridden := dynamic[iter.Key().String()]
				entries = append(entries, ConfigEntry{
					Name:       iter.Key().String(),
					Values:     redactEntryValues(values),
					Source:     "static",
					Overridden: overridden,
				})
			}
		}
		for name, values := range dynamic {
			entries = append(entries, ConfigEntry{
				Name:   name,
				Values: redactEntryValues(values),
				Source: "dynamic",
			})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Name != entries[j].Name {
				return entries[i].Name < entries[j].Name
			}
			return entries[i].Source < entries[j].Source // dynamic before static
		})
		ret[section] = entries
	}
	return ret, nil
}

// SetConfigEntry creates or replaces one dynamic config entry. Unlike RBAC
// changes, entry updates are not staged: the update is validated against the
// config schema, written as a new config version and takes effect
// immediately. versionId is the CAS token (the live version the caller saw);
// empty means last-writer-wins. Secret fields submitted with the redaction
// placeholder keep their stored value
func (s *Server) SetConfigEntry(ctx context.Context, section, name string, values map[string]any, versionId string) (*types.DynamicConfig, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return nil, err
	}

	current := s.GetDynamicConfig()
	config, err := copyDynamicConfig(&current)
	if err != nil {
		return nil, err
	}

	existing := map[string]any{}
	if config.Entries[section] != nil && config.Entries[section][name] != nil {
		existing = config.Entries[section][name]
	}
	for key, value := range values {
		if str, ok := value.(string); ok && str == RedactedValue {
			prev, ok := existing[key]
			if !ok {
				return nil, fmt.Errorf("field %s has no stored value to keep, provide a value", key)
			}
			values[key] = prev
		}
	}

	if err := validateConfigEntry(section, name, values); err != nil {
		return nil, err
	}

	if config.Entries == nil {
		config.Entries = map[string]map[string]map[string]any{}
	}
	if config.Entries[section] == nil {
		config.Entries[section] = map[string]map[string]any{}
	}
	config.Entries[section][name] = values
	if versionId != "" {
		config.VersionId = versionId
	}
	return s.UpdateDynamicConfig(ctx, config, false)
}

// DeleteConfigEntry removes one dynamic config entry, immediately reverting
// to the static entry of the same name if one exists. Static entries cannot
// be deleted through the API
func (s *Server) DeleteConfigEntry(ctx context.Context, section, name string, versionId string) (*types.DynamicConfig, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return nil, err
	}

	current := s.GetDynamicConfig()
	config, err := copyDynamicConfig(&current)
	if err != nil {
		return nil, err
	}
	if config.Entries[section] == nil || config.Entries[section][name] == nil {
		return nil, fmt.Errorf("no dynamic config entry [%s.%s] (static entries cannot be deleted through the API)", section, name)
	}
	delete(config.Entries[section], name)
	if len(config.Entries[section]) == 0 {
		delete(config.Entries, section)
	}
	if versionId != "" {
		config.VersionId = versionId
	}
	return s.UpdateDynamicConfig(ctx, config, false)
}

// ConfigSectionValues holds the field values of one struct config section
// (security, system, logging, ...) for the read APIs: the static values from
// openrun.toml flattened to dotted keys, and the dynamic overrides. Secret
// values are redacted
type ConfigSectionValues struct {
	Static  map[string]any `json:"static"`
	Dynamic map[string]any `json:"dynamic"`
}

// GetConfigValues returns the static and dynamic field values for the
// requested struct config sections (all settings sections when empty)
func (s *Server) GetConfigValues(ctx context.Context, sections []string) (map[string]*ConfigSectionValues, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigRead, ""); err != nil {
		return nil, err
	}
	if len(sections) == 0 {
		sections = listConfigSettingsSections()
	}

	config := s.GetDynamicConfig()
	ret := map[string]*ConfigSectionValues{}
	staticVal := reflect.ValueOf(s.staticConfig).Elem()
	for _, section := range sections {
		if !isConfigSettingsSection(section) {
			return nil, fmt.Errorf("unknown config settings section %q, valid sections are: %s",
				section, strings.Join(listConfigSettingsSections(), ", "))
		}

		field, _ := structFieldByTag(staticVal, section)
		nested, err := structEntryValues(field.Interface())
		if err != nil {
			return nil, err
		}
		flat := map[string]any{}
		flattenConfigValues(nested, "", flat)

		values := &ConfigSectionValues{Static: redactEntryValues(flat), Dynamic: map[string]any{}}
		if dynamic := config.Settings[section]; dynamic != nil {
			values.Dynamic = redactEntryValues(dynamic)
		}
		ret[section] = values
	}
	return ret, nil
}

// SetConfigValue sets one dynamic config field (section + dotted key). Like
// entries, settings updates are not staged: the change is validated against
// the config schema, written as a new config version and takes effect
// immediately. A value equal to the redaction placeholder keeps the stored
// value
func (s *Server) SetConfigValue(ctx context.Context, section, key string, value any, versionId string) (*types.DynamicConfig, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return nil, err
	}

	current := s.GetDynamicConfig()
	config, err := copyDynamicConfig(&current)
	if err != nil {
		return nil, err
	}

	if str, ok := value.(string); ok && str == RedactedValue {
		prev, ok := config.Settings[section][key]
		if !ok {
			return nil, fmt.Errorf("%s %s has no stored value to keep, provide a value", section, key)
		}
		value = prev
	}

	if err := validateConfigValue(section, key, value); err != nil {
		return nil, err
	}

	if config.Settings == nil {
		config.Settings = map[string]map[string]any{}
	}
	if config.Settings[section] == nil {
		config.Settings[section] = map[string]any{}
	}
	config.Settings[section][key] = value
	if versionId != "" {
		config.VersionId = versionId
	}
	return s.UpdateDynamicConfig(ctx, config, false)
}

// DeleteConfigValue removes one dynamic config field, immediately reverting
// to the static openrun.toml value
func (s *Server) DeleteConfigValue(ctx context.Context, section, key string, versionId string) (*types.DynamicConfig, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return nil, err
	}

	current := s.GetDynamicConfig()
	config, err := copyDynamicConfig(&current)
	if err != nil {
		return nil, err
	}
	if config.Settings[section] == nil || config.Settings[section][key] == nil {
		return nil, fmt.Errorf("no dynamic config value for %s %s", section, key)
	}
	delete(config.Settings[section], key)
	if len(config.Settings[section]) == 0 {
		delete(config.Settings, section)
	}
	if versionId != "" {
		config.VersionId = versionId
	}
	return s.UpdateDynamicConfig(ctx, config, false)
}

// validateRBACCandidate runs the full config validation (the same checks the
// file upload path runs) plus the lockout check: publishing a config which
// removes the caller's own config:update permission requires force
func (s *Server) validateRBACCandidate(ctx context.Context, candidate *types.RBACConfig, force bool) error {
	scratch, err := rbac.NewRBACHandler(s.Logger, candidate, s.Config())
	if err != nil {
		return fmt.Errorf("invalid rbac config: %w", err)
	}

	// The lockout check only applies when the caller would actually be subject
	// to enforcement after publish: the enabled flag AND rbac applying to the
	// calling app's auth - every app when the candidate forces rbac (the
	// default), only rbac: prefixed auth otherwise. Admin access always works
	user := system.GetContextUserId(ctx)
	// No app context (CLI, unix socket) is never enforced, force or not
	callerSubject := rbac.RequestHasRBACAuth(ctx) ||
		(candidate.ForceRBAC() && ctx.Value(types.APP_AUTH) != nil)
	if candidate.Enabled && callerSubject && user != "" && user != types.ADMIN_USER && !force {
		authorized, err := scratch.AuthorizeUserPerm(user, system.GetContextGroups(ctx), types.PermissionConfigUpdate)
		if err != nil {
			return err
		}
		if !authorized {
			return fmt.Errorf("this change would remove your own config:update permission, locking you out of configuration changes. Use force to publish anyway")
		}
	}
	return nil
}

// PublishRBACConfig validates the draft config and swaps it live atomically.
// draftVersion must match the current draft (the publisher has seen the
// latest edits); the live config must still be the draft's base version
// unless force is set (a CLI file upload mid-draft surfaces here)
func (s *Server) PublishRBACConfig(ctx context.Context, draftVersion string, force bool) (*types.DynamicConfig, error) {
	draft, err := s.db.GetConfigDraft(ctx)
	if err == metadata.ErrNoConfigDraft {
		return nil, fmt.Errorf("no staged config changes to publish")
	} else if err != nil {
		return nil, err
	}
	if draft.DraftVersion != draftVersion {
		return nil, fmt.Errorf("draft was updated by %s since you loaded it, reload and retry", draft.UpdatedBy)
	}

	config := s.GetDynamicConfig()
	if config.VersionId != draft.BaseVersion && !force {
		return nil, fmt.Errorf("the live config changed since this draft was created (by upload or restore), review the draft against the current config. Use force to publish anyway")
	}

	candidate, err := copyRBACConfig(&draft.RBAC)
	if err != nil {
		return nil, err
	}
	if err := s.validateRBACCandidate(ctx, candidate, force); err != nil {
		return nil, err
	}

	config.RBAC = *candidate
	updated, err := s.UpdateDynamicConfig(ctx, &config, false)
	if err != nil {
		return nil, err
	}
	if err := s.db.DeleteConfigDraft(ctx); err != nil {
		return nil, err
	}
	return updated, nil
}

// DiscardRBACDraft drops the staged config changes. draftVersion is the CAS
// token: only a draft state the caller has actually seen can be discarded
func (s *Server) DiscardRBACDraft(ctx context.Context, draftVersion string) error {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return err
	}

	draft, err := s.db.GetConfigDraft(ctx)
	if err == metadata.ErrNoConfigDraft {
		return fmt.Errorf("no staged config changes to discard")
	} else if err != nil {
		return err
	}
	if draft.DraftVersion != draftVersion {
		return fmt.Errorf("draft was updated by %s since you loaded it, reload and review before discarding", draft.UpdatedBy)
	}
	return s.db.DeleteConfigDraft(ctx)
}

// ListConfigHistory returns the dynamic config snapshots, newest first
func (s *Server) ListConfigHistory(ctx context.Context) ([]types.ConfigHistoryEntry, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigRead, ""); err != nil {
		return nil, err
	}
	return s.db.ListConfigHistory(ctx)
}

// GetConfigVersion returns one full config snapshot from the history
func (s *Server) GetConfigVersion(ctx context.Context, versionId string) (*types.DynamicConfig, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigRead, ""); err != nil {
		return nil, err
	}
	return s.db.GetConfigVersion(ctx, versionId)
}

// RestoreConfig restores the full dynamic config from a history snapshot. The
// restore is validated like a publish and written as a new version, keeping
// the history linear. An open draft is unaffected (it CAS's against its base
// version at publish time)
func (s *Server) RestoreConfig(ctx context.Context, historyVersionId string, force bool) (*types.DynamicConfig, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return nil, err
	}

	snapshot, err := s.db.GetConfigVersion(ctx, historyVersionId)
	if err != nil {
		return nil, err
	}
	if err := s.validateRBACCandidate(ctx, &snapshot.RBAC, force); err != nil {
		return nil, err
	}
	for section, sectionEntries := range snapshot.Entries {
		for name, values := range sectionEntries {
			if err := validateConfigEntry(section, name, values); err != nil {
				return nil, fmt.Errorf("invalid entry in snapshot: %w", err)
			}
		}
	}
	for section, values := range snapshot.Settings {
		for key, value := range values {
			if err := validateConfigValue(section, key, value); err != nil {
				return nil, fmt.Errorf("invalid setting in snapshot: %w", err)
			}
		}
	}

	current := s.GetDynamicConfig()
	candidate := *snapshot
	candidate.VersionId = current.VersionId
	return s.UpdateDynamicConfig(ctx, &candidate, false)
}
