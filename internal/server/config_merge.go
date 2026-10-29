// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/openrundev/openrun/internal/builder"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// Generic machinery for the dynamic config (DynamicConfig.Entries and
// DynamicConfig.Settings): which openrun.toml sections can be set dynamically,
// schema validation and the merge of dynamic values over the static config.
// Entries cover the named-entry map sections ([git_auth.x], [auth.y], ...),
// settings cover individual fields of the struct sections (security.
// default_git_auth, system.default_domain, app_config.cors.allow_origin, ...).
// Schema validation and the merge are driven by the types.ServerConfig struct
// tags. Which sections and fields can be set dynamically is an explicit
// allowlist (dynamicEntrySections, dynamicSettingKeys): a new toml section or
// field is static-config only until it is added there.

// RedactedValue is returned in place of secret field values by the config
// read APIs. An update which submits this value keeps the stored value, so
// edit forms can round-trip without ever seeing the secret
const RedactedValue = "<redacted>"

// isEntrySectionType reports whether a field type holds named config entries:
// map[string]V with struct or map values ([git_auth.x], [secret.y], ...).
// Flat key/value maps like node_config (map[string]any) are settings instead
func isEntrySectionType(fieldType reflect.Type) bool {
	if fieldType.Kind() != reflect.Map || fieldType.Key().Kind() != reflect.String {
		return false
	}
	elemKind := fieldType.Elem().Kind()
	return elemKind == reflect.Struct || elemKind == reflect.Map
}

// isFlatKVSectionType reports whether a field type is a flat key/value
// section: map[string]any (node_config), managed through Settings with
// literal (non dotted-path) keys
func isFlatKVSectionType(fieldType reflect.Type) bool {
	return fieldType.Kind() == reflect.Map && fieldType.Key().Kind() == reflect.String &&
		fieldType.Elem().Kind() == reflect.Interface
}

// configSectionField returns the ServerConfig field type for a section tag
func configSectionField(section string) (reflect.Type, bool) {
	t := reflect.TypeFor[types.ServerConfig]()
	for i := range t.NumField() {
		field := t.Field(i)
		tag := strings.Split(field.Tag.Get("toml"), ",")[0]
		if field.Anonymous || tag == "" || tag == "-" || tag != section {
			continue
		}
		return field.Type, true
	}
	return nil, false
}

// configSectionType returns the map type for a dynamically settable entry
// section. Entries merge at whole-entry granularity, so only named-entry map
// sections qualify, and not the static-only ones
func configSectionType(section string) (reflect.Type, bool) {
	fieldType, ok := configSectionField(section)
	if !ok || !dynamicEntrySections[section] || !isEntrySectionType(fieldType) {
		return nil, false
	}
	return fieldType, true
}

// listConfigSections returns the names of all dynamically settable sections
func listConfigSections() []string {
	return slices.Sorted(maps.Keys(dynamicEntrySections))
}

// The dynamic config allowlist: only what the console config pages manage
// can be set through the dynamic config API (config:update is held by
// operators who are not admin). Everything else in openrun.toml - host
// commands, exec/mount/container arg allowlists, plugin provider sources,
// listeners, logging, telemetry, every unsafe_* flag - is static config
// only, rejected on write and ignored (with a warning) when a previously
// persisted value is merged. Adding a section or key here makes it settable
// by config:update holders, so it must be safe for a non-admin to change.

// dynamicEntrySections are the named-entry sections which can be set
// dynamically, at whole-entry granularity
var dynamicEntrySections = map[string]bool{
	"git_auth":        true,
	"auth":            true,
	"saml":            true,
	"secret":          true,
	"builder_agent":   true,
	"builder_profile": true,
	"builder_git":     true,
}

// dynamicSettingKeys are the struct section fields (dotted keys) which can be
// set dynamically
var dynamicSettingKeys = map[string]map[string]bool{
	"security": {
		"app_default_auth_type": true,
		"default_git_auth":      true,
	},
	"system": {
		"default_domain":   true,
		"stage_at":         true,
		"list_apps_title":  true,
		"show_hosted_with": true,
	},
	"api": {
		"external_url":                 true,
		"access_token_ttl":             true,
		"refresh_token_ttl":            true,
		"grant_max_ttl":                true,
		"federated_identity_ttl":       true,
		"pat_default_ttl":              true,
		"rest.enable":                  true,
		"rest.auth":                    true,
		"rest.enable_apis":             true,
		"rest.disable_apis":            true,
		"mcp.enable":                   true,
		"mcp.auth":                     true,
		"mcp.enable_apis":              true,
		"mcp.disable_apis":             true,
		"mcp.skip_destructive_confirm": true,
		"app_mcp.enable":               true,
		"app_mcp.allowed_auth":         true,
		"app_mcp.max_tools":            true,
		"app_mcp.list_ttl":             true,
	},
	"app_builder": {
		"enabled":                 true,
		"default_builder_profile": true,
		"preview_path":            true,
		"max_sessions":            true,
		"session_idle_mins":       true,
		"system_prompt":           true,
	},
}

// dynamicFreeFormSections are the settings sections where any key can be set
// dynamically: app_config holds the server wide app defaults, which app
// updaters can already override per app, and node_config holds free form
// values apps read with the config() builtin
var dynamicFreeFormSections = map[string]bool{"app_config": true, "node_config": true}

// isConfigSettingsSection reports whether a section holds settings which can
// be set dynamically field by field: a struct section of ServerConfig, or a
// flat key/value map section (node_config). The named-entry map sections are
// handled through Entries instead
func isConfigSettingsSection(section string) bool {
	if dynamicSettingKeys[section] == nil && !dynamicFreeFormSections[section] {
		return false
	}
	fieldType, ok := configSectionField(section)
	if !ok {
		return false
	}
	return fieldType.Kind() == reflect.Struct || isFlatKVSectionType(fieldType)
}

// staticOnlySettingKey reports whether a field of a dynamically settable
// section is static-config only: a key not in the section's allowlist, or
// any component of the dotted key whose name starts with "unsafe_" (a
// security escape hatch must not be settable through the API it weakens,
// even in a free form section)
func staticOnlySettingKey(section, key string) bool {
	for part := range strings.SplitSeq(key, ".") {
		if strings.HasPrefix(part, "unsafe_") {
			return true
		}
	}
	if dynamicFreeFormSections[section] {
		return false
	}
	return !dynamicSettingKeys[section][key]
}

// staticOnlySectionError returns the error for a dynamic write to a section
// of openrun.toml which is not dynamically settable, or nil when the section
// does not exist in the config schema at all
func staticOnlySectionError(section string) error {
	if _, ok := configSectionField(section); !ok {
		return nil
	}
	return fmt.Errorf("[%s] can only be set in the static openrun.toml config, not through the dynamic config API. "+
		"Dynamically settable entry sections are: %s; settings sections are: %s",
		section, strings.Join(listConfigSections(), ", "), strings.Join(listConfigSettingsSections(), ", "))
}

// isFlatKVSection reports whether a settings section is a flat key/value map
// (node_config): its keys are literal, not dotted field paths
func isFlatKVSection(section string) bool {
	fieldType, ok := configSectionField(section)
	return ok && isFlatKVSectionType(fieldType)
}

// listConfigSettingsSections returns the names of all sections whose fields
// can be set dynamically
func listConfigSettingsSections() []string {
	sections := slices.Collect(maps.Keys(dynamicSettingKeys))
	sections = slices.AppendSeq(sections, maps.Keys(dynamicFreeFormSections))
	slices.Sort(sections)
	return sections
}

// expandDottedKeys turns {"cors.allow_origin": v} into {"cors":
// {"allow_origin": v}} so the tree encodes as nested toml tables. Conflicting
// keys (a value at both "a" and "a.b") are an error
func expandDottedKeys(values map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for key, value := range values {
		parts := strings.Split(key, ".")
		node := out
		for i, part := range parts {
			if part == "" {
				return nil, fmt.Errorf("invalid config key %q", key)
			}
			if i == len(parts)-1 {
				if _, exists := node[part]; exists {
					return nil, fmt.Errorf("conflicting config keys at %q", key)
				}
				node[part] = value
				break
			}
			child, exists := node[part]
			if !exists {
				childMap := map[string]any{}
				node[part] = childMap
				node = childMap
				continue
			}
			childMap, ok := child.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("conflicting config keys at %q", key)
			}
			node = childMap
		}
	}
	return out, nil
}

// encodeSettingsTOML encodes a settings tree (section -> key -> value) in
// toml format. Keys of struct sections are dotted field paths, expanded to
// nested tables; keys of flat key/value sections (node_config) are literal
// and encode as-is (quoted when they contain dots)
func encodeSettingsTOML(settings map[string]map[string]any) (string, error) {
	doc := map[string]any{}
	for section, values := range settings {
		cleaned := make(map[string]any, len(values))
		for key, value := range values {
			if value != nil { // json null after the metadata round trip
				cleaned[key] = value
			}
		}
		if isFlatKVSection(section) {
			doc[section] = cleaned
			continue
		}
		expanded, err := expandDottedKeys(cleaned)
		if err != nil {
			return "", fmt.Errorf("section %s: %w", section, err)
		}
		doc[section] = expanded
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(doc); err != nil {
		return "", fmt.Errorf("error encoding config settings: %w", err)
	}
	return buf.String(), nil
}

// validateConfigValue checks one settings field against the ServerConfig
// schema by a toml round trip, like validateConfigEntry does for entries
func validateConfigValue(section, key string, value any) error {
	if key == "" {
		return fmt.Errorf("config key cannot be empty")
	}
	if !isConfigSettingsSection(section) {
		if _, isEntry := configSectionType(section); !isEntry {
			if err := staticOnlySectionError(section); err != nil {
				return err
			}
		}
		return fmt.Errorf("unknown config settings section %q, valid sections are: %s",
			section, strings.Join(listConfigSettingsSections(), ", "))
	}
	if staticOnlySettingKey(section, key) {
		allowed := "any key except unsafe_* keys"
		if !dynamicFreeFormSections[section] {
			allowed = strings.Join(slices.Sorted(maps.Keys(dynamicSettingKeys[section])), ", ")
		}
		return fmt.Errorf("%s %s can only be set in the static openrun.toml config, not through the dynamic config API. "+
			"Dynamically settable %s keys are: %s", section, key, section, allowed)
	}
	if value == nil {
		return fmt.Errorf("config value cannot be empty")
	}

	contents, err := encodeSettingsTOML(map[string]map[string]any{section: {key: value}})
	if err != nil {
		return err
	}
	var scratch types.ServerConfig
	md, err := toml.Decode(contents, &scratch)
	if err != nil {
		return fmt.Errorf("invalid value for %s %s: %w", section, key, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		unknown := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			unknown = append(unknown, k.String())
		}
		return fmt.Errorf("unknown config fields: %s", strings.Join(unknown, ", "))
	}
	return nil
}

// encodeEntriesTOML encodes an entries tree in toml format, so it can be
// decoded into ServerConfig with the same semantics as the static config file
func encodeEntriesTOML(entries map[string]map[string]map[string]any) (string, error) {
	// Drop nil values (json null after the metadata round trip), the toml
	// encoder rejects them
	cleaned := map[string]any{}
	for section, sectionEntries := range entries {
		cleanedSection := map[string]any{}
		for name, values := range sectionEntries {
			cleanedValues := map[string]any{}
			for key, value := range values {
				if value != nil {
					cleanedValues[key] = value
				}
			}
			cleanedSection[name] = cleanedValues
		}
		cleaned[section] = cleanedSection
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cleaned); err != nil {
		return "", fmt.Errorf("error encoding config entries: %w", err)
	}
	return buf.String(), nil
}

// validateConfigEntry checks one entry against the ServerConfig schema by a
// toml round trip: unknown sections, unknown fields and ill-typed values all
// surface here. This is the only validation an entry needs, so new sections
// require no backend change
func validateConfigEntry(section, name string, values map[string]any) error {
	if name == "" {
		return fmt.Errorf("config entry name cannot be empty")
	}
	if _, ok := configSectionType(section); !ok {
		if !isConfigSettingsSection(section) {
			if err := staticOnlySectionError(section); err != nil {
				return err
			}
		}
		return fmt.Errorf("unknown config section %q, valid sections are: %s",
			section, strings.Join(listConfigSections(), ", "))
	}

	contents, err := encodeEntriesTOML(map[string]map[string]map[string]any{section: {name: values}})
	if err != nil {
		return err
	}
	var scratch types.ServerConfig
	md, err := toml.Decode(contents, &scratch)
	if err != nil {
		return fmt.Errorf("invalid values for [%s.%s]: %w", section, name, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		unknown := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			unknown = append(unknown, key.String())
		}
		return fmt.Errorf("unknown config fields: %s", strings.Join(unknown, ", "))
	}

	if section == "builder_agent" {
		// The agent type comes from the entry name; a name that infers no
		// type would only fail at session start, so reject it here
		if _, err := builder.AgentTypeFromName(name); err != nil {
			return err
		}
	}
	if section == "builder_profile" {
		// Reject at staging what would otherwise only fail at session start
		if agent, _ := values["agent"].(string); agent == "" {
			return fmt.Errorf("agent is required for a builder profile")
		}
		mode, _ := values["publish_mode"].(string)
		target, _ := values["publish_target"].(string)
		if err := validateProfilePublish(mode, target); err != nil {
			return err
		}
		if err := validateProfileServices(configStringList(values["services"])); err != nil {
			return err
		}
	}
	return nil
}

// configStringList returns the string items of a list value from an entry
// document ([]any after the json round trip, []string from Go callers)
func configStringList(value any) []string {
	switch raw := value.(type) {
	case []any:
		var out []string
		for _, entry := range raw {
			if str, ok := entry.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case []string:
		return raw
	}
	return nil
}

// checkBuilderAgentPaths checks the server paths of a dynamic builder_agent
// entry which do not need the caller's context. config_files host paths are
// bind mounted into the agent sandbox (which runs as root), so each must be
// an absolute path within one of the security.allowed_mounts directories,
// like app container volumes; allowed_mounts is static config only, so a
// config:update holder cannot widen it. The path fields cannot be templates:
// a {{secret ...}} resolved at merge time would bypass the write-time checks.
// The dockerfile path is checked against the caller's disk access by
// Server.checkDynamicEntry
func checkBuilderAgentPaths(values map[string]any, allowedMounts []string) error {
	if dockerfile, _ := values["dockerfile"].(string); strings.Contains(dockerfile, "{{") {
		return fmt.Errorf("builder agent dockerfile %q cannot be a template", dockerfile)
	}
	for _, entry := range configStringList(values["config_files"]) {
		if strings.Contains(entry, "{{") {
			return fmt.Errorf("builder agent config_files entry %q cannot be a template", entry)
		}
		host, err := builder.ConfigMountHostPath(entry)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(host) || filepath.Clean(host) != host {
			// Docker gets the raw path, where a .. after a symlink resolves
			// against the link target, not lexically as the check would
			return fmt.Errorf("builder agent config_files host path %q must be a clean absolute path", host)
		}
		if !pathWithinRoots(host, allowedMounts) {
			return fmt.Errorf("builder agent config_files host path %q is not within a security.allowed_mounts directory: "+
				"add its directory to security.allowed_mounts, or define this agent in the static openrun.toml config", host)
		}
	}
	return nil
}

// pathWithinRoots reports whether path is inside one of the roots (env
// expanded). Both sides are made absolute with symlinks resolved, so a link
// under a root pointing elsewhere does not qualify
func pathWithinRoots(path string, roots []string) bool {
	target, err := resolveExistingPrefix(path)
	if err != nil {
		return false
	}
	for _, root := range roots {
		cleanRoot, err := system.CleanAbsolutePath(os.ExpandEnv(root))
		if err != nil {
			continue
		}
		if inside, err := system.PathWithinDir(cleanRoot, target); err == nil && inside {
			return true
		}
	}
	return false
}

// validateChangedConfigItems validates the entries and settings of a full
// dynamic config document (update-config upload, history restore, RBAC
// publish) which differ from the current config, applying the same checks as
// the per-item set APIs. Unchanged values are not revalidated: a value
// persisted before its section or key was made static only is ignored by the
// merge, and must not block unrelated updates like an RBAC publish.
// checkEntry runs the context dependent entry checks on changed entries
func validateChangedConfigItems(candidate, current *types.DynamicConfig,
	checkEntry func(section string, values map[string]any) error) error {
	for section, entries := range candidate.Entries {
		for name, values := range entries {
			if configValueEqual(values, current.Entries[section][name]) {
				continue
			}
			if section == "builtin_auth" {
				return fmt.Errorf("entry [%s.%s]: builtin users are managed with \"openrun user\", not as config entries", section, name)
			}
			if err := validateConfigEntry(section, name, values); err != nil {
				return fmt.Errorf("entry [%s.%s]: %w", section, name, err)
			}
			if err := checkEntry(section, values); err != nil {
				return fmt.Errorf("entry [%s.%s]: %w", section, name, err)
			}
		}
	}
	for section, values := range candidate.Settings {
		for key, value := range values {
			if value == nil || configValueEqual(value, current.Settings[section][key]) {
				continue
			}
			if err := validateConfigValue(section, key, value); err != nil {
				return fmt.Errorf("setting %s %s: %w", section, key, err)
			}
		}
	}
	return nil
}

// configValueEqual compares two config document values by their canonical
// json encoding, so typed and json decoded representations compare equal
func configValueEqual(a, b any) bool {
	if b == nil {
		return false
	}
	aJSON, errA := json.Marshal(a, json.Deterministic(true))
	bJSON, errB := json.Marshal(b, json.Deterministic(true))
	return errA == nil && errB == nil && bytes.Equal(aJSON, bJSON)
}

// resolveExistingPrefix makes path absolute and resolves the symlinks of its
// longest existing prefix, so a file not created yet compares against its
// resolved root (on macOS /var is a link to /private/var)
func resolveExistingPrefix(path string) (string, error) {
	abs, err := system.CleanAbsolutePath(path)
	if err != nil {
		return "", err
	}
	rest := ""
	for dir := abs; ; {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(resolved, rest), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

// structEntryValues converts a static config entry struct (GitAuthEntry,
// AuthConfig, ...) to a field-name -> value map via a toml round trip, so the
// read APIs return static and dynamic entries in the same shape
func structEntryValues(entry any) (map[string]any, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(entry); err != nil {
		return nil, fmt.Errorf("error encoding config entry: %w", err)
	}
	values := map[string]any{}
	if _, err := toml.Decode(buf.String(), &values); err != nil {
		return nil, fmt.Errorf("error decoding config entry: %w", err)
	}
	return values, nil
}

// flattenConfigValues flattens a nested values map (as produced by
// structEntryValues for a struct section) into dotted keys, matching the
// settings key format
func flattenConfigValues(values map[string]any, prefix string, out map[string]any) {
	for key, value := range values {
		full := key
		if prefix != "" {
			full = prefix + "." + key
		}
		if nested, ok := value.(map[string]any); ok {
			flattenConfigValues(nested, full, out)
			continue
		}
		out[full] = value
	}
}

// isSecretConfigField reports whether a field holds a secret which must not
// be returned by the read APIs. Dotted settings keys check the leaf segment.
// Durations (api.access_token_ttl) and provider names (app_config.security.
// default_secrets_provider) only name a secret concept, they are not secrets
func isSecretConfigField(fieldName string) bool {
	fieldName = strings.ToLower(fieldName)
	if idx := strings.LastIndex(fieldName, "."); idx >= 0 {
		fieldName = fieldName[idx+1:]
	}
	if strings.HasSuffix(fieldName, "_ttl") || strings.HasSuffix(fieldName, "_provider") {
		return false
	}
	return strings.Contains(fieldName, "secret") || strings.Contains(fieldName, "password") ||
		strings.Contains(fieldName, "token") || fieldName == "private_key"
}

// secretTemplateRefRegex matches a value that is exactly one {{secret ...}}
// or {{secret_from ...}} template action, with nothing outside it
var secretTemplateRefRegex = regexp.MustCompile(`^\{\{\s*(secret_from|secret)\s[^{}]*\}\}$`)

// isSecretTemplateRef reports whether a value is a single {{secret ...}} or
// {{secret_from ...}} template reference. The reference itself is not
// sensitive (the value lives encrypted in the secret provider), so the read
// APIs return it as is instead of redacting, letting the UI show which
// secret a field points to. The whole value must be the reference: anything
// before or after it (a literal fallback, a composite template) is redacted
func isSecretTemplateRef(value string) bool {
	return secretTemplateRefRegex.MatchString(strings.TrimSpace(value))
}

// redactEntryValues returns a copy of the entry values with secret fields
// replaced by RedactedValue. {{secret ...}} template references are not
// sensitive and are returned as is
func redactEntryValues(values map[string]any) map[string]any {
	redacted := make(map[string]any, len(values))
	for key, value := range values {
		redacted[key] = redactConfigValue(key, value)
	}
	return redacted
}

// redactConfigValue redacts a secret string, or recurses into nested maps and
// lists (list items inherit the parent key, so a list of tokens is redacted)
func redactConfigValue(key string, value any) any {
	switch value := normalizeConfigValue(value).(type) {
	case string:
		if isSecretConfigField(key) && value != "" && !isSecretTemplateRef(value) {
			return RedactedValue
		}
		return value
	case map[string]any:
		return redactEntryValues(value)
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = redactConfigValue(key, item)
		}
		return out
	default:
		return value
	}
}

// normalizeConfigValue converts the typed maps and lists that Go callers and
// the static TOML config produce to the JSON document shapes (map[string]any,
// []any), so the redaction helpers handle one representation
func normalizeConfigValue(value any) any {
	switch typed := value.(type) {
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = item
		}
		return out
	case []string:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = item
		}
		return out
	case []map[string]any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = item
		}
		return out
	}
	return value
}

// evalSecretsDeep returns a copy of the value with every string run through
// the secret template evaluation, matching how the static config entries are
// handled at startup
func evalSecretsDeep(v any, evalSecret func(string) (string, error)) (any, error) {
	switch val := v.(type) {
	case string:
		return evalSecret(val)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			evaled, err := evalSecretsDeep(item, evalSecret)
			if err != nil {
				return nil, err
			}
			out[i] = evaled
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			evaled, err := evalSecretsDeep(item, evalSecret)
			if err != nil {
				return nil, err
			}
			out[k] = evaled
		}
		return out, nil
	default:
		return v, nil
	}
}

// evalEntrySecrets evaluates secret templates in every entry field value
func evalEntrySecrets(entries map[string]map[string]map[string]any,
	evalSecret func(string) (string, error)) (map[string]map[string]map[string]any, error) {
	out := make(map[string]map[string]map[string]any, len(entries))
	for section, sectionEntries := range entries {
		outSection := make(map[string]map[string]any, len(sectionEntries))
		for name, values := range sectionEntries {
			evaled, err := evalSecretsDeep(values, evalSecret)
			if err != nil {
				return nil, fmt.Errorf("error evaluating secret in [%s.%s]: %w", section, name, err)
			}
			outSection[name] = evaled.(map[string]any)
		}
		out[section] = outSection
	}
	return out, nil
}

// evalSettingsSecrets evaluates secret templates in every settings value
func evalSettingsSecrets(settings map[string]map[string]any,
	evalSecret func(string) (string, error)) (map[string]map[string]any, error) {
	out := make(map[string]map[string]any, len(settings))
	for section, values := range settings {
		evaled, err := evalSecretsDeep(values, evalSecret)
		if err != nil {
			return nil, fmt.Errorf("error evaluating secret in [%s]: %w", section, err)
		}
		out[section] = evaled.(map[string]any)
	}
	return out, nil
}

// structFieldByTag returns the struct field with the given toml tag
func structFieldByTag(v reflect.Value, tag string) (reflect.Value, bool) {
	structType := v.Type()
	for i := range structType.NumField() {
		fieldTag := strings.Split(structType.Field(i).Tag.Get("toml"), ",")[0]
		if fieldTag == tag {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

// applySettingField copies the value at one dotted settings key from the
// overlay config (freshly decoded from the settings toml) into the effective
// config. Walks struct fields by toml tag; a map field consumes the remaining
// key as the map key (the effective map is cloned so the static config's map
// is never modified). Overriding a non-zero static value logs a warning
func applySettingField(logger *types.Logger, effective, overlay reflect.Value, section string, key string) error {
	effField, ok := structFieldByTag(effective, section)
	if !ok {
		return fmt.Errorf("unknown config section %q", section)
	}
	overlayField, _ := structFieldByTag(overlay, section)

	parts := strings.Split(key, ".")
	for i, part := range parts {
		if effField.Kind() == reflect.Map && effField.Type().Key().Kind() == reflect.String {
			// The map key is the rest of the dotted key (map values are
			// scalars in the config, e.g. telemetry headers)
			mapKey := reflect.ValueOf(strings.Join(parts[i:], "."))
			overlayEntry := overlayField.MapIndex(mapKey)
			if !overlayEntry.IsValid() {
				return fmt.Errorf("config value %s %s not found after decode", section, key)
			}
			cloned := reflect.MakeMapWithSize(effField.Type(), effField.Len()+1)
			iter := effField.MapRange()
			for iter.Next() {
				cloned.SetMapIndex(iter.Key(), iter.Value())
			}
			if effField.MapIndex(mapKey).IsValid() {
				logger.Warn().Msgf("dynamic config overrides static config value %s %s", section, key)
			}
			cloned.SetMapIndex(mapKey, overlayEntry)
			effField.Set(cloned)
			return nil
		}
		if effField.Kind() != reflect.Struct {
			return fmt.Errorf("config key %s %s does not resolve to a settable field", section, key)
		}
		sub, ok := structFieldByTag(effField, part)
		if !ok {
			return fmt.Errorf("unknown config field %s in %s %s", part, section, key)
		}
		overlaySub, _ := structFieldByTag(overlayField, part)
		effField, overlayField = sub, overlaySub
	}

	if effField.Kind() == reflect.Struct || (effField.Kind() == reflect.Map && effField.Type().Key().Kind() == reflect.String) {
		return fmt.Errorf("config key %s %s addresses a section, not a field", section, key)
	}
	if !effField.IsZero() && !reflect.DeepEqual(effField.Interface(), overlayField.Interface()) {
		logger.Warn().Msgf("dynamic config overrides static config value %s %s", section, key)
	}
	effField.Set(overlayField)
	return nil
}

// mergeDynamicConfig computes the effective server config: a copy of the
// static config with the dynamic entries merged into the named-entry map
// sections and the dynamic settings applied to the struct section fields.
// Dynamic values take precedence (whole-entry granularity for entries, field
// granularity for settings); shadowing a static value logs a warning. The
// static config is never modified
func mergeDynamicConfig(logger *types.Logger, static *types.ServerConfig,
	dynamic *types.DynamicConfig,
	evalSecret func(string) (string, error)) (*types.ServerConfig, error) {

	effective := *static // shallow copy, merged sections get fresh maps below
	entries := dynamic.Entries
	settings := dynamic.Settings
	if len(entries) == 0 && len(settings) == 0 {
		return &effective, nil
	}

	if len(settings) > 0 {
		// Drop sections which are not dynamically settable (previously
		// persisted values for a section since made static-only)
		filtered := make(map[string]map[string]any, len(settings))
		for section, values := range settings {
			if !isConfigSettingsSection(section) {
				logger.Warn().Msgf("dynamic config settings for section %s are not supported, ignored", section)
				continue
			}
			filtered[section] = values
		}
		settings = filtered
	}

	if evalSecret != nil {
		var err error
		if len(entries) > 0 {
			if entries, err = evalEntrySecrets(entries, evalSecret); err != nil {
				return nil, err
			}
		}
		if len(settings) > 0 {
			if settings, err = evalSettingsSecrets(settings, evalSecret); err != nil {
				return nil, err
			}
		}
	}

	if len(entries["builder_agent"]) > 0 {
		// A previously persisted agent whose mounts are outside the
		// allowed mounts must not apply. Checked after the secret
		// evaluation, on the paths the sandbox would mount
		agents := make(map[string]map[string]any, len(entries["builder_agent"]))
		for name, values := range entries["builder_agent"] {
			if err := checkBuilderAgentPaths(values, static.Security.AllowedMounts); err != nil {
				logger.Warn().Err(err).Msgf("dynamic config entry [builder_agent.%s] ignored", name)
				continue
			}
			agents[name] = values
		}
		entries = maps.Clone(entries)
		entries["builder_agent"] = agents
	}

	staticVal := reflect.ValueOf(static).Elem()
	effectiveVal := reflect.ValueOf(&effective).Elem()

	if len(entries) > 0 {
		contents, err := encodeEntriesTOML(entries)
		if err != nil {
			return nil, err
		}
		var overlay types.ServerConfig
		md, err := toml.Decode(contents, &overlay)
		if err != nil {
			return nil, fmt.Errorf("error decoding dynamic config entries: %w", err)
		}
		for _, key := range md.Undecoded() {
			logger.Warn().Msgf("dynamic config entry %s does not match the config schema, ignored", key)
		}

		overlayVal := reflect.ValueOf(&overlay).Elem()
		structType := staticVal.Type()
		for i := range structType.NumField() {
			field := structType.Field(i)
			tag := strings.Split(field.Tag.Get("toml"), ",")[0]
			if tag == "" || tag == "-" || field.Type.Kind() != reflect.Map || field.Type.Key().Kind() != reflect.String {
				continue
			}
			if len(entries[tag]) == 0 {
				continue
			}
			if _, ok := configSectionType(tag); !ok {
				// A previously persisted entry for a section which is
				// not (or no longer) dynamically settable must not apply
				logger.Warn().Msgf("dynamic config entries for section %s are static config only, ignored", tag)
				continue
			}

			merged := reflect.MakeMapWithSize(field.Type, staticVal.Field(i).Len()+len(entries[tag]))
			iter := staticVal.Field(i).MapRange()
			for iter.Next() {
				merged.SetMapIndex(iter.Key(), iter.Value())
			}
			overlayField := overlayVal.Field(i)
			iter = overlayField.MapRange()
			for iter.Next() {
				if staticVal.Field(i).MapIndex(iter.Key()).IsValid() {
					logger.Warn().Msgf("dynamic config overrides static config entry [%s.%s]", tag, iter.Key().String())
				}
				merged.SetMapIndex(iter.Key(), iter.Value())
			}
			effectiveVal.Field(i).Set(merged)
		}
	}

	if len(settings) > 0 {
		contents, err := encodeSettingsTOML(settings)
		if err != nil {
			return nil, err
		}
		var overlay types.ServerConfig
		md, err := toml.Decode(contents, &overlay)
		if err != nil {
			return nil, fmt.Errorf("error decoding dynamic config settings: %w", err)
		}
		for _, key := range md.Undecoded() {
			logger.Warn().Msgf("dynamic config setting %s does not match the config schema, ignored", key)
		}
		undecoded := map[string]bool{}
		for _, key := range md.Undecoded() {
			undecoded[key.String()] = true
		}

		overlayVal := reflect.ValueOf(&overlay).Elem()
		sections := make([]string, 0, len(settings))
		for section := range settings {
			sections = append(sections, section)
		}
		sort.Strings(sections)
		for _, section := range sections {
			keys := make([]string, 0, len(settings[section]))
			for key := range settings[section] {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if settings[section][key] == nil || undecoded[section+"."+key] {
					continue
				}
				if staticOnlySettingKey(section, key) {
					// A previously persisted value for a field which is
					// not (or no longer) dynamically settable must not apply
					logger.Warn().Msgf("dynamic config setting %s %s is static config only, ignored", section, key)
					continue
				}
				if err := applySettingField(logger, effectiveVal, overlayVal, section, key); err != nil {
					logger.Warn().Err(err).Msgf("dynamic config setting %s %s not applied", section, key)
				}
			}
		}
	}

	return &effective, nil
}
