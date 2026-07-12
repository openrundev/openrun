// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/openrundev/openrun/internal/builder"
	"github.com/openrundev/openrun/internal/types"
)

// Generic machinery for the dynamic config (DynamicConfig.Entries and
// DynamicConfig.Settings): which openrun.toml sections can be set dynamically,
// schema validation and the merge of dynamic values over the static config.
// Entries cover the named-entry map sections ([git_auth.x], [auth.y], ...),
// settings cover individual fields of the struct sections (security.
// default_git_auth, system.default_domain, app_config.cors.allow_origin, ...).
// Everything here is driven by the types.ServerConfig struct tags, so a new
// toml section or field becomes dynamically configurable without code changes.

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
// sections qualify
func configSectionType(section string) (reflect.Type, bool) {
	fieldType, ok := configSectionField(section)
	if !ok || !isEntrySectionType(fieldType) {
		return nil, false
	}
	return fieldType, true
}

// listConfigSections returns the names of all dynamically settable sections
func listConfigSections() []string {
	t := reflect.TypeFor[types.ServerConfig]()
	sections := []string{}
	for i := range t.NumField() {
		field := t.Field(i)
		tag := strings.Split(field.Tag.Get("toml"), ",")[0]
		if field.Anonymous || tag == "" || tag == "-" {
			continue
		}
		if isEntrySectionType(field.Type) {
			sections = append(sections, tag)
		}
	}
	sort.Strings(sections)
	return sections
}

// staticOnlySections are struct sections which cannot be set dynamically:
// logging and telemetry are read on hot paths by components which cache the
// config at startup, so a dynamic value would be misleading (and applying it
// at runtime would put synchronization on those paths)
var staticOnlySections = map[string]bool{"logging": true, "telemetry": true}

// isConfigSettingsSection reports whether a section holds settings which can
// be set dynamically field by field: a struct section of ServerConfig, or a
// flat key/value map section (node_config). The named-entry map sections are
// handled through Entries instead
func isConfigSettingsSection(section string) bool {
	if staticOnlySections[section] {
		return false
	}
	fieldType, ok := configSectionField(section)
	if !ok {
		return false
	}
	return fieldType.Kind() == reflect.Struct || isFlatKVSectionType(fieldType)
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
	t := reflect.TypeFor[types.ServerConfig]()
	sections := []string{}
	for i := range t.NumField() {
		field := t.Field(i)
		tag := strings.Split(field.Tag.Get("toml"), ",")[0]
		if field.Anonymous || tag == "" || tag == "-" || staticOnlySections[tag] {
			continue
		}
		if field.Type.Kind() == reflect.Struct || isFlatKVSectionType(field.Type) {
			sections = append(sections, tag)
		}
	}
	sort.Strings(sections)
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
		return fmt.Errorf("unknown config settings section %q, valid sections are: %s",
			section, strings.Join(listConfigSettingsSections(), ", "))
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
	return nil
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
// be returned by the read APIs. Dotted settings keys check the leaf segment
func isSecretConfigField(fieldName string) bool {
	if idx := strings.LastIndex(fieldName, "."); idx >= 0 {
		fieldName = fieldName[idx+1:]
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
		if isSecretConfigField(key) {
			if str, ok := value.(string); ok && str != "" && !isSecretTemplateRef(str) {
				redacted[key] = RedactedValue
				continue
			}
		}
		redacted[key] = value
	}
	return redacted
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
				if err := applySettingField(logger, effectiveVal, overlayVal, section, key); err != nil {
					logger.Warn().Err(err).Msgf("dynamic config setting %s %s not applied", section, key)
				}
			}
		}
	}

	return &effective, nil
}
