// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestValidateConfigEntry(t *testing.T) {
	valid := map[string]any{"user_id": "git", "key_file_path": "/keys/k1", "password": "pw"}
	if err := validateConfigEntry("git_auth", "gh", valid); err != nil {
		t.Errorf("valid git_auth entry rejected: %v", err)
	}

	if err := validateConfigEntry("git_auth", "", valid); err == nil {
		t.Error("empty entry name accepted")
	}

	if err := validateConfigEntry("nosuchsection", "x", valid); err == nil ||
		!strings.Contains(err.Error(), "unknown config section") {
		t.Errorf("unknown section accepted: %v", err)
	}

	if err := validateConfigEntry("git_auth", "gh",
		map[string]any{"nosuchfield": "x"}); err == nil ||
		!strings.Contains(err.Error(), "unknown config fields") {
		t.Errorf("unknown field accepted: %v", err)
	}

	// Typed fields validate: scopes must be a list, not a string
	if err := validateConfigEntry("auth", "github",
		map[string]any{"key": "k", "secret": "s", "scopes": "email"}); err == nil {
		t.Error("ill-typed scopes value accepted")
	}
	if err := validateConfigEntry("auth", "github",
		map[string]any{"key": "k", "secret": "s", "scopes": []any{"email"}}); err != nil {
		t.Errorf("valid auth entry rejected: %v", err)
	}

	// Bool fields validate for saml
	if err := validateConfigEntry("saml", "okta",
		map[string]any{"metadata_url": "https://idp/metadata", "use_post": true}); err != nil {
		t.Errorf("valid saml entry rejected: %v", err)
	}
}

func TestMergeDynamicEntries(t *testing.T) {
	logger := types.NewLogger(&types.LogConfig{Level: "ERROR"})
	static := &types.ServerConfig{
		GitAuth: map[string]types.GitAuthEntry{
			"gh":     {UserID: "git", KeyFilePath: "/static/key"},
			"static": {UserID: "staticuser"},
		},
		Auth: map[string]types.AuthConfig{
			"github": {Key: "statickey", Secret: "staticsecret"},
		},
	}

	entries := map[string]map[string]map[string]any{
		"git_auth": {
			"gh": {"user_id": "dyngit", "key_file_path": "/dyn/key"}, // overrides static
			"gl": {"user_id": "gitlab"},                              // new entry
		},
		"saml": {
			"okta": {"metadata_url": "https://idp/metadata", "use_post": true},
		},
	}

	merged, err := mergeDynamicConfig(logger, static, &types.DynamicConfig{Entries: entries}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Dynamic takes precedence at whole-entry granularity
	if got := merged.GitAuth["gh"]; got.UserID != "dyngit" || got.KeyFilePath != "/dyn/key" {
		t.Errorf("dynamic gh entry not merged: %+v", got)
	}
	// Untouched static entries are kept
	if got := merged.GitAuth["static"]; got.UserID != "staticuser" {
		t.Errorf("static entry lost: %+v", got)
	}
	// New dynamic entries and sections appear
	if got := merged.GitAuth["gl"]; got.UserID != "gitlab" {
		t.Errorf("new dynamic entry missing: %+v", got)
	}
	if got := merged.SAML["okta"]; got.MetadataURL != "https://idp/metadata" || !got.UsePost {
		t.Errorf("saml entry not merged: %+v", got)
	}
	// Sections without dynamic entries are untouched
	if got := merged.Auth["github"]; got.Key != "statickey" {
		t.Errorf("auth section changed without dynamic entries: %+v", got)
	}

	// The static config must never be modified
	if static.GitAuth["gh"].UserID != "git" {
		t.Errorf("static config modified: %+v", static.GitAuth["gh"])
	}
	if len(static.SAML) != 0 {
		t.Errorf("static config gained a saml section: %+v", static.SAML)
	}
}

func TestMergeDynamicEntriesSecrets(t *testing.T) {
	logger := types.NewLogger(&types.LogConfig{Level: "ERROR"})
	static := &types.ServerConfig{}
	entries := map[string]map[string]map[string]any{
		"git_auth": {"gh": {"password": "tmpl:pw", "user_id": "git"}},
	}

	evalSecret := func(s string) (string, error) {
		return strings.Replace(s, "tmpl:", "evaled:", 1), nil
	}
	merged, err := mergeDynamicConfig(logger, static, &types.DynamicConfig{Entries: entries}, evalSecret)
	if err != nil {
		t.Fatal(err)
	}
	if got := merged.GitAuth["gh"].Password; got != "evaled:pw" {
		t.Errorf("secret template not evaluated: %q", got)
	}
	// The stored entries keep the template, only the merged view is evaluated
	if entries["git_auth"]["gh"]["password"] != "tmpl:pw" {
		t.Error("secret evaluation modified the stored entries")
	}
}

func TestRedactEntryValues(t *testing.T) {
	values := map[string]any{
		"user_id":  "git",
		"password": "supersecret",
		"secret":   "clientsecret",
		"scopes":   []any{"email"},
	}
	redacted := redactEntryValues(values)
	if redacted["password"] != RedactedValue || redacted["secret"] != RedactedValue {
		t.Errorf("secret fields not redacted: %v", redacted)
	}
	if redacted["user_id"] != "git" {
		t.Errorf("non-secret field changed: %v", redacted)
	}
	// Durations and provider names only mention a secret concept
	plain := redactEntryValues(map[string]any{
		"access_token_ttl":                  "1h",
		"refresh_token_ttl":                 "720h",
		"security.default_secrets_provider": "asm",
		"builder_auth_token":                "tok",
	})
	if plain["access_token_ttl"] != "1h" || plain["refresh_token_ttl"] != "720h" ||
		plain["security.default_secrets_provider"] != "asm" {
		t.Errorf("non-secret ttl/provider fields redacted: %v", plain)
	}
	if plain["builder_auth_token"] != RedactedValue {
		t.Errorf("token field not redacted: %v", plain)
	}
	if values["password"] != "supersecret" {
		t.Error("redaction modified the input map")
	}

	// Empty secrets stay empty rather than showing a placeholder
	empty := redactEntryValues(map[string]any{"password": ""})
	if empty["password"] != "" {
		t.Errorf("empty secret got a placeholder: %v", empty)
	}

	// {{secret ...}} references are not sensitive and pass through, so the
	// UI can show which secret a field points to
	refs := redactEntryValues(map[string]any{
		"password":     `{{secret_from "db" "gitauth_a1b2c3d4"}}`,
		"secret":       `{{ secret "mysecret" }}`,
		"token":        "{{secretive}}", // not a secret ref, must redact
		"private_key":  "-----BEGIN OPENSSH PRIVATE KEY-----",
		"api_token":    `{{secret "a"}}:literal-fallback`, // trailing literal, must redact
		"db_password":  `pw-{{secret "a"}}`,               // leading literal, must redact
		"jwt_secret":   `{{secret "a"}}{{secret "b"}}`,    // composite template, must redact
		"vault_secret": "{{secret_fromage}}",              // not a ref keyword, must redact
	})
	if refs["password"] != `{{secret_from "db" "gitauth_a1b2c3d4"}}` || refs["secret"] != `{{ secret "mysecret" }}` {
		t.Errorf("secret template refs were redacted: %v", refs)
	}
	for _, key := range []string{"token", "private_key", "api_token", "db_password", "jwt_secret", "vault_secret"} {
		if refs[key] != RedactedValue {
			t.Errorf("%s not redacted, got: %v", key, refs[key])
		}
	}
}

func TestConfigSettingsSections(t *testing.T) {
	sections := listConfigSettingsSections()
	for _, want := range []string{"security", "system", "api", "app_builder", "app_config", "node_config"} {
		found := false
		for _, section := range sections {
			if section == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected settings section %q in %v", want, sections)
		}
	}

	if !isConfigSettingsSection("security") {
		t.Error("security should be a settings section")
	}
	if !isConfigSettingsSection("node_config") {
		t.Error("node_config should be a settings section (flat key/value map)")
	}
	if !isFlatKVSection("node_config") || isFlatKVSection("security") {
		t.Error("only map[string]any sections are flat kv sections")
	}
	if isConfigSettingsSection("git_auth") || isConfigSettingsSection("secret") {
		t.Error("named-entry map sections are not settings sections")
	}
	if isConfigSettingsSection("nosuchsection") {
		t.Error("unknown section must not be a settings section")
	}
	// Only the allowlisted sections are dynamically settable
	for _, section := range []string{"logging", "telemetry", "bindings", "plugin_providers",
		"http", "https", "metadata", "registry", "builder", "kubernetes", "restart", "permissions"} {
		if isConfigSettingsSection(section) {
			t.Errorf("%s must not be dynamically settable", section)
		}
		if err := validateConfigValue(section, "x", "v"); err == nil ||
			!strings.Contains(err.Error(), "static openrun.toml config") {
			t.Errorf("%s write must be rejected as static only, got %v", section, err)
		}
	}
	for _, section := range []string{"builtin_auth", "client_auth", "forward", "plugin", "litestream"} {
		if _, ok := configSectionType(section); ok {
			t.Errorf("%s entries must not be dynamically settable", section)
		}
		if err := validateConfigEntry(section, "x", map[string]any{}); err == nil ||
			!strings.Contains(err.Error(), "static openrun.toml config") {
			t.Errorf("%s entry write must be rejected as static only, got %v", section, err)
		}
	}
}

func TestValidateConfigValue(t *testing.T) {
	if err := validateConfigValue("security", "default_git_auth", "gh"); err != nil {
		t.Errorf("valid security value rejected: %v", err)
	}
	if err := validateConfigValue("system", "show_hosted_with", true); err != nil {
		t.Errorf("valid bool value rejected: %v", err)
	}
	if err := validateConfigValue("app_builder", "max_sessions", 5); err != nil {
		t.Errorf("valid int value rejected: %v", err)
	}
	// Dotted keys reach into nested app_config structs
	if err := validateConfigValue("app_config", "cors.allow_origin", "*"); err != nil {
		t.Errorf("valid dotted key rejected: %v", err)
	}

	if err := validateConfigValue("security", "", "x"); err == nil {
		t.Error("empty key accepted")
	}
	if err := validateConfigValue("git_auth", "user_id", "x"); err == nil {
		t.Error("entry section accepted as settings section")
	}
	if err := validateConfigValue("app_config", "nosuchfield", "x"); err == nil ||
		!strings.Contains(err.Error(), "unknown config fields") {
		t.Errorf("unknown field accepted: %v", err)
	}
	if err := validateConfigValue("system", "nosuchfield", "x"); err == nil ||
		!strings.Contains(err.Error(), "static openrun.toml config") {
		t.Errorf("non allowlisted field accepted: %v", err)
	}
	if err := validateConfigValue("app_config", "cors.nosuchfield", "x"); err == nil {
		t.Error("unknown nested field accepted")
	}
	if err := validateConfigValue("app_builder", "max_sessions", "notanumber"); err == nil {
		t.Error("ill-typed int value accepted")
	}
	// Static-only sections are rejected
	if err := validateConfigValue("logging", "level", "WARN"); err == nil {
		t.Error("logging accepted as settings section")
	}
	if err := validateConfigValue("telemetry", "enabled", true); err == nil {
		t.Error("telemetry accepted as settings section")
	}

	// node_config keys are free form and literal (dots are not field paths)
	if err := validateConfigValue("node_config", "any_key", "v"); err != nil {
		t.Errorf("valid node_config value rejected: %v", err)
	}
	if err := validateConfigValue("node_config", "dotted.key", 5); err != nil {
		t.Errorf("dotted node_config key rejected: %v", err)
	}

	// secret entries are free form (provider specific properties)
	if err := validateConfigEntry("secret", "env_test", map[string]any{"anyprop": "x"}); err != nil {
		t.Errorf("valid secret entry rejected: %v", err)
	}
}

func TestMergeDynamicSettings(t *testing.T) {
	logger := types.NewLogger(&types.LogConfig{Level: "ERROR"})
	static := &types.ServerConfig{}
	static.Security.DefaultGitAuth = "staticgit"
	static.Security.AppDefaultAuthType = "system"
	static.Security.AllowedContainerArgs = map[string]string{"static_arg": "1"}
	static.System.DefaultDomain = "static.example.com"
	static.System.ListAppsTitle = "Static title"
	static.AppConfig.CORS.AllowOrigin = "https://static.example.com"
	static.Log.MaxBackups = 3
	static.NodeConfig = types.NodeConfig{"static_key": "sv"}

	dynamic := &types.DynamicConfig{
		Settings: map[string]map[string]any{
			"security": {
				"default_git_auth": "dyngit",
				// Not allowlisted: a persisted value is ignored
				"allowed_container_args.dyn_arg": "2",
			},
			"system": {"list_apps_title": "Dynamic title", "show_hosted_with": true},
			"app_config": {
				"cors.allow_origin":             "https://dyn.example.com",
				"container.health_timeout_secs": 42,
			},
			// node_config keys are literal, dots included
			"node_config": {"dyn_key": 7, "dotted.key": "dv"},
			// Static-only sections are ignored even if values were persisted
			"logging":   {"max_backups": 7},
			"telemetry": {"enabled": true},
		},
	}

	merged, err := mergeDynamicConfig(logger, static, dynamic, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Dynamic values win at field granularity
	if merged.Security.DefaultGitAuth != "dyngit" {
		t.Errorf("default_git_auth not overridden: %q", merged.Security.DefaultGitAuth)
	}
	if merged.System.ListAppsTitle != "Dynamic title" || !merged.System.ShowHostedWith {
		t.Errorf("system settings not applied: %+v", merged.System)
	}
	if merged.AppConfig.CORS.AllowOrigin != "https://dyn.example.com" {
		t.Errorf("nested app_config setting not applied: %q", merged.AppConfig.CORS.AllowOrigin)
	}
	if merged.AppConfig.Container.HealthTimeoutSecs != 42 {
		t.Errorf("int app_config setting not applied: %d", merged.AppConfig.Container.HealthTimeoutSecs)
	}
	if _, ok := merged.Security.AllowedContainerArgs["dyn_arg"]; ok ||
		merged.Security.AllowedContainerArgs["static_arg"] != "1" {
		t.Errorf("static only allowed_container_args merged: %v", merged.Security.AllowedContainerArgs)
	}
	// Flat kv sections merge key by key, dotted keys stay literal
	if merged.NodeConfig["dyn_key"] != int64(7) || merged.NodeConfig["dotted.key"] != "dv" ||
		merged.NodeConfig["static_key"] != "sv" {
		t.Errorf("node_config not merged: %v", merged.NodeConfig)
	}

	// Static-only sections keep the static values
	if merged.Log.MaxBackups != 3 {
		t.Errorf("logging setting applied despite being static-only: %+v", merged.Log)
	}
	if merged.Telemetry.Enabled {
		t.Errorf("telemetry setting applied despite being static-only: %+v", merged.Telemetry)
	}

	// Untouched fields keep the static value
	if merged.Security.AppDefaultAuthType != "system" {
		t.Errorf("untouched security field changed: %q", merged.Security.AppDefaultAuthType)
	}
	if merged.System.DefaultDomain != "static.example.com" {
		t.Errorf("untouched system field changed: %q", merged.System.DefaultDomain)
	}

	// The static config must never be modified
	if static.Security.DefaultGitAuth != "staticgit" || static.System.ListAppsTitle != "Static title" {
		t.Error("static config modified by settings merge")
	}
	if static.AppConfig.CORS.AllowOrigin != "https://static.example.com" {
		t.Errorf("static app_config modified: %q", static.AppConfig.CORS.AllowOrigin)
	}
	if len(static.Security.AllowedContainerArgs) != 1 {
		t.Errorf("static allowed_container_args modified: %v", static.Security.AllowedContainerArgs)
	}
	if len(static.NodeConfig) != 1 {
		t.Errorf("static node_config modified: %v", static.NodeConfig)
	}
}

func TestFlattenConfigValues(t *testing.T) {
	flat := map[string]any{}
	flattenConfigValues(map[string]any{
		"level": "INFO",
		"cors":  map[string]any{"allow_origin": "*"},
	}, "", flat)
	if flat["level"] != "INFO" || flat["cors.allow_origin"] != "*" {
		t.Errorf("unexpected flattened values: %v", flat)
	}
}

// TestStaticOnlySettingKeys verifies the dynamic-config write path rejects
// every field outside the allowlist, in particular the host command, exec,
// mount and container arg settings, and any unsafe_* field
func TestStaticOnlySettingKeys(t *testing.T) {
	staticOnly := [][2]string{
		{"security", "unsafe_disable_rbac"},
		{"security", "unsafe_allow_system_plugins_anon"},
		{"security", "trusted_proxies"},
		{"security", "remote_disk_read_paths"},
		{"security", "allowed_exec_commands"},
		{"security", "allowed_exec_env"},
		{"security", "allowed_mounts"},
		{"security", "allowed_container_args.--privileged"},
		{"security", "callback_url"},
		{"system", "container_command"},
		{"system", "tailwindcss_command"},
		{"system", "node_path"},
		{"system", "builder_auth_token"},
		{"app_builder", "workspace_dir"},
		{"api", "cimd_allow_private_hosts"},
		{"app_config", "unsafe_x"},
		{"node_config", "unsafe_x"},
	}
	for _, pair := range staticOnly {
		if !staticOnlySettingKey(pair[0], pair[1]) {
			t.Errorf("%s %s must be static only", pair[0], pair[1])
		}
		if err := validateConfigValue(pair[0], pair[1], true); err == nil ||
			!strings.Contains(err.Error(), "static openrun.toml config") {
			t.Errorf("%s %s write must be rejected as static only, got %v", pair[0], pair[1], err)
		}
	}
	for _, pair := range [][2]string{
		{"security", "default_git_auth"},
		{"security", "app_default_auth_type"},
		{"system", "default_domain"},
		{"api", "rest.enable"},
		{"api", "external_url"},
		{"app_builder", "enabled"},
		{"app_config", "cors.allow_origin"},
		{"node_config", "any_key"},
	} {
		if staticOnlySettingKey(pair[0], pair[1]) {
			t.Errorf("%s %s must stay dynamically settable", pair[0], pair[1])
		}
	}
}

// TestDynamicAllowlistMatchesSchema verifies every allowlisted section and
// key exists in the config schema, so a renamed field cannot leave a stale
// allowlist entry behind
func TestDynamicAllowlistMatchesSchema(t *testing.T) {
	for section := range dynamicEntrySections {
		if _, ok := configSectionType(section); !ok {
			t.Errorf("allowlisted entry section %s is not a named-entry section", section)
		}
	}
	for section, keys := range dynamicSettingKeys {
		if !isConfigSettingsSection(section) {
			t.Errorf("allowlisted settings section %s is not a settings section", section)
		}
		for key := range keys {
			fieldType, _ := configSectionField(section)
			for part := range strings.SplitSeq(key, ".") {
				field, ok := fieldByTomlTag(fieldType, part)
				if !ok {
					t.Errorf("allowlisted key %s %s is not in the config schema", section, key)
					break
				}
				fieldType = field.Type
			}
		}
	}
}

func fieldByTomlTag(t reflect.Type, tag string) (reflect.StructField, bool) {
	if t.Kind() != reflect.Struct {
		return reflect.StructField{}, false
	}
	for i := range t.NumField() {
		if strings.Split(t.Field(i).Tag.Get("toml"), ",")[0] == tag {
			return t.Field(i), true
		}
	}
	return reflect.StructField{}, false
}

// noEntryCheck is the validateChangedConfigItems entry check for tests which
// exercise the context free validation only
func noEntryCheck(string, map[string]any) error { return nil }

// TestCheckBuilderAgentPaths verifies dynamic builder_agent config_files must
// mount from within security.allowed_mounts, and path fields cannot be
// templates resolved after the write-time check
func TestCheckBuilderAgentPaths(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "mounts")
	if err := os.MkdirAll(filepath.Join(allowed, "claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	// A link under the allowed root pointing outside does not qualify
	if err := os.Symlink(outside, filepath.Join(allowed, "link")); err != nil {
		t.Fatal(err)
	}
	mounts := []string{allowed}

	for _, entries := range [][]any{
		nil,
		{filepath.Join(allowed, "claude") + ":/root/.claude:ro"},
		{filepath.Join(allowed, "claude", "auth.json") + ":/root/auth.json"},
	} {
		if err := checkBuilderAgentPaths(map[string]any{"config_files": entries}, mounts); err != nil {
			t.Errorf("allowed config_files %v rejected: %v", entries, err)
		}
	}
	for name, values := range map[string]map[string]any{
		"outside":          {"config_files": []any{"/:/host"}},
		"outside dir":      {"config_files": []any{outside + ":/x"}},
		"traversal":        {"config_files": []any{allowed + "/../outside:/x"}},
		"link traversal":   {"config_files": []any{filepath.Join(allowed, "link") + "/../x:/x"}},
		"missing escape":   {"config_files": []any{filepath.Join(outside, "new", "auth.json") + ":/x"}},
		"symlink escape":   {"config_files": []any{filepath.Join(allowed, "link") + ":/x"}},
		"relative":         {"config_files": []any{"somevolume:/x"}},
		"no allowed":       {"config_files": []string{filepath.Join(allowed, "claude") + ":/x"}},
		"template mount":   {"config_files": []any{`{{secret "p"}}:/x`}},
		"template docker":  {"dockerfile": `{{secret "p"}}`},
		"bad mount syntax": {"config_files": []any{filepath.Join(allowed, "claude")}},
	} {
		allowedMounts := mounts
		if name == "no allowed" {
			allowedMounts = nil
		}
		if err := checkBuilderAgentPaths(values, allowedMounts); err == nil {
			t.Errorf("%s: config %v accepted", name, values)
		}
	}
}

// TestMergeSkipsDisallowedBuilderAgents verifies a persisted dynamic
// builder_agent entry mounting from outside security.allowed_mounts does not
// apply, while a valid one does
func TestMergeSkipsDisallowedBuilderAgents(t *testing.T) {
	allowed := t.TempDir()
	static := &types.ServerConfig{}
	static.Security.AllowedMounts = []string{allowed}
	dynamic := &types.DynamicConfig{Entries: map[string]map[string]map[string]any{
		"builder_agent": {
			"claude":   {"config_files": []any{allowed + ":/root/.claude"}},
			"opencode": {"config_files": []any{"/:/host"}},
		},
	}}
	effective, err := mergeDynamicConfig(testutil.TestLogger(), static, dynamic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := effective.BuilderAgent["claude"]; !ok {
		t.Error("valid dynamic builder agent not merged")
	}
	if _, ok := effective.BuilderAgent["opencode"]; ok {
		t.Error("builder agent mounting / must not apply")
	}
	if len(dynamic.Entries["builder_agent"]) != 2 {
		t.Error("merge modified the dynamic config")
	}
}

// TestValidateChangedConfigItems verifies the full document update path
// rejects new or changed static-only values, while unchanged previously
// persisted values do not block an update
func TestValidateChangedConfigItems(t *testing.T) {
	current := &types.DynamicConfig{
		Settings: map[string]map[string]any{"system": {"container_command": "docker"}},
		Entries:  map[string]map[string]map[string]any{"forward": {"f": {"url": "x"}}},
	}
	unchanged := &types.DynamicConfig{
		Settings: map[string]map[string]any{
			"system": {"container_command": "docker", "default_domain": "example.com"},
		},
		Entries: map[string]map[string]map[string]any{
			"forward":  {"f": {"url": "x"}},
			"git_auth": {"gh": {"user_id": "git"}},
		},
	}
	if err := validateChangedConfigItems(unchanged, current, noEntryCheck); err != nil {
		t.Errorf("unchanged persisted values must not block an update: %v", err)
	}

	for name, candidate := range map[string]*types.DynamicConfig{
		"changed setting": {Settings: map[string]map[string]any{"system": {"container_command": "/tmp/evil"}}},
		"new setting":     {Settings: map[string]map[string]any{"system": {"tailwindcss_command": "/tmp/evil"}}},
		"new section":     {Settings: map[string]map[string]any{"bindings": {"cache_dir": "/tmp"}}},
		"changed entry":   {Entries: map[string]map[string]map[string]any{"forward": {"f": {"url": "y"}}}},
		"new entry":       {Entries: map[string]map[string]map[string]any{"plugin": {"p": {"k": "v"}}}},
	} {
		if err := validateChangedConfigItems(candidate, current, noEntryCheck); err == nil ||
			!strings.Contains(err.Error(), "static openrun.toml config") {
			t.Errorf("%s: static only change must be rejected, got %v", name, err)
		}
	}
	builtin := &types.DynamicConfig{Entries: map[string]map[string]map[string]any{"builtin_auth": {"u": {"password": "x"}}}}
	if err := validateChangedConfigItems(builtin, current, noEntryCheck); err == nil ||
		!strings.Contains(err.Error(), "openrun user") {
		t.Errorf("builtin_auth entry must point at openrun user, got %v", err)
	}
}

// TestMergeSkipsStaticOnlySettings verifies a previously persisted value for
// a static-only field does not apply during the merge
func TestMergeSkipsStaticOnlySettings(t *testing.T) {
	static := &types.ServerConfig{}
	dynamic := &types.DynamicConfig{
		Settings: map[string]map[string]any{
			"security": {"unsafe_disable_rbac": true, "default_git_auth": "gh",
				"allowed_exec_commands": []any{"/bin/sh"}},
			"system":   {"container_command": "/tmp/evil"},
			"bindings": {"cache_dir": "/tmp/evil"},
		},
		Entries: map[string]map[string]map[string]any{
			"forward": {"f": {"auth_url": "http://evil"}},
		},
	}
	effective, err := mergeDynamicConfig(testutil.TestLogger(), static, dynamic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Security.UnsafeDisableRBAC {
		t.Fatal("persisted unsafe_disable_rbac must not apply from dynamic settings")
	}
	if len(effective.Security.AllowedExecCommands) != 0 || effective.System.ContainerCommand != "" ||
		effective.Bindings.CacheDir != "" {
		t.Fatalf("persisted static only settings must not apply: %+v %+v", effective.Security, effective.System)
	}
	if len(effective.Forward) != 0 {
		t.Fatalf("persisted static only entries must not apply: %v", effective.Forward)
	}
	if effective.Security.DefaultGitAuth != "gh" {
		t.Fatal("regular security settings must still merge")
	}
}

func TestNestedRedactionRestoresArrayCredentials(t *testing.T) {
	original := map[string]any{
		"agents": []any{map[string]any{"env": map[string]string{"ACCESS_TOKEN": "private", "USER": "public"}}},
		"tokens": []string{"one", "two"},
	}
	redacted := redactEntryValues(original)
	if redacted["agents"].([]any)[0].(map[string]any)["env"].(map[string]any)["ACCESS_TOKEN"] != RedactedValue {
		t.Fatal("array entry leaked credential")
	}
	if redacted["tokens"].([]any)[0] != RedactedValue {
		t.Fatal("credential list leaked")
	}
	if err := restoreRedactedConfigFields(redacted, original, "test"); err != nil {
		t.Fatal(err)
	}
	if redacted["agents"].([]any)[0].(map[string]any)["env"].(map[string]any)["ACCESS_TOKEN"] != "private" || redacted["tokens"].([]any)[1] != "two" {
		t.Fatal("nested credential round trip corrupted stored values")
	}
	if original["agents"].([]any)[0].(map[string]any)["env"].(map[string]string)["ACCESS_TOKEN"] != "private" {
		t.Fatal("read mutated source tree")
	}
}

func TestRedactStaticTOMLArrayCredentials(t *testing.T) {
	values, err := structEntryValues(struct {
		Agents []map[string]any `toml:"agents"`
	}{Agents: []map[string]any{{"env": map[string]string{"API_TOKEN": "private-token"}}}})
	if err != nil {
		t.Fatal(err)
	}
	redacted := redactEntryValues(values)
	env := redacted["agents"].([]any)[0].(map[string]any)["env"].(map[string]any)
	if env["API_TOKEN"] != RedactedValue {
		t.Fatal("TOML table array leaked credential")
	}
	if err := restoreRedactedConfigFields(redacted, values, "config"); err != nil {
		t.Fatal(err)
	}
	if redacted["agents"].([]any)[0].(map[string]any)["env"].(map[string]any)["API_TOKEN"] != "private-token" {
		t.Fatal("TOML table array lost credential during restore")
	}
}
