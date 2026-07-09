// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func TestConfigSections(t *testing.T) {
	sections := listConfigSections()
	for _, want := range []string{"git_auth", "auth", "saml", "client_auth", "secret", "forward", "plugin"} {
		found := false
		for _, section := range sections {
			if section == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected section %q in %v", want, sections)
		}
	}

	if _, ok := configSectionType("git_auth"); !ok {
		t.Error("git_auth should be a settable section")
	}
	if _, ok := configSectionType("secret"); !ok {
		t.Error("secret should be an entry section (named providers with free-form fields)")
	}
	if _, ok := configSectionType("http"); ok {
		t.Error("http is not a named-entry map section, must not be settable")
	}
	if _, ok := configSectionType("node_config"); ok {
		t.Error("node_config is a flat key/value section, managed through settings not entries")
	}
	if _, ok := configSectionType("nosuchsection"); ok {
		t.Error("unknown section must not be settable")
	}
}

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
	for _, want := range []string{"security", "system", "app_config", "node_config"} {
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
	// logging and telemetry are read on hot paths by components which cache
	// the config at startup, they are static-only
	for _, section := range []string{"logging", "telemetry"} {
		if isConfigSettingsSection(section) {
			t.Errorf("%s must not be dynamically settable", section)
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
	if err := validateConfigValue("system", "max_concurrent_builds", 5); err != nil {
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
	if err := validateConfigValue("system", "nosuchfield", "x"); err == nil ||
		!strings.Contains(err.Error(), "unknown config fields") {
		t.Errorf("unknown field accepted: %v", err)
	}
	if err := validateConfigValue("app_config", "cors.nosuchfield", "x"); err == nil {
		t.Error("unknown nested field accepted")
	}
	if err := validateConfigValue("system", "max_concurrent_builds", "notanumber"); err == nil {
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
				"default_git_auth":               "dyngit",
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
	// Map-valued fields merge at key granularity with a cloned map
	if merged.Security.AllowedContainerArgs["dyn_arg"] != "2" ||
		merged.Security.AllowedContainerArgs["static_arg"] != "1" {
		t.Errorf("allowed_container_args not merged: %v", merged.Security.AllowedContainerArgs)
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

func TestStructEntryValues(t *testing.T) {
	values, err := structEntryValues(types.GitAuthEntry{
		UserID: "git", KeyFilePath: "/keys/k1", Password: "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	if values["user_id"] != "git" || values["key_file_path"] != "/keys/k1" || values["password"] != "pw" {
		t.Errorf("unexpected values: %v", values)
	}
}
