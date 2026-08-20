// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// TestGetPluginSettings verifies the plugin settings resolution (config file
// blocks plus app account links) used by both the in-process and external
// plugin dispatch paths.
func TestGetPluginSettings(t *testing.T) {
	// Plugin config info from config file
	pluginConfig := map[string]types.PluginSettings{
		"plugin1.in":          {"key": "v1"},
		"plugin1.in#account1": {"key": "v2"},
		"plugin2.in":          {"key": "v3"},
		"plugin2.in#account1": {"key": "v4"},
		"plugin2.in#account2": {"key": "v5"},
		"plugin2.in#account3": {"key": "v6"},
	}

	// App account links
	appAccounts := []types.AccountLink{
		{Plugin: "plugin2.in", AccountName: "account2"},
		{Plugin: "plugin2.in#account2", AccountName: "plugin2.in#account3"},
	}

	app := &App{
		Logger:   types.NewLogger(&types.LogConfig{}),
		AppEntry: &types.AppEntry{Id: "testApp", Path: "/test", Domain: "", SourceUrl: ".", IsDev: false},
	}
	appPlugins := NewAppPlugins(app, pluginConfig, appAccounts)

	// No account, no account link: the plugin's base settings block
	settings := appPlugins.GetPluginSettings("plugin1.in", "")
	testutil.AssertEqualsString(t, "base settings", "v1", settings["key"].(string))

	// No account, with an account link: the linked account's settings block
	settings = appPlugins.GetPluginSettings("plugin2.in", "")
	testutil.AssertEqualsString(t, "linked settings", "v5", settings["key"].(string))

	// Account with a (full path) account link: the linked block
	settings = appPlugins.GetPluginSettings("plugin2.in", "account2")
	testutil.AssertEqualsString(t, "chained link settings", "v6", settings["key"].(string))

	// Account without an account link: falls back to the base settings block
	settings = appPlugins.GetPluginSettings("plugin2.in", "account1")
	testutil.AssertEqualsString(t, "unlinked account settings", "v3", settings["key"].(string))

	// Unknown plugin: empty settings
	settings = appPlugins.GetPluginSettings("plugin3.in", "")
	testutil.AssertEqualsInt(t, "unknown plugin settings", 0, len(settings))
}
