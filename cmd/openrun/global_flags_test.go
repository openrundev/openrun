// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/urfave/cli/v2"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// runGlobalFlags runs the app with the global flags against a config file
// containing the given server_uri and returns the loaded configs
func runGlobalFlags(t *testing.T, configServerUri string, args ...string) (*types.GlobalConfig, *types.ClientConfig, *types.ServerConfig) {
	t.Helper()
	configFile := filepath.Join(t.TempDir(), "openrun.toml")
	if err := os.WriteFile(configFile, []byte("server_uri = \""+configServerUri+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	globalConfig, clientConfig, serverConfig, err := system.GetDefaultConfigs()
	if err != nil {
		t.Fatal(err)
	}
	flags, err := globalFlags(globalConfig, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	app := cli.NewApp()
	app.Flags = flags
	app.Before = func(ctx *cli.Context) error {
		if err := parseConfig(ctx, globalConfig, clientConfig, serverConfig); err != nil {
			return err
		}
		applyGlobalOverrides(ctx, globalConfig, clientConfig, serverConfig)
		return nil
	}
	app.Action = func(*cli.Context) error { return nil }

	argv := append([]string{"openrun", "--config-file", configFile}, args...)
	if err := app.Run(argv); err != nil {
		t.Fatalf("app run failed: %v", err)
	}
	return globalConfig, clientConfig, serverConfig
}

func TestServerUriFromConfig(t *testing.T) {
	t.Setenv("OPENRUN_SERVER_URI", "")
	os.Unsetenv("OPENRUN_SERVER_URI") //nolint:errcheck
	_, clientConfig, _ := runGlobalFlags(t, "https://config.example.com:25223")
	if clientConfig.ServerUri != "https://config.example.com:25223" {
		t.Errorf("expected config server_uri, got %q", clientConfig.ServerUri)
	}
}

func TestServerUriFlagOverridesConfig(t *testing.T) {
	globalConfig, clientConfig, serverConfig := runGlobalFlags(t, "https://config.example.com:25223",
		"--server-uri", "https://flag.example.com:25223")
	for name, got := range map[string]string{
		"global": globalConfig.ServerUri,
		"client": clientConfig.ServerUri,
		"server": serverConfig.ServerUri,
	} {
		if got != "https://flag.example.com:25223" {
			t.Errorf("%s config: expected flag server uri, got %q", name, got)
		}
	}
}

func TestServerUriEnvOverridesConfig(t *testing.T) {
	t.Setenv("OPENRUN_SERVER_URI", "https://env.example.com:25223")
	_, clientConfig, _ := runGlobalFlags(t, "https://config.example.com:25223")
	if clientConfig.ServerUri != "https://env.example.com:25223" {
		t.Errorf("expected env server uri, got %q", clientConfig.ServerUri)
	}
}
