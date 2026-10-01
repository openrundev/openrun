// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/types"
)

func TestParseProviderName(t *testing.T) {
	kind, name, err := parseProviderName("mongodb")
	if err != nil || kind.typeName != "binding" || name != "mongodb" {
		t.Fatalf("bare name: kind=%v name=%q err=%v", kind, name, err)
	}

	kind, name, err = parseProviderName("binding/mongodb")
	if err != nil || kind.typeName != "binding" || name != "mongodb" {
		t.Fatalf("qualified binding: kind=%v name=%q err=%v", kind, name, err)
	}

	kind, name, err = parseProviderName("plugin/store")
	if err != nil || kind.typeName != "plugin" || name != "store" {
		t.Fatalf("qualified plugin: kind=%v name=%q err=%v", kind, name, err)
	}

	if _, _, err = parseProviderName("bogus/x"); err == nil ||
		!strings.Contains(err.Error(), "unknown provider type") {
		t.Fatalf("expected unknown type error, got %v", err)
	}

	if _, _, err = parseProviderName("plugin/"); err == nil ||
		!strings.Contains(err.Error(), "invalid provider name") {
		t.Fatalf("expected invalid name error, got %v", err)
	}

	if _, _, err = parseProviderName("plugin/a/b"); err == nil ||
		!strings.Contains(err.Error(), "invalid provider name") {
		t.Fatalf("expected invalid nested name error, got %v", err)
	}
}

// Preinstalled plugin providers: a pre-placed openrun-plugin-<name> binary in
// plugin_providers.preinstalled_dir is described, checksum-pinned and its
// modules registered, mirroring the binding OCI init-container path.
func TestRegisterPreinstalledPluginProviders(t *testing.T) {
	dir := t.TempDir()
	execPath := filepath.Join(dir, "openrun-plugin-store")
	cmd := exec.Command("go", "build", "-o", execPath, "./internal/app/store/storeprovider")
	cmd.Dir = "../.."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("error building store provider: %v\n%s", err, out)
	}
	// Decoy entries must be skipped
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a provider"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		Logger: nopLogger(),
		staticConfig: &types.ServerConfig{
			PluginProviders: types.PluginProvidersConfig{PreinstalledDir: dir},
		},
	}
	t.Cleanup(func() { app.UnregisterExternalProvider("preinstalled:store") })
	s.registerPreinstalledProviders(context.Background())

	gotPath, modules, ok := app.GetExternalProviderInfo("preinstalled:store")
	if !ok {
		t.Fatal("preinstalled plugin provider not registered")
	}
	if gotPath != execPath {
		t.Errorf("exec path = %q, want %q", gotPath, execPath)
	}
	if len(modules) != 2 || modules[0] != "store.ex" || modules[1] != "store.in" {
		t.Errorf("modules = %v, want [store.ex store.in]", modules)
	}
}
