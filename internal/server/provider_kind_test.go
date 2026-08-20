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

func TestProviderKindDefaults(t *testing.T) {
	s := &Server{staticConfig: &types.ServerConfig{}}

	// Per-kind binary naming and cache dirs
	bindingPath := providerKinds["binding"].execPath(s, "mongodb")
	if !strings.Contains(bindingPath, "openrun-binding-mongodb") || !strings.Contains(bindingPath, "bindings") {
		t.Errorf("binding exec path = %q", bindingPath)
	}
	pluginPath := providerKinds["plugin"].execPath(s, "store")
	if !strings.Contains(pluginPath, "openrun-plugin-store") || !strings.Contains(pluginPath, "plugins") {
		t.Errorf("plugin exec path = %q", pluginPath)
	}

	// Per-kind release url defaults
	url, err := s.providerSourceURL(providerKinds["plugin"], &types.ProviderInstallRequest{Name: "pdftool", Version: "v0.1.0"})
	if err != nil || !strings.Contains(url, "openrun-plugin-pdftool") {
		t.Errorf("plugin release url = %q err = %v", url, err)
	}

	// Per-kind config template override
	s.staticConfig.PluginProviders.ReleaseURLTemplate = "https://mirror.internal/plugins/{provider}/{version}"
	url, err = s.providerSourceURL(providerKinds["plugin"], &types.ProviderInstallRequest{Name: "pdftool", Version: "v0.1.0"})
	if err != nil || url != "https://mirror.internal/plugins/pdftool/{version}" {
		t.Errorf("plugin mirror url = %q err = %v", url, err)
	}

	// Display names: bindings stay bare, other kinds are qualified
	if got := providerKinds["binding"].qualifiedName("mongodb"); got != "mongodb" {
		t.Errorf("binding qualified name = %q", got)
	}
	if got := providerKinds["plugin"].qualifiedName("store"); got != "plugin/store" {
		t.Errorf("plugin qualified name = %q", got)
	}
}

func TestProviderKindConfigChecks(t *testing.T) {
	s := &Server{staticConfig: &types.ServerConfig{}}
	plugin := providerKinds["plugin"]

	if err := s.providerModifyError(plugin, "store", "install"); err != nil {
		t.Fatalf("expected install allowed, got %v", err)
	}

	s.staticConfig.PluginProviders.Install = map[string]string{"store": "v0.1.0"}
	if err := s.providerModifyError(plugin, "store", "install"); err == nil ||
		!strings.Contains(err.Error(), "[plugin_providers.install]") {
		t.Fatalf("expected config-managed error, got %v", err)
	}

	s.staticConfig.PluginProviders.DisableInstall = true
	if err := s.providerModifyError(plugin, "other", "uninstall"); err == nil ||
		!strings.Contains(err.Error(), "plugin_providers.disable_install") {
		t.Fatalf("expected disable_install error, got %v", err)
	}

	// Kind configs are independent: binding installs stay allowed
	if err := s.providerModifyError(providerKinds["binding"], "mongodb", "install"); err != nil {
		t.Fatalf("expected binding install unaffected, got %v", err)
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
