// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
)

// nopLogger is a no-op logger for tests that exercise error paths.
func nopLogger() *types.Logger {
	logger := zerolog.Nop()
	return &types.Logger{Logger: &logger}
}

func TestProviderSourceURL(t *testing.T) {
	s := &Server{staticConfig: &types.ServerConfig{}}

	// Explicit source url wins
	url, err := s.providerSourceURL(&types.ProviderInstallRequest{Name: "redis", SourceURL: "/tmp/openrun-binding-redis"})
	if err != nil || url != "/tmp/openrun-binding-redis" {
		t.Fatalf("url = %q err = %v", url, err)
	}

	// Defaulted source requires a version
	if _, err := s.providerSourceURL(&types.ProviderInstallRequest{Name: "redis"}); err == nil ||
		!strings.Contains(err.Error(), "either source_url or version is required") {
		t.Fatalf("expected version-required error, got %v", err)
	}

	// Default template with {provider} substituted; {version}/{os}/{arch} kept
	// for per-fetch expansion
	url, err = s.providerSourceURL(&types.ProviderInstallRequest{Name: "redis", Version: "v0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	want := "https://github.com/openrundev/bindings/releases/download/redis%2F{version}/openrun-binding-redis-{os}-{arch}{ext}"
	if url != want {
		t.Fatalf("url = %q, want %q", url, want)
	}

	// Config template override
	s.staticConfig.Bindings.ReleaseURLTemplate = "https://mirror.internal/{provider}/{version}/{os}-{arch}"
	url, err = s.providerSourceURL(&types.ProviderInstallRequest{Name: "mongodb", Version: "v0.2.0"})
	if err != nil || url != "https://mirror.internal/mongodb/{version}/{os}-{arch}" {
		t.Fatalf("mirror url = %q err = %v", url, err)
	}
}

func TestExpandProviderSourceURL(t *testing.T) {
	got := expandProviderSourceURL("https://x/{version}/b-{os}-{arch}{ext}", "v0.1.0")
	// {ext} is ".exe" on Windows only; on other platforms it expands to empty
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	want := "https://x/v0.1.0/b-" + runtime.GOOS + "-" + runtime.GOARCH + ext
	if got != want {
		t.Fatalf("expanded = %q, want %q", got, want)
	}
}

func TestProviderModifyError(t *testing.T) {
	s := &Server{staticConfig: &types.ServerConfig{}}
	if err := s.providerModifyError("redis", "install"); err != nil {
		t.Fatalf("expected install allowed, got %v", err)
	}

	s.staticConfig.Bindings.Install = map[string]string{"redis": "v0.1.0"}
	if err := s.providerModifyError("redis", "install"); err == nil ||
		!strings.Contains(err.Error(), "[bindings.install]") {
		t.Fatalf("expected config-managed error, got %v", err)
	}
	if err := s.providerModifyError("mongodb", "install"); err != nil {
		t.Fatalf("expected non-config-managed provider allowed, got %v", err)
	}

	s.staticConfig.Bindings.DisableInstall = true
	if err := s.providerModifyError("mongodb", "uninstall"); err == nil ||
		!strings.Contains(err.Error(), "bindings.disable_install") {
		t.Fatalf("expected disable_install error, got %v", err)
	}
}

func TestRegisterPreinstalledProviders(t *testing.T) {
	// Build the fixture provider into a preinstalled dir under its
	// openrun-binding-<name> file name, alongside files that must be skipped.
	dir := t.TempDir()
	execPath := filepath.Join(dir, "openrun-binding-fixture")
	cmd := exec.Command("go", "build", "-o", execPath, ".")
	cmd.Dir = "../bindings/testdata/fixtureprovider"
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("error building fixture provider: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a provider"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openrun-binding-broken"), []byte("not executable"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		Logger:       nopLogger(),
		staticConfig: &types.ServerConfig{Bindings: types.BindingsConfig{PreinstalledDir: dir}},
	}
	t.Cleanup(func() {
		bindings.UnregisterProviderBindings("preinstalled:fixture")
		bindings.UnregisterProviderBindings("preinstalled:broken")
	})
	s.registerPreinstalledProviders(context.Background())

	if _, ok := bindings.GetServiceBinding("fixture"); !ok {
		t.Fatal("fixture service type not registered from preinstalled dir")
	}

	// The registration works end to end: launch the provider and make a call.
	builder, _ := bindings.GetServiceBinding("fixture")
	params, _, err := builder().GetAccountEnv(context.Background())
	if err != nil || len(params) != 1 || params[0] != "user" {
		t.Fatalf("GetAccountEnv through preinstalled provider: params=%v err=%v", params, err)
	}
}

func TestRegisterPreinstalledProvidersMissingDir(t *testing.T) {
	// A missing dir (or empty config) logs and returns without registering.
	s := &Server{
		Logger:       nopLogger(),
		staticConfig: &types.ServerConfig{Bindings: types.BindingsConfig{PreinstalledDir: "/nonexistent/providers"}},
	}
	s.registerPreinstalledProviders(context.Background())

	s.staticConfig.Bindings.PreinstalledDir = ""
	s.registerPreinstalledProviders(context.Background())
}

func TestParseProviderVersion(t *testing.T) {
	version, pins := parseProviderVersion("v0.1.0")
	if version != "v0.1.0" || pins != nil {
		t.Fatalf("plain: %q %v", version, pins)
	}
	version, pins = parseProviderVersion("v0.1.0@sha256:abc123")
	if version != "v0.1.0" || len(pins) != 1 || pins[0] != "abc123" {
		t.Fatalf("pinned: %q %v", version, pins)
	}
	// Multiple accepted digests (mixed-architecture deployments)
	version, pins = parseProviderVersion("v0.1.0@sha256:abc123, def456")
	if version != "v0.1.0" || len(pins) != 2 || pins[0] != "abc123" || pins[1] != "def456" {
		t.Fatalf("multi-pinned: %q %v", version, pins)
	}
	if !digestMatches(pins, "DEF456") { // case-insensitive membership
		t.Fatal("expected digest match")
	}
	if digestMatches(pins, "other") {
		t.Fatal("unexpected digest match")
	}
}
