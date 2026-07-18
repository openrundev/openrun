// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"runtime"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

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
