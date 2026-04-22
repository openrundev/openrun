// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"path/filepath"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func newVolumeTestHandler(t *testing.T) (*ContainerHandler, string) {
	t.Helper()

	home := t.TempDir()
	t.Setenv(types.OPENRUN_HOME, home)

	appID := types.AppId("app_prd_volume_test")
	return &ContainerHandler{
		app: &App{
			AppEntry: &types.AppEntry{
				Id:        appID,
				SourceUrl: filepath.Join(home, "source"),
			},
			AppRunPath: filepath.Join(home, "run", "app", string(appID)),
		},
		serverConfig: &types.ServerConfig{
			Security: types.SecurityConfig{
				AllowedMounts: []string{"$OPENRUN_HOME/mounts"},
			},
		},
	}, home
}

func TestParseVolumeStringAllowsAllowedMountSource(t *testing.T) {
	h, home := newVolumeTestHandler(t)
	source := filepath.Join(home, "mounts", "config.yaml")

	vol, err := h.parseVolumeString("$OPENRUN_HOME/mounts/config.yaml:/etc/config.yaml:ro")
	if err != nil {
		t.Fatalf("parseVolumeString returned error: %v", err)
	}
	if vol.VolumeName != "" {
		t.Fatalf("VolumeName = %q, want bind mount", vol.VolumeName)
	}
	if vol.SourcePath != source {
		t.Fatalf("SourcePath = %q, want %q", vol.SourcePath, source)
	}
	if vol.TargetPath != "/etc/config.yaml" {
		t.Fatalf("TargetPath = %q, want /etc/config.yaml", vol.TargetPath)
	}
	if !vol.ReadOnly {
		t.Fatal("ReadOnly = false, want true")
	}
}

func TestParseVolumeStringRejectsBindSourceOutsideAllowedMounts(t *testing.T) {
	h, home := newVolumeTestHandler(t)
	source := filepath.Join(home, "outside", "config.yaml")

	if _, err := h.parseVolumeString(source + ":/etc/config.yaml"); err == nil {
		t.Fatal("parseVolumeString should reject bind sources outside allowed mount roots")
	}
}

func TestParseVolumeStringRejectsRelativeBindTraversal(t *testing.T) {
	h, _ := newVolumeTestHandler(t)

	if _, err := h.parseVolumeString("../config.yaml:/etc/config.yaml"); err == nil {
		t.Fatal("parseVolumeString should reject relative bind sources with parent traversal")
	}
}

func TestParseVolumeStringAllowsSourceRelativeBind(t *testing.T) {
	h, _ := newVolumeTestHandler(t)

	vol, err := h.parseVolumeString("./config.yaml:/etc/config.yaml")
	if err != nil {
		t.Fatalf("parseVolumeString returned error: %v", err)
	}
	want := "." + string(filepath.Separator) + "config.yaml"
	if vol.SourcePath != want {
		t.Fatalf("SourcePath = %q, want %q", vol.SourcePath, want)
	}
}

func TestParseVolumeStringRejectsSecretSourceOutsideAllowedMounts(t *testing.T) {
	h, home := newVolumeTestHandler(t)
	source := filepath.Join(home, "outside", "secret.tmpl")

	if _, err := h.parseVolumeString(VOL_PREFIX_SECRET + source + ":/etc/secret"); err == nil {
		t.Fatal("parseVolumeString should reject absolute secret sources outside allowed mount roots")
	}
}

func TestParseVolumeStringLeavesNamedVolumesUnchanged(t *testing.T) {
	h, _ := newVolumeTestHandler(t)

	vol, err := h.parseVolumeString("cache:/var/cache")
	if err != nil {
		t.Fatalf("parseVolumeString returned error: %v", err)
	}
	if vol.VolumeName != "cache" {
		t.Fatalf("VolumeName = %q, want cache", vol.VolumeName)
	}
}
