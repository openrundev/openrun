// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"path/filepath"
	"strings"
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

func newBindingEnvTestHandler(approvedSources []string, serverSources []string, bindingSource string) *ContainerHandler {
	return &ContainerHandler{
		app: &App{
			AppEntry: &types.AppEntry{
				Id:   types.AppId(types.ID_PREFIX_APP_PROD + "binding_env_test"),
				Path: "/binding-env",
				Metadata: types.AppMetadata{
					ApprovedBindingSourcePerms: approvedSources,
				},
			},
		},
		serverConfig: &types.ServerConfig{
			Permissions: types.PermissionsConfig{
				BindingSourcePerms: serverSources,
			},
		},
		bindings: []*types.Binding{
			{
				Source:           bindingSource,
				ServiceType:      "postgres",
				ServiceName:      "default",
				ServiceIsDefault: true,
				Metadata: types.BindingMetadata{
					Account: map[string]string{"url": "postgres://prod"},
				},
			},
		},
	}
}

func TestGetBindingEnvRejectsUnapprovedBindingSource(t *testing.T) {
	t.Parallel()

	h := newBindingEnvTestHandler(nil, nil, "postgres/private")

	_, err := h.getBindingEnv()
	if err == nil {
		t.Fatal("expected unapproved binding source error")
	}
	if !strings.Contains(err.Error(), "not approved to use binding source postgres/private") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestGetBindingEnvAllowsApprovedBindingSource(t *testing.T) {
	t.Parallel()

	h := newBindingEnvTestHandler([]string{"postgres/private"}, nil, "postgres/private")

	env, err := h.getBindingEnv()
	if err != nil {
		t.Fatalf("getBindingEnv: %v", err)
	}
	if env["POSTGRES_URL"] != "postgres://prod" {
		t.Fatalf("POSTGRES_URL = %q", env["POSTGRES_URL"])
	}
}

func TestGetBindingEnvAllowsServerBindingSource(t *testing.T) {
	t.Parallel()

	h := newBindingEnvTestHandler(nil, []string{"postgres/private"}, "postgres/private")

	if _, err := h.getBindingEnv(); err != nil {
		t.Fatalf("getBindingEnv: %v", err)
	}
}

func TestBindingSourceMatchesDefaultServiceShorthand(t *testing.T) {
	t.Parallel()

	binding := &types.Binding{
		Source:           "postgres",
		ServiceType:      "postgres",
		ServiceName:      "default",
		ServiceIsDefault: true,
	}
	if !bindingSourceMatches(binding, "postgres/default") {
		t.Fatal("expected default service approval to allow shorthand source")
	}

	binding.Source = "postgres/default"
	if !bindingSourceMatches(binding, "postgres") {
		t.Fatal("expected shorthand approval to allow default service source")
	}

	binding.ServiceName = "private"
	binding.ServiceIsDefault = false
	if bindingSourceMatches(binding, "postgres") {
		t.Fatal("did not expect shorthand approval to allow non-default service source")
	}

	binding.Source = "postgres/private"
	if bindingSourceMatches(binding, "postgres") {
		t.Fatal("did not expect shorthand approval to allow explicit non-default service source")
	}
}
