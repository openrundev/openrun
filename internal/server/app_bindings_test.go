// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func TestAutoBindingPathForApp(t *testing.T) {
	tests := []struct {
		name string
		id   types.AppId
		want string
	}{
		{name: "prod app", id: "app_prd_123", want: "/auto/app_prd_123/postgres"},
		{name: "dev app", id: "app_dev_456", want: "/auto/app_dev_456/postgres"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := autoBindingPathForAppID(tc.id, "postgres"); got != tc.want {
				t.Fatalf("autoBindingPathForApp = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAutoBindingAppIDUsesMainAppID(t *testing.T) {
	appEntry := &types.AppEntry{
		Path:    "/p1" + types.STAGE_SUFFIX,
		Domain:  "example.com",
		MainApp: "app_prd_123",
	}

	got := autoBindingAppID(appEntry)
	if got != "app_prd_123" {
		t.Fatalf("autoBindingAppID = %q, want app_prd_123", got)
	}
}

func TestAutoBindingAppIDUsesDevAppID(t *testing.T) {
	appEntry := &types.AppEntry{
		Id:      "app_dev_456",
		Path:    "/p1",
		Domain:  "example.com",
		MainApp: "app_prd_123",
		IsDev:   true,
	}

	got := autoBindingAppID(appEntry)
	if got != "app_dev_456" {
		t.Fatalf("autoBindingAppID = %q, want app_dev_456", got)
	}
}

func TestUseStagedBindingMetadata(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		useStaging bool
		want       bool
	}{
		{name: "explicit staging", path: "/apps/b1", useStaging: true, want: true},
		{name: "dev auto binding", path: "/auto/app_dev_456/postgres", want: true},
		{name: "prod auto binding", path: "/auto/app_prd_123/postgres", want: false},
		{name: "regular binding", path: "/apps/b1", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			binding := &types.Binding{Path: tc.path}
			if got := useStagedBindingMetadata(binding, tc.useStaging); got != tc.want {
				t.Fatalf("useStagedBindingMetadata = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestLoadApplyInfoParsesAppBindingsAndBindingPerms(t *testing.T) {
	server := &Server{config: &types.ServerConfig{}}

	apps, bindings, err := server.loadApplyInfo("test.ace", []byte(`app("/p1", "-", bindings=["postgres", "/existing"], bind_perm=["postgres/private"])`), "", false)
	if err != nil {
		t.Fatalf("loadApplyInfo returned error: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("binding defs length = %d, want 0", len(bindings))
	}
	if len(apps) != 1 {
		t.Fatalf("app defs length = %d, want 1", len(apps))
	}
	if got := apps[0].Bindings; len(got) != 2 || got[0] != "postgres" || got[1] != "/existing" {
		t.Fatalf("app bindings = %#v, want [postgres /existing]", got)
	}
	if got := apps[0].BindingSourcePerms; len(got) != 1 || got[0] != "postgres/private" {
		t.Fatalf("app binding source perms = %#v, want [postgres/private]", got)
	}
}
