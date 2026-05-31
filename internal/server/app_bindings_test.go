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

func TestLoadApplyInfoParsesAppBindings(t *testing.T) {
	server := &Server{config: &types.ServerConfig{}}

	apps, bindings, err := server.loadApplyInfo("test.ace", []byte(`app("/p1", "-", bindings=["postgres", "/existing"])`), "", false)
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
}
