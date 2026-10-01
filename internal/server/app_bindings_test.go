// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

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

func TestParseBindingSourceParams(t *testing.T) {
	t.Parallel()

	source, params, err := parseBindingSourceParams("sqlite")
	if err != nil || source != "sqlite" || params != nil {
		t.Fatalf("plain source = %q, %v, %v", source, params, err)
	}

	source, params, err = parseBindingSourceParams("postgres/main")
	if err != nil || source != "postgres/main" || params != nil {
		t.Fatalf("typed source = %q, %v, %v", source, params, err)
	}

	source, params, err = parseBindingSourceParams("sqlite;path=/mydata/test,example=val2")
	if err != nil {
		t.Fatalf("params parse: %v", err)
	}
	if source != "sqlite" {
		t.Fatalf("source = %q", source)
	}
	if params["path"] != "/mydata/test" || params["example"] != "val2" || len(params) != 2 {
		t.Fatalf("params = %v", params)
	}

	// key without value is an error
	if _, _, err := parseBindingSourceParams("sqlite;path"); err == nil {
		t.Fatal("param without value should be rejected")
	}
	if _, _, err := parseBindingSourceParams("sqlite;=val"); err == nil {
		t.Fatal("param without key should be rejected")
	}

	// A trailing semicolon with no params resolves to the bare source
	source, params, err = parseBindingSourceParams("sqlite;")
	if err != nil || source != "sqlite" || params != nil {
		t.Fatalf("empty params = %q, %v, %v", source, params, err)
	}
}

func TestEqualStringMaps(t *testing.T) {
	t.Parallel()

	if !equalStringMaps(nil, map[string]string{}) {
		t.Fatal("nil and empty should be equal")
	}
	if !equalStringMaps(map[string]string{"a": "1"}, map[string]string{"a": "1"}) {
		t.Fatal("equal maps")
	}
	if equalStringMaps(map[string]string{"a": "1"}, map[string]string{"a": "2"}) {
		t.Fatal("different values")
	}
	if equalStringMaps(map[string]string{"a": "1"}, map[string]string{"a": "1", "b": "2"}) {
		t.Fatal("different sizes")
	}
}
