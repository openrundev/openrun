// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

// TestApiRegistryRoutes checks the registry's routing invariants: every
// entry is either fully routed (method + path + handler) or a purely
// logical operation, no two routes collide, and building the router from
// the registry does not panic (chi rejects duplicate method+path)
func TestApiRegistryRoutes(t *testing.T) {
	logicalOps := map[API_NAME]bool{
		// resolved inside handlers after request validation
		API_SECRET_REVEAL:       true,
		API_CREATE_APIKEY_OTHER: true,
		API_DELETE_APIKEY_OTHER: true,
	}

	seen := map[string]API_NAME{}
	for name, entry := range apiRegistry {
		if logicalOps[name] {
			if entry.Path != "" || entry.ApiFunc != nil {
				t.Fatalf("logical op %s must not carry a route", name)
			}
			continue
		}
		if entry.Path == "" || entry.Method == "" || entry.ApiFunc == nil {
			t.Fatalf("op %s is missing route fields (method=%q path=%q apiFunc=%v)",
				name, entry.Method, entry.Path, entry.ApiFunc != nil)
		}
		key := entry.Method + " " + entry.Path
		if other, dup := seen[key]; dup {
			t.Fatalf("ops %s and %s share route %s", name, other, key)
		}
		seen[key] = name
	}

	// Building the router registers every routed entry; chi panics on any
	// duplicate pattern this map check might have missed
	handler := &Handler{Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}), server: &Server{}}
	if router := handler.serveInternal(false); router == nil {
		t.Fatal("serveInternal returned nil")
	}
}
