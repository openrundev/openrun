// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

func TestOperationCategory(t *testing.T) {
	tests := map[string]string{
		// app ops, including the ones without "app" in the name
		"create_app":     "app_ops",
		"reload_apps":    "app_ops",
		"approve":        "app_ops",
		"promote":        "app_ops",
		"switch_version": "app_ops",
		// sync wins over the app fallback
		"create_sync": "sync_ops",
		"run_sync":    "sync_ops",
		// builder session/publish operations
		"create_session": "builder_ops",
		"publish_app":    "builder_ops",
		"delete_session": "builder_ops",
		// binding/service/secret operations
		"create_binding":  "binding_ops",
		"update_bindings": "binding_ops",
		"create_service":  "binding_ops",
		"delete_secret":   "binding_ops",
		// everything else
		"update_rbac_enabled": "other_ops",
		"http_get":            "other_ops",
	}
	for op, want := range tests {
		if got := operationCategory(op); got != want {
			t.Errorf("operationCategory(%q) = %q, want %q", op, got, want)
		}
	}
}
