// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func boolPtr(v bool) *bool { return &v }

func forceTestManager(t *testing.T, config *types.RBACConfig) *RBACManager {
	t.Helper()
	manager, err := NewRBACHandler(testutil.TestLogger(), config, &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
	})
	if err != nil {
		t.Fatalf("failed to create RBACManager: %v", err)
	}
	return manager
}

func appAuthCtx(auth string) context.Context {
	return context.WithValue(context.Background(), types.APP_AUTH, types.AppAuthnType(auth))
}

// TestForceRBACDefault verifies that with RBAC enabled and
// force_rbac_when_enabled unset (the default), every app is enforced as if
// its auth carried the rbac: prefix
func TestForceRBACDefault(t *testing.T) {
	t.Parallel()

	config := &types.RBACConfig{
		Enabled: true,
		Roles:   map[string][]types.RBACPermission{"access": {types.PermissionAccess}},
		Grants: []types.RBACGrant{
			{Users: []string{"granted"}, Roles: []string{"access"}, Targets: []string{"all"}},
		},
	}
	if !config.ForceRBAC() {
		t.Fatal("ForceRBAC must default to true when the field is unset")
	}
	manager := forceTestManager(t, config)

	// An app WITHOUT the rbac: prefix is enforced: no grant means no access
	allowed, err := manager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test"}, "none",
		types.PermissionAccess, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("force on: non-prefixed app auth must be enforced (user without grant denied)")
	}

	// A granted user passes
	allowed, err = manager.AuthorizeInt("granted", types.AppPathDomain{Path: "/test"}, "none",
		types.PermissionAccess, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("force on: granted user must be authorized on a non-prefixed app")
	}

	// The request-setup check treats non-prefixed auth as rbac enabled
	if !manager.IsAppRBACEnabled(appAuthCtx("none")) {
		t.Fatal("force on: IsAppRBACEnabled must be true for non-prefixed app auth")
	}
	if !manager.IsAppRBACEnabled(appAuthCtx("rbac:none")) {
		t.Fatal("force on: IsAppRBACEnabled must be true for prefixed app auth")
	}
}

// TestForceRBACOff verifies the legacy behavior when the flag is set to
// false: only apps whose auth carries the rbac: prefix are enforced
func TestForceRBACOff(t *testing.T) {
	t.Parallel()

	config := &types.RBACConfig{
		Enabled:              true,
		ForceRBACWhenEnabled: boolPtr(false),
	}
	manager := forceTestManager(t, config)

	// Non-prefixed app auth is not enforced: access allowed without grants
	allowed, err := manager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test"}, "none",
		types.PermissionAccess, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("force off: non-prefixed app auth must not be enforced")
	}

	// Prefixed app auth is enforced: no grant means no access
	allowed, err = manager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test"}, "rbac:none",
		types.PermissionAccess, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("force off: prefixed app auth must be enforced (user without grant denied)")
	}

	if manager.IsAppRBACEnabled(appAuthCtx("none")) {
		t.Fatal("force off: IsAppRBACEnabled must be false for non-prefixed app auth")
	}
	if !manager.IsAppRBACEnabled(appAuthCtx("rbac:none")) {
		t.Fatal("force off: IsAppRBACEnabled must be true for prefixed app auth")
	}
}

// TestForceRBACDisabledConfig verifies the flag has no effect while RBAC is
// disabled
func TestForceRBACDisabledConfig(t *testing.T) {
	t.Parallel()

	for _, force := range []*bool{nil, boolPtr(true), boolPtr(false)} {
		manager := forceTestManager(t, &types.RBACConfig{Enabled: false, ForceRBACWhenEnabled: force})
		allowed, err := manager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test"}, "none",
			types.PermissionAccess, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Fatal("disabled rbac must authorize regardless of the force flag")
		}
		if manager.IsAppRBACEnabled(appAuthCtx("none")) {
			t.Fatal("disabled rbac: IsAppRBACEnabled must be false")
		}
	}
}
