// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

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

// TestRBACAppliesToAllApps verifies that when RBAC is enabled it applies to
// every app: authorization does not consider the app's auth setting at all
// (the rbac: prefix has no special effect). A user with no grant is denied,
// a granted user passes.
func TestRBACAppliesToAllApps(t *testing.T) {
	t.Parallel()

	config := &types.RBACConfig{
		Enabled: true,
		Roles:   map[string][]types.RBACPermission{"access": {types.PermissionAccess}},
		Grants: []types.RBACGrant{
			{Users: []string{"granted"}, Roles: []string{"access"}, Targets: []string{"all"}},
		},
	}
	manager := forceTestManager(t, config)

	allowed, err := manager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test"},
		types.PermissionAccess, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("ungranted user must be denied when RBAC is enabled")
	}

	allowed, err = manager.AuthorizeInt("granted", types.AppPathDomain{Path: "/test"},
		types.PermissionAccess, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("granted user must be authorized")
	}

	if !manager.IsAppRBACEnabled(context.Background()) {
		t.Fatal("IsAppRBACEnabled must be true when RBAC is enabled")
	}
}

// TestRBACDisabledAuthorizesAll verifies that a disabled config authorizes
// everything and reports IsAppRBACEnabled false
func TestRBACDisabledAuthorizesAll(t *testing.T) {
	t.Parallel()

	manager := forceTestManager(t, &types.RBACConfig{Enabled: false})
	allowed, err := manager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test"},
		types.PermissionAccess, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("disabled rbac must authorize")
	}
	if manager.IsAppRBACEnabled(context.Background()) {
		t.Fatal("disabled rbac IsAppRBACEnabled must be false")
	}
}
