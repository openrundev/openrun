// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

// TestDefaultConfig verifies the built-in default config is valid and gives
// every principal - the anonymous user included - app access and read on
// every app, and nothing else
func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	manager := newTestManager(t, DefaultConfig())

	app := types.AppPathDomain{Domain: "example.com", Path: "/any/app"}
	for _, user := range []string{"builtin:alice", "github:someone", types.ANONYMOUS_USER} {
		for _, perm := range []types.RBACPermission{types.PermissionAccess, types.PermissionRead} {
			allowed, err := manager.AuthorizeInt(user, app, perm, nil, false)
			if err != nil || !allowed {
				t.Fatalf("default grant must allow %s %s: allowed=%v err=%v", user, perm, allowed, err)
			}
		}
	}

	// No management authority comes from the default grant
	for _, perm := range []types.RBACPermission{types.PermissionCreate, types.PermissionDelete,
		types.PermissionConfigRead, types.PermissionSecretRead} {
		allowed, err := manager.AuthorizeInt("builtin:alice", app, perm, nil, false)
		if err != nil || allowed {
			t.Fatalf("default grant must not allow %s: allowed=%v err=%v", perm, allowed, err)
		}
	}
}

// TestWildcardUserGrant verifies the "*" users entry matches any principal
// while regular entries still match exactly
func TestWildcardUserGrant(t *testing.T) {
	t.Parallel()
	manager := newTestManager(t, &types.RBACConfig{
		Grants: []types.RBACGrant{{Description: "wildcard read", Users: []string{"*"},
			Roles: []string{"openrun-monitor"}, Targets: []string{"all"}}},
	})
	for _, user := range []string{"anyone", types.ANONYMOUS_USER, "provider:user"} {
		allowed, err := manager.AuthorizeInt(user, types.AppPathDomain{Path: "/x"}, types.PermissionRead, nil, false)
		if err != nil || !allowed {
			t.Fatalf("wildcard grant must match %s: allowed=%v err=%v", user, allowed, err)
		}
	}
	// Empty user still fails closed (context propagation bug guard)
	allowed, err := manager.AuthorizeInt("", types.AppPathDomain{Path: "/x"}, types.PermissionRead, nil, false)
	if err != nil || allowed {
		t.Fatalf("empty user must fail closed even with a wildcard grant: allowed=%v err=%v", allowed, err)
	}
}
