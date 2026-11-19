// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func approverConfig(targets ...string) *types.RBACConfig {
	return &types.RBACConfig{
		Roles: map[string][]types.RBACPermission{
			"approver": {types.PermissionApprove, types.PermissionRead, "service:read", "binding:read"},
		},
		Grants: []types.RBACGrant{{Users: []string{"user1"}, Roles: []string{"approver"}, Targets: targets}},
	}
}

// An empty grant target must not act as "all": it is rejected by the strict
// update validation and, when already stored, loads as an entry matching nothing
func TestEmptyGrantTargetMatchesNothing(t *testing.T) {
	if err := ValidateGlob(""); err == nil {
		t.Fatal("empty target must be rejected by ValidateGlob")
	}
	config := approverConfig("")
	if err := ValidateGrantTargets(config); err == nil {
		t.Fatal("empty target must be rejected by ValidateGrantTargets")
	}

	// a stored config with an empty target still loads
	manager := newTestManager(t, config)
	ctx := enforcedCtx("user1")
	if ok, err := manager.AuthorizeAPI(ctx, types.PermissionRead, testTarget(), ""); err != nil || ok {
		t.Errorf("empty target must not match an app, got %v err %v", ok, err)
	}
	if ok, err := manager.AuthorizeResourceAPI(ctx, "service:read", "postgres/main", ""); err != nil || ok {
		t.Errorf("empty target must not match a service, got %v err %v", ok, err)
	}
	if ok, err := manager.AuthorizeResourceAPI(ctx, "binding:read", "/apps/db", ""); err != nil || ok {
		t.Errorf("empty target must not match a binding, got %v err %v", ok, err)
	}
	if ok, err := manager.AuthorizeAllTargetsAPI(ctx, types.PermissionApprove); err != nil || ok {
		t.Errorf("empty target must not be an all target, got %v err %v", ok, err)
	}
	perms, err := manager.GetAPIPermissions(ctx, types.AppPathDomain{}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, perm := range perms {
		if perm == string(types.PermissionRead) || perm == "service:read" {
			t.Errorf("empty target must not report scoped permission %s", perm)
		}
	}

	// a valid entry next to the empty one keeps working
	manager = newTestManager(t, approverConfig("", "/test/**"))
	if ok, err := manager.AuthorizeAPI(ctx, types.PermissionRead, types.AppPathDomain{Path: "/test/app"}, ""); err != nil || !ok {
		t.Errorf("valid target next to an empty one must match, got %v err %v", ok, err)
	}
}

// Holding a permission on all targets needs an all target entry: globs that
// match the empty app path without covering every domain do not qualify
func TestAuthorizeAllTargets(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{"all", true},
		{"ALL", true},
		{"*:**", true},
		{"**", false},
		{"/**", false},
		{"{,/dev/**}", false},
		{"*:/**", false},
		{"/dev/**", false},
		{"service:**", false},
	}
	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			manager := newTestManager(t, approverConfig(tc.target))
			ctx := enforcedCtx("user1")
			got, err := manager.AuthorizeAllTargetsAPI(ctx, types.PermissionApprove)
			if err != nil || got != tc.want {
				t.Errorf("live: got %v err %v, want %v", got, err, tc.want)
			}
			snap, err := manager.SnapshotUserGrants(ctx)
			if err != nil {
				t.Fatal(err)
			}
			got, err = manager.AuthorizeAllTargetsAPI(WithSyncAuthorizer(trustedCtx(), NewSyncAuthorizer(snap)), types.PermissionApprove)
			if err != nil || got != tc.want {
				t.Errorf("snapshot: got %v err %v, want %v", got, err, tc.want)
			}
		})
	}

	manager := newTestManager(t, approverConfig("all"))
	// another user, and a permission the role does not confer
	if ok, err := manager.AuthorizeAllTargetsAPI(enforcedCtx("user2"), types.PermissionApprove); err != nil || ok {
		t.Errorf("unrelated user: got %v err %v", ok, err)
	}
	if ok, err := manager.AuthorizeAllTargetsAPI(enforcedCtx("user1"), types.PermissionDelete); err != nil || ok {
		t.Errorf("permission not in role: got %v err %v", ok, err)
	}
	if ok, err := manager.AuthorizeAllTargetsAPI(enforcedCtx(""), types.PermissionApprove); err != nil || ok {
		t.Errorf("empty user: got %v err %v", ok, err)
	}
	// admin and trusted callers pass
	if ok, err := manager.AuthorizeAllTargetsAPI(enforcedCtx(types.ADMIN_USER), types.PermissionApprove); err != nil || !ok {
		t.Errorf("admin: got %v err %v", ok, err)
	}
	if ok, err := manager.AuthorizeAllTargetsAPI(trustedCtx(), types.PermissionApprove); err != nil || !ok {
		t.Errorf("trusted: got %v err %v", ok, err)
	}
}
