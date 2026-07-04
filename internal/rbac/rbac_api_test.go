// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func newTestManager(t *testing.T, config *types.RBACConfig) *RBACManager {
	t.Helper()
	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
	}
	manager, err := NewRBACHandler(logger, config, serverConfig)
	if err != nil {
		t.Fatalf("failed to create RBACManager: %v", err)
	}
	return manager
}

func enforcedCtx(user string, groups ...string) context.Context {
	ctx := context.WithValue(context.Background(), types.RBAC_ENABLED, true)
	ctx = context.WithValue(ctx, types.USER_ID, user)
	ctx = context.WithValue(ctx, types.GROUPS, groups)
	return ctx
}

func testTarget() types.AppPathDomain {
	return types.AppPathDomain{Path: "/test", Domain: ""}
}

func grantConfig(roles map[string][]types.RBACPermission, grants ...types.RBACGrant) *types.RBACConfig {
	return &types.RBACConfig{
		Enabled: true,
		Groups:  map[string][]string{},
		Roles:   roles,
		Grants:  grants,
	}
}

func TestAuthorizeAPIGating(t *testing.T) {
	t.Parallel()

	// No grants at all: everything is denied when enforced
	manager := newTestManager(t, grantConfig(map[string][]types.RBACPermission{}))

	tests := []struct {
		name    string
		ctx     context.Context
		allowed bool
	}{
		{"no app context - not enforced", context.Background(), true},
		{"rbac_enabled false in context", context.WithValue(context.Background(), types.RBAC_ENABLED, false), true},
		{"enforced - user with no grants denied", enforcedCtx("user1"), false},
		{"enforced - admin always allowed", enforcedCtx(types.ADMIN_USER), true},
		{"enforced - empty user treated as admin", enforcedCtx(""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			allowed, err := manager.AuthorizeAPI(tt.ctx, types.PermissionDelete, testTarget(), "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tt.allowed {
				t.Errorf("expected %v, got %v", tt.allowed, allowed)
			}
		})
	}
}

func TestPermissionImplications(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"editor": {types.PermissionUpdate},
		},
		types.RBACGrant{Description: "editor grant", Users: []string{"user1"},
			Roles: []string{"editor"}, Targets: []string{"/test"}},
	))

	tests := []struct {
		perm    types.RBACPermission
		allowed bool
	}{
		{types.PermissionUpdate, true},
		{types.PermissionReload, true}, // implied by app:update
		{types.PermissionApply, true},  // implied by app:update
		{types.PermissionRead, true},   // implied by app:update
		{types.PermissionDelete, false},
		{types.PermissionApprove, false},
		{types.PermissionAccess, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.perm), func(t *testing.T) {
			t.Parallel()
			allowed, err := manager.AuthorizeAPI(enforcedCtx("user1"), tt.perm, testTarget(), "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tt.allowed {
				t.Errorf("perm %s: expected %v, got %v", tt.perm, tt.allowed, allowed)
			}
		})
	}
}

func TestAppAdminPermission(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"app_owner": {types.PermissionAppAdmin},
		},
		types.RBACGrant{Description: "app admin grant", Users: []string{"user1"},
			Roles: []string{"app_owner"}, Targets: []string{"/test"}},
	))

	for _, perm := range appPermissions {
		t.Run(string(perm), func(t *testing.T) {
			t.Parallel()
			allowed, err := manager.AuthorizeAPI(enforcedCtx("user1"), perm, testTarget(), "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// app:admin grants everything app scoped except app:approve
			expected := perm != types.PermissionApprove
			if allowed != expected {
				t.Errorf("perm %s: expected %v, got %v", perm, expected, allowed)
			}
		})
	}
}

func TestPermissionGlobsNeverMatchApprove(t *testing.T) {
	t.Parallel()

	for _, glob := range []string{"app:*", "**", "*:*"} {
		t.Run(glob, func(t *testing.T) {
			t.Parallel()
			manager := newTestManager(t, grantConfig(
				map[string][]types.RBACPermission{
					"globrole": {types.RBACPermission(glob)},
				},
				types.RBACGrant{Description: "glob grant", Users: []string{"user1"},
					Roles: []string{"globrole"}, Targets: []string{"/test"}},
			))

			allowed, err := manager.AuthorizeAPI(enforcedCtx("user1"), types.PermissionDelete, testTarget(), "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !allowed {
				t.Errorf("glob %s should match app:delete", glob)
			}

			allowed, err = manager.AuthorizeAPI(enforcedCtx("user1"), types.PermissionApprove, testTarget(), "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed {
				t.Errorf("glob %s must not match app:approve", glob)
			}
		})
	}
}

func TestBuiltinAdminRole(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{},
		types.RBACGrant{Description: "full admin", Users: []string{"user1"},
			Roles: []string{AdminRoleName}, Targets: []string{"all"}},
		types.RBACGrant{Description: "subtree admin", Users: []string{"user2"},
			Roles: []string{AdminRoleName}, Targets: []string{"/test/*"}},
	))

	// user1 has admin on all: gets app:approve and global permissions
	allowed, err := manager.AuthorizeAPI(enforcedCtx("user1"), types.PermissionApprove, testTarget(), "")
	if err != nil || !allowed {
		t.Errorf("admin role should grant app:approve, got %v err %v", allowed, err)
	}
	allowed, err = manager.AuthorizeGlobalAPI(enforcedCtx("user1"), types.PermissionSyncCreate, "")
	if err != nil || !allowed {
		t.Errorf("admin role with all target should grant sync:create, got %v err %v", allowed, err)
	}

	// user2 has admin scoped to /test/*: app perms there, no global perms
	allowed, err = manager.AuthorizeAPI(enforcedCtx("user2"), types.PermissionDelete,
		types.AppPathDomain{Path: "/test/app1"}, "")
	if err != nil || !allowed {
		t.Errorf("subtree admin should grant app:delete on /test/app1, got %v err %v", allowed, err)
	}
	allowed, err = manager.AuthorizeAPI(enforcedCtx("user2"), types.PermissionDelete,
		types.AppPathDomain{Path: "/other"}, "")
	if err != nil || allowed {
		t.Errorf("subtree admin must not grant app:delete on /other, got %v err %v", allowed, err)
	}
	allowed, err = manager.AuthorizeGlobalAPI(enforcedCtx("user2"), types.PermissionSyncCreate, "")
	if err != nil || allowed {
		t.Errorf("subtree admin must not grant global sync:create, got %v err %v", allowed, err)
	}
}

func TestAdminRoleReserved(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}
	_, err := NewRBACHandler(logger, grantConfig(map[string][]types.RBACPermission{
		"admin": {types.PermissionRead},
	}), serverConfig)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("expected reserved role error, got %v", err)
	}
}

func TestLegacyPermissionAliases(t *testing.T) {
	t.Parallel()

	// The old public permission names keep working as aliases: list is
	// normalized to app:read and access to app:access
	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"legacy": {"list", "access"},
		},
		types.RBACGrant{Description: "legacy grant", Users: []string{"user1"},
			Roles: []string{"legacy"}, Targets: []string{"/test"}},
	))

	for _, perm := range []types.RBACPermission{types.PermissionRead, types.PermissionAccess} {
		allowed, err := manager.AuthorizeAPI(enforcedCtx("user1"), perm, testTarget(), "")
		if err != nil || !allowed {
			t.Errorf("legacy alias should grant %s, got %v err %v", perm, allowed, err)
		}
	}
	allowed, err := manager.AuthorizeAPI(enforcedCtx("user1"), types.PermissionDelete, testTarget(), "")
	if err != nil || allowed {
		t.Errorf("legacy alias must not grant app:delete, got %v err %v", allowed, err)
	}

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}

	// Unknown permission names are rejected
	_, err = NewRBACHandler(logger, grantConfig(map[string][]types.RBACPermission{
		"viewer": {"app:relaod"},
	}), serverConfig)
	if err == nil || !strings.Contains(err.Error(), "unknown permission") {
		t.Errorf("expected unknown permission error, got %v", err)
	}

	// A disabled config is not validated, so server startup is never blocked
	disabled := grantConfig(map[string][]types.RBACPermission{
		"viewer": {"badperm"},
	})
	disabled.Enabled = false
	if _, err := NewRBACHandler(logger, disabled, serverConfig); err != nil {
		t.Errorf("disabled config must not be validated, got %v", err)
	}
}

func TestGlobalPermissionTargets(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"syncer": {types.PermissionSyncCreate},
		},
		types.RBACGrant{Description: "global sync", Users: []string{"user1"},
			Roles: []string{"syncer"}, Targets: []string{"all"}},
		types.RBACGrant{Description: "narrow sync", Users: []string{"user2"},
			Roles: []string{"syncer"}, Targets: []string{"/test"}},
	))

	allowed, err := manager.AuthorizeGlobalAPI(enforcedCtx("user1"), types.PermissionSyncCreate, "")
	if err != nil || !allowed {
		t.Errorf("sync:create with all target should be allowed, got %v err %v", allowed, err)
	}

	// Global permission granted with a narrow target never applies
	allowed, err = manager.AuthorizeGlobalAPI(enforcedCtx("user2"), types.PermissionSyncCreate, "")
	if err != nil || allowed {
		t.Errorf("sync:create with narrow target must be denied, got %v err %v", allowed, err)
	}
}

func TestOwnerPermissions(t *testing.T) {
	t.Parallel()

	// No grants: user1 has permissions only through ownership
	manager := newTestManager(t, grantConfig(map[string][]types.RBACPermission{}))

	ctx := enforcedCtx("user1")

	// Owner gets app:admin equivalent on their own app
	for _, perm := range []types.RBACPermission{types.PermissionRead, types.PermissionUpdate,
		types.PermissionDelete, types.PermissionReload, types.PermissionAccess, types.PermissionTokenManage} {
		allowed, err := manager.AuthorizeAPI(ctx, perm, testTarget(), "user1")
		if err != nil || !allowed {
			t.Errorf("owner should hold %s, got %v err %v", perm, allowed, err)
		}
	}

	// app:approve is never part of the owner permissions
	allowed, err := manager.AuthorizeAPI(ctx, types.PermissionApprove, testTarget(), "user1")
	if err != nil || allowed {
		t.Errorf("owner must not hold app:approve, got %v err %v", allowed, err)
	}

	// Non-owner gets nothing
	allowed, err = manager.AuthorizeAPI(ctx, types.PermissionRead, testTarget(), "user2")
	if err != nil || allowed {
		t.Errorf("non-owner must be denied, got %v err %v", allowed, err)
	}

	// Sync entry owner can run/delete/read their entry, not others
	allowed, err = manager.AuthorizeGlobalAPI(ctx, types.PermissionSyncRun, "user1")
	if err != nil || !allowed {
		t.Errorf("sync owner should hold sync:run, got %v err %v", allowed, err)
	}
	allowed, err = manager.AuthorizeGlobalAPI(ctx, types.PermissionSyncCreate, "user1")
	if err != nil || allowed {
		t.Errorf("sync owner must not hold sync:create, got %v err %v", allowed, err)
	}
	allowed, err = manager.AuthorizeGlobalAPI(ctx, types.PermissionSyncRun, "user2")
	if err != nil || allowed {
		t.Errorf("non-owner must not hold sync:run, got %v err %v", allowed, err)
	}
}

func TestOwnerPermissionsConfigured(t *testing.T) {
	t.Parallel()

	// Narrow app owner permissions to read only
	config := grantConfig(map[string][]types.RBACPermission{})
	config.OwnerPermissions = map[string][]types.RBACPermission{
		"app": {types.PermissionRead},
	}
	manager := newTestManager(t, config)

	ctx := enforcedCtx("user1")
	allowed, err := manager.AuthorizeAPI(ctx, types.PermissionRead, testTarget(), "user1")
	if err != nil || !allowed {
		t.Errorf("owner should hold app:read, got %v err %v", allowed, err)
	}
	allowed, err = manager.AuthorizeAPI(ctx, types.PermissionDelete, testTarget(), "user1")
	if err != nil || allowed {
		t.Errorf("narrowed owner must not hold app:delete, got %v err %v", allowed, err)
	}

	// Empty list disables the owner rule for the resource
	config = grantConfig(map[string][]types.RBACPermission{})
	config.OwnerPermissions = map[string][]types.RBACPermission{
		"app": {},
	}
	manager = newTestManager(t, config)
	allowed, err = manager.AuthorizeAPI(ctx, types.PermissionRead, testTarget(), "user1")
	if err != nil || allowed {
		t.Errorf("disabled owner rule must deny, got %v err %v", allowed, err)
	}
}

func TestOwnerPermissionsValidation(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}

	tests := []struct {
		name   string
		perms  map[string][]types.RBACPermission
		errMsg string
	}{
		{"approve rejected", map[string][]types.RBACPermission{
			"app": {types.PermissionApprove}}, "cannot be granted to owners"},
		{"unknown resource", map[string][]types.RBACPermission{
			"widget": {types.PermissionRead}}, "unknown resource"},
		{"wrong resource perm", map[string][]types.RBACPermission{
			"sync": {types.PermissionRead}}, "does not belong to resource"},
		{"glob rejected", map[string][]types.RBACPermission{
			"app": {"app:*"}}, "glob patterns are not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			config := grantConfig(map[string][]types.RBACPermission{})
			config.OwnerPermissions = tt.perms
			_, err := NewRBACHandler(logger, config, serverConfig)
			if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got %v", tt.errMsg, err)
			}
		})
	}
}

func TestGetAPIPermissions(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"deployer": {types.PermissionRead, types.PermissionReload},
		},
		types.RBACGrant{Description: "deployer grant", Users: []string{"user1"},
			Roles: []string{"deployer"}, Targets: []string{"/test"}},
	))

	// Enforcement not active: all permissions
	perms, err := manager.GetAPIPermissions(context.Background(), testTarget(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(perms) != len(allPermissionNames) {
		t.Errorf("expected all permissions when not enforced, got %v", perms)
	}

	// Granted permissions on the target
	perms, err = manager.GetAPIPermissions(enforcedCtx("user1"), testTarget(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	slices.Sort(perms)
	expected := []string{"app:read", "app:reload"}
	if !slices.Equal(perms, expected) {
		t.Errorf("expected %v, got %v", expected, perms)
	}

	// Owner holds the app:admin expansion (everything app scoped except approve/admin)
	perms, err = manager.GetAPIPermissions(enforcedCtx("user2"), testTarget(), "user2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if slices.Contains(perms, string(types.PermissionApprove)) {
		t.Errorf("owner permissions must not include app:approve, got %v", perms)
	}
	if !slices.Contains(perms, string(types.PermissionDelete)) || !slices.Contains(perms, string(types.PermissionAccess)) {
		t.Errorf("owner permissions should include app:delete and app:access, got %v", perms)
	}
}

func TestCustomPermissionGlobs(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"actions":  {"custom:action_*"},
			"appperms": {"app:*"},
		},
		types.RBACGrant{Description: "custom glob", Users: []string{"user1"},
			Roles: []string{"actions"}, Targets: []string{"/test"}},
		types.RBACGrant{Description: "app glob", Users: []string{"user2"},
			Roles: []string{"appperms"}, Targets: []string{"/test"}},
	))

	// custom: glob matches custom (app level) permissions
	allowed, err := manager.AuthorizeInt("user1", testTarget(), "rbac:test",
		"action_run", []string{}, true)
	if err != nil || !allowed {
		t.Errorf("custom glob should match action_run, got %v err %v", allowed, err)
	}

	// app:* glob does not leak into custom permissions
	allowed, err = manager.AuthorizeInt("user2", testTarget(), "rbac:test",
		"action_run", []string{}, true)
	if err != nil || allowed {
		t.Errorf("app:* must not match custom permissions, got %v err %v", allowed, err)
	}

	// custom: glob does not leak into app permissions
	allowed, err = manager.AuthorizeAPI(enforcedCtx("user1"), types.PermissionDelete, testTarget(), "")
	if err != nil || allowed {
		t.Errorf("custom glob must not match app:delete, got %v err %v", allowed, err)
	}
}
