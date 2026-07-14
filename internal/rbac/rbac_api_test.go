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
			"app_owner": {types.PermissionAppManage},
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
			// app:manage grants every app-scoped permission
			if !allowed {
				t.Errorf("perm %s: app:manage should grant it, got %v", perm, allowed)
			}
		})
	}

	// approve is global and operator-only: app:manage never confers it
	allowed, err := manager.AuthorizeGlobalAPI(enforcedCtx("user1"), types.PermissionApprove, "")
	if err != nil || allowed {
		t.Errorf("app:manage must not grant the global approve permission, got %v err %v", allowed, err)
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
				// target "all" so the glob could confer global perms too - the
				// approve exclusion must hold even then
				types.RBACGrant{Description: "glob grant", Users: []string{"user1"},
					Roles: []string{"globrole"}, Targets: []string{"all"}},
			))

			allowed, err := manager.AuthorizeAPI(enforcedCtx("user1"), types.PermissionDelete, testTarget(), "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !allowed {
				t.Errorf("glob %s should match app:delete", glob)
			}

			// approve is global and never matched by a glob, even on target all
			allowed, err = manager.AuthorizeGlobalAPI(enforcedCtx("user1"), types.PermissionApprove, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed {
				t.Errorf("glob %s must not match approve", glob)
			}
		})
	}
}

// TestOpenrunAdminSuperUser verifies the openrun-admin role (which holds the
// admin permission) is a full super-user: it passes every check, including
// app permissions on any target and app-level custom permissions. It replaces
// the removed built-in "admin" role
func TestOpenrunAdminSuperUser(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{},
		types.RBACGrant{Description: "super", Users: []string{"user1"},
			Roles: []string{"openrun-admin"}, Targets: []string{"all"}},
	))

	// Every management permission passes, on any target and owner
	for _, perm := range []types.RBACPermission{types.PermissionApprove, types.PermissionServerStop,
		types.PermissionSyncCreate, types.PermissionSecretReveal} {
		allowed, err := manager.AuthorizeGlobalAPI(enforcedCtx("user1"), perm, "")
		if err != nil || !allowed {
			t.Errorf("openrun-admin should grant %s, got %v err %v", perm, allowed, err)
		}
	}
	allowed, err := manager.AuthorizeAPI(enforcedCtx("user1"), types.PermissionDelete,
		types.AppPathDomain{Path: "/anywhere"}, "someone-else")
	if err != nil || !allowed {
		t.Errorf("openrun-admin should grant app:delete on any app, got %v err %v", allowed, err)
	}
}

// TestPredefinedRoles grants each built-in openrun-* role (on target all) and
// checks representative allowed/denied permissions, including the app-scoped vs
// global split and openrun-builder composing openrun-developer
func TestPredefinedRoles(t *testing.T) {
	t.Parallel()

	roleNames := []string{"openrun-admin", "openrun-operator", "openrun-developer",
		"openrun-builder", "openrun-user", "openrun-monitor"}
	grants := make([]types.RBACGrant, 0, len(roleNames))
	for _, r := range roleNames {
		grants = append(grants, types.RBACGrant{
			Description: r, Users: []string{"u:" + r}, Roles: []string{r}, Targets: []string{"all"},
		})
	}
	manager := newTestManager(t, grantConfig(map[string][]types.RBACPermission{}, grants...))

	appPerm := func(role string, perm types.RBACPermission) bool {
		ok, err := manager.AuthorizeAPI(enforcedCtx("u:"+role), perm, testTarget(), "")
		if err != nil {
			t.Fatalf("app authorize %s/%s: %v", role, perm, err)
		}
		return ok
	}
	globalPerm := func(role string, perm types.RBACPermission) bool {
		ok, err := manager.AuthorizeGlobalAPI(enforcedCtx("u:"+role), perm, "")
		if err != nil {
			t.Fatalf("global authorize %s/%s: %v", role, perm, err)
		}
		return ok
	}

	type check struct {
		perm    types.RBACPermission
		global  bool
		allowed bool
	}
	cases := map[string][]check{
		"openrun-admin": {
			{types.PermissionAdmin, true, true},
			{types.PermissionApprove, true, true},
			{types.PermissionServerStop, true, true},
			{types.PermissionDelete, false, true},
		},
		"openrun-operator": {
			{types.PermissionDelete, false, true}, // app:manage
			{types.PermissionApprove, true, true}, // operator holds approve
			{types.PermissionSecretReveal, true, true},
			{types.PermissionConfigUpdate, true, true},
			{types.PermissionServerStop, true, true},
			{types.PermissionBuilderCreate, true, true},
			{types.PermissionAdmin, true, false}, // operator is not a super-user
		},
		"openrun-developer": {
			{types.PermissionCreate, false, true}, // app:manage
			{types.PermissionDelete, false, true},
			{types.PermissionSecretCreate, true, true},
			{types.PermissionSyncRun, true, true},
			{types.PermissionApprove, true, false}, // operator-only
			{types.PermissionConfigUpdate, true, false},
			{types.PermissionSecretReveal, true, false},
			{types.PermissionServerStop, true, false},
			{types.PermissionSyncCreate, true, false},
			{types.PermissionBuilderCreate, true, false}, // developer has no builder
		},
		"openrun-builder": {
			{types.PermissionCreate, false, true},       // inherits developer app:manage
			{types.PermissionBuilderCreate, true, true}, // plus builder
			{types.PermissionBuilderPublish, true, true},
			{types.PermissionSecretCreate, true, true}, // via developer
			{types.PermissionApprove, true, false},
			{types.PermissionConfigUpdate, true, false},
		},
		"openrun-user": {
			{types.PermissionAccess, false, true},
			{types.PermissionRead, false, true},
			{types.PermissionCreate, false, false},
			{types.PermissionDelete, false, false},
			{types.PermissionBuilderCreate, true, false},
		},
		"openrun-monitor": {
			{types.PermissionRead, false, true},
			{types.PermissionAuditRead, true, true},
			{types.PermissionContainerRead, true, true},
			{types.PermissionConfigRead, true, true},
			{types.PermissionSecretRead, true, true},
			{types.PermissionCreate, false, false},
			{types.PermissionConfigUpdate, true, false},
			{types.PermissionSecretReveal, true, false},
			{types.PermissionApprove, true, false},
			{types.PermissionContainerManage, true, false},
		},
	}

	for role, checks := range cases {
		for _, c := range checks {
			got := appPerm(role, c.perm)
			if c.global {
				got = globalPerm(role, c.perm)
			}
			if got != c.allowed {
				t.Errorf("%s: perm %s (global=%v) = %v, want %v", role, c.perm, c.global, got, c.allowed)
			}
		}
	}
}

// TestPredefinedRolesReserved verifies the built-in openrun-* role names cannot
// be redefined in the config
func TestPredefinedRolesReserved(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"openrun-admin", "openrun-operator", "openrun-developer",
		"openrun-builder", "openrun-user", "openrun-monitor"} {
		_, err := NewRBACHandler(testutil.TestLogger(), grantConfig(map[string][]types.RBACPermission{
			name: {types.PermissionRead},
		}), &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}})
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("defining reserved role %q should be rejected, got %v", name, err)
		}
	}
}

// TestUserRoleReferencesPredefined verifies a user-defined role can compose a
// predefined role via the role: prefix and add extra permissions
func TestUserRoleReferencesPredefined(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			// a team lead is a developer who can also approve
			"team-lead": {types.RBACPermission("role:openrun-developer"), types.PermissionApprove},
		},
		types.RBACGrant{Description: "lead", Users: []string{"u1"},
			Roles: []string{"team-lead"}, Targets: []string{"all"}},
	))

	if ok, _ := manager.AuthorizeAPI(enforcedCtx("u1"), types.PermissionCreate, testTarget(), ""); !ok {
		t.Error("team-lead should inherit developer app:create")
	}
	if ok, _ := manager.AuthorizeGlobalAPI(enforcedCtx("u1"), types.PermissionApprove, ""); !ok {
		t.Error("team-lead should hold the extra approve permission")
	}
	if ok, _ := manager.AuthorizeGlobalAPI(enforcedCtx("u1"), types.PermissionBuilderCreate, ""); ok {
		t.Error("team-lead should not have builder (developer has none)")
	}
}

func TestAdminPermission(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"superuser": {types.PermissionAdmin},
		},
		types.RBACGrant{Description: "granted admin", Users: []string{"user1"},
			Roles: []string{"superuser"}, Targets: []string{"all"}},
		types.RBACGrant{Description: "admin on app target", Users: []string{"user2"},
			Roles: []string{"superuser"}, Targets: []string{"/test"}},
	))

	// The admin permission passes every check: app perms on any target
	// (including approve) and all global permissions
	for _, perm := range []types.RBACPermission{types.PermissionDelete, types.PermissionApprove} {
		allowed, err := manager.AuthorizeAPI(enforcedCtx("user1"), perm,
			types.AppPathDomain{Path: "/anywhere"}, "someone-else")
		if err != nil || !allowed {
			t.Errorf("admin permission should grant %s, got %v err %v", perm, allowed, err)
		}
	}
	allowed, err := manager.AuthorizeGlobalAPI(enforcedCtx("user1"), types.PermissionAdmin, "")
	if err != nil || !allowed {
		t.Errorf("admin permission holder should pass the admin check, got %v err %v", allowed, err)
	}
	perms, err := manager.GetAPIPermissions(enforcedCtx("user1"), testTarget(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(perms) != len(allPermissionNames) || !slices.Contains(perms, string(types.PermissionAdmin)) {
		t.Errorf("admin permission holder should hold all permissions, got %v", perms)
	}

	// admin is a global permission: a grant scoped to an app target does not
	// confer it (and the superuser role carries nothing else)
	allowed, err = manager.AuthorizeGlobalAPI(enforcedCtx("user2"), types.PermissionAdmin, "")
	if err != nil || allowed {
		t.Errorf("app-targeted admin grant must not confer the admin permission, got %v err %v", allowed, err)
	}
	allowed, err = manager.AuthorizeAPI(enforcedCtx("user2"), types.PermissionDelete, testTarget(), "")
	if err != nil || allowed {
		t.Errorf("the admin permission implies nothing on non-global grants, got %v err %v", allowed, err)
	}

	// The admin user holds the admin permission implicitly, with no grants
	allowed, err = manager.AuthorizeGlobalAPI(enforcedCtx(types.ADMIN_USER), types.PermissionAdmin, "")
	if err != nil || !allowed {
		t.Errorf("admin user should hold the admin permission by default, got %v err %v", allowed, err)
	}
}

func TestPermissionGlobsNeverMatchAdmin(t *testing.T) {
	t.Parallel()

	for _, glob := range []string{"**", "ad*", "*"} {
		t.Run(glob, func(t *testing.T) {
			t.Parallel()
			manager := newTestManager(t, grantConfig(
				map[string][]types.RBACPermission{
					"globrole": {types.RBACPermission(glob)},
				},
				types.RBACGrant{Description: "glob grant", Users: []string{"user1"},
					Roles: []string{"globrole"}, Targets: []string{"all"}},
			))

			// The glob grants regular global permissions but never the admin
			// super-user permission (nor approve through it)
			if glob != "ad*" { // ad* is here only to probe an admin-prefix glob
				allowed, err := manager.AuthorizeGlobalAPI(enforcedCtx("user1"), types.PermissionSyncCreate, "")
				if err != nil || !allowed {
					t.Errorf("glob %s should match sync:create, got %v err %v", glob, allowed, err)
				}
			}
			allowed, err := manager.AuthorizeGlobalAPI(enforcedCtx("user1"), types.PermissionAdmin, "")
			if err != nil || allowed {
				t.Errorf("glob %s must not match the admin permission, got %v err %v", glob, allowed, err)
			}
			allowed, err = manager.AuthorizeAPI(enforcedCtx("user1"), types.PermissionApprove, testTarget(), "")
			if err != nil || allowed {
				t.Errorf("glob %s must not match approve, got %v err %v", glob, allowed, err)
			}
		})
	}
}

// TestReservedRolePrefix verifies the openrun- prefix is reserved for
// built-in roles, so no user-defined role name may use it (even a name that
// is not itself a predefined role). A plain "admin" role name is allowed now
// that the built-in admin role is gone
func TestReservedRolePrefix(t *testing.T) {
	t.Parallel()

	serverConfig := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}

	// a not-predefined openrun- name is still rejected by the prefix reservation
	_, err := NewRBACHandler(testutil.TestLogger(), grantConfig(map[string][]types.RBACPermission{
		"openrun-custom": {types.PermissionRead},
	}), serverConfig)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("openrun- prefixed role should be rejected, got %v", err)
	}

	// "admin" is no longer a reserved role name (the built-in admin role was removed)
	if _, err := NewRBACHandler(testutil.TestLogger(), grantConfig(map[string][]types.RBACPermission{
		"admin": {types.PermissionRead},
	}), serverConfig); err != nil {
		t.Errorf("a user role named admin should be allowed, got %v", err)
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

func TestContainerPermissions(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"viewer":   {types.PermissionContainerRead},
			"operator": {types.PermissionContainerManage},
		},
		// user1: read only, user2: manage only (implies read), both need the all target
		types.RBACGrant{Description: "container viewer", Users: []string{"user1"},
			Roles: []string{"viewer"}, Targets: []string{"all"}},
		types.RBACGrant{Description: "container operator", Users: []string{"user2"},
			Roles: []string{"operator"}, Targets: []string{"all"}},
		// user3: read granted with a narrow target, which never applies to a global permission
		types.RBACGrant{Description: "narrow container read", Users: []string{"user3"},
			Roles: []string{"viewer"}, Targets: []string{"/test"}},
	))

	tests := []struct {
		name    string
		user    string
		perm    types.RBACPermission
		allowed bool
	}{
		{"viewer has container:read", "user1", types.PermissionContainerRead, true},
		{"viewer lacks container:manage", "user1", types.PermissionContainerManage, false},
		{"operator has container:manage", "user2", types.PermissionContainerManage, true},
		{"container:manage implies container:read", "user2", types.PermissionContainerRead, true},
		{"narrow target never grants global container:read", "user3", types.PermissionContainerRead, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			allowed, err := manager.AuthorizeGlobalAPI(enforcedCtx(tt.user), tt.perm, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tt.allowed {
				t.Errorf("%s: expected %v, got %v", tt.name, tt.allowed, allowed)
			}
		})
	}
}

func TestAuditReadPermission(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"auditor": {types.PermissionAuditRead},
		},
		types.RBACGrant{Description: "audit reader", Users: []string{"user1"},
			Roles: []string{"auditor"}, Targets: []string{"all"}},
		types.RBACGrant{Description: "narrow audit", Users: []string{"user2"},
			Roles: []string{"auditor"}, Targets: []string{"/test"}},
	))

	allowed, err := manager.AuthorizeGlobalAPI(enforcedCtx("user1"), types.PermissionAuditRead, "")
	if err != nil || !allowed {
		t.Errorf("audit:read with all target should be allowed, got %v err %v", allowed, err)
	}

	// A user without the grant is denied
	allowed, err = manager.AuthorizeGlobalAPI(enforcedCtx("nobody"), types.PermissionAuditRead, "")
	if err != nil || allowed {
		t.Errorf("audit:read without grant must be denied, got %v err %v", allowed, err)
	}

	// audit:read is global, a narrow target never confers it
	allowed, err = manager.AuthorizeGlobalAPI(enforcedCtx("user2"), types.PermissionAuditRead, "")
	if err != nil || allowed {
		t.Errorf("audit:read with narrow target must be denied, got %v err %v", allowed, err)
	}
}

func TestOwnerPermissions(t *testing.T) {
	t.Parallel()

	// No grants: user1 has permissions only through ownership
	manager := newTestManager(t, grantConfig(map[string][]types.RBACPermission{}))

	ctx := enforcedCtx("user1")

	// Owner gets app:manage equivalent on their own app
	for _, perm := range []types.RBACPermission{types.PermissionRead, types.PermissionUpdate,
		types.PermissionDelete, types.PermissionReload, types.PermissionAccess, types.PermissionTokenManage} {
		allowed, err := manager.AuthorizeAPI(ctx, perm, testTarget(), "user1")
		if err != nil || !allowed {
			t.Errorf("owner should hold %s, got %v err %v", perm, allowed, err)
		}
	}

	// approve is never part of the owner permissions (it is global/operator-only)
	allowed, err := manager.AuthorizeGlobalAPI(ctx, types.PermissionApprove, "user1")
	if err != nil || allowed {
		t.Errorf("owner must not hold approve, got %v err %v", allowed, err)
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

	// Owner holds the app:manage expansion (everything app scoped except approve/admin)
	perms, err = manager.GetAPIPermissions(enforcedCtx("user2"), testTarget(), "user2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if slices.Contains(perms, string(types.PermissionApprove)) {
		t.Errorf("owner permissions must not include approve, got %v", perms)
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
