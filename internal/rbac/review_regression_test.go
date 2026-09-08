// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"slices"
	"testing"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func TestSnapshotCredentialCeiling(t *testing.T) {
	for _, user := range []string{types.ADMIN_USER, "operator"} {
		for _, scopes := range [][]string{nil, {}, {"app:read"}, {"*"}} {
			t.Run(user+"/"+stringsForTest(scopes), func(t *testing.T) {
				manager := newTestManager(t, grantConfig(nil, types.RBACGrant{
					Users: []string{"operator"}, Roles: []string{"openrun-operator"}, Targets: []string{"all"},
				}))
				ctx := system.WithApiScopes(enforcedCtx(user), scopes)
				snap, err := manager.SnapshotUserGrants(ctx)
				if err != nil {
					t.Fatal(err)
				}
				sa := NewSyncAuthorizer(roundTrip(t, snap))
				for _, perm := range []types.RBACPermission{types.PermissionRead, types.PermissionUpdate,
					types.PermissionApprove, types.PermissionConfigUpdate, types.PermissionSecretReveal} {
					allowed, err := sa.Authorize(perm, testTarget(), "", user)
					if err != nil || allowed != ScopesAllow(scopes, perm) {
						t.Errorf("snapshot %s = %v, %v; expected ceiling %v", perm, allowed, err, ScopesAllow(scopes, perm))
					}
				}
			})
		}
	}
}

func stringsForTest(scopes []string) string {
	if scopes == nil {
		return "nil"
	}
	if len(scopes) == 0 {
		return "empty"
	}
	return scopes[0]
}

func TestPermissionReportCredentialCeiling(t *testing.T) {
	manager := newTestManager(t, grantConfig(nil, types.RBACGrant{
		Users: []string{"developer"}, Roles: []string{"openrun-developer"}, Targets: []string{"/test"},
	}))
	for _, user := range []string{types.ADMIN_USER, "developer"} {
		for _, target := range []types.AppPathDomain{{}, testTarget()} {
			ctx := system.WithApiScopes(enforcedCtx(user), []string{"app:read"})
			perms, err := manager.GetAPIPermissions(ctx, target, user)
			if err != nil || !slices.Equal(perms, []string{"app:read"}) {
				t.Errorf("%s on %v: permissions %v, %v", user, target, perms, err)
			}
			perms, err = manager.GetAPIPermissions(system.WithApiScopes(ctx, nil), target, user)
			if err != nil || len(perms) != 0 {
				t.Errorf("empty ceiling must report no permissions: %v, %v", perms, err)
			}
		}
	}
}

func TestAppAccessOwnerPermissions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ownerPerms map[string][]types.RBACPermission
		allowed    bool
	}{
		{"default", nil, true},
		{"disabled", map[string][]types.RBACPermission{"app": {}}, false},
		{"read only", map[string][]types.RBACPermission{"app": {types.PermissionRead}}, false},
		{"explicit access", map[string][]types.RBACPermission{"app": {types.PermissionAccess}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := newTestManager(t, &types.RBACConfig{OwnerPermissions: tc.ownerPerms})
			for _, user := range []string{"owner", "other", ""} {
				allowed, err := manager.AuthorizeAppAccess(user, testTarget(), nil, "owner")
				if err != nil || allowed != (tc.allowed && user == "owner") {
					t.Errorf("%q: access %v, %v", user, allowed, err)
				}
			}
		})
	}
}

func TestConfigCallerMutationIsolation(t *testing.T) {
	config := grantConfig(nil, types.RBACGrant{
		Users: []string{"reader"}, Roles: []string{"openrun-user"}, Targets: []string{"/test"},
	})
	manager := newTestManager(t, config)
	config.Grants[0].Users[0] = "attacker"
	config.Grants[0].Roles[0] = "openrun-admin"
	config.Grants = append(config.Grants, types.RBACGrant{})
	allowed, err := manager.AuthorizeAPI(enforcedCtx("attacker"), types.PermissionDelete, testTarget(), "")
	if err != nil || allowed {
		t.Fatalf("mutating caller config must not grant authority: %v, %v", allowed, err)
	}
	allowed, err = manager.AuthorizeAPI(enforcedCtx("reader"), types.PermissionRead, testTarget(), "")
	if err != nil || !allowed {
		t.Fatalf("mutating caller config must not revoke live grant: %v, %v", allowed, err)
	}
	if err := manager.UpdateRBACConfig(nil); err == nil {
		t.Fatal("nil config update must return an error")
	}
}

func TestCustomPermissionsFailClosedAndStable(t *testing.T) {
	manager := newTestManager(t, grantConfig(map[string][]types.RBACPermission{
		"custom": {"custom:read"},
	}, types.RBACGrant{Users: []string{"regex:.*"}, Roles: []string{"openrun-admin"}}))
	perms, err := manager.GetCustomPermissionsInt("", testTarget(), nil)
	if err != nil || len(perms) != 0 {
		t.Fatalf("empty user must not get custom permissions through admin regex: %v, %v", perms, err)
	}
	perms, err = manager.GetCustomPermissionsInt("admin", testTarget(), nil)
	if err != nil || len(perms) != 1 {
		t.Fatalf("admin custom permissions: %v, %v", perms, err)
	}
	if err := manager.UpdateRBACConfig(grantConfig(map[string][]types.RBACPermission{
		"custom": {"custom:write"},
	})); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(perms, []string{"read"}) {
		t.Fatalf("old read-only result changed after publish: %v", perms)
	}
}

func TestPermissionGlobValidation(t *testing.T) {
	manager := newTestManager(t, &types.RBACConfig{})
	for _, perm := range []types.RBACPermission{"app:[", "{app,service:read"} {
		if err := ValidatePermissionName(perm); err == nil {
			t.Errorf("draft validation accepted malformed permission %q", perm)
		}
		if err := manager.UpdateRBACConfig(grantConfig(map[string][]types.RBACPermission{"bad": {perm}})); err == nil {
			t.Errorf("config validation accepted malformed permission %q", perm)
		}
	}
	for _, perm := range []types.RBACPermission{"custom:read[", "custom:read*", "{app,service}:read", "list", "access"} {
		if err := ValidatePermissionName(perm); err != nil {
			t.Errorf("valid permission %q rejected: %v", perm, err)
		}
	}
}

func TestPrepareRBACPreservesLiveGrantsUntilPublish(t *testing.T) {
	manager := newTestManager(t, &types.RBACConfig{})
	publish, err := manager.PrepareRBACConfig(grantConfig(map[string][]types.RBACPermission{
		"legacy": {"custom:report[", types.PermissionRead},
	}, types.RBACGrant{Users: []string{"reader"}, Roles: []string{"legacy"}, Targets: []string{"/test"}}))
	if err != nil {
		t.Fatalf("persisted legacy custom permission must remain loadable: %v", err)
	}
	allowed, err := manager.AuthorizeAPI(enforcedCtx("reader"), types.PermissionRead, testTarget(), "")
	if err != nil || allowed {
		t.Fatalf("prepared grants became live before publish: %v, %v", allowed, err)
	}
	publish()
	allowed, err = manager.AuthorizeAPI(enforcedCtx("reader"), types.PermissionRead, testTarget(), "")
	if err != nil || !allowed {
		t.Fatalf("legacy config lost its valid grants: %v, %v", allowed, err)
	}
}
