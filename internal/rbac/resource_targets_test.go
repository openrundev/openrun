// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"slices"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// TestServiceBindingTargets verifies service:* and binding:* permissions are
// scoped to the grant's service:<glob> / binding:<glob> target entries:
// service globs match the service id (<type>/<name>, no leading slash),
// binding globs match the binding path, and app path targets confer neither
func TestServiceBindingTargets(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"dbops": {types.PermissionServiceRead, types.PermissionServiceBind,
				types.PermissionBindingRead, types.PermissionBindingUse},
		},
		types.RBACGrant{Description: "scoped dbops", Users: []string{"user1"}, Roles: []string{"dbops"},
			Targets: []string{"/apps/**", "service:postgres/*", "binding:/apps/team1/**"}},
		types.RBACGrant{Description: "all target", Users: []string{"user2"}, Roles: []string{"dbops"},
			Targets: []string{"all"}},
		types.RBACGrant{Description: "app targets only", Users: []string{"user3"}, Roles: []string{"dbops"},
			Targets: []string{"/apps/**"}},
	))

	tests := []struct {
		name       string
		user       string
		perm       types.RBACPermission
		resourceId string
		allowed    bool
	}{
		{"service glob matches", "user1", types.PermissionServiceRead, "postgres/main", true},
		{"service glob star does not cross slash", "user1", types.PermissionServiceRead, "postgres/a/b", false},
		{"service glob wrong type", "user1", types.PermissionServiceRead, "mysql/main", false},
		{"service bind within glob", "user1", types.PermissionServiceBind, "postgres/main", true},
		{"binding glob matches", "user1", types.PermissionBindingRead, "/apps/team1/db1", true},
		{"binding glob outside", "user1", types.PermissionBindingUse, "/apps/team2/db1", false},
		{"app target does not confer binding perm", "user1", types.PermissionBindingRead, "/apps/anything", false},
		{"all target confers service perm", "user2", types.PermissionServiceRead, "mysql/x", true},
		{"all target confers binding perm", "user2", types.PermissionBindingUse, "/anywhere/at/all", true},
		{"app-only targets confer no service perm", "user3", types.PermissionServiceRead, "postgres/main", false},
		{"app-only targets confer no binding perm", "user3", types.PermissionBindingRead, "/apps/x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			allowed, err := manager.AuthorizeResourceAPI(enforcedCtx(tt.user), tt.perm, tt.resourceId, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tt.allowed {
				t.Errorf("expected %v, got %v", tt.allowed, allowed)
			}
		})
	}

	// App permissions are still scoped by the app path targets of the same grant
	allowed, err := manager.AuthorizeAPI(enforcedCtx("user1"), types.PermissionRead,
		types.AppPathDomain{Path: "/apps/x"}, "")
	if err != nil || allowed {
		t.Errorf("dbops role has no app perms, got %v err %v", allowed, err)
	}
}

// TestServiceBindingManage verifies the service:manage / binding:manage
// composites expand to all permissions of their resource
func TestServiceBindingManage(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"dbadmin": {types.PermissionServiceManage, types.PermissionBindingManage},
		},
		types.RBACGrant{Description: "db admin", Users: []string{"user1"}, Roles: []string{"dbadmin"},
			Targets: []string{"service:**", "binding:/**"}},
	))

	for _, perm := range []types.RBACPermission{types.PermissionServiceCreate, types.PermissionServiceUpdate,
		types.PermissionServiceDelete, types.PermissionServiceRead, types.PermissionServiceBind} {
		allowed, err := manager.AuthorizeResourceAPI(enforcedCtx("user1"), perm, "postgres/main", "")
		if err != nil || !allowed {
			t.Errorf("service:manage should grant %s, got %v err %v", perm, allowed, err)
		}
	}
	for _, perm := range []types.RBACPermission{types.PermissionBindingCreate, types.PermissionBindingUpdate,
		types.PermissionBindingDelete, types.PermissionBindingRead, types.PermissionBindingRunCommand,
		types.PermissionBindingUse} {
		allowed, err := manager.AuthorizeResourceAPI(enforcedCtx("user1"), perm, "/apps/db1", "")
		if err != nil || !allowed {
			t.Errorf("binding:manage should grant %s, got %v err %v", perm, allowed, err)
		}
	}
	// binding:reveal always needs an explicit grant, it is never implied by
	// binding:manage (like app:approve and app:manage)
	allowed, err := manager.AuthorizeResourceAPI(enforcedCtx("user1"), types.PermissionBindingReveal, "/apps/db1", "")
	if err != nil || allowed {
		t.Errorf("binding:manage must not imply binding:reveal, got %v err %v", allowed, err)
	}
	// manage does not leak across resources
	allowed, err = manager.AuthorizeAPI(enforcedCtx("user1"), types.PermissionRead, testTarget(), "")
	if err != nil || allowed {
		t.Errorf("service/binding manage must not grant app perms, got %v err %v", allowed, err)
	}
}

// TestBindingReveal verifies binding:reveal is granted only explicitly: not
// through binding:manage, not through the default owner rule, but grantable
// directly and via an owner_permissions.binding opt-in
func TestBindingReveal(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"revealer": {types.PermissionBindingReveal},
		},
		types.RBACGrant{Description: "revealer", Users: []string{"user1"}, Roles: []string{"revealer"},
			Targets: []string{"binding:/apps/**"}},
	))

	allowed, err := manager.AuthorizeResourceAPI(enforcedCtx("user1"), types.PermissionBindingReveal, "/apps/db1", "")
	if err != nil || !allowed {
		t.Errorf("explicit binding:reveal grant should authorize, got %v err %v", allowed, err)
	}
	allowed, err = manager.AuthorizeResourceAPI(enforcedCtx("user1"), types.PermissionBindingReveal, "/elsewhere/db1", "")
	if err != nil || allowed {
		t.Errorf("binding:reveal is scoped by the binding targets, got %v err %v", allowed, err)
	}

	// The default owner rule (binding:manage) does not include reveal
	allowed, err = manager.AuthorizeResourceAPI(enforcedCtx("creator"), types.PermissionBindingReveal, "/apps/db1", "creator")
	if err != nil || allowed {
		t.Errorf("binding owner must not hold binding:reveal by default, got %v err %v", allowed, err)
	}

	// Operators can opt owners in via owner_permissions.binding
	optIn := grantConfig(map[string][]types.RBACPermission{})
	optIn.OwnerPermissions = map[string][]types.RBACPermission{
		ResourceBinding: {types.PermissionBindingManage, types.PermissionBindingReveal},
	}
	optInManager := newTestManager(t, optIn)
	allowed, err = optInManager.AuthorizeResourceAPI(enforcedCtx("creator"), types.PermissionBindingReveal, "/apps/db1", "creator")
	if err != nil || !allowed {
		t.Errorf("owner_permissions opt-in should grant owner binding:reveal, got %v err %v", allowed, err)
	}
}

// TestResourceTargetValidation verifies service:/binding: target entries are
// validated on config update
func TestResourceTargetValidation(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}
	roles := map[string][]types.RBACPermission{"reader": {types.PermissionServiceRead}}

	tests := []struct {
		target string
		errMsg string // "" means valid
	}{
		{"service:postgres/*", ""},
		{"service:**", ""},
		{"binding:/apps/**", ""},
		{"service:", "cannot be empty"},
		{"service:/postgres/*", "without a leading /"},
		{"binding:apps/**", "starting with /"},
		{"service:postgres/[", "invalid service target glob"},
		{"binding:/apps/[", "invalid binding target glob"},
	}
	for _, tt := range tests {
		_, err := NewRBACHandler(logger, grantConfig(roles,
			types.RBACGrant{Description: "t", Users: []string{"user1"},
				Roles: []string{"reader"}, Targets: []string{tt.target}},
		), serverConfig)
		if tt.errMsg == "" {
			if err != nil {
				t.Errorf("target %q should be valid, got %v", tt.target, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
			t.Errorf("target %q: expected error containing %q, got %v", tt.target, tt.errMsg, err)
		}
	}
}

// TestSyncAuthorizerResourceTargets verifies frozen snapshots carry the typed
// target entries and enforce them on background runs
func TestSyncAuthorizerResourceTargets(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"dbops": {types.PermissionServiceBind, types.PermissionBindingUse, types.PermissionBindingCreate},
		},
		types.RBACGrant{Description: "scoped dbops", Users: []string{"user1"}, Roles: []string{"dbops"},
			Targets: []string{"service:postgres/*", "binding:/apps/team1/**"}},
	))
	snap, err := manager.SnapshotUserGrants(enforcedCtx("user1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sa := NewSyncAuthorizer(snap)

	allowed, err := sa.Authorize(types.PermissionServiceBind, types.AppPathDomain{}, "postgres/main", "")
	if err != nil || !allowed {
		t.Errorf("snapshot should confer service:bind on postgres/main, got %v err %v", allowed, err)
	}
	allowed, err = sa.Authorize(types.PermissionServiceBind, types.AppPathDomain{}, "mysql/main", "")
	if err != nil || allowed {
		t.Errorf("snapshot must not confer service:bind on mysql/main, got %v err %v", allowed, err)
	}
	allowed, err = sa.Authorize(types.PermissionBindingUse, types.AppPathDomain{}, "/apps/team1/db1", "")
	if err != nil || !allowed {
		t.Errorf("snapshot should confer binding:use within glob, got %v err %v", allowed, err)
	}
	allowed, err = sa.Authorize(types.PermissionBindingCreate, types.AppPathDomain{}, "/elsewhere/db", "")
	if err != nil || allowed {
		t.Errorf("snapshot must not confer binding:create outside glob, got %v err %v", allowed, err)
	}
}

func TestProviderPermsInCatalog(t *testing.T) {
	t.Parallel()

	for _, perm := range []types.RBACPermission{
		types.PermissionProviderRead,
		types.PermissionProviderManage,
	} {
		if !slices.Contains(allPermissionNames, string(perm)) {
			t.Errorf("expected %s in allPermissionNames", perm)
		}
	}

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{
			"provider-admin": {types.PermissionProviderManage},
		},
		types.RBACGrant{Description: "provider admin", Users: []string{"user1"},
			Roles: []string{"provider-admin"}, Targets: []string{"all"}},
	))

	for _, perm := range []types.RBACPermission{
		types.PermissionProviderManage,
		types.PermissionProviderRead,
	} {
		allowed, err := manager.AuthorizeGlobalAPI(enforcedCtx("user1"), perm, "")
		if err != nil || !allowed {
			t.Errorf("provider:manage should confer %s, got allowed=%v err=%v", perm, allowed, err)
		}
	}
}
