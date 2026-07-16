// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

// snapshotConfig is a config with groups, role hierarchy, custom and glob
// entries, exercising everything the snapshot must capture
func snapshotConfig() *types.RBACConfig {
	return &types.RBACConfig{
		Enabled: true,
		Groups: map[string]([]string){
			"devs":   {"user1", "regex:qa-.*"},
			"nested": {"group:devs"},
		},
		Roles: map[string][]types.RBACPermission{
			"editor":   {types.PermissionUpdate},
			"composed": {"role:editor", "custom:report_access", "app:tok*"},
		},
		Grants: []types.RBACGrant{
			{Description: "editor grant", Users: []string{"user1"},
				Roles: []string{"editor"}, Targets: []string{"/apps/allowed*"}},
			{Description: "composed grant", Users: []string{"group:nested"},
				Roles: []string{"composed"}, Targets: []string{"/apps/other"}},
			{Description: "unrelated grant", Users: []string{"user2"},
				Roles: []string{"editor"}, Targets: []string{"all"}},
			{Description: "sync grant", Users: []string{"regex:sync-.*"},
				Roles: []string{"openrun-operator"}, Targets: []string{}},
		},
	}
}

func TestSnapshotUserGrants(t *testing.T) {
	t.Parallel()
	manager := newTestManager(t, snapshotConfig())

	t.Run("nil when not enforced", func(t *testing.T) {
		t.Parallel()
		// A trusted admin/UDS create call is not enforced: no snapshot, the
		// sync runs unrestricted. Same when RBAC is disabled in the config
		snap, err := manager.SnapshotUserGrants(trustedCtx())
		if err != nil || snap != nil {
			t.Errorf("trusted ctx: expected nil snapshot, got %v err %v", snap, err)
		}
		disabledManager := newTestManager(t, &types.RBACConfig{Enabled: false})
		snap, err = disabledManager.SnapshotUserGrants(context.Background())
		if err != nil || snap != nil {
			t.Errorf("rbac disabled: expected nil snapshot, got %v err %v", snap, err)
		}
	})

	t.Run("admin user", func(t *testing.T) {
		t.Parallel()
		snap, err := manager.SnapshotUserGrants(enforcedCtx(types.ADMIN_USER))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !snap.Admin || snap.UserId != types.ADMIN_USER || len(snap.Grants) != 0 {
			t.Errorf("expected admin snapshot with no grants, got %+v", snap)
		}
	})

	t.Run("grant based admin", func(t *testing.T) {
		t.Parallel()
		adminManager := newTestManager(t, grantConfig(
			map[string][]types.RBACPermission{},
			types.RBACGrant{Description: "admins", Users: []string{"user1"},
				Roles: []string{"openrun-admin"}, Targets: []string{"all"}},
		))
		snap, err := adminManager.SnapshotUserGrants(enforcedCtx("user1"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !snap.Admin || len(snap.Grants) != 0 {
			t.Errorf("expected admin snapshot, got %+v", snap)
		}
	})

	t.Run("matched grants flattened", func(t *testing.T) {
		t.Parallel()
		// user1 matches "editor grant" directly and "composed grant" through
		// the nested group; "unrelated grant" and "sync grant" must not appear
		snap, err := manager.SnapshotUserGrants(enforcedCtx("user1"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if snap.Admin || snap.UserId != "user1" || len(snap.Grants) != 2 {
			t.Fatalf("expected 2 matched grants for user1, got %+v", snap)
		}
		editor := snap.Grants[0]
		if editor.Description != "editor grant" || !slices.Equal(editor.Targets, []string{"/apps/allowed*"}) {
			t.Errorf("unexpected first grant %+v", editor)
		}
		// implications of app:update are expanded
		for _, perm := range []types.RBACPermission{types.PermissionUpdate, types.PermissionApply,
			types.PermissionReload, types.PermissionRead} {
			if !slices.Contains(editor.Permissions, perm) {
				t.Errorf("expected %s in flattened editor perms %v", perm, editor.Permissions)
			}
		}
		// role hierarchy is flattened, custom: and glob entries are preserved
		composed := snap.Grants[1]
		for _, perm := range []types.RBACPermission{types.PermissionUpdate, "custom:report_access", "app:tok*"} {
			if !slices.Contains(composed.Permissions, perm) {
				t.Errorf("expected %s in flattened composed perms %v", perm, composed.Permissions)
			}
		}
		// owner permissions are captured (app defaults expand app:manage)
		if !slices.Contains(snap.OwnerPermissions[ResourceApp], types.PermissionAppManage) ||
			!slices.Contains(snap.OwnerPermissions[ResourceSync], types.PermissionSyncRun) {
			t.Errorf("expected owner permissions captured, got %v", snap.OwnerPermissions)
		}
	})

	t.Run("group regex member and user regex", func(t *testing.T) {
		t.Parallel()
		// qa-1 matches devs through the regex: group member, and the nested group
		snap, err := manager.SnapshotUserGrants(enforcedCtx("qa-1"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(snap.Grants) != 1 || snap.Grants[0].Description != "composed grant" {
			t.Errorf("expected composed grant for qa-1, got %+v", snap.Grants)
		}
		// sync-bot matches the regex: user entry
		snap, err = manager.SnapshotUserGrants(enforcedCtx("sync-bot"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(snap.Grants) != 1 || snap.Grants[0].Description != "sync grant" {
			t.Errorf("expected sync grant for sync-bot, got %+v", snap.Grants)
		}
	})

	t.Run("sso context group", func(t *testing.T) {
		t.Parallel()
		snap, err := manager.SnapshotUserGrants(enforcedCtx("ssouser", "nested"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(snap.Grants) != 1 || snap.Grants[0].Description != "composed grant" {
			t.Errorf("expected composed grant via SSO group, got %+v", snap.Grants)
		}
	})
}

// roundTrip serializes the snapshot the way it is persisted in the sync
// metadata and rebuilds it, proving the stored form is sufficient
func roundTrip(t *testing.T, snap *types.RBACSnapshot) *types.RBACSnapshot {
	t.Helper()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	restored := &types.RBACSnapshot{}
	if err := json.Unmarshal(data, restored); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	return restored
}

func TestSyncAuthorizer(t *testing.T) {
	t.Parallel()
	manager := newTestManager(t, snapshotConfig())
	snap, err := manager.SnapshotUserGrants(enforcedCtx("user1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sa := NewSyncAuthorizer(roundTrip(t, snap))

	tests := []struct {
		name    string
		perm    types.RBACPermission
		target  types.AppPathDomain
		owner   string
		allowed bool
	}{
		{"scoped perm inside target glob", types.PermissionApply, types.AppPathDomain{Path: "/apps/allowed1"}, "", true},
		{"implied perm inside target glob", types.PermissionRead, types.AppPathDomain{Path: "/apps/allowed1"}, "", true},
		{"scoped perm outside target glob", types.PermissionApply, types.AppPathDomain{Path: "/apps/denied"}, "", false},
		{"perm not granted", types.PermissionDelete, types.AppPathDomain{Path: "/apps/allowed1"}, "", false},
		{"glob role entry scoped to target", "app:token_read", types.AppPathDomain{Path: "/apps/other"}, "", true},
		{"approve never granted by globs", types.PermissionApprove, types.AppPathDomain{}, "", false},
		{"admin never granted by globs", types.PermissionAdmin, types.AppPathDomain{}, "", false},
		{"owner virtual grant", types.PermissionDelete, types.AppPathDomain{Path: "/apps/denied"}, "user1", true},
		{"owner rule needs matching owner", types.PermissionDelete, types.AppPathDomain{Path: "/apps/denied"}, "user2", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			allowed, err := sa.Authorize(tt.perm, tt.target, "", tt.owner)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tt.allowed {
				t.Errorf("expected %v, got %v", tt.allowed, allowed)
			}
		})
	}

	t.Run("global perm ignores targets", func(t *testing.T) {
		t.Parallel()
		// openrun-operator confers global sync permissions even with no targets
		opManager := newTestManager(t, snapshotConfig())
		opSnap, err := opManager.SnapshotUserGrants(enforcedCtx("sync-bot"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		opSa := NewSyncAuthorizer(roundTrip(t, opSnap))
		allowed, err := opSa.Authorize(types.PermissionSyncCreate, types.AppPathDomain{}, "", "")
		if err != nil || !allowed {
			t.Errorf("expected global sync:create allowed, got %v err %v", allowed, err)
		}
	})

	t.Run("admin bypass", func(t *testing.T) {
		t.Parallel()
		adminSa := NewSyncAuthorizer(roundTrip(t, &types.RBACSnapshot{UserId: "boss", Admin: true}))
		allowed, err := adminSa.Authorize(types.PermissionDelete, types.AppPathDomain{Path: "/any"}, "", "")
		if err != nil || !allowed {
			t.Errorf("expected admin snapshot to allow everything, got %v err %v", allowed, err)
		}
	})

	t.Run("empty user fails closed", func(t *testing.T) {
		t.Parallel()
		emptySa := NewSyncAuthorizer(roundTrip(t, &types.RBACSnapshot{UserId: "", Admin: true}))
		allowed, err := emptySa.Authorize(types.PermissionRead, types.AppPathDomain{Path: "/apps/allowed1"}, "", "")
		if err != nil || allowed {
			t.Errorf("expected empty user snapshot to fail closed, got %v err %v", allowed, err)
		}
	})

	t.Run("owner rule never grants approve", func(t *testing.T) {
		t.Parallel()
		ownerSnap := &types.RBACSnapshot{UserId: "user1",
			OwnerPermissions: map[string][]types.RBACPermission{ResourceApp: {types.PermissionApprove}}}
		ownerSa := NewSyncAuthorizer(roundTrip(t, ownerSnap))
		// approve has no resource prefix match with app perms; even a
		// hand-crafted owner permission list cannot leak it through the app resource
		allowed, err := ownerSa.Authorize(types.PermissionApprove, types.AppPathDomain{Path: "/a"}, "", "user1")
		if err != nil || allowed {
			t.Errorf("expected approve never granted via owner rule, got %v err %v", allowed, err)
		}
	})

	t.Run("nil snapshot", func(t *testing.T) {
		t.Parallel()
		if NewSyncAuthorizer(nil) != nil {
			t.Error("expected nil authorizer for nil snapshot")
		}
	})
}

func TestSyncAuthorizerFrozen(t *testing.T) {
	t.Parallel()
	manager := newTestManager(t, snapshotConfig())
	snap, err := manager.SnapshotUserGrants(enforcedCtx("user1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sa := NewSyncAuthorizer(roundTrip(t, snap))

	// Remove every grant and role from the live config
	if err := manager.UpdateRBACConfig(grantConfig(map[string][]types.RBACPermission{})); err != nil {
		t.Fatalf("config update failed: %v", err)
	}

	// The frozen snapshot still authorizes what the creator held at create time
	allowed, err := sa.Authorize(types.PermissionApply, types.AppPathDomain{Path: "/apps/allowed1"}, "", "")
	if err != nil || !allowed {
		t.Errorf("expected frozen snapshot to authorize after config shrink, got %v err %v", allowed, err)
	}

	// Conversely, widening the live config does not widen an existing snapshot
	if err := manager.UpdateRBACConfig(grantConfig(
		map[string][]types.RBACPermission{"all": {"app:*"}},
		types.RBACGrant{Description: "wide", Users: []string{"user1"}, Roles: []string{"all"}, Targets: []string{"all"}},
	)); err != nil {
		t.Fatalf("config update failed: %v", err)
	}
	allowed, err = sa.Authorize(types.PermissionDelete, types.AppPathDomain{Path: "/apps/allowed1"}, "", "")
	if err != nil || allowed {
		t.Errorf("expected frozen snapshot to ignore config widening, got %v err %v", allowed, err)
	}
}

func TestSyncAuthorizerContextIntegration(t *testing.T) {
	t.Parallel()
	manager := newTestManager(t, snapshotConfig())
	snap, err := manager.SnapshotUserGrants(enforcedCtx("user1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A background context (no RBAC_ENABLED) carrying the authorizer is enforced
	ctx := WithSyncAuthorizer(context.Background(), NewSyncAuthorizer(roundTrip(t, snap)))
	if !manager.APIEnforced(ctx) {
		t.Fatal("expected APIEnforced with sync authorizer attached")
	}

	allowed, err := manager.AuthorizeAPI(ctx, types.PermissionApply, types.AppPathDomain{Path: "/apps/allowed1"}, "")
	if err != nil || !allowed {
		t.Errorf("expected snapshot to authorize app:apply on /apps/allowed1, got %v err %v", allowed, err)
	}
	allowed, err = manager.AuthorizeAPI(ctx, types.PermissionApply, types.AppPathDomain{Path: "/apps/denied"}, "")
	if err != nil || allowed {
		t.Errorf("expected snapshot to deny app:apply on /apps/denied, got %v err %v", allowed, err)
	}
	allowed, err = manager.AuthorizeGlobalAPI(ctx, types.PermissionSyncCreate, "")
	if err != nil || allowed {
		t.Errorf("expected snapshot to deny global sync:create, got %v err %v", allowed, err)
	}

	perms, err := manager.GetAPIPermissions(ctx, types.AppPathDomain{Path: "/apps/allowed1"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Contains(perms, string(types.PermissionApply)) || slices.Contains(perms, string(types.PermissionDelete)) {
		t.Errorf("unexpected snapshot permission report %v", perms)
	}

	// Attaching nil is a no-op: a trusted background context stays unenforced,
	// while an unmarked context reports enforced (fail closed) with RBAC enabled
	if manager.APIEnforced(WithSyncAuthorizer(trustedCtx(), nil)) {
		t.Error("expected nil authorizer attachment on a trusted context to stay unenforced")
	}
	if !manager.APIEnforced(WithSyncAuthorizer(context.Background(), nil)) {
		t.Error("expected unattributed context to report enforced (fail closed)")
	}
}
