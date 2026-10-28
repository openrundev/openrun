// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

// adminSurfaceConfig is a config with admin conferred three ways: the
// openrun-admin role through a nested group, a custom role composing
// openrun-admin, and a custom role listing admin literally. ops-editors is a
// non-admin grant for the config editor under test
func adminSurfaceConfig() *types.RBACConfig {
	return &types.RBACConfig{
		Groups: map[string][]string{
			"platform-admins": {"builtin:root", "group:sre", "group:idp-admins"},
			"sre":             {"builtin:sre1", "regex:^github:sre-.*$"},
			"ops-editors":     {"builtin:editor"},
			"unrelated":       {"builtin:someone"},
		},
		Roles: map[string][]types.RBACPermission{
			"super":      {types.RBACPermission(RBAC_ROLE_PREFIX + "openrun-admin")},
			"literal":    {types.PermissionAdmin, types.PermissionRead},
			"wildcard":   {"*"},
			"editor":     {types.PermissionConfigUpdate, types.PermissionConfigRead},
			"adminmgr":   {types.PermissionAdminManage},
			"roleglob":   {"admin:*"},
			"composesup": {types.RBACPermission(RBAC_ROLE_PREFIX + "super")},
		},
		Grants: []types.RBACGrant{
			{Description: "admins", Users: []string{"group:platform-admins"}, Roles: []string{"openrun-admin"}, Targets: []string{"all"}},
			{Description: "super users", Users: []string{"builtin:alice"}, Roles: []string{"super"}},
			{Description: "literal admins", Users: []string{"builtin:bob", "group:board"}, Roles: []string{"literal"}},
			{Description: "editors", Users: []string{"group:ops-editors"}, Roles: []string{"editor"}, Targets: []string{"all"}},
			{Description: "wildcard is not admin", Users: []string{"builtin:carol"}, Roles: []string{"wildcard"}},
			{Description: "manager", Users: []string{"builtin:manager"}, Roles: []string{"editor", "adminmgr"}},
		},
	}
}

func TestComputeAdminSurface(t *testing.T) {
	t.Parallel()
	surface := ComputeAdminSurface(adminSurfaceConfig())

	wantRoles := []string{"adminmgr=admin:manage", "composesup=admin", "literal=admin", "openrun-admin=admin", "super=admin"}
	if !slices.Equal(surface.Roles, wantRoles) {
		t.Fatalf("admin roles = %v, want %v", surface.Roles, wantRoles)
	}
	if len(surface.Grants) != 4 {
		t.Fatalf("admin grants = %v, want 4", surface.Grants)
	}
	// Referenced groups are collected through the hierarchy, config-defined or
	// sign-in only; unreferenced groups are not part of the surface
	for _, name := range []string{"platform-admins", "sre", "idp-admins", "board"} {
		if !surface.GroupNames[name] {
			t.Errorf("group %s must be in the admin surface: %v", name, surface.GroupNames)
		}
	}
	for _, name := range []string{"ops-editors", "unrelated"} {
		if surface.GroupNames[name] {
			t.Errorf("group %s must not be in the admin surface", name)
		}
	}
	if _, ok := surface.Groups["idp-admins"]; ok {
		t.Error("a sign-in only group has no config membership")
	}
	if got := surface.Groups["sre"]; !slices.Equal(got, []string{"builtin:sre1", "regex:^github:sre-.*$"}) {
		t.Errorf("sre members = %v", got)
	}

	// A nil or empty config has an empty surface, and the predefined
	// openrun-admin role always resolves to admin
	empty := ComputeAdminSurface(&types.RBACConfig{})
	if !slices.Equal(empty.Roles, []string{"openrun-admin=admin"}) || len(empty.Grants) != 0 || len(empty.GroupNames) != 0 {
		t.Fatalf("empty surface = %+v", empty)
	}
	if ComputeAdminSurface(nil).Diff(empty) != "" {
		t.Fatal("nil config must equal the empty config")
	}
}

func TestAdminSurfaceDiff(t *testing.T) {
	t.Parallel()
	base := ComputeAdminSurface(adminSurfaceConfig())

	tests := []struct {
		name    string
		mutate  func(c *types.RBACConfig)
		changed string // substring of the expected diff, "" for no change
	}{
		{"grant description", func(c *types.RBACConfig) { c.Grants[0].Description = "renamed" }, ""},
		{"grant targets", func(c *types.RBACConfig) { c.Grants[0].Targets = []string{"/apps/**"} }, ""},
		{"grant order", func(c *types.RBACConfig) { c.Grants[0], c.Grants[1] = c.Grants[1], c.Grants[0] }, ""},
		{"member order", func(c *types.RBACConfig) { slices.Reverse(c.Groups["platform-admins"]) }, ""},
		{"unrelated group", func(c *types.RBACConfig) { c.Groups["unrelated"] = append(c.Groups["unrelated"], "builtin:editor") }, ""},
		{"editor group", func(c *types.RBACConfig) { c.Groups["ops-editors"] = append(c.Groups["ops-editors"], "builtin:new") }, ""},
		{"non-admin grant", func(c *types.RBACConfig) { c.Grants[3].Users = append(c.Grants[3].Users, "builtin:editor") }, ""},
		{"non-admin role", func(c *types.RBACConfig) { c.Roles["editor"] = append(c.Roles["editor"], types.PermissionAppManage) }, ""},
		{"new non-admin grant", func(c *types.RBACConfig) {
			c.Grants = append(c.Grants, types.RBACGrant{Users: []string{"builtin:editor"}, Roles: []string{"editor"}})
		}, ""},
		{"glob role never confers admin", func(c *types.RBACConfig) { c.Roles["wildcard"] = []types.RBACPermission{"*", "admin:*"} }, ""},

		{"join admin group", func(c *types.RBACConfig) {
			c.Groups["platform-admins"] = append(c.Groups["platform-admins"], "builtin:editor")
		}, "group \"platform-admins\""},
		{"join nested admin group", func(c *types.RBACConfig) { c.Groups["sre"] = append(c.Groups["sre"], "builtin:editor") }, "group \"sre\""},
		{"leave admin group", func(c *types.RBACConfig) { c.Groups["sre"] = []string{} }, "group \"sre\""},
		{"delete admin group", func(c *types.RBACConfig) { delete(c.Groups, "sre") }, "group \"sre\""},
		{"define a sign-in admin group", func(c *types.RBACConfig) { c.Groups["board"] = []string{"builtin:editor"} }, "group \"board\""},
		{"add user to admin grant", func(c *types.RBACConfig) {
			c.Grants[1].Users = append(c.Grants[1].Users, "builtin:editor")
		}, "grants conferring"},
		{"add group to admin grant", func(c *types.RBACConfig) {
			c.Grants[1].Users = append(c.Grants[1].Users, "group:ops-editors")
		}, "grants conferring"},
		{"add regex to admin grant", func(c *types.RBACConfig) { c.Grants[1].Users = append(c.Grants[1].Users, "regex:.*") }, "grants conferring"},
		{"new admin grant", func(c *types.RBACConfig) {
			c.Grants = append(c.Grants, types.RBACGrant{Users: []string{"builtin:editor"}, Roles: []string{"openrun-admin"}})
		}, "grants conferring"},
		{"delete admin grant", func(c *types.RBACConfig) { c.Grants = c.Grants[1:] }, "grants conferring"},
		{"admin role on existing grant", func(c *types.RBACConfig) { c.Grants[3].Roles = append(c.Grants[3].Roles, "super") }, "grants conferring"},
		{"role gains admin", func(c *types.RBACConfig) { c.Roles["editor"] = append(c.Roles["editor"], types.PermissionAdmin) }, "roles conferring"},
		{"role composes admin", func(c *types.RBACConfig) {
			c.Roles["editor"] = append(c.Roles["editor"], RBAC_ROLE_PREFIX+"composesup")
		}, "roles conferring"},
		{"role loses admin", func(c *types.RBACConfig) { c.Roles["literal"] = []types.RBACPermission{types.PermissionRead} }, "roles conferring"},
		{"dangling role reference tolerated", func(c *types.RBACConfig) { delete(c.Roles, "super") }, "roles conferring"},
		{"role cycle tolerated", func(c *types.RBACConfig) {
			c.Roles["a"] = []types.RBACPermission{RBAC_ROLE_PREFIX + "b"}
			c.Roles["b"] = []types.RBACPermission{RBAC_ROLE_PREFIX + "a"}
		}, ""},
		{"cycle reaching admin", func(c *types.RBACConfig) {
			c.Roles["a"] = []types.RBACPermission{RBAC_ROLE_PREFIX + "b"}
			c.Roles["b"] = []types.RBACPermission{RBAC_ROLE_PREFIX + "a", RBAC_ROLE_PREFIX + "super"}
		}, "roles conferring"},

		// admin:manage is protected like admin: granting it is the first step
		// of a two-update escalation to admin
		{"role gains admin:manage", func(c *types.RBACConfig) {
			c.Roles["editor"] = append(c.Roles["editor"], types.PermissionAdminManage)
		}, "roles conferring"},
		{"role composes admin:manage", func(c *types.RBACConfig) {
			c.Roles["editor"] = append(c.Roles["editor"], RBAC_ROLE_PREFIX+"adminmgr")
		}, "roles conferring"},
		{"join admin:manage grant", func(c *types.RBACConfig) {
			c.Grants[5].Users = append(c.Grants[5].Users, "builtin:editor")
		}, "grants conferring"},
		{"admin:manage role on existing grant", func(c *types.RBACConfig) {
			c.Grants[3].Roles = append(c.Grants[3].Roles, "adminmgr")
		}, "grants conferring"},
		{"admin:manage role becomes admin", func(c *types.RBACConfig) {
			c.Roles["adminmgr"] = []types.RBACPermission{types.PermissionAdmin}
		}, "roles conferring"},
		{"admin role becomes admin:manage", func(c *types.RBACConfig) {
			c.Roles["literal"] = []types.RBACPermission{types.PermissionAdminManage, types.PermissionRead}
		}, "roles conferring"},
		{"admin:manage role also gains admin", func(c *types.RBACConfig) {
			c.Roles["adminmgr"] = append(c.Roles["adminmgr"], types.PermissionAdmin)
		}, "roles conferring"},
		{"new admin:manage grant", func(c *types.RBACConfig) {
			c.Grants = append(c.Grants, types.RBACGrant{Users: []string{"builtin:editor"}, Roles: []string{"adminmgr"}})
		}, "grants conferring"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := adminSurfaceConfig()
			tt.mutate(config)
			diff := base.Diff(ComputeAdminSurface(config))
			if tt.changed == "" && diff != "" {
				t.Fatalf("unexpected admin surface change: %s", diff)
			}
			if tt.changed != "" && !strings.Contains(diff, tt.changed) {
				t.Fatalf("diff = %q, want it to mention %q", diff, tt.changed)
			}
		})
	}
}

// A dense cyclic role graph (every role composing every other) is
// evaluated in bounded time: the surface is computed before publish
// validation rejects the cycle, while the config lock is held
func TestAdminSurfaceDenseRoleCycle(t *testing.T) {
	t.Parallel()
	const count = 40
	config := &types.RBACConfig{Roles: map[string][]types.RBACPermission{}}
	for i := range count {
		var perms []types.RBACPermission
		for j := range count {
			if i != j {
				perms = append(perms, types.RBACPermission(fmt.Sprintf("%srole%d", RBAC_ROLE_PREFIX, j)))
			}
		}
		config.Roles[fmt.Sprintf("role%d", i)] = perms
	}
	config.Grants = []types.RBACGrant{{Users: []string{"builtin:x"}, Roles: []string{"role0"}}}
	start := time.Now()
	surface := ComputeAdminSurface(config)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("dense role cycle took %v", elapsed)
	}
	if len(surface.Grants) != 0 {
		t.Fatalf("no role confers admin: %v", surface.Grants)
	}
	// One role in the cycle listing admin makes every role protected
	config.Roles["role39"] = append(config.Roles["role39"], types.PermissionAdmin)
	surface = ComputeAdminSurface(config)
	if len(surface.Roles) != count+1 || len(surface.Grants) != 1 { // + openrun-admin=admin
		t.Fatalf("every role in the cycle must be protected: %d roles, %v grants", len(surface.Roles), surface.Grants)
	}
}

// admin:manage is literal-only in roles (like admin and app:approve), is
// held implicitly by admin holders, and is reported by the manager's admin
// group lookup for the live config
func TestAdminManagePermission(t *testing.T) {
	t.Parallel()
	manager := newTestManager(t, adminSurfaceConfig())

	for _, tt := range []struct {
		user   string
		groups []string
		want   bool
	}{
		{"builtin:manager", nil, true},    // literal grant
		{"builtin:root", nil, true},       // admin through the group hierarchy
		{"github:sre-1", nil, true},       // admin through a regex member of a nested group
		{"okta:x", []string{"sre"}, true}, // sign-in group named by a nested group: member
		{"builtin:editor", nil, false},    // config:update only
		{"builtin:carol", nil, false},     // "*" and "admin:*" globs never match admin:manage
		{"builtin:someone", nil, false},
	} {
		got, err := manager.AuthorizeUserPerm(tt.user, tt.groups, types.PermissionAdminManage)
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("admin:manage for %s %v = %v, want %v", tt.user, tt.groups, got, tt.want)
		}
	}

	got := manager.AdminGroupsIn([]string{"dev", "sre", "board", "ops-editors", "idp-admins"})
	if !slices.Equal(got, []string{"board", "idp-admins", "sre"}) {
		t.Fatalf("admin groups = %v", got)
	}
	if manager.AdminGroupsIn(nil) != nil {
		t.Fatal("no groups, no admin groups")
	}
}
