// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/types"
)

// adminManageTestConfig: editor holds config:update and user:manage but not
// admin; manager additionally holds admin:manage; root is an admin through
// the platform-admins group, which nests the sre group
func adminManageTestConfig() types.RBACConfig {
	return types.RBACConfig{
		Groups: map[string][]string{
			"platform-admins": {"builtin:root", "group:sre"},
			"sre":             {"builtin:sre1"},
			"editors":         {"builtin:editor"},
		},
		Roles: map[string][]types.RBACPermission{
			"editor":   {types.PermissionConfigUpdate, types.PermissionConfigRead, types.PermissionUserManage},
			"adminmgr": {types.PermissionAdminManage},
		},
		Grants: []types.RBACGrant{
			{Description: "default", Users: []string{"*"}, Roles: []string{"openrun-user"}, Targets: []string{"all"}},
			{Description: "admins", Users: []string{"group:platform-admins"}, Roles: []string{"openrun-admin"}, Targets: []string{"all"}},
			{Description: "editors", Users: []string{"group:editors"}, Roles: []string{"editor"}, Targets: []string{"all"}},
			{Description: "manager", Users: []string{"builtin:manager"}, Roles: []string{"editor", "adminmgr"}, Targets: []string{"all"}},
		},
	}
}

// newAdminManageTestServer builds a server whose live and stored dynamic
// config is adminManageTestConfig, so UpdateDynamicConfig runs end to end
func newAdminManageTestServer(t *testing.T) (*Server, *metadata.Metadata, context.Context) {
	t.Helper()
	server, db, trusted := newSyncRBACTestServer(t)
	t.Setenv("OPENRUN_HOME", t.TempDir())
	server.staticConfig.Api.MCP.Auth = []string{"admin"}
	server.staticConfig.Api.Rest.Auth = []string{"admin"}
	config := &types.DynamicConfig{VersionId: "ver_base", RBAC: adminManageTestConfig()}
	if err := seedTestConfig(trusted, db, config); err != nil {
		t.Fatal(err)
	}
	server.dynamicConfig = config
	if err := server.rbacManager.UpdateRBACConfig(&config.RBAC); err != nil {
		t.Fatal(err)
	}
	return server, db, trusted
}

func TestAdminSurfaceChangeRequiresAdminManage(t *testing.T) {
	server, db, trusted := newAdminManageTestServer(t)
	defer db.Close()

	editorCtx := rbacEnforcedCtx(trusted, "builtin:editor")
	managerCtx := rbacEnforcedCtx(trusted, "builtin:manager")
	rootCtx := rbacEnforcedCtx(trusted, "builtin:root")

	joinAdmins := func(config *types.RBACConfig, user string) {
		config.Groups["platform-admins"] = append(config.Groups["platform-admins"], user)
	}
	candidate := func(mutate func(*types.RBACConfig)) *types.DynamicConfig {
		live := server.GetDynamicConfig()
		copied, err := copyDynamicConfig(&live)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&copied.RBAC)
		return copied
	}

	// The escalation: a config editor adds themselves to the admin group,
	// directly, through the nested group, through the admin grant's users,
	// with a new admin grant, or by making their own role confer admin.
	// force does not bypass the check, unlike the self-lockout check
	escalations := map[string]func(*types.RBACConfig){
		"join admin group":        func(c *types.RBACConfig) { joinAdmins(c, "builtin:editor") },
		"join nested admin group": func(c *types.RBACConfig) { c.Groups["sre"] = append(c.Groups["sre"], "builtin:editor") },
		"join admin grant":        func(c *types.RBACConfig) { c.Grants[1].Users = append(c.Grants[1].Users, "group:editors") },
		"new admin grant": func(c *types.RBACConfig) {
			c.Grants = append(c.Grants, types.RBACGrant{Users: []string{"builtin:editor"}, Roles: []string{"openrun-admin"}})
		},
		"role gains admin": func(c *types.RBACConfig) { c.Roles["editor"] = append(c.Roles["editor"], types.PermissionAdmin) },
		// The two-step escalation: admin:manage first, admin with the next update
		"role gains admin:manage": func(c *types.RBACConfig) {
			c.Roles["editor"] = append(c.Roles["editor"], types.PermissionAdminManage)
		},
		"join admin:manage grant": func(c *types.RBACConfig) { c.Grants[3].Users = append(c.Grants[3].Users, "group:editors") },
		"admin:manage role becomes admin": func(c *types.RBACConfig) {
			c.Roles["adminmgr"] = []types.RBACPermission{types.PermissionAdmin}
		},
		"remove an admin": func(c *types.RBACConfig) { c.Groups["platform-admins"] = []string{"group:sre"} },
	}
	for name, mutate := range escalations {
		for _, force := range []bool{false, true} {
			_, err := server.UpdateDynamicConfig(editorCtx, candidate(mutate), force)
			if err == nil || !strings.Contains(err.Error(), "admin:manage") {
				t.Fatalf("%s (force %v): config editor must be denied with an admin:manage error, got %v", name, force, err)
			}
		}
	}
	for _, perm := range []types.RBACPermission{types.PermissionAdmin, types.PermissionAdminManage} {
		if err := server.enforceGlobalPerm(editorCtx, perm, ""); err == nil {
			t.Fatalf("rejected escalation went live: editor holds %s", perm)
		}
	}

	// Unrelated changes by the editor go through: a non-admin grant, a group
	// no admin grant references, an admin grant's description and targets
	unrelated := map[string]func(*types.RBACConfig){
		"non-admin grant":     func(c *types.RBACConfig) { c.Grants[2].Users = append(c.Grants[2].Users, "builtin:editor2") },
		"non-admin group":     func(c *types.RBACConfig) { c.Groups["editors"] = append(c.Groups["editors"], "builtin:editor2") },
		"admin grant comment": func(c *types.RBACConfig) { c.Grants[1].Description = "the platform admins" },
		"admin grant targets": func(c *types.RBACConfig) { c.Grants[1].Targets = []string{"/apps/**"} },
	}
	for name, mutate := range unrelated {
		if _, err := server.UpdateDynamicConfig(editorCtx, candidate(mutate), false); err != nil {
			t.Fatalf("%s: unrelated change by the config editor must be allowed: %v", name, err)
		}
	}

	// admin:manage and admin holders can change the admin surface
	if _, err := server.UpdateDynamicConfig(managerCtx, candidate(func(c *types.RBACConfig) { joinAdmins(c, "builtin:promoted1") }), false); err != nil {
		t.Fatalf("admin:manage holder must be allowed: %v", err)
	}
	if _, err := server.UpdateDynamicConfig(rootCtx, candidate(func(c *types.RBACConfig) { joinAdmins(c, "builtin:promoted2") }), false); err != nil {
		t.Fatalf("admin must be allowed: %v", err)
	}
	if _, err := server.UpdateDynamicConfig(trusted, candidate(func(c *types.RBACConfig) { joinAdmins(c, "builtin:promoted3") }), false); err != nil {
		t.Fatalf("trusted UDS call must be allowed: %v", err)
	}
	for _, user := range []string{"builtin:promoted1", "builtin:promoted2", "builtin:promoted3"} {
		if err := server.enforceGlobalPerm(rbacEnforcedCtx(trusted, user), types.PermissionAdmin, ""); err != nil {
			t.Fatalf("%s must be an admin after the accepted update: %v", user, err)
		}
	}

	// A scoped credential must name admin:manage literally: an admin scope
	// does not cover it, so the manager cannot turn their admin:manage role
	// into an admin role with a token scoped to config:update and admin
	scopedManager := server.apiTokenRequestContext(trusted, "builtin:manager", nil, []string{"config:update", "admin"}, InvokerRest, nil)
	if _, err := server.UpdateDynamicConfig(scopedManager, candidate(func(c *types.RBACConfig) {
		c.Roles["adminmgr"] = []types.RBACPermission{types.PermissionAdmin}
	}), false); err == nil || !strings.Contains(err.Error(), "admin:manage") {
		t.Fatalf("role switch with a token scoped without admin:manage must be denied: %v", err)
	}
	if err := server.enforceGlobalPerm(managerCtx, types.PermissionAdmin, ""); err == nil {
		t.Fatal("manager must not have become an admin")
	}
	scopedManager = server.apiTokenRequestContext(trusted, "builtin:manager", nil, []string{"config:update", "*"}, InvokerRest, nil)
	if _, err := server.UpdateDynamicConfig(scopedManager, candidate(func(c *types.RBACConfig) { joinAdmins(c, "builtin:promoted4") }), false); err == nil || !strings.Contains(err.Error(), "admin:manage") {
		t.Fatalf("a token scoped without admin:manage must be denied: %v", err)
	}
	scopedManager = server.apiTokenRequestContext(trusted, "builtin:manager", nil, []string{"config:update", "admin:manage"}, InvokerRest, nil)
	if _, err := server.UpdateDynamicConfig(scopedManager, candidate(func(c *types.RBACConfig) { joinAdmins(c, "builtin:promoted4") }), false); err != nil {
		t.Fatalf("a token scoped with admin:manage must be allowed: %v", err)
	}
}

func TestAdminSurfaceChangeInDraft(t *testing.T) {
	server, db, trusted := newAdminManageTestServer(t)
	defer db.Close()
	editorCtx := rbacEnforcedCtx(trusted, "builtin:editor")
	managerCtx := rbacEnforcedCtx(trusted, "builtin:manager")

	// Draft edits give early feedback: an admin surface change is rejected
	// at edit time for the editor and the draft stays untouched
	_, err := server.UpdateRBACDraft(editorCtx, "", func(c *types.RBACConfig) error {
		c.Groups["platform-admins"] = append(c.Groups["platform-admins"], "builtin:editor")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "admin:manage") {
		t.Fatalf("draft escalation must be denied: %v", err)
	}
	if _, err := db.GetConfigDraft(trusted); err != metadata.ErrNoConfigDraft {
		t.Fatalf("rejected draft edit must not be stored: %v", err)
	}

	draft, err := server.UpdateRBACDraft(editorCtx, "", func(c *types.RBACConfig) error {
		c.Groups["editors"] = append(c.Groups["editors"], "builtin:editor2")
		return nil
	})
	if err != nil {
		t.Fatalf("unrelated draft edit must be allowed: %v", err)
	}
	draft, err = server.UpdateRBACDraft(managerCtx, draft.DraftVersion, func(c *types.RBACConfig) error {
		c.Groups["platform-admins"] = append(c.Groups["platform-admins"], "builtin:promoted")
		return nil
	})
	if err != nil {
		t.Fatalf("admin:manage holder's draft edit must be allowed: %v", err)
	}

	// Publishing is the authoritative check, against the live config: the
	// editor cannot publish the manager's staged admin change
	if _, err := server.PublishRBACConfig(editorCtx, draft.DraftVersion, false); err == nil || !strings.Contains(err.Error(), "admin:manage") {
		t.Fatalf("editor publishing an admin change must be denied: %v", err)
	}
	if _, err := server.PublishRBACConfig(managerCtx, draft.DraftVersion, false); err != nil {
		t.Fatalf("manager publish must succeed: %v", err)
	}
	if err := server.enforceGlobalPerm(rbacEnforcedCtx(trusted, "builtin:promoted"), types.PermissionAdmin, ""); err != nil {
		t.Fatalf("promoted user must be an admin: %v", err)
	}
}

func TestBuiltinUserAdminGroupRequiresAdminManage(t *testing.T) {
	server, db, trusted := newAdminManageTestServer(t)
	defer db.Close()
	editorCtx := rbacEnforcedCtx(trusted, "builtin:editor")
	managerCtx := rbacEnforcedCtx(trusted, "builtin:manager")

	// Creating a user in an admin group (directly or nested) needs admin:manage
	for _, group := range []string{"platform-admins", "sre"} {
		_, err := server.CreateUpdateUser(editorCtx, "newadmin", types.UserUpdateRequest{Password: "a-long-password", Groups: []string{"dev", group}}, false)
		if err == nil || !strings.Contains(err.Error(), "admin:manage") {
			t.Fatalf("create in %s by the editor must be denied: %v", group, err)
		}
	}
	if _, err := server.GetUser(trusted, "newadmin"); err == nil {
		t.Fatal("denied create must not store the user")
	}
	if _, err := server.CreateUpdateUser(editorCtx, "dev1", types.UserUpdateRequest{Password: "a-long-password", Groups: []string{"dev", "editors"}}, false); err != nil {
		t.Fatalf("create in non-admin groups must be allowed: %v", err)
	}

	// Moving an existing user into or out of an admin group needs admin:manage;
	// other updates (password, other groups) do not
	if _, err := server.CreateUpdateUser(editorCtx, "dev1", types.UserUpdateRequest{Groups: []string{"dev", "sre"}}, true); err == nil || !strings.Contains(err.Error(), "admin:manage") {
		t.Fatalf("move into an admin group by the editor must be denied: %v", err)
	}
	if _, err := server.CreateUpdateUser(editorCtx, "dev1", types.UserUpdateRequest{Password: "another-long-password", Groups: []string{"qa"}}, true); err != nil {
		t.Fatalf("non-admin update must be allowed: %v", err)
	}
	if _, err := server.CreateUpdateUser(managerCtx, "dev1", types.UserUpdateRequest{Groups: []string{"qa", "sre"}}, true); err != nil {
		t.Fatalf("admin:manage holder must be allowed: %v", err)
	}
	if _, err := server.CreateUpdateUser(editorCtx, "dev1", types.UserUpdateRequest{Password: "yet-another-long-password"}, true); err != nil {
		t.Fatalf("password change of an admin user keeps the groups and needs no admin:manage: %v", err)
	}
	if _, err := server.CreateUpdateUser(editorCtx, "dev1", types.UserUpdateRequest{Groups: []string{"qa"}}, true); err == nil || !strings.Contains(err.Error(), "admin:manage") {
		t.Fatalf("removal from an admin group by the editor must be denied: %v", err)
	}
	if _, err := server.CreateUpdateUser(editorCtx, "dev1", types.UserUpdateRequest{Groups: []string{"qa", "sre", "dev"}}, true); err != nil {
		t.Fatalf("changing other groups while keeping the admin group must be allowed: %v", err)
	}
	if _, err := server.CreateUpdateUser(trusted, "dev1", types.UserUpdateRequest{Groups: []string{}}, true); err != nil {
		t.Fatalf("trusted UDS call must be allowed: %v", err)
	}
}
