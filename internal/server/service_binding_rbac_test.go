// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/types"
)

// TestServiceBindingRBAC verifies the service and binding management APIs
// enforce the scoped service:*/binding:* permissions: target globs match the
// service id / binding path, listings are filtered, the owner rule covers the
// creator's own entries, and creating bindings needs source authority
func TestServiceBindingRBAC(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	registerApplyTestBinding(t, db, ctx)

	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Enabled: true,
		Roles: map[string][]types.RBACPermission{
			"dbops": {types.PermissionServiceManage, types.PermissionBindingManage},
		},
		Grants: []types.RBACGrant{
			{Description: "scoped dbops", Users: []string{"dbops"}, Roles: []string{"dbops"},
				Targets: []string{"service:applytest/*", "binding:/apps/**"}},
			{Description: "other scope", Users: []string{"other"}, Roles: []string{"dbops"},
				Targets: []string{"service:mysql/*", "binding:/elsewhere/**"}},
		},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}

	dbopsCtx := rbacEnforcedCtx(ctx, "dbops")
	otherCtx := rbacEnforcedCtx(ctx, "other")

	// Create a second service as dbops: service:create is scoped by the id glob
	newService := &types.Service{Name: "secondary", ServiceType: "applytest", Config: map[string]string{}}
	if err := server.CreateService(dbopsCtx, newService, false); err != nil {
		t.Fatalf("dbops create service: %v", err)
	}
	if newService.CreatedBy != "dbops" {
		t.Fatalf("service created_by = %q, want dbops", newService.CreatedBy)
	}
	err := server.CreateService(otherCtx, &types.Service{Name: "third", ServiceType: "applytest",
		Config: map[string]string{}}, false)
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionServiceCreate)) {
		t.Fatalf("expected service:create denial outside glob, got %v", err)
	}

	// Listing is filtered to the readable services ("primary" from the fixture
	// has no created_by, "secondary" is owned by dbops and matched by the glob)
	services, err := server.ListServices(dbopsCtx, "", "")
	if err != nil {
		t.Fatalf("dbops list services: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("dbops should see 2 applytest services, got %d", len(services))
	}
	services, err = server.ListServices(otherCtx, "", "")
	if err != nil {
		t.Fatalf("other list services: %v", err)
	}
	if len(services) != 0 {
		t.Fatalf("other should see no services, got %d", len(services))
	}

	// Binding create needs binding:create on the path and service:bind on the source
	createReq := &types.CreateBindingRequest{Path: "/apps/db1", Source: "applytest/primary"}
	if _, err := server.CreateBinding(dbopsCtx, createReq, false); err != nil {
		t.Fatalf("dbops create binding: %v", err)
	}
	_, err = server.CreateBinding(otherCtx, &types.CreateBindingRequest{
		Path: "/elsewhere/db1", Source: "applytest/primary"}, false)
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionServiceBind)) {
		t.Fatalf("expected service:bind denial for source outside glob, got %v", err)
	}

	// Binding operations are scoped by the binding path
	if _, err := server.GetBinding(dbopsCtx, "/apps/db1"); err != nil {
		t.Fatalf("dbops get binding: %v", err)
	}
	_, err = server.GetBinding(otherCtx, "/apps/db1")
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionBindingRead)) {
		t.Fatalf("expected binding:read denial outside glob, got %v", err)
	}

	// show-account reveals credentials: it needs binding:reveal, which
	// binding:manage does not imply — even the creator holding manage on the
	// path is denied without an explicit grant
	_, err = server.GetBindingAccount(dbopsCtx, "/apps/db1", false)
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionBindingReveal)) {
		t.Fatalf("expected binding:reveal denial for show-account, got %v", err)
	}
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Enabled: true,
		Roles: map[string][]types.RBACPermission{
			"dbops":    {types.PermissionServiceManage, types.PermissionBindingManage},
			"revealer": {types.PermissionBindingReveal},
		},
		Grants: []types.RBACGrant{
			{Description: "scoped dbops", Users: []string{"dbops"}, Roles: []string{"dbops"},
				Targets: []string{"service:applytest/*", "binding:/apps/**"}},
			{Description: "revealer", Users: []string{"revealer"}, Roles: []string{"revealer"},
				Targets: []string{"binding:/apps/**"}},
		},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	if _, err := server.GetBindingAccount(rbacEnforcedCtx(ctx, "revealer"), "/apps/db1", false); err != nil {
		t.Fatalf("explicit binding:reveal grant show-account: %v", err)
	}

	// The owner rule covers entries outside the user's grant targets: "other"
	// creates a binding in their own scope, then keeps access through ownership
	// even after the grants are narrowed away
	if _, err := server.CreateBinding(rbacEnforcedCtx(ctx, "admin"), &types.CreateBindingRequest{
		Path: "/elsewhere/owned", Source: "applytest/primary"}, false); err != nil {
		t.Fatalf("admin create binding: %v", err)
	}
	// created by the admin identity; re-create one owned by "other"
	if err := server.DeleteBinding(rbacEnforcedCtx(ctx, "admin"), "/elsewhere/owned", false); err != nil {
		t.Fatalf("admin delete binding: %v", err)
	}
	if _, err := server.CreateBinding(rbacEnforcedCtx(ctx, "admin"), &types.CreateBindingRequest{
		Path: "/apps/adminowned", Source: "applytest/primary"}, false); err != nil {
		t.Fatalf("admin create binding: %v", err)
	}
	// dbops can read it through the binding:/apps/** grant even though admin owns it
	if _, err := server.GetBinding(dbopsCtx, "/apps/adminowned"); err != nil {
		t.Fatalf("dbops get admin-owned binding: %v", err)
	}

	// Attaching a binding to an app requires binding:use on it: "other" holds
	// app perms via a new grant but no binding:use on /apps/db1
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Enabled: true,
		Roles: map[string][]types.RBACPermission{
			"appdev": {types.PermissionAppManage},
			"dbops":  {types.PermissionServiceManage, types.PermissionBindingManage},
		},
		Grants: []types.RBACGrant{
			{Description: "app dev", Users: []string{"other"}, Roles: []string{"appdev"}, Targets: []string{"all"}},
			{Description: "scoped dbops", Users: []string{"dbops"}, Roles: []string{"dbops"},
				Targets: []string{"service:applytest/*", "binding:/apps/**"}},
		},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	_, err = server.resolveAppBindings(rbacEnforcedCtx(ctx, "other"), tx, "app_prd_x",
		[]string{"/apps/db1"}, nil, false, nil)
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionBindingUse)) {
		t.Fatalf("expected binding:use denial on attach, got %v", err)
	}
	// Already-attached bindings are kept without a new check
	resolved, err := server.resolveAppBindings(rbacEnforcedCtx(ctx, "other"), tx, "app_prd_x",
		[]string{"/apps/db1"}, []string{"/apps/db1"}, false, nil)
	if err != nil || len(resolved) != 1 {
		t.Fatalf("existing binding should be kept without a check, got %v err %v", resolved, err)
	}
	tx.Rollback() //nolint:errcheck

	// The public listing (REST handler and plugin) is filtered to binding:read:
	// "other" holds only app permissions, so no bindings are enumerable
	listed, err := server.ListBindings(rbacEnforcedCtx(ctx, "other"), "")
	if err != nil {
		t.Fatalf("other list bindings: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("other should see no bindings, got %d", len(listed))
	}
	listed, err = server.ListBindings(dbopsCtx, "")
	if err != nil {
		t.Fatalf("dbops list bindings: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("dbops should see 2 bindings under /apps/**, got %d", len(listed))
	}
	// The internal listing used by the apply diff stays unfiltered
	internal, err := server.listBindingsInternal(rbacEnforcedCtx(ctx, "other"), "")
	if err != nil {
		t.Fatalf("internal list bindings: %v", err)
	}
	if len(internal) != 2 {
		t.Fatalf("internal listing should see all 2 bindings, got %d", len(internal))
	}
}

// TestBindingStagingServiceBindRBAC verifies that creating a base binding on a
// service with a linked staging service requires service:bind on BOTH service
// ids: the staged account artifacts are provisioned on the staging service, so
// a grant scoped to only the main service must not reach it
func TestBindingStagingServiceBindRBAC(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	registerApplyTestBinding(t, db, ctx)

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	for _, service := range []*types.Service{
		{Id: types.ID_PREFIX_SERVICE + "mainsvc", Name: "mainsvc", ServiceType: "applytest",
			Staging: "stagesvc", Config: map[string]string{}},
		{Id: types.ID_PREFIX_SERVICE + "stagesvc", Name: "stagesvc", ServiceType: "applytest",
			Config: map[string]string{}},
	} {
		if err := db.CreateService(ctx, tx, service); err != nil {
			t.Fatalf("create service %s: %v", service.Name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit services: %v", err)
	}

	makeConfig := func(serviceTarget string) *types.RBACConfig {
		return &types.RBACConfig{
			Enabled: true,
			Roles: map[string][]types.RBACPermission{
				"binder": {types.PermissionBindingCreate, types.PermissionServiceBind},
			},
			Grants: []types.RBACGrant{
				{Description: "binder", Users: []string{"binder"}, Roles: []string{"binder"},
					Targets: []string{"binding:/apps/**", serviceTarget}},
			},
		}
	}

	// Grant scoped to the main service only: creating the binding is denied on
	// the staging service, before any account artifacts are provisioned
	if err := server.rbacManager.UpdateRBACConfig(makeConfig("service:applytest/mainsvc")); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	binderCtx := rbacEnforcedCtx(ctx, "binder")
	_, err = server.CreateBinding(binderCtx, &types.CreateBindingRequest{
		Path: "/apps/sb1", Source: "applytest/mainsvc"}, false)
	if err == nil || !strings.Contains(err.Error(), "applytest/stagesvc") ||
		!strings.Contains(err.Error(), string(types.PermissionServiceBind)) {
		t.Fatalf("expected service:bind denial on the staging service, got %v", err)
	}

	// The source preflight (shared by builder publish, apply and version
	// switch) makes the same main-plus-staging check without reaching
	// createBindingTx
	tx, err = db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	err = server.enforceBindingSource(binderCtx, tx, "applytest/mainsvc")
	if err == nil || !strings.Contains(err.Error(), "applytest/stagesvc") {
		t.Fatalf("expected preflight denial on the staging service, got %v", err)
	}
	tx.Rollback() //nolint:errcheck

	// A grant covering both services succeeds
	if err := server.rbacManager.UpdateRBACConfig(makeConfig("service:applytest/*")); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	if _, err := server.CreateBinding(binderCtx, &types.CreateBindingRequest{
		Path: "/apps/sb1", Source: "applytest/mainsvc"}, false); err != nil {
		t.Fatalf("create binding with both services granted: %v", err)
	}
}

// TestServiceDefaultDisplacementRBAC verifies that making a service the type
// default requires service:update on the CURRENT default service: bare-type
// binding sources resolve to the default, so displacing it is a change to
// that service, not just to the one being promoted
func TestServiceDefaultDisplacementRBAC(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	registerApplyTestBinding(t, db, ctx) // creates applytest/primary as the default

	makeConfig := func(target string) *types.RBACConfig {
		return &types.RBACConfig{
			Enabled: true,
			Roles: map[string][]types.RBACPermission{
				"teamdev": {types.PermissionServiceManage},
			},
			Grants: []types.RBACGrant{
				{Description: "teamdev", Users: []string{"teamdev"}, Roles: []string{"teamdev"},
					Targets: []string{target}},
			},
		}
	}
	if err := server.rbacManager.UpdateRBACConfig(makeConfig("service:applytest/team*")); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	teamCtx := rbacEnforcedCtx(ctx, "teamdev")

	// Creating a service inside the glob works; making it the default would
	// displace applytest/primary, which the grant does not cover
	teamService := &types.Service{Name: "teamsvc", ServiceType: "applytest", Config: map[string]string{}}
	if err := server.CreateService(teamCtx, teamService, false); err != nil {
		t.Fatalf("create team service: %v", err)
	}
	teamService.IsDefault = true
	err := server.UpdateService(teamCtx, teamService, false)
	if err == nil || !strings.Contains(err.Error(), "applytest/primary") ||
		!strings.Contains(err.Error(), string(types.PermissionServiceUpdate)) {
		t.Fatalf("expected service:update denial on the displaced default, got %v", err)
	}
	// Creating a new service directly as the default is denied the same way
	err = server.CreateService(teamCtx, &types.Service{Name: "teamsvc2", ServiceType: "applytest",
		IsDefault: true, Config: map[string]string{}}, false)
	if err == nil || !strings.Contains(err.Error(), "applytest/primary") {
		t.Fatalf("expected service:update denial on create-as-default, got %v", err)
	}

	// With the current default in scope, the displacement is allowed
	if err := server.rbacManager.UpdateRBACConfig(makeConfig("service:applytest/*")); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	if err := server.UpdateService(teamCtx, teamService, false); err != nil {
		t.Fatalf("update service to default with both in scope: %v", err)
	}
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	newDefault, err := db.GetDefaultService(ctx, tx, "applytest")
	if err != nil || newDefault.Name != "teamsvc" {
		t.Fatalf("default service = %v (err %v), want teamsvc", newDefault, err)
	}
}

// TestVersionSwitchBindingRBAC verifies that switching an app to a version
// whose metadata re-attaches a since-removed binding requires binding:use on
// that binding: the switch hands the binding credentials back to the app
func TestVersionSwitchBindingRBAC(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	registerApplyTestBinding(t, db, ctx)

	if _, err := server.CreateBinding(rbacEnforcedCtx(ctx, "admin"), &types.CreateBindingRequest{
		Path: "/apps/db1", Source: "applytest/primary"}, false); err != nil {
		t.Fatalf("admin create binding: %v", err)
	}

	// App owned by "switcher" at version 2 (no bindings); version 1 carried
	// the binding, so switching back re-attaches it
	appEntry := &types.AppEntry{
		Id:        types.ID_PREFIX_APP_PROD + "switchapp",
		Path:      "/apps/vs",
		SourceUrl: t.TempDir(),
		UserID:    "switcher",
	}
	appEntry.Metadata.VersionMetadata.Version = 2
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	if err := db.CreateApp(ctx, tx, appEntry); err != nil {
		t.Fatalf("create app: %v", err)
	}
	fileStore, err := metadata.NewFileStore(appEntry.Id, 2, db, tx)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	v1 := types.AppMetadata{Bindings: []string{"/apps/db1"}}
	v1.VersionMetadata.Version = 1
	if err := fileStore.AddAppVersionDisk(ctx, tx, v1, types.NO_SOURCE); err != nil {
		t.Fatalf("add version 1: %v", err)
	}
	v2 := types.AppMetadata{}
	v2.VersionMetadata.Version = 2
	v2.VersionMetadata.PreviousVersion = 1
	if err := fileStore.AddAppVersionDisk(ctx, tx, v2, types.NO_SOURCE); err != nil {
		t.Fatalf("add version 2: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit app: %v", err)
	}
	server.apps.ResetAllAppCache()

	// The owner holds app:update through the owner rule but no binding:use
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{Enabled: true}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	switcherCtx := rbacEnforcedCtx(ctx, "switcher")
	_, err = server.VersionSwitch(switcherCtx, "/apps/vs", true, "1")
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionBindingUse)) {
		t.Fatalf("expected binding:use denial on version switch, got %v", err)
	}

	// With binding:use granted the switch is allowed
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Enabled: true,
		Roles: map[string][]types.RBACPermission{
			"user-of-bindings": {types.PermissionBindingUse},
		},
		Grants: []types.RBACGrant{
			{Description: "binding user", Users: []string{"switcher"},
				Roles: []string{"user-of-bindings"}, Targets: []string{"binding:/apps/**"}},
		},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	result, err := server.VersionSwitch(switcherCtx, "/apps/vs", true, "1")
	if err != nil {
		t.Fatalf("version switch with binding:use granted: %v", err)
	}
	if result.ToVersion != 1 {
		t.Fatalf("switched to version %d, want 1", result.ToVersion)
	}
}

// TestPreviewAndBuilderBindingRBAC verifies the two indirect binding attach
// paths enforce binding:use: preview apps copy the main app's bindings into a
// new caller-owned app, and builder fork publishes export the original app's
// bindings into the new app's stanza
func TestPreviewAndBuilderBindingRBAC(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	registerApplyTestBinding(t, db, ctx)

	// A binding owned by admin, attached to an app owned by "previewer"
	if _, err := server.CreateBinding(rbacEnforcedCtx(ctx, "admin"), &types.CreateBindingRequest{
		Path: "/apps/db1", Source: "applytest/primary"}, false); err != nil {
		t.Fatalf("admin create binding: %v", err)
	}
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	appEntry := &types.AppEntry{
		Id:        types.ID_PREFIX_APP_PROD + "previewapp",
		Path:      "/apps/pv",
		SourceUrl: t.TempDir(),
		UserID:    "previewer",
	}
	appEntry.Metadata.Bindings = []string{"/apps/db1"}
	if err := db.CreateApp(ctx, tx, appEntry); err != nil {
		t.Fatalf("create app: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit app: %v", err)
	}
	server.apps.ResetAllAppCache()

	// The owner holds app:preview through the owner rule but no binding:use on
	// the attached binding: preview creation is denied before any app is made
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{Enabled: true}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	previewerCtx := rbacEnforcedCtx(ctx, "previewer")
	_, err = server.PreviewApp(previewerCtx, "/apps/pv", "abc123", false, false)
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionBindingUse)) {
		t.Fatalf("expected binding:use denial on preview, got %v", err)
	}

	// With binding:use granted the binding gate passes: the preview then fails
	// on the non-git source, proving the denial above came from the gate
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Enabled: true,
		Roles: map[string][]types.RBACPermission{
			"user-of-bindings": {types.PermissionBindingUse},
		},
		Grants: []types.RBACGrant{
			{Description: "binding user", Users: []string{"previewer"},
				Roles: []string{"user-of-bindings"}, Targets: []string{"binding:/apps/**"}},
		},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	_, err = server.PreviewApp(previewerCtx, "/apps/pv", "abc123", false, false)
	if err == nil || !strings.Contains(err.Error(), "source is not git") {
		t.Fatalf("expected non-git source error after the binding gate, got %v", err)
	}

	// The builder publish stanza export enforces the same rule on the exported
	// binding references, before the git/apps-file mutation
	_, err = server.builderExportStanza(rbacEnforcedCtx(ctx, "someone"), "/apps/pv",
		"/apps/forked", "srcurl", types.BuilderGitConfig{})
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionBindingUse)) {
		t.Fatalf("expected binding:use denial on builder export, got %v", err)
	}
	stanza, err := server.builderExportStanza(previewerCtx, "/apps/pv",
		"/apps/forked", "srcurl", types.BuilderGitConfig{})
	if err != nil {
		t.Fatalf("builder export with binding:use granted: %v", err)
	}
	if !strings.Contains(stanza, "/apps/db1") {
		t.Fatalf("exported stanza should carry the binding, got %q", stanza)
	}
}
