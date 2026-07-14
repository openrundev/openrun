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

func testUrlCtx(perms []string) context.Context {
	return context.WithValue(context.Background(),
		types.TESTURL_DIRECTIVES, NewUrlDirectives(perms, "/abc/_cl_perm=test"))
}

func TestUrlDirectivesMatching(t *testing.T) {
	dirs := NewUrlDirectives([]string{"app:read", "binding:create"}, "/abc/_cl_perm=x")
	if !dirs.MatchesPerm(types.PermissionRead) {
		t.Error("app:read should match")
	}
	if !dirs.MatchesPerm(types.PermissionBindingCreate) {
		t.Error("binding:create should match")
	}
	if dirs.MatchesPerm(types.PermissionBindingDelete) {
		t.Error("binding:delete should not match")
	}
	if dirs.MatchesPerm(types.PermissionCreate) {
		t.Error("app:create should not match")
	}

	// app:manage expands like a real grant: all app perms except app:approve
	dirs = NewUrlDirectives([]string{"app:manage"}, "")
	if !dirs.MatchesPerm(types.PermissionRead) || !dirs.MatchesPerm(types.PermissionDelete) ||
		!dirs.MatchesPerm(types.PermissionUpdate) {
		t.Error("app:manage should expand to app permissions")
	}
	if dirs.MatchesPerm(types.PermissionApprove) {
		t.Error("app:manage must not imply app:approve")
	}
	if dirs.MatchesPerm(types.PermissionBindingCreate) {
		t.Error("app:manage must not imply global permissions")
	}

	// app:update implies reload/apply/read, like real grants
	dirs = NewUrlDirectives([]string{"app:update"}, "")
	if !dirs.MatchesPerm(types.PermissionReload) || !dirs.MatchesPerm(types.PermissionRead) {
		t.Error("app:update should imply app:reload and app:read")
	}

	// Globs match, but never app:approve
	dirs = NewUrlDirectives([]string{"app:*"}, "")
	if !dirs.MatchesPerm(types.PermissionRead) || !dirs.MatchesPerm(types.PermissionDelete) {
		t.Error("app:* should match app permissions")
	}
	if dirs.MatchesPerm(types.PermissionApprove) {
		t.Error("glob must not match app:approve")
	}
	if dirs.MatchesPerm(types.PermissionBindingCreate) {
		t.Error("app:* must not match binding permissions")
	}

	// app:approve matches only by literal name
	dirs = NewUrlDirectives([]string{"app:approve"}, "")
	if !dirs.MatchesPerm(types.PermissionApprove) {
		t.Error("literal app:approve should match")
	}

	// Custom permissions match with and without the custom: prefix
	dirs = NewUrlDirectives([]string{"report_view"}, "")
	if !dirs.MatchesCustomPerm("report_view") {
		t.Error("custom perm should match")
	}
	if !dirs.MatchesCustomPerm("custom:report_view") {
		t.Error("custom perm should match with prefix")
	}
	if dirs.MatchesCustomPerm("report_edit") {
		t.Error("other custom perm should not match")
	}
	if dirs.MatchesPerm(types.PermissionRead) {
		t.Error("custom perm should not match builtin perms")
	}

	// Empty simulated set denies everything
	dirs = NewUrlDirectives([]string{}, "")
	if !dirs.HasPerms() {
		t.Error("empty (non-nil) perms should count as present")
	}

	// nil safety
	var nilDirs *UrlDirectives
	if nilDirs.HasPerms() || nilDirs.MatchesPerm(types.PermissionRead) || nilDirs.MatchesCustomPerm("x") {
		t.Error("nil directives should not match")
	}
	if NewUrlDirectives(nil, "/abc/_cl_other=x").HasPerms() {
		t.Error("nil perms means no simulated set")
	}
}

func TestUrlDirectivesContextHelpers(t *testing.T) {
	ctx := context.Background()
	if GetUrlDirectives(ctx) != nil || HasTestUrlPerms(ctx) || GetTestUrlPrefix(ctx) != "" {
		t.Error("empty context should have no directives")
	}
	if _, ok := GetTestUrlPerms(ctx); ok {
		t.Error("empty context should have no perms")
	}

	ctx = testUrlCtx([]string{"app:read"})
	if !HasTestUrlPerms(ctx) {
		t.Error("perms should be present")
	}
	perms, ok := GetTestUrlPerms(ctx)
	if !ok || !slices.Equal(perms, []string{"app:read"}) {
		t.Errorf("perms: got %v %v", perms, ok)
	}
	if GetTestUrlPrefix(ctx) != "/abc/_cl_perm=test" {
		t.Errorf("prefix: got %q", GetTestUrlPrefix(ctx))
	}
}

// newTestUrlManager builds a manager with RBAC config disabled, the state in
// which test URL directives are honored
func newTestUrlManager(t *testing.T) *RBACManager {
	t.Helper()
	return newTestManager(t, &types.RBACConfig{Enabled: false})
}

func TestUrlDirectivesManagementAPI(t *testing.T) {
	manager := newTestUrlManager(t)
	target := types.AppPathDomain{Domain: "example.com", Path: "/abc"}

	// Without directives, enforcement is inactive: allow-all
	ctx := context.Background()
	if manager.APIEnforced(ctx) {
		t.Error("APIEnforced should be false without directives")
	}
	authorized, err := manager.AuthorizeAPI(ctx, types.PermissionDelete, target, "")
	if err != nil || !authorized {
		t.Errorf("allow-all expected without directives: %v %v", authorized, err)
	}
	perms, err := manager.GetAPIPermissions(ctx, target, "")
	if err != nil || len(perms) != len(allPermissionNames) {
		t.Errorf("all perms expected without directives: %d %v", len(perms), err)
	}

	// With directives, the simulated set replaces allow-all
	ctx = testUrlCtx([]string{"app:read", "binding:create"})
	if !manager.APIEnforced(ctx) {
		t.Error("APIEnforced should be true with directives")
	}

	authorized, err = manager.AuthorizeAPI(ctx, types.PermissionRead, target, "")
	if err != nil || !authorized {
		t.Errorf("simulated app:read should authorize: %v %v", authorized, err)
	}
	authorized, err = manager.AuthorizeAPI(ctx, types.PermissionDelete, target, "")
	if err != nil || authorized {
		t.Errorf("unsimulated app:delete should be denied: %v %v", authorized, err)
	}
	// The owner rule is bypassed under simulation: owner match does not widen
	authorized, err = manager.AuthorizeAPI(ctx, types.PermissionDelete, target, "anonymous")
	if err != nil || authorized {
		t.Errorf("owner rule should not apply under simulation: %v %v", authorized, err)
	}

	authorized, err = manager.AuthorizeGlobalAPI(ctx, types.PermissionBindingCreate, "")
	if err != nil || !authorized {
		t.Errorf("simulated binding:create should authorize: %v %v", authorized, err)
	}
	authorized, err = manager.AuthorizeGlobalAPI(ctx, types.PermissionSyncCreate, "")
	if err != nil || authorized {
		t.Errorf("unsimulated sync:create should be denied: %v %v", authorized, err)
	}

	// get_permissions reports exactly the simulated set (with implications)
	perms, err = manager.GetAPIPermissions(ctx, target, "")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(perms)
	want := []string{"app:read", "binding:create"}
	if !slices.Equal(perms, want) {
		t.Errorf("simulated perms: want %v got %v", want, perms)
	}

	// app:manage simulation expands, still excluding app:approve
	ctx = testUrlCtx([]string{"app:manage"})
	perms, err = manager.GetAPIPermissions(ctx, target, "")
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(perms, string(types.PermissionApprove)) {
		t.Error("app:approve must not be reported for simulated app:manage")
	}
	if !slices.Contains(perms, string(types.PermissionDelete)) || !slices.Contains(perms, string(types.PermissionRead)) {
		t.Errorf("expanded app perms expected, got %v", perms)
	}
}

func TestBuildUrlDirectivesRoles(t *testing.T) {
	// Roles resolve even when the RBAC config is disabled (the state in which
	// test URL directives are honored), with hierarchy flattened
	rbacConfig := &types.RBACConfig{
		Enabled: false,
		Roles: map[string][]types.RBACPermission{
			"viewer":   {"app:read", "custom:report_view"},
			"editor":   {"role:viewer", "app:update", "custom:report_edit"},
			"operator": {"binding:read"},
		},
	}
	manager, err := NewRBACHandler(testutil.TestLogger(), rbacConfig, &types.ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}

	// No roles: same as the plain constructor, Perms stays nil when perms is nil
	dirs, err := manager.BuildUrlDirectives(nil, nil, "/abc/_cl_x")
	if err != nil || dirs.HasPerms() {
		t.Fatalf("no perms expected: %+v %v", dirs, err)
	}

	// Single role: builtin perms match with implications, custom perms are
	// derived into the app visible list
	dirs, err = manager.BuildUrlDirectives(nil, []string{"editor"}, "/abc/_cl_role=editor")
	if err != nil {
		t.Fatal(err)
	}
	if !dirs.HasPerms() {
		t.Fatal("simulation should be active with roles")
	}
	// editor includes viewer (hierarchy) and app:update implies reload/read
	for _, perm := range []types.RBACPermission{types.PermissionRead, types.PermissionUpdate, types.PermissionReload} {
		if !dirs.MatchesPerm(perm) {
			t.Errorf("%s should match for editor", perm)
		}
	}
	if dirs.MatchesPerm(types.PermissionDelete) || dirs.MatchesPerm(types.PermissionBindingRead) {
		t.Error("perms outside the role should not match")
	}
	if !dirs.MatchesCustomPerm("report_view") || !dirs.MatchesCustomPerm("report_edit") {
		t.Error("role custom perms should match")
	}
	gotPerms := slices.Clone(dirs.Perms)
	slices.Sort(gotPerms)
	if !slices.Equal(gotPerms, []string{"report_edit", "report_view"}) {
		t.Errorf("derived custom perms: got %v", dirs.Perms)
	}

	// Multiple roles union; explicit perms merge in and are not duplicated
	dirs, err = manager.BuildUrlDirectives([]string{"app:delete", "report_view"}, []string{"viewer", "operator"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !dirs.MatchesPerm(types.PermissionDelete) || !dirs.MatchesPerm(types.PermissionBindingRead) ||
		!dirs.MatchesPerm(types.PermissionRead) {
		t.Error("union of roles and explicit perms should match")
	}
	gotPerms = slices.Clone(dirs.Perms)
	slices.Sort(gotPerms)
	if !slices.Equal(gotPerms, []string{"app:delete", "report_view"}) {
		t.Errorf("perms list: got %v", dirs.Perms)
	}

	// A role that confers no custom perms still activates simulation
	dirs, err = manager.BuildUrlDirectives(nil, []string{"operator"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !dirs.HasPerms() || len(dirs.Perms) != 0 {
		t.Errorf("empty but non-nil perms expected, got %v", dirs.Perms)
	}
	if !dirs.MatchesPerm(types.PermissionBindingRead) {
		t.Error("binding:read should match for operator")
	}

	// The openrun-admin role holds the admin super-user permission, so it
	// matches everything, including approve and arbitrary custom permissions
	dirs, err = manager.BuildUrlDirectives(nil, []string{"openrun-admin"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !dirs.MatchesPerm(types.PermissionApprove) || !dirs.MatchesPerm(types.PermissionServerStop) ||
		!dirs.MatchesCustomPerm("anything") {
		t.Error("openrun-admin role should match all permissions")
	}

	// Unknown role fails closed
	_, err = manager.BuildUrlDirectives(nil, []string{"viewer", "bogus"}, "")
	if err == nil || !strings.Contains(err.Error(), "unknown role \"bogus\"") {
		t.Errorf("unknown role error expected, got %v", err)
	}

	// Role simulation drives the management API layer
	ctx := context.WithValue(context.Background(), types.TESTURL_DIRECTIVES, mustBuild(t, manager, nil, []string{"viewer"}))
	perms, err := manager.GetAPIPermissions(ctx, types.AppPathDomain{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(perms, string(types.PermissionRead)) || slices.Contains(perms, string(types.PermissionDelete)) {
		t.Errorf("api perms for viewer: got %v", perms)
	}
	authorized, err := manager.AuthorizeAny(ctx, []string{"report_view"})
	if err != nil || !authorized {
		t.Errorf("permit via role custom perm should authorize: %v %v", authorized, err)
	}
}

func mustBuild(t *testing.T, manager *RBACManager, perms, roles []string) *UrlDirectives {
	t.Helper()
	dirs, err := manager.BuildUrlDirectives(perms, roles, "/abc/_cl_test")
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

func TestUrlDirectivesAppLevel(t *testing.T) {
	manager := newTestUrlManager(t)

	ctx := testUrlCtx([]string{"report_view", "app:read"})

	// AuthorizeAny matches permit lists against the simulated set
	authorized, err := manager.AuthorizeAny(ctx, []string{"report_view", "report_edit"})
	if err != nil || !authorized {
		t.Errorf("permit with simulated perm should authorize: %v %v", authorized, err)
	}
	authorized, err = manager.AuthorizeAny(ctx, []string{"report_edit"})
	if err != nil || authorized {
		t.Errorf("permit without simulated perm should be denied: %v %v", authorized, err)
	}

	// Authorize with custom and builtin permissions
	authorized, err = manager.Authorize(ctx, "report_view", true)
	if err != nil || !authorized {
		t.Errorf("simulated custom perm should authorize: %v %v", authorized, err)
	}
	authorized, err = manager.Authorize(ctx, types.PermissionRead, false)
	if err != nil || !authorized {
		t.Errorf("simulated app:read should authorize: %v %v", authorized, err)
	}
	authorized, err = manager.Authorize(ctx, types.PermissionDelete, false)
	if err != nil || authorized {
		t.Errorf("unsimulated app:delete should be denied: %v %v", authorized, err)
	}

	// GetCustomPermissions returns the simulated set as-is
	perms, err := manager.GetCustomPermissions(ctx)
	if err != nil || !slices.Equal(perms, []string{"report_view", "app:read"}) {
		t.Errorf("custom perms: got %v %v", perms, err)
	}
}
