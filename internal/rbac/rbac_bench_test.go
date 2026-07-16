// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"testing"

	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
)

// benchManager builds a manager with a representative config: a few groups
// (one with a regex member), roles and grants, none conferring admin
func benchManager(b *testing.B, enabled bool) *RBACManager {
	b.Helper()
	config := &types.RBACConfig{
		Enabled: enabled,
		Groups: map[string][]string{
			"developers": {"user1", "user2", "user3", "regex:dev_.*"},
			"ops":        {"user4", "group:developers"},
		},
		Roles: map[string][]types.RBACPermission{
			"viewer":   {types.PermissionAccess, types.PermissionRead},
			"deployer": {types.PermissionAppManage, "custom:reports"},
		},
		Grants: []types.RBACGrant{
			{Description: "viewers", Users: []string{"group:developers"},
				Roles: []string{"viewer"}, Targets: []string{"/test/**"}},
			{Description: "deployers", Users: []string{"group:ops"},
				Roles: []string{"deployer"}, Targets: []string{"example.com:/apps/**"}},
			{Description: "individual", Users: []string{"user5", "regex:svc_.*"},
				Roles: []string{"viewer"}, Targets: []string{"all"}},
		},
	}
	// Warn level, matching a production setup: the deny path debug logging
	// must not dominate the measurement
	l := zerolog.Nop().Level(zerolog.WarnLevel)
	logger := &types.Logger{Logger: &l}
	serverConfig := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}
	manager, err := NewRBACHandler(logger, config, serverConfig)
	if err != nil {
		b.Fatalf("failed to create RBACManager: %v", err)
	}
	return manager
}

// BenchmarkAuthorizeDisabled is the per-request app access check with RBAC
// disabled (the default), run on every app request
func BenchmarkAuthorizeDisabled(b *testing.B) {
	manager := benchManager(b, false)
	target := types.AppPathDomain{Path: "/test/app1"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := manager.AuthorizeInt("user1", target, types.PermissionAccess, nil, false); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuthorizeGrantMatch is the app access check with RBAC enabled and
// a grant matching through a group membership and a target glob
func BenchmarkAuthorizeGrantMatch(b *testing.B) {
	manager := benchManager(b, true)
	target := types.AppPathDomain{Path: "/test/app1"}
	groups := []string{"sso-group"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		allowed, err := manager.AuthorizeInt("user1", target, types.PermissionAccess, groups, false)
		if err != nil || !allowed {
			b.Fatalf("expected allowed, got %v err %v", allowed, err)
		}
	}
}

// BenchmarkAuthorizeDenied is the enabled-path deny: no grant matches the user
func BenchmarkAuthorizeDenied(b *testing.B) {
	manager := benchManager(b, true)
	target := types.AppPathDomain{Path: "/test/app1"}
	groups := []string{"sso-group"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		allowed, err := manager.AuthorizeInt("other_user", target, types.PermissionAccess, groups, false)
		if err != nil || allowed {
			b.Fatalf("expected denied, got %v err %v", allowed, err)
		}
	}
}

// BenchmarkGetAPIPermissions is the console's get_permissions call: the full
// permission enumeration for one app target
func BenchmarkGetAPIPermissions(b *testing.B) {
	manager := benchManager(b, true)
	target := types.AppPathDomain{Path: "/test/app1"}
	ctx := enforcedCtx("user1", "sso-group")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := manager.GetAPIPermissions(ctx, target, "someone"); err != nil {
			b.Fatal(err)
		}
	}
}
