// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// newAsUserTestServer builds a minimal server with two builtin users and the
// given RBAC config state
func newAsUserTestServer(t *testing.T, rbacConfig *types.RBACConfig) *Server {
	t.Helper()
	logger := testutil.TestLogger()
	config := &types.ServerConfig{
		BuiltinAuth: map[string]types.BuiltinAuthEntry{
			"alice": {Password: "unused", Groups: []string{"dev", "qa"}},
			"bob":   {Password: "unused"},
		},
	}
	rbacManager, err := rbac.NewRBACHandler(logger, rbacConfig, config)
	if err != nil {
		t.Fatalf("new rbac manager: %v", err)
	}
	return &Server{
		Logger:       logger,
		staticConfig: config,
		rbacManager:  rbacManager,
	}
}

func TestAsUserRequiresRBAC(t *testing.T) {
	server := newAsUserTestServer(t, &types.RBACConfig{Enabled: false})

	_, err := server.asUserRequestContext(context.Background(), "builtin:alice")
	if err == nil || !strings.Contains(err.Error(), "RBAC is not enabled") {
		t.Fatalf("expected RBAC not enabled error, got %v", err)
	}
}

func TestAsUserContextAttribution(t *testing.T) {
	server := newAsUserTestServer(t, &types.RBACConfig{Enabled: true})

	ctx, err := server.asUserRequestContext(context.Background(), "builtin:alice")
	if err != nil {
		t.Fatalf("as user context: %v", err)
	}
	testutil.AssertEqualsString(t, "userId", "builtin:alice", system.GetContextUserId(ctx))
	groups := system.GetContextGroups(ctx)
	testutil.AssertEqualsInt(t, "groups", 2, len(groups))
	testutil.AssertEqualsString(t, "group", "dev", groups[0])

	// The context is enforced, not trusted: the enforcement marker is the
	// per-request one app requests carry, so APIEnforced applies live config
	testutil.AssertEqualsBool(t, "rbac enabled", true, system.IsAppRBACEnabled(ctx))
	testutil.AssertEqualsBool(t, "trusted", false, system.IsTrustedOperation(ctx))

	// Groups default to an empty list when the entry has none configured
	ctx, err = server.asUserRequestContext(context.Background(), "builtin:bob")
	if err != nil {
		t.Fatalf("as user context: %v", err)
	}
	testutil.AssertEqualsInt(t, "groups", 0, len(system.GetContextGroups(ctx)))

	// A non-builtin provider id is taken literally with no groups, so grants
	// for SSO identities can be tested without creating the user
	ctx, err = server.asUserRequestContext(context.Background(), "github:carol")
	if err != nil {
		t.Fatalf("as user context: %v", err)
	}
	testutil.AssertEqualsString(t, "userId", "github:carol", system.GetContextUserId(ctx))
	testutil.AssertEqualsInt(t, "groups", 0, len(system.GetContextGroups(ctx)))
}

func TestAsUserValidation(t *testing.T) {
	server := newAsUserTestServer(t, &types.RBACConfig{Enabled: true})

	_, err := server.asUserRequestContext(context.Background(), "builtin:nosuchuser")
	if err == nil || !strings.Contains(err.Error(), "is not configured") {
		t.Fatalf("expected unknown builtin user error, got %v", err)
	}

	for _, invalid := range []string{"alice", "builtin:", ":alice"} {
		_, err := server.asUserRequestContext(context.Background(), invalid)
		if err == nil || !strings.Contains(err.Error(), "format is <provider>:<username>") {
			t.Fatalf("expected format error for %q, got %v", invalid, err)
		}
	}
}

func TestAsUserEnforcement(t *testing.T) {
	server := newAsUserTestServer(t, &types.RBACConfig{
		Enabled: true,
		Roles: map[string][]types.RBACPermission{
			"stopper": {types.PermissionServerStop},
		},
		Grants: []types.RBACGrant{
			// alice gets server:stop through her dev group, bob has no grant
			{Description: "dev group stops the server", Users: []string{"group:dev"},
				Roles: []string{"stopper"}, Targets: []string{"all"}},
		},
	})

	aliceCtx, err := server.asUserRequestContext(context.Background(), "builtin:alice")
	if err != nil {
		t.Fatalf("as user context: %v", err)
	}
	if err := server.enforceGlobalPerm(aliceCtx, types.PermissionServerStop, ""); err != nil {
		t.Fatalf("expected alice to hold server:stop through group:dev, got %v", err)
	}

	bobCtx, err := server.asUserRequestContext(context.Background(), "builtin:bob")
	if err != nil {
		t.Fatalf("as user context: %v", err)
	}
	err = server.enforceGlobalPerm(bobCtx, types.PermissionServerStop, "")
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionServerStop)) {
		t.Fatalf("expected server:stop denial for bob, got %v", err)
	}

	// The trusted administrative path (no as user) stays unenforced
	trustedCtx := system.WithTrustedOperation(context.Background())
	if err := server.enforceGlobalPerm(trustedCtx, types.PermissionServerStop, ""); err != nil {
		t.Fatalf("expected trusted context to pass, got %v", err)
	}
}
