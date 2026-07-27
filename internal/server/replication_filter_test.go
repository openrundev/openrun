// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// TestFilterReplicationEntries pins the replication_status visibility rules:
// metadata rows need config:basic_read, app rows are trimmed to the apps the
// caller holds app:read on and dropped when no using app is readable.
// Without RBAC enforcement everything passes through unchanged.
func TestFilterReplicationEntries(t *testing.T) {
	logger := testutil.TestLogger()
	config := &types.ServerConfig{
		BuiltinAuth: map[string]types.BuiltinAuthEntry{
			"alice": {Password: "unused"},
			"bob":   {Password: "unused"},
		},
	}
	rbacConfig := &types.RBACConfig{
		Enabled: true,
		Groups:  map[string][]string{},
		Roles: map[string][]types.RBACPermission{
			"viewer": {types.PermissionRead},
			"sys":    {types.PermissionConfigBasicRead},
		},
		Grants: []types.RBACGrant{
			{Users: []string{"builtin:alice"}, Roles: []string{"viewer"}, Targets: []string{"/visible*"}},
			{Users: []string{"builtin:alice"}, Roles: []string{"sys"}, Targets: []string{"all"}},
		},
	}
	rbacManager, err := rbac.NewRBACHandler(logger, rbacConfig, config)
	if err != nil {
		t.Fatalf("new rbac manager: %v", err)
	}
	server := &Server{
		Logger:       logger,
		staticConfig: config,
		rbacManager:  rbacManager,
	}
	server.apps = &AppStore{
		Logger: logger,
		server: server,
		allApps: []types.AppInfo{
			{AppPathDomain: types.AppPathDomain{Path: "/visible1"}, Id: "app_prd_v1"},
			{AppPathDomain: types.AppPathDomain{Path: "/hidden1"}, Id: "app_prd_h1"},
			{AppPathDomain: types.AppPathDomain{Path: "/hidden2"}, Id: "app_prd_h2"},
		},
	}

	entries := []types.ReplicationStatusEntry{
		{Kind: "metadata", Target: "metadata"},
		{Kind: "app", Target: "/bind/db1", AppPaths: []string{"/visible1", "/hidden1"}},
		{Kind: "app", Target: "/bind/db2", AppPaths: []string{"/hidden2"}},
	}

	// alice: metadata (config:basic_read) plus the app row trimmed to her
	// readable app; the all-hidden row is dropped
	ctx, err := server.asUserRequestContext(context.Background(), "builtin:alice")
	if err != nil {
		t.Fatalf("alice context: %v", err)
	}
	got, err := server.filterReplicationEntries(ctx, entries)
	if err != nil {
		t.Fatalf("filter as alice: %v", err)
	}
	testutil.AssertEqualsInt(t, "alice entries", 2, len(got))
	testutil.AssertEqualsString(t, "alice metadata", "metadata", got[0].Kind)
	testutil.AssertEqualsString(t, "alice app target", "/bind/db1", got[1].Target)
	testutil.AssertEqualsInt(t, "alice app paths", 1, len(got[1].AppPaths))
	testutil.AssertEqualsString(t, "alice app path", "/visible1", got[1].AppPaths[0])
	// The shared (cached) input must not be mutated by the trim
	testutil.AssertEqualsInt(t, "input app paths intact", 2, len(entries[1].AppPaths))

	// bob: no grants, nothing is visible
	ctx, err = server.asUserRequestContext(context.Background(), "builtin:bob")
	if err != nil {
		t.Fatalf("bob context: %v", err)
	}
	got, err = server.filterReplicationEntries(ctx, entries)
	if err != nil {
		t.Fatalf("filter as bob: %v", err)
	}
	testutil.AssertEqualsInt(t, "bob entries", 0, len(got))

	// Trusted (internal/CLI) operations are not RBAC enforced: everything
	// passes through unchanged
	got, err = server.filterReplicationEntries(system.WithTrustedOperation(context.Background()), entries)
	if err != nil {
		t.Fatalf("filter unenforced: %v", err)
	}
	testutil.AssertEqualsInt(t, "unenforced entries", 3, len(got))
}
