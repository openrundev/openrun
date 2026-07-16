// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// TestRegexFullMatch verifies regex: user patterns must match the entire user
// id: an unanchored pattern must not match a superstring of the intended ids
// (e.g. .*@example\.com matching evil@example.com.attacker.io)
func TestRegexFullMatch(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, &types.RBACConfig{
		Enabled: true,
		Groups: map[string][]string{
			"emails": {"regex:.*@example\\.com"},
		},
		Roles: map[string][]types.RBACPermission{
			"read": {types.PermissionRead},
		},
		Grants: []types.RBACGrant{
			{Description: "regex grant", Users: []string{"regex:dev_.*"},
				Roles: []string{"read"}, Targets: []string{"/test"}},
			{Description: "group regex grant", Users: []string{"group:emails"},
				Roles: []string{"read"}, Targets: []string{"/test"}},
		},
	})

	tests := []struct {
		user    string
		allowed bool
	}{
		{"dev_john", true},
		{"xdev_john", false}, // pattern must match from the start of the user id
		{"user@example.com", true},
		{"user@example.com.attacker.io", false}, // and up to the end of the user id
		{"", false},                             // empty user fails closed, even though .* matches ""
	}
	for _, tt := range tests {
		allowed, err := manager.AuthorizeInt(tt.user, testTarget(), types.PermissionRead, []string{}, false)
		if err != nil {
			t.Fatalf("user %q: unexpected error: %v", tt.user, err)
		}
		if allowed != tt.allowed {
			t.Errorf("user %q: expected %v, got %v", tt.user, tt.allowed, allowed)
		}
	}
}

// TestGrantTargetValidation verifies malformed target globs are rejected when
// the config is updated, instead of erroring authorization checks at request time
func TestGrantTargetValidation(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}
	roles := map[string][]types.RBACPermission{"read": {types.PermissionRead}}

	_, err := NewRBACHandler(logger, grantConfig(roles,
		types.RBACGrant{Description: "bad target", Users: []string{"user1"},
			Roles: []string{"read"}, Targets: []string{"/app["}},
	), serverConfig)
	if err == nil || !strings.Contains(err.Error(), "invalid target") {
		t.Errorf("expected invalid target error, got %v", err)
	}

	// Valid glob forms are accepted
	if _, err := NewRBACHandler(logger, grantConfig(roles,
		types.RBACGrant{Description: "good targets", Users: []string{"user1"}, Roles: []string{"read"},
			Targets: []string{"all", "*:**", "/app/**", "example.com:/app*", "{a,b}.example.com:/x"}},
	), serverConfig); err != nil {
		t.Errorf("valid targets should be accepted, got %v", err)
	}

	// A disabled config is not validated, so server startup is never blocked
	disabled := grantConfig(roles,
		types.RBACGrant{Description: "bad target", Users: []string{"user1"},
			Roles: []string{"read"}, Targets: []string{"/app["}})
	disabled.Enabled = false
	if _, err := NewRBACHandler(logger, disabled, serverConfig); err != nil {
		t.Errorf("disabled config must not be validated, got %v", err)
	}
}

// TestUpdateRBACConfigAtomic verifies a rejected config update leaves the
// manager fully on the previous config: the old grants keep working and the
// enabled state stays consistent, with no partially updated internal state
func TestUpdateRBACConfigAtomic(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, grantConfig(
		map[string][]types.RBACPermission{"read": {types.PermissionRead}},
		types.RBACGrant{Description: "old grant", Users: []string{"user1"},
			Roles: []string{"read"}, Targets: []string{"/test"}},
	))

	assertOldConfigLive := func(t *testing.T) {
		t.Helper()
		if !manager.ConfigEnabled() {
			t.Error("enabled state must still report the last successful config")
		}
		allowed, err := manager.AuthorizeInt("user1", testTarget(), types.PermissionRead, []string{}, false)
		if err != nil || !allowed {
			t.Errorf("old grant should still authorize after a rejected update, got %v err %v", allowed, err)
		}
		allowed, err = manager.AuthorizeInt("user2", testTarget(), types.PermissionRead, []string{}, false)
		if err != nil || allowed {
			t.Errorf("rejected config must not grant anything, got %v err %v", allowed, err)
		}
	}

	// Failure in the last validation step (undefined role in a grant)
	bad := grantConfig(map[string][]types.RBACPermission{},
		types.RBACGrant{Description: "bad grant", Users: []string{"user2"},
			Roles: []string{"nosuchrole"}, Targets: []string{"all"}})
	if err := manager.UpdateRBACConfig(bad); err == nil {
		t.Fatal("expected error for undefined role reference")
	}
	assertOldConfigLive(t)

	// Failure in the first resolution step (undefined group reference), with
	// the rejected config disabled: the enabled state must not flip
	badGroups := &types.RBACConfig{
		Enabled: false,
		Groups:  map[string][]string{"g1": {"group:undefined"}},
		Roles:   map[string][]types.RBACPermission{},
		Grants:  []types.RBACGrant{},
	}
	if err := manager.UpdateRBACConfig(badGroups); err == nil {
		t.Fatal("expected error for undefined group reference")
	}
	assertOldConfigLive(t)

	// A valid update still applies
	newConfig := grantConfig(
		map[string][]types.RBACPermission{"read": {types.PermissionRead}},
		types.RBACGrant{Description: "new grant", Users: []string{"user2"},
			Roles: []string{"read"}, Targets: []string{"/test"}},
	)
	if err := manager.UpdateRBACConfig(newConfig); err != nil {
		t.Fatalf("valid update should succeed: %v", err)
	}
	allowed, err := manager.AuthorizeInt("user2", testTarget(), types.PermissionRead, []string{}, false)
	if err != nil || !allowed {
		t.Errorf("new grant should authorize after the update, got %v err %v", allowed, err)
	}
}
