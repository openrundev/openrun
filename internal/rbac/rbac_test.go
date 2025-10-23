// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestNewRBACHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rbacConfig  *types.RBACConfig
		expectError bool
	}{
		{
			name: "valid config",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
					"admins":     {"group:developers", "user3"},
				},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionList},
					"write": {types.PermissionAccess, "role:read"},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid group reference",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"group:nonexistent"},
				},
				Roles:  map[string][]types.RBACPermission{},
				Grants: []types.RBACGrant{},
			},
			expectError: true,
		},
		{
			name: "invalid role reference",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {"role:nonexistent"},
				},
				Grants: []types.RBACGrant{},
			},
			expectError: true,
		},
		{
			name: "nil config",
			rbacConfig: &types.RBACConfig{
				Enabled: false,
				Groups:  nil,
				Roles:   nil,
				Grants:  nil,
			},
			expectError: false,
		},
		{
			name: "circular group reference",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"group1": {"group:group2"},
					"group2": {"group:group1"},
				},
				Roles:  map[string][]types.RBACPermission{},
				Grants: []types.RBACGrant{},
			},
			expectError: true,
		},
		{
			name: "circular role reference",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"role1": {"role:role2"},
					"role2": {"role:role1"},
				},
				Grants: []types.RBACGrant{},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{
					AdminUser: "admin",
				},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if rbacManager == nil {
				t.Errorf("expected RBACManager but got nil")
			}
		})
	}
}

func TestAuthorizeAccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		rbacConfig     *types.RBACConfig
		serverConfig   *types.ServerConfig
		user           string
		appPathDomain  types.AppPathDomain
		appAuthSetting string
		permission     types.RBACPermission
		expectedResult bool
		expectError    bool
	}{
		{
			name: "rbac disabled - should authorize all",
			rbacConfig: &types.RBACConfig{
				Enabled: false,
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "anyuser",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionAccess,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "admin user - should always authorize",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles:   map[string][]types.RBACPermission{},
				Grants:  []types.RBACGrant{},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "admin",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionAccess,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "non-rbac auth setting - should authorize",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles:   map[string][]types.RBACPermission{},
				Grants:  []types.RBACGrant{},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "none",
			permission:     types.PermissionAccess,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "valid user with matching grant",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "user not in grant",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "user2",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionList,
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "user in group with matching grant",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"group:developers"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "role hierarchy - user with inherited permission",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionList},
					"write": {types.PermissionAccess, "role:read"},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"write"},
						Targets:     []string{"/test"},
					},
				},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "target glob matching",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"read"},
						Targets:     []string{"/test/*"},
					},
				},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test/app1", Domain: ""},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "target glob not matching",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"read"},
						Targets:     []string{"/test/*"},
					},
				},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/other/app1", Domain: ""},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionList,
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "domain matching",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"read"},
						Targets:     []string{"example.com:/test"},
					},
				},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: "example.com"},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "domain not matching",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"read"},
						Targets:     []string{"example.com:/test"},
					},
				},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: "other.com"},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionList,
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "multiple grants - first match",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionList},
					"write": {types.PermissionAccess},
				},
				Grants: []types.RBACGrant{
					{
						Description: "deny grant",
						Users:       []string{"user1"},
						Roles:       []string{"write"},
						Targets:     []string{"/test"},
					},
					{
						Description: "allow grant",
						Users:       []string{"user1"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "empty user",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			permission:     types.PermissionList,
			expectedResult: false,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, tt.serverConfig)
			if err != nil {
				t.Fatalf("failed to create RBACManager: %v", err)
			}

			result, err := rbacManager.AuthorizeInt(tt.user, tt.appPathDomain, tt.appAuthSetting, tt.permission, []string{}, false)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expectedResult {
				t.Errorf("expected result %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestAuthorizeAccessWithGroupHierarchy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		rbacConfig     *types.RBACConfig
		user           string
		appPathDomain  types.AppPathDomain
		permission     types.RBACPermission
		expectedResult bool
	}{
		{
			name: "user in nested group",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1"},
					"seniors":    {"group:developers", "user2"},
					"leads":      {"group:seniors"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"group:leads"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
		},
		{
			name: "user not in nested group",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1"},
					"seniors":    {"group:developers", "user2"},
					"leads":      {"group:seniors"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"group:leads"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user3",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)
			if err != nil {
				t.Fatalf("failed to create RBACManager: %v", err)
			}

			result, err := rbacManager.AuthorizeInt(tt.user, tt.appPathDomain, "rbac:test", tt.permission, []string{}, false)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expectedResult {
				t.Errorf("expected result %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestAuthorizeAccessWithRoleHierarchy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		rbacConfig     *types.RBACConfig
		user           string
		appPathDomain  types.AppPathDomain
		permission     types.RBACPermission
		expectedResult bool
	}{
		{
			name: "user with inherited role permission",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionList},
					"write": {types.PermissionAccess, "role:read"},
					"admin": {"role:write"},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"admin"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
		},
		{
			name: "user with inherited role permission - access",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionList},
					"write": {types.PermissionAccess, "role:read"},
					"admin": {"role:write"},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"admin"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionAccess,
			expectedResult: true,
		},
		{
			name: "user without required permission",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionAccess,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)
			if err != nil {
				t.Fatalf("failed to create RBACManager: %v", err)
			}

			result, err := rbacManager.AuthorizeInt(tt.user, tt.appPathDomain, "rbac:test", tt.permission, []string{}, false)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expectedResult {
				t.Errorf("expected result %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestAuthorizeAccessWithDynamicGroups(t *testing.T) {
	t.Parallel()

	rbacConfig := &types.RBACConfig{
		Enabled: true,
		Groups:  map[string][]string{},
		Roles: map[string][]types.RBACPermission{
			"read": {types.PermissionList},
		},
		Grants: []types.RBACGrant{
			{
				Description: "grant via dynamic group",
				Users:       []string{"group:sso_devs"},
				Roles:       []string{"read"},
				Targets:     []string{"/test"},
			},
		},
	}

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
	}

	rbacManager, err := NewRBACHandler(logger, rbacConfig, serverConfig)
	if err != nil {
		t.Fatalf("failed to create RBACManager: %v", err)
	}

	t.Run("denied when no dynamic groups passed", func(t *testing.T) {
		t.Parallel()
		// user is not part of any configured group, and no dynamic groups provided
		allowed, err := rbacManager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatalf("expected authorization to be denied without dynamic groups")
		}
	})

	t.Run("allowed when dynamic group passed", func(t *testing.T) {
		t.Parallel()
		// user is considered part of sso_devs via dynamic groups argument
		allowed, err := rbacManager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test",
			types.PermissionList, []string{"sso_devs"}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatalf("expected authorization to be allowed with dynamic group membership")
		}
	})
}

func TestAuthorizeAccessWithDynamicAndConfiguredGroups(t *testing.T) {
	t.Parallel()

	rbacConfig := &types.RBACConfig{
		Enabled: true,
		Groups: map[string][]string{
			"devs": {"user2"},
		},
		Roles: map[string][]types.RBACPermission{
			"read": {types.PermissionList},
		},
		Grants: []types.RBACGrant{
			{
				Description: "grant via either configured or dynamic group",
				Users:       []string{"group:devs", "group:sso_devs"},
				Roles:       []string{"read"},
				Targets:     []string{"/test"},
			},
		},
	}

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
	}

	rbacManager, err := NewRBACHandler(logger, rbacConfig, serverConfig)
	if err != nil {
		t.Fatalf("failed to create RBACManager: %v", err)
	}

	// user1 not in configured groups; denied without dynamic groups
	allowed, err := rbacManager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("expected user1 to be denied without dynamic groups")
	}

	// user1 allowed when dynamic group provided
	allowed, err = rbacManager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{"sso_devs"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected user1 to be allowed with dynamic group")
	}

	// user2 is in configured group; allowed even without dynamic groups
	allowed, err = rbacManager.AuthorizeInt("user2", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected user2 to be allowed via configured group")
	}
}

func TestUpdateRBACConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		initialConfig *types.RBACConfig
		updateConfig  *types.RBACConfig
		expectError   bool
	}{
		{
			name: "valid update",
			initialConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{},
			},
			updateConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
					"admins":     {"user3"},
				},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionList},
					"write": {types.PermissionAccess},
				},
				Grants: []types.RBACGrant{
					{
						Description: "new grant",
						Users:       []string{"group:developers"},
						Roles:       []string{"read"},
						Targets:     []string{"/new"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid group reference in update",
			initialConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles:   map[string][]types.RBACPermission{},
				Grants:  []types.RBACGrant{},
			},
			updateConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"group:nonexistent"},
				},
				Roles:  map[string][]types.RBACPermission{},
				Grants: []types.RBACGrant{},
			},
			expectError: true,
		},
		{
			name: "disable rbac",
			initialConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{},
			},
			updateConfig: &types.RBACConfig{
				Enabled: false,
				Groups:  map[string][]string{},
				Roles:   map[string][]types.RBACPermission{},
				Grants:  []types.RBACGrant{},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			}

			rbacManager, err := NewRBACHandler(logger, tt.initialConfig, serverConfig)
			if err != nil {
				t.Fatalf("failed to create initial RBACManager: %v", err)
			}

			err = rbacManager.UpdateRBACConfig(tt.updateConfig)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Test that the update worked by checking authorization
			result, err := rbacManager.AuthorizeInt("user1", types.AppPathDomain{Path: "/new", Domain: ""}, "rbac:test", types.PermissionList, []string{}, false)
			if err != nil {
				t.Errorf("unexpected error during authorization test: %v", err)
				return
			}

			// For the valid update case, user1 should have access to /new
			if tt.name == "valid update" && !result {
				t.Errorf("expected user1 to have access to /new after update, but got false")
			}
		})
	}
}

func TestAuthorizeAccessConcurrency(t *testing.T) {
	t.Parallel()

	rbacConfig := &types.RBACConfig{
		Enabled: true,
		Groups: map[string][]string{
			"developers": {"user1", "user2"},
		},
		Roles: map[string][]types.RBACPermission{
			"read": {types.PermissionList},
		},
		Grants: []types.RBACGrant{
			{
				Description: "test grant",
				Users:       []string{"group:developers"},
				Roles:       []string{"read"},
				Targets:     []string{"/test"},
			},
		},
	}

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
	}

	rbacManager, err := NewRBACHandler(logger, rbacConfig, serverConfig)
	if err != nil {
		t.Fatalf("failed to create RBACManager: %v", err)
	}

	// Test concurrent access
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(user string) {
			defer func() { done <- true }()

			result, err := rbacManager.AuthorizeInt(user, types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{}, false)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// user1 and user2 should be authorized, others should not
			expected := user == "user1" || user == "user2"
			if result != expected {
				t.Errorf("expected result %v for user %s, got %v", expected, user, result)
			}
		}([]string{"user1", "user2", "user3", "user4", "user5"}[i%5])
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestAuthorizeAppLevelPermissions(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
	}

	t.Run("non-rbac auth allows app-level permission", func(t *testing.T) {
		t.Parallel()

		rbacConfig := &types.RBACConfig{Enabled: true}
		rbacManager, err := NewRBACHandler(logger, rbacConfig, serverConfig)
		if err != nil {
			t.Fatalf("failed to create RBACManager: %v", err)
		}

		allowed, err := rbacManager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test", Domain: ""}, "none",
			types.RBACPermission("action_run"), []string{}, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatalf("expected authorization to be allowed for app-level permission with non-rbac auth")
		}
	})

	t.Run("rbac denies when no role includes app-level permission", func(t *testing.T) {
		t.Parallel()

		rbacConfig := &types.RBACConfig{
			Enabled: true,
			Groups:  map[string][]string{},
			Roles: map[string][]types.RBACPermission{
				"read": {types.PermissionList},
			},
			Grants: []types.RBACGrant{
				{
					Description: "grant read only",
					Users:       []string{"user1"},
					Roles:       []string{"read"},
					Targets:     []string{"/test"},
				},
			},
		}

		rbacManager, err := NewRBACHandler(logger, rbacConfig, serverConfig)
		if err != nil {
			t.Fatalf("failed to create RBACManager: %v", err)
		}

		allowed, err := rbacManager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test",
			types.RBACPermission("action_run"), []string{}, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatalf("expected authorization to be denied when role lacks app-level permission")
		}
	})

	t.Run("rbac allows when role includes app-level permission", func(t *testing.T) {
		t.Parallel()

		rbacConfig := &types.RBACConfig{
			Enabled: true,
			Groups:  map[string][]string{},
			Roles: map[string][]types.RBACPermission{
				"actor": {types.RBACPermission("custom:action_run")},
			},
			Grants: []types.RBACGrant{
				{
					Description: "grant actor",
					Users:       []string{"user1"},
					Roles:       []string{"actor"},
					Targets:     []string{"/test"},
				},
			},
		}

		rbacManager, err := NewRBACHandler(logger, rbacConfig, serverConfig)
		if err != nil {
			t.Fatalf("failed to create RBACManager: %v", err)
		}

		allowed, err := rbacManager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test",
			types.RBACPermission("action_run"), []string{}, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatalf("expected authorization to be allowed when role includes app-level permission")
		}
	})
}

func TestValidateGrants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rbacConfig  *types.RBACConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid grants with direct users and roles",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
					"admins":     {"user3"},
				},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionList},
					"write": {types.PermissionAccess},
				},
				Grants: []types.RBACGrant{
					{
						Description: "valid grant 1",
						Users:       []string{"user1", "user2"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
					{
						Description: "valid grant 2",
						Users:       []string{"user3"},
						Roles:       []string{"write"},
						Targets:     []string{"/admin"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid grants with group references",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
					"admins":     {"user3"},
				},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionList},
					"write": {types.PermissionAccess},
				},
				Grants: []types.RBACGrant{
					{
						Description: "valid grant with groups",
						Users:       []string{"group:developers", "group:admins"},
						Roles:       []string{"read", "write"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid grants with mixed users and groups",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "mixed users and groups",
						Users:       []string{"user3", "group:developers"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid grant - undefined group reference (no longer validated)",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "valid grant with undefined group",
						Users:       []string{"group:nonexistent"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid grant - undefined role reference",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "invalid grant",
						Users:       []string{"user1"},
						Roles:       []string{"nonexistent"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: true,
			errorMsg:    "grant 0 ('invalid grant'): Roles references undefined role 'nonexistent'",
		},
		{
			name: "valid grant - multiple undefined group references (no longer validated)",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "valid grant with multiple undefined groups",
						Users:       []string{"group:nonexistent1", "group:nonexistent2"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid grant - multiple undefined role references",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "invalid grant",
						Users:       []string{"user1"},
						Roles:       []string{"nonexistent1", "nonexistent2"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: true,
			errorMsg:    "grant 0 ('invalid grant'): Roles references undefined role 'nonexistent1'",
		},
		{
			name: "valid grants - multiple grants with undefined group (no longer validated)",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "valid grant",
						Users:       []string{"user1"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
					{
						Description: "valid grant with undefined group",
						Users:       []string{"group:nonexistent"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "empty grants - should be valid",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{},
			},
			expectError: false,
		},
		{
			name: "grants with empty users and roles - should be valid",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "empty users and roles",
						Users:       []string{},
						Roles:       []string{},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "rbac disabled - should be valid regardless of grants",
			rbacConfig: &types.RBACConfig{
				Enabled: false,
				Groups:  map[string][]string{},
				Roles:   map[string][]types.RBACPermission{},
				Grants: []types.RBACGrant{
					{
						Description: "invalid grant but rbac disabled",
						Users:       []string{"group:nonexistent"},
						Roles:       []string{"nonexistent"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if rbacManager == nil {
				t.Errorf("expected RBACManager but got nil")
			}
		})
	}
}

func TestRegexSupportInGrants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		rbacConfig     *types.RBACConfig
		user           string
		appPathDomain  types.AppPathDomain
		permission     types.RBACPermission
		expectedResult bool
		expectError    bool
	}{
		{
			name: "regex matches user in grant",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with regex",
						Users:       []string{"regex:^dev_.*"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "dev_john",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "regex does not match user in grant",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with regex",
						Users:       []string{"regex:^dev_.*"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "admin_john",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "regex with email pattern",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with email regex",
						Users:       []string{"regex:.*@example\\.com$"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "john@example.com",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "regex with email pattern - no match",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with email regex",
						Users:       []string{"regex:.*@example\\.com$"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "john@other.com",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "multiple regex patterns - first matches",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with multiple regex",
						Users:       []string{"regex:^dev_.*", "regex:^admin_.*"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "dev_jane",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "multiple regex patterns - second matches",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with multiple regex",
						Users:       []string{"regex:^dev_.*", "regex:^admin_.*"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "admin_jane",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "mixed regex and direct users",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with mixed users",
						Users:       []string{"user1", "regex:^dev_.*", "user2"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "dev_bob",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "mixed regex, groups and direct users",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with mixed users and groups",
						Users:       []string{"group:developers", "regex:^admin_.*", "user3"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "admin_steve",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "regex with special characters",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with special char regex",
						Users:       []string{"regex:^[a-z]+\\.[a-z]+@(example|test)\\.com$"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "john.doe@example.com",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "case sensitive regex",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with case sensitive regex",
						Users:       []string{"regex:^DEV_.*"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "dev_john",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "case insensitive regex",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with case insensitive regex",
						Users:       []string{"regex:(?i)^dev_.*"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "DEV_john",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)
			if err != nil {
				if !tt.expectError {
					t.Fatalf("unexpected error creating RBACManager: %v", err)
				}
				return
			}

			if tt.expectError {
				t.Fatalf("expected error but got none")
			}

			result, err := rbacManager.AuthorizeInt(tt.user, tt.appPathDomain, "rbac:test", tt.permission, []string{}, false)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expectedResult {
				t.Errorf("expected result %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestRegexSupportInGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		rbacConfig     *types.RBACConfig
		user           string
		appPathDomain  types.AppPathDomain
		permission     types.RBACPermission
		expectedResult bool
		expectError    bool
	}{
		{
			name: "regex in group definition",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"regex:^dev_.*", "user1"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant via group with regex",
						Users:       []string{"group:developers"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "dev_alice",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "regex in nested group definition",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"juniors": {"regex:^jr_.*"},
					"seniors": {"regex:^sr_.*", "group:juniors"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant via nested group with regex",
						Users:       []string{"group:seniors"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "jr_bob",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "regex in nested group - senior user",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"juniors": {"regex:^jr_.*"},
					"seniors": {"regex:^sr_.*", "group:juniors"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant via nested group with regex",
						Users:       []string{"group:seniors"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "sr_alice",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "regex in group does not match",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"regex:^dev_.*"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant via group with regex",
						Users:       []string{"group:developers"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "admin_alice",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "multiple regex patterns in group",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"staff": {"regex:^dev_.*", "regex:^qa_.*", "regex:^pm_.*"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant via group with multiple regex",
						Users:       []string{"group:staff"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "qa_charlie",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionList,
			expectedResult: true,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)
			if err != nil {
				if !tt.expectError {
					t.Fatalf("unexpected error creating RBACManager: %v", err)
				}
				return
			}

			if tt.expectError {
				t.Fatalf("expected error but got none")
			}

			result, err := rbacManager.AuthorizeInt(tt.user, tt.appPathDomain, "rbac:test", tt.permission, []string{}, false)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expectedResult {
				t.Errorf("expected result %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestRegexValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rbacConfig  *types.RBACConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "invalid regex in grant - missing closing bracket",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with invalid regex",
						Users:       []string{"regex:^dev_[.*"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: true,
			errorMsg:    "error compiling regex",
		},
		{
			name: "invalid regex in grant - unmatched parenthesis",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with invalid regex",
						Users:       []string{"regex:^(dev_.*"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: true,
			errorMsg:    "error compiling regex",
		},
		{
			name: "invalid regex in group",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"regex:^dev_[.*"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{},
			},
			expectError: true,
			errorMsg:    "error initializing rbac group info",
		},
		{
			name: "valid complex regex in grant",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with valid complex regex",
						Users:       []string{"regex:^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid complex regex in group",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"emails": {"regex:^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{},
			},
			expectError: false,
		},
		{
			name: "empty regex pattern in grant",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with empty regex",
						Users:       []string{"regex:"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: false, // Empty regex is technically valid, matches empty string
		},
		{
			name: "multiple invalid regexes in grant",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with multiple invalid regex",
						Users:       []string{"regex:^dev_[.*", "regex:^admin_(.*"},
						Roles:       []string{"read"},
						Targets:     []string{"/test"},
					},
				},
			},
			expectError: true,
			errorMsg:    "error compiling regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if rbacManager == nil {
				t.Errorf("expected RBACManager but got nil")
			}
		})
	}
}

func TestRegexCaching(t *testing.T) {
	t.Parallel()

	// Test that regex patterns are compiled once and cached
	rbacConfig := &types.RBACConfig{
		Enabled: true,
		Groups: map[string][]string{
			"developers": {"regex:^dev_.*"},
		},
		Roles: map[string][]types.RBACPermission{
			"read": {types.PermissionList},
		},
		Grants: []types.RBACGrant{
			{
				Description: "grant with regex",
				Users:       []string{"regex:^admin_.*"},
				Roles:       []string{"read"},
				Targets:     []string{"/test"},
			},
		},
	}

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
	}

	rbacManager, err := NewRBACHandler(logger, rbacConfig, serverConfig)
	if err != nil {
		t.Fatalf("failed to create RBACManager: %v", err)
	}

	// Verify that regex cache is populated
	rbacManager.mu.RLock()
	cacheSize := len(rbacManager.regexCache)
	rbacManager.mu.RUnlock()

	// We expect 2 regexes to be cached: one from group and one from grant
	expectedCacheSize := 2
	if cacheSize != expectedCacheSize {
		t.Errorf("expected regex cache size %d, got %d", expectedCacheSize, cacheSize)
	}

	// Test that the same regex is reused (multiple authorize calls should work)
	for i := 0; i < 10; i++ {
		_, err := rbacManager.AuthorizeInt("dev_user1", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{}, false)
		if err != nil {
			t.Errorf("unexpected error on iteration %d: %v", i, err)
		}
	}
}

func TestRegexWithDynamicGroups(t *testing.T) {
	t.Parallel()

	rbacConfig := &types.RBACConfig{
		Enabled: true,
		Groups:  map[string][]string{},
		Roles: map[string][]types.RBACPermission{
			"read": {types.PermissionList},
		},
		Grants: []types.RBACGrant{
			{
				Description: "grant with regex and dynamic groups",
				Users:       []string{"regex:^dev_.*", "group:sso_admins"},
				Roles:       []string{"read"},
				Targets:     []string{"/test"},
			},
		},
	}

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
	}

	rbacManager, err := NewRBACHandler(logger, rbacConfig, serverConfig)
	if err != nil {
		t.Fatalf("failed to create RBACManager: %v", err)
	}

	t.Run("regex matches user", func(t *testing.T) {
		t.Parallel()
		allowed, err := rbacManager.AuthorizeInt("dev_alice", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatalf("expected regex to match user dev_alice")
		}
	})

	t.Run("dynamic group matches", func(t *testing.T) {
		t.Parallel()
		allowed, err := rbacManager.AuthorizeInt("bob", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{"sso_admins"}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatalf("expected dynamic group to match")
		}
	})

	t.Run("neither regex nor dynamic group matches", func(t *testing.T) {
		t.Parallel()
		allowed, err := rbacManager.AuthorizeInt("charlie", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatalf("expected authorization to be denied")
		}
	})
}

func TestRegexUpdateConfig(t *testing.T) {
	t.Parallel()

	initialConfig := &types.RBACConfig{
		Enabled: true,
		Groups: map[string][]string{
			"developers": {"regex:^dev_.*"},
		},
		Roles: map[string][]types.RBACPermission{
			"read": {types.PermissionList},
		},
		Grants: []types.RBACGrant{
			{
				Description: "initial grant",
				Users:       []string{"group:developers"},
				Roles:       []string{"read"},
				Targets:     []string{"/test"},
			},
		},
	}

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
	}

	rbacManager, err := NewRBACHandler(logger, initialConfig, serverConfig)
	if err != nil {
		t.Fatalf("failed to create RBACManager: %v", err)
	}

	// Verify initial config works
	allowed, err := rbacManager.AuthorizeInt("dev_alice", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected dev_alice to be authorized with initial config")
	}

	// Update config with different regex
	updatedConfig := &types.RBACConfig{
		Enabled: true,
		Groups: map[string][]string{
			"developers": {"regex:^admin_.*"},
		},
		Roles: map[string][]types.RBACPermission{
			"read": {types.PermissionList},
		},
		Grants: []types.RBACGrant{
			{
				Description: "updated grant",
				Users:       []string{"group:developers"},
				Roles:       []string{"read"},
				Targets:     []string{"/test"},
			},
		},
	}

	err = rbacManager.UpdateRBACConfig(updatedConfig)
	if err != nil {
		t.Fatalf("failed to update RBAC config: %v", err)
	}

	// Verify old regex no longer matches
	allowed, err = rbacManager.AuthorizeInt("dev_alice", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("expected dev_alice to not be authorized after config update")
	}

	// Verify new regex matches
	allowed, err = rbacManager.AuthorizeInt("admin_bob", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected admin_bob to be authorized with updated config")
	}
}

func TestGetCustomPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		rbacConfig     *types.RBACConfig
		user           string
		appPathDomain  types.AppPathDomain
		appAuthSetting string
		groups         []string
		expectedPerms  []string
		expectError    bool
	}{
		{
			name: "no custom permissions defined",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionList},
				},
				Grants: []types.RBACGrant{},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  nil,
			expectError:    false,
		},
		{
			name: "rbac disabled - returns all custom permissions",
			rbacConfig: &types.RBACConfig{
				Enabled: false,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{"action_run", "action_delete"},
			expectError:    false,
		},
		{
			name: "admin user - returns all custom permissions",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{},
			},
			user:           "admin",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{"action_run", "action_delete"},
			expectError:    false,
		},
		{
			name: "user with all custom permissions granted",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant all actions",
						Users:       []string{"user1"},
						Roles:       []string{"actor"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{"action_run", "action_delete"},
			expectError:    false,
		},
		{
			name: "user with some custom permissions granted",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"runner":  {types.RBACPermission("custom:action_run")},
					"deleter": {types.RBACPermission("custom:action_delete")},
					"updater": {types.RBACPermission("custom:action_update")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant run action",
						Users:       []string{"user1"},
						Roles:       []string{"runner"},
						Targets:     []string{"/test"},
					},
					{
						Description: "grant update action",
						Users:       []string{"user1"},
						Roles:       []string{"updater"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{"action_run", "action_update"},
			expectError:    false,
		},
		{
			name: "user with no custom permissions granted",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant to other user",
						Users:       []string{"user2"},
						Roles:       []string{"actor"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{},
			expectError:    false,
		},
		{
			name: "user in group with custom permissions",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant to developers",
						Users:       []string{"group:developers"},
						Roles:       []string{"actor"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{"action_run", "action_delete"},
			expectError:    false,
		},
		{
			name: "user with custom permissions via dynamic groups",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant via dynamic group",
						Users:       []string{"group:sso_devs"},
						Roles:       []string{"actor"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{"sso_devs"},
			expectedPerms:  []string{"action_run", "action_delete"},
			expectError:    false,
		},
		{
			name: "user with custom permissions via regex",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant via regex",
						Users:       []string{"regex:^dev_.*"},
						Roles:       []string{"actor"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "dev_alice",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{"action_run", "action_delete"},
			expectError:    false,
		},
		{
			name: "user with custom permissions but wrong target",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant to different path",
						Users:       []string{"user1"},
						Roles:       []string{"actor"},
						Targets:     []string{"/other"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{},
			expectError:    false,
		},
		{
			name: "user with custom permissions - glob target matching",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with glob",
						Users:       []string{"user1"},
						Roles:       []string{"actor"},
						Targets:     []string{"/test/*"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test/app1", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{"action_run", "action_delete"},
			expectError:    false,
		},
		{
			name: "user with mixed standard and custom permissions",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"reader": {types.PermissionList, types.PermissionAccess},
					"actor":  {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant reader and actor",
						Users:       []string{"user1"},
						Roles:       []string{"reader", "actor"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{"action_run", "action_delete"},
			expectError:    false,
		},
		{
			name: "multiple roles with overlapping custom permissions",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"runner":  {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
					"updater": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_update")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant runner",
						Users:       []string{"user1"},
						Roles:       []string{"runner"},
						Targets:     []string{"/test"},
					},
					{
						Description: "grant updater",
						Users:       []string{"user1"},
						Roles:       []string{"updater"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{"action_run", "action_delete", "action_update"},
			expectError:    false,
		},
		{
			name: "user with custom permissions and domain matching",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with domain",
						Users:       []string{"user1"},
						Roles:       []string{"actor"},
						Targets:     []string{"example.com:/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: "example.com"},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{"action_run"},
			expectError:    false,
		},
		{
			name: "user with custom permissions but domain not matching",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run")},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant with domain",
						Users:       []string{"user1"},
						Roles:       []string{"actor"},
						Targets:     []string{"example.com:/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: "other.com"},
			appAuthSetting: "rbac:test",
			groups:         []string{},
			expectedPerms:  []string{},
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)
			if err != nil {
				t.Fatalf("failed to create RBACManager: %v", err)
			}

			perms, err := rbacManager.GetCustomPermissionsInt(tt.user, tt.appPathDomain, tt.appAuthSetting, tt.groups)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Check if returned permissions match expected
			if len(perms) != len(tt.expectedPerms) {
				t.Errorf("expected %d permissions, got %d. Expected: %v, Got: %v",
					len(tt.expectedPerms), len(perms), tt.expectedPerms, perms)
				return
			}

			// Create a map for easier comparison
			permMap := make(map[string]bool)
			for _, p := range perms {
				permMap[p] = true
			}

			for _, expectedPerm := range tt.expectedPerms {
				if !permMap[expectedPerm] {
					t.Errorf("expected permission '%s' not found in result: %v", expectedPerm, perms)
				}
			}
		})
	}
}

func TestGetCustomPermissionsWithRoleHierarchy(t *testing.T) {
	t.Parallel()

	rbacConfig := &types.RBACConfig{
		Enabled: true,
		Groups:  map[string][]string{},
		Roles: map[string][]types.RBACPermission{
			"runner": {types.RBACPermission("custom:action_run")},
			"editor": {types.RBACPermission("custom:action_edit"), "role:runner"},
			"admin":  {types.RBACPermission("custom:action_delete"), "role:editor"},
		},
		Grants: []types.RBACGrant{
			{
				Description: "grant admin role",
				Users:       []string{"user1"},
				Roles:       []string{"admin"},
				Targets:     []string{"/test"},
			},
		},
	}

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
	}

	rbacManager, err := NewRBACHandler(logger, rbacConfig, serverConfig)
	if err != nil {
		t.Fatalf("failed to create RBACManager: %v", err)
	}

	perms, err := rbacManager.GetCustomPermissionsInt("user1", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have all three permissions due to role hierarchy
	expectedPerms := map[string]bool{
		"action_run":    true,
		"action_edit":   true,
		"action_delete": true,
	}

	if len(perms) != len(expectedPerms) {
		t.Errorf("expected %d permissions, got %d: %v", len(expectedPerms), len(perms), perms)
	}

	for _, perm := range perms {
		if !expectedPerms[perm] {
			t.Errorf("unexpected permission: %s", perm)
		}
	}
}

func TestGetCustomPermissionsWithGroupHierarchy(t *testing.T) {
	t.Parallel()

	rbacConfig := &types.RBACConfig{
		Enabled: true,
		Groups: map[string][]string{
			"juniors": {"user1"},
			"seniors": {"group:juniors"},
		},
		Roles: map[string][]types.RBACPermission{
			"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
		},
		Grants: []types.RBACGrant{
			{
				Description: "grant to seniors",
				Users:       []string{"group:seniors"},
				Roles:       []string{"actor"},
				Targets:     []string{"/test"},
			},
		},
	}

	logger := testutil.TestLogger()
	serverConfig := &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
	}

	rbacManager, err := NewRBACHandler(logger, rbacConfig, serverConfig)
	if err != nil {
		t.Fatalf("failed to create RBACManager: %v", err)
	}

	perms, err := rbacManager.GetCustomPermissionsInt("user1", types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have permissions via nested group membership
	expectedPerms := map[string]bool{
		"action_run":    true,
		"action_delete": true,
	}

	if len(perms) != len(expectedPerms) {
		t.Errorf("expected %d permissions, got %d: %v", len(expectedPerms), len(perms), perms)
	}

	for _, perm := range perms {
		if !expectedPerms[perm] {
			t.Errorf("unexpected permission: %s", perm)
		}
	}
}

func TestGetCustomPermissionsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		rbacConfig *types.RBACConfig
		user       string
	}{
		{
			name: "no roles defined",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles:   map[string][]types.RBACPermission{},
				Grants:  []types.RBACGrant{},
			},
			user: "user1",
		},
		{
			name: "only standard permissions, no custom",
			rbacConfig: &types.RBACConfig{
				Enabled: true,
				Groups:  map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"reader": {types.PermissionList, types.PermissionAccess},
				},
				Grants: []types.RBACGrant{
					{
						Description: "grant reader",
						Users:       []string{"user1"},
						Roles:       []string{"reader"},
						Targets:     []string{"/test"},
					},
				},
			},
			user: "user1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)
			if err != nil {
				t.Fatalf("failed to create RBACManager: %v", err)
			}

			perms, err := rbacManager.GetCustomPermissionsInt(tt.user, types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", []string{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(perms) != 0 {
				t.Errorf("expected empty permissions, got: %v", perms)
			}
		})
	}
}
