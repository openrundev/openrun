// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
)

// createTestLogger creates a logger that discards all output for testing
func createTestLogger() *types.Logger {
	logger := zerolog.New(io.Discard).Level(zerolog.InfoLevel)
	return &types.Logger{Logger: &logger}
}

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

			logger := createTestLogger()
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

			logger := createTestLogger()
			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, tt.serverConfig)
			if err != nil {
				t.Fatalf("failed to create RBACManager: %v", err)
			}

			result, err := rbacManager.Authorize(tt.user, tt.appPathDomain, tt.appAuthSetting, tt.permission, []string{})

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

			logger := createTestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)
			if err != nil {
				t.Fatalf("failed to create RBACManager: %v", err)
			}

			result, err := rbacManager.Authorize(tt.user, tt.appPathDomain, "rbac:test", tt.permission, []string{})
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

			logger := createTestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)
			if err != nil {
				t.Fatalf("failed to create RBACManager: %v", err)
			}

			result, err := rbacManager.Authorize(tt.user, tt.appPathDomain, "rbac:test", tt.permission, []string{})
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

			logger := createTestLogger()
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
			result, err := rbacManager.Authorize("user1", types.AppPathDomain{Path: "/new", Domain: ""}, "rbac:test", types.PermissionList, []string{})
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

	logger := createTestLogger()
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

			result, err := rbacManager.Authorize(user, types.AppPathDomain{Path: "/test", Domain: ""}, "rbac:test", types.PermissionList, []string{})
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

			logger := createTestLogger()
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
