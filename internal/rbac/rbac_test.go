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
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
					"admins":     {"group:developers", "user3"},
				},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionRead},
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
				Groups: map[string][]string{},
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
				Groups: nil,
				Roles:  nil,
				Grants: nil,
			},
			expectError: false,
		},
		{
			name: "circular group reference",
			rbacConfig: &types.RBACConfig{
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
				Groups: map[string][]string{},
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
		permission     types.RBACPermission
		expectedResult bool
		expectError    bool
	}{
		{
			name:       "rbac disabled - should authorize all",
			rbacConfig: &types.RBACConfig{},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
				Security:     types.SecurityConfig{UnsafeDisableRBAC: true},
			},
			user:           "anyuser",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionAccess,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "admin user - should always authorize",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles:  map[string][]types.RBACPermission{},
				Grants: []types.RBACGrant{},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "admin",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionAccess,
			expectedResult: true,
			expectError:    false,
		},
		{
			// RBAC applies to every app when enabled (no rbac: prefix needed);
			// a non-prefixed app with no grant denies access
			name: "non-rbac auth setting - enforced, no grant denies",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles:  map[string][]types.RBACPermission{},
				Grants: []types.RBACGrant{},
			},
			serverConfig: &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionAccess,
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "valid user with matching grant",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
			permission:     types.PermissionRead,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "user not in grant",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
			permission:     types.PermissionRead,
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "user in group with matching grant",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{
					"developers": {"user1", "user2"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
			permission:     types.PermissionRead,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "role hierarchy - user with inherited permission",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionRead},
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
			permission:     types.PermissionRead,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "target glob matching",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
			permission:     types.PermissionRead,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "target glob not matching",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
			permission:     types.PermissionRead,
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "domain matching",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
			permission:     types.PermissionRead,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "domain not matching",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
			permission:     types.PermissionRead,
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "multiple grants - first match",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionRead},
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
			permission:     types.PermissionRead,
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "empty user",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
			permission:     types.PermissionRead,
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

			result, err := rbacManager.AuthorizeInt(tt.user, tt.appPathDomain, tt.permission, []string{}, false)

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
				Groups: map[string][]string{
					"developers": {"user1"},
					"seniors":    {"group:developers", "user2"},
					"leads":      {"group:seniors"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
			permission:     types.PermissionRead,
			expectedResult: true,
		},
		{
			name: "user not in nested group",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{
					"developers": {"user1"},
					"seniors":    {"group:developers", "user2"},
					"leads":      {"group:seniors"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
			permission:     types.PermissionRead,
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

			result, err := rbacManager.AuthorizeInt(tt.user, tt.appPathDomain, tt.permission, []string{}, false)
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
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionRead},
					"write": {types.PermissionAccess, "role:read"},
					"lead":  {"role:write"},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"lead"},
						Targets:     []string{"/test"},
					},
				},
			},
			user:           "user1",
			appPathDomain:  types.AppPathDomain{Path: "/test", Domain: ""},
			permission:     types.PermissionRead,
			expectedResult: true,
		},
		{
			name: "user with inherited role permission - access",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read":  {types.PermissionRead},
					"write": {types.PermissionAccess, "role:read"},
					"lead":  {"role:write"},
				},
				Grants: []types.RBACGrant{
					{
						Description: "test grant",
						Users:       []string{"user1"},
						Roles:       []string{"lead"},
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
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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

			result, err := rbacManager.AuthorizeInt(tt.user, tt.appPathDomain, tt.permission, []string{}, false)
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

func TestAuthorizeAccessWithDynamicAndConfiguredGroups(t *testing.T) {
	t.Parallel()

	rbacConfig := &types.RBACConfig{
		Groups: map[string][]string{
			"devs": {"user2"},
		},
		Roles: map[string][]types.RBACPermission{
			"read": {types.PermissionRead},
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
	allowed, err := rbacManager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test", Domain: ""}, types.PermissionRead, []string{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("expected user1 to be denied without dynamic groups")
	}

	// user1 allowed when dynamic group provided
	allowed, err = rbacManager.AuthorizeInt("user1", types.AppPathDomain{Path: "/test", Domain: ""}, types.PermissionRead, []string{"sso_devs"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected user1 to be allowed with dynamic group")
	}

	// user2 is in configured group; allowed even without dynamic groups
	allowed, err = rbacManager.AuthorizeInt("user2", types.AppPathDomain{Path: "/test", Domain: ""}, types.PermissionRead, []string{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected user2 to be allowed via configured group")
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
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
				Groups: map[string][]string{
					"developers": {"regex:^dev_[.*"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
				},
				Grants: []types.RBACGrant{},
			},
			expectError: true,
			errorMsg:    "error initializing rbac group info",
		},
		{
			name: "valid complex regex in grant",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
				Groups: map[string][]string{
					"emails": {"regex:^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"},
				},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
				},
				Grants: []types.RBACGrant{},
			},
			expectError: false,
		},
		{
			name: "empty regex pattern in grant",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
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

func TestRegexUpdateConfig(t *testing.T) {
	t.Parallel()

	initialConfig := &types.RBACConfig{
		Groups: map[string][]string{
			"developers": {"regex:^dev_.*"},
		},
		Roles: map[string][]types.RBACPermission{
			"read": {types.PermissionRead},
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
	allowed, err := rbacManager.AuthorizeInt("dev_alice", types.AppPathDomain{Path: "/test", Domain: ""}, types.PermissionRead, []string{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected dev_alice to be authorized with initial config")
	}

	// Update config with different regex
	updatedConfig := &types.RBACConfig{
		Groups: map[string][]string{
			"developers": {"regex:^admin_.*"},
		},
		Roles: map[string][]types.RBACPermission{
			"read": {types.PermissionRead},
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
	allowed, err = rbacManager.AuthorizeInt("dev_alice", types.AppPathDomain{Path: "/test", Domain: ""}, types.PermissionRead, []string{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("expected dev_alice to not be authorized after config update")
	}

	// Verify new regex matches
	allowed, err = rbacManager.AuthorizeInt("admin_bob", types.AppPathDomain{Path: "/test", Domain: ""}, types.PermissionRead, []string{}, false)
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
		name          string
		rbacConfig    *types.RBACConfig
		disableRBAC   bool
		user          string
		appPathDomain types.AppPathDomain
		groups        []string
		expectedPerms []string
		expectError   bool
	}{
		{
			name: "no custom permissions defined",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"read": {types.PermissionRead},
				},
				Grants: []types.RBACGrant{},
			},
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{},
			expectedPerms: nil,
			expectError:   false,
		},
		{
			name:        "rbac disabled - returns all custom permissions",
			disableRBAC: true,
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{},
			},
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{},
			expectedPerms: []string{"action_run", "action_delete"},
			expectError:   false,
		},
		{
			name: "admin user - returns all custom permissions",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"actor": {types.RBACPermission("custom:action_run"), types.RBACPermission("custom:action_delete")},
				},
				Grants: []types.RBACGrant{},
			},
			user:          "admin",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{},
			expectedPerms: []string{"action_run", "action_delete"},
			expectError:   false,
		},
		{
			name: "user with all custom permissions granted",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
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
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{},
			expectedPerms: []string{"action_run", "action_delete"},
			expectError:   false,
		},
		{
			name: "user with some custom permissions granted",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
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
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{},
			expectedPerms: []string{"action_run", "action_update"},
			expectError:   false,
		},
		{
			name: "user with no custom permissions granted",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
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
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{},
			expectedPerms: []string{},
			expectError:   false,
		},
		{
			name: "user in group with custom permissions",
			rbacConfig: &types.RBACConfig{
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
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{},
			expectedPerms: []string{"action_run", "action_delete"},
			expectError:   false,
		},
		{
			name: "user with custom permissions via dynamic groups",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
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
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{"sso_devs"},
			expectedPerms: []string{"action_run", "action_delete"},
			expectError:   false,
		},
		{
			name: "user with custom permissions via regex",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
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
			user:          "dev_alice",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{},
			expectedPerms: []string{"action_run", "action_delete"},
			expectError:   false,
		},
		{
			name: "user with custom permissions but wrong target",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
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
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{},
			expectedPerms: []string{},
			expectError:   false,
		},
		{
			name: "user with custom permissions - glob target matching",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
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
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test/app1", Domain: ""},
			groups:        []string{},
			expectedPerms: []string{"action_run", "action_delete"},
			expectError:   false,
		},
		{
			name: "user with mixed standard and custom permissions",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
				Roles: map[string][]types.RBACPermission{
					"reader": {types.PermissionRead, types.PermissionAccess},
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
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{},
			expectedPerms: []string{"action_run", "action_delete"},
			expectError:   false,
		},
		{
			name: "multiple roles with overlapping custom permissions",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
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
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: ""},
			groups:        []string{},
			expectedPerms: []string{"action_run", "action_delete", "action_update"},
			expectError:   false,
		},
		{
			name: "user with custom permissions and domain matching",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
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
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: "example.com"},
			groups:        []string{},
			expectedPerms: []string{"action_run"},
			expectError:   false,
		},
		{
			name: "user with custom permissions but domain not matching",
			rbacConfig: &types.RBACConfig{
				Groups: map[string][]string{},
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
			user:          "user1",
			appPathDomain: types.AppPathDomain{Path: "/test", Domain: "other.com"},
			groups:        []string{},
			expectedPerms: []string{},
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutil.TestLogger()
			serverConfig := &types.ServerConfig{
				GlobalConfig: types.GlobalConfig{AdminUser: "admin"},
				Security:     types.SecurityConfig{UnsafeDisableRBAC: tt.disableRBAC},
			}

			rbacManager, err := NewRBACHandler(logger, tt.rbacConfig, serverConfig)
			if err != nil {
				t.Fatalf("failed to create RBACManager: %v", err)
			}

			perms, err := rbacManager.GetCustomPermissionsInt(tt.user, tt.appPathDomain, tt.groups)

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
