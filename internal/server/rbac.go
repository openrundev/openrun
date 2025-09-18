// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/openrundev/openrun/internal/types"
)

const RBAC_AUTH_PREFIX = "rbac:"
const RBAC_GROUP_PREFIX = "group:"
const RBAC_ROLE_PREFIX = "role:"

type RBACManager struct {
	*types.Logger
	rbacConfig   *types.RBACConfig
	serverConfig *types.ServerConfig
	mu           sync.RWMutex

	groups map[string][]string               // group name to user ids (with group hierarchy resolved)
	roles  map[string][]types.RBACPermission // role name to permissions (with role: hierarchy resolved)
}

func NewRBACHandler(logger *types.Logger, rbacConfig *types.RBACConfig, serverConfig *types.ServerConfig) (*RBACManager, error) {
	rbacManager := &RBACManager{
		Logger:       logger,
		rbacConfig:   rbacConfig,
		serverConfig: serverConfig,
	}

	err := rbacManager.UpdateRBACConfig(rbacConfig)
	if err != nil {
		return nil, err
	}
	return rbacManager, nil
}

func (h *RBACManager) Authorize(user string, appPathDomain types.AppPathDomain, appAuthSetting string, permission types.RBACPermission) (bool, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.rbacConfig.Enabled {
		// rbac is not enabled, authorize all requests
		return true, nil
	}

	if user != "" && user == types.ADMIN_USER {
		// admin user is always authorized if enabled
		return true, nil
	}

	if !strings.HasPrefix(appAuthSetting, RBAC_AUTH_PREFIX) && permission == types.PermissionAccess {
		// if app auth does not have rbac enabled, authorize access for Access permission
		// If authenticated, then app access is allowed
		return true, nil
	}

	// Trim stage and preview suffixes, grant check are done on the main app path
	appPathDomain.Path = strings.TrimSuffix(appPathDomain.Path, types.STAGE_SUFFIX)
	appPathDomain.Path = strings.TrimSuffix(appPathDomain.Path, types.PREVIEW_SUFFIX)

	return h.checkGrants(user, appPathDomain, permission)
}

func (h *RBACManager) checkGrants(inputUser string, appPathDomain types.AppPathDomain, inputPermission types.RBACPermission) (bool, error) {
	for _, grant := range h.rbacConfig.Grants {
		match, err := h.checkGrant(grant, inputUser, appPathDomain, inputPermission)
		if err != nil {
			return false, err
		}
		if match {
			// User, role and target matched. This is a valid grant.
			h.Trace().Msgf("Allowed user %s access to app %s with permission %s using grant %s",
				inputUser, appPathDomain.String(), inputPermission, grant.Description)
			return true, nil
		}
	}
	h.Debug().Msgf("Denied user %s access to app %s with permission %s", inputUser, appPathDomain.String(), inputPermission)
	return false, nil
}

func (h *RBACManager) checkGrant(grant types.RBACGrant, inputUser string, appPathDomain types.AppPathDomain, inputPermission types.RBACPermission) (bool, error) {
	userMatched := false
	for _, user := range grant.Users {
		if strings.HasPrefix(user, RBAC_GROUP_PREFIX) {
			refGroupName := user[len(RBAC_GROUP_PREFIX):]
			if slices.Contains(h.groups[refGroupName], inputUser) {
				userMatched = true
				break
			}
		} else if user == inputUser {
			userMatched = true
			break
		}
	}

	if !userMatched {
		return false, nil
	}

	// user matched, check if role matches
	roleMatched := false
	for _, role := range grant.Roles {
		if slices.Contains(h.roles[role], inputPermission) {
			roleMatched = true
			break
		}
	}

	if !roleMatched {
		return false, nil
	}

	targetMatched := false
	for _, target := range grant.Targets {
		match, err := MatchGlob(target, appPathDomain)
		if err != nil {
			return false, err
		}
		if match {
			targetMatched = true
			break
		}
	}

	if !targetMatched {
		return false, nil
	}

	return true, nil
}

func (h *RBACManager) initGroupInfo(rbacConfig *types.RBACConfig) (map[string][]string, error) {
	groupMembers := make(map[string][]string)

	// Initialize all groups
	for group := range rbacConfig.Groups {
		groupMembers[group] = make([]string, 0)
	}

	// Helper function to recursively resolve group membership
	var resolveGroup func(groupName string, visited map[string]bool) ([]string, error)
	resolveGroup = func(groupName string, visited map[string]bool) ([]string, error) {
		if visited[groupName] {
			return nil, fmt.Errorf("circular group reference detected for group: %s", groupName)
		}

		users, exists := rbacConfig.Groups[groupName]
		if !exists {
			return nil, fmt.Errorf("group: %s is not defined", groupName)
		}

		visited[groupName] = true
		defer func() { visited[groupName] = false }()

		var members []string
		for _, user := range users {
			if strings.HasPrefix(user, RBAC_GROUP_PREFIX) {
				refGroupName := user[len(RBAC_GROUP_PREFIX):]
				refMembers, err := resolveGroup(refGroupName, visited)
				if err != nil {
					return nil, err
				}
				members = append(members, refMembers...)
			} else {
				members = append(members, user)
			}
		}

		return members, nil
	}

	// Resolve all groups
	for group := range rbacConfig.Groups {
		visited := make(map[string]bool)
		members, err := resolveGroup(group, visited)
		if err != nil {
			return nil, err
		}
		groupMembers[group] = members
	}

	return groupMembers, nil
}

func (h *RBACManager) initRoleInfo(rbacConfig *types.RBACConfig) (map[string][]types.RBACPermission, error) {
	roles := make(map[string][]types.RBACPermission)

	// Initialize all roles
	for role := range rbacConfig.Roles {
		roles[role] = make([]types.RBACPermission, 0)
	}

	// Helper function to recursively resolve role permissions
	var resolveRole func(roleName string, visited map[string]bool) ([]types.RBACPermission, error)
	resolveRole = func(roleName string, visited map[string]bool) ([]types.RBACPermission, error) {
		if visited[roleName] {
			return nil, fmt.Errorf("circular role reference detected for role: %s", roleName)
		}

		perms, exists := rbacConfig.Roles[roleName]
		if !exists {
			return nil, fmt.Errorf("role: %s is not defined", roleName)
		}

		visited[roleName] = true
		defer func() { visited[roleName] = false }()

		var permissions []types.RBACPermission
		for _, perm := range perms {
			if strings.HasPrefix(string(perm), RBAC_ROLE_PREFIX) {
				refRoleName := string(perm)[len(RBAC_ROLE_PREFIX):]
				refPermissions, err := resolveRole(refRoleName, visited)
				if err != nil {
					return nil, err
				}
				permissions = append(permissions, refPermissions...)
			} else {
				permissions = append(permissions, perm)
			}
		}

		return permissions, nil
	}

	// Resolve all roles
	for role := range rbacConfig.Roles {
		visited := make(map[string]bool)
		permissions, err := resolveRole(role, visited)
		if err != nil {
			return nil, err
		}
		roles[role] = permissions
	}

	return roles, nil
}
func (h *RBACManager) validateGrants(rbacConfig *types.RBACConfig) error {
	// Skip validation if RBAC is disabled
	if !rbacConfig.Enabled {
		return nil
	}

	for i, grant := range rbacConfig.Grants {
		// Validate group references in Users
		for _, user := range grant.Users {
			if strings.HasPrefix(user, RBAC_GROUP_PREFIX) {
				groupName := user[len(RBAC_GROUP_PREFIX):]
				if _, exists := rbacConfig.Groups[groupName]; !exists {
					return fmt.Errorf("grant %d ('%s'): Users references undefined group '%s'", i, grant.Description, groupName)
				}
			}
		}

		// Validate role references in Roles
		for _, role := range grant.Roles {
			if _, exists := rbacConfig.Roles[role]; !exists {
				return fmt.Errorf("grant %d ('%s'): Roles references undefined role '%s'", i, grant.Description, role)
			}
		}
	}
	return nil
}

func (h *RBACManager) UpdateRBACConfig(rbacConfig *types.RBACConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.rbacConfig = rbacConfig

	var err error
	h.groups, err = h.initGroupInfo(rbacConfig)
	if err != nil {
		return fmt.Errorf("error initializing rbac group info: %w", err)
	}

	h.roles, err = h.initRoleInfo(rbacConfig)
	if err != nil {
		return fmt.Errorf("error initializing rbac role info: %w", err)
	}

	err = h.validateGrants(rbacConfig)
	if err != nil {
		return fmt.Errorf("error validating rbac grants: %w", err)
	}

	return nil
}
