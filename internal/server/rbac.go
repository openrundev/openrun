// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/openrundev/openrun/internal/types"
)

const RBAC_AUTH_PREFIX = "rbac:"
const RBAC_GROUP_PREFIX = "group:"
const RBAC_ROLE_PREFIX = "role:"
const RBAC_CUSTOM_PREFIX = "custom:" // used for app level custom permissions
const RBAC_REGEX_PREFIX = "regex:"   // used for regex matching in users list

type RBACManager struct {
	*types.Logger
	rbacConfig   *types.RBACConfig
	serverConfig *types.ServerConfig
	mu           sync.RWMutex

	groups      map[string][]string               // group name to user ids (with group hierarchy resolved)
	roles       map[string][]types.RBACPermission // role name to permissions (with role: hierarchy resolved)
	regexCache  map[string]*regexp.Regexp         // cache of compiled regex patterns
	customPerms []string                          // custom permissions are permissions defined by the user. This list does not have the custom: prefix
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

func (h *RBACManager) Authorize(user string, appPathDomain types.AppPathDomain,
	appAuthSetting string, permission types.RBACPermission, groups []string, isAppLevelPermission bool) (bool, error) {
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

	if !strings.HasPrefix(appAuthSetting, RBAC_AUTH_PREFIX) && (permission == types.PermissionAccess || isAppLevelPermission) {
		// if app auth does not have rbac enabled, authorize access for Access permission
		// If authenticated, then app access is allowed
		return true, nil
	}

	// Trim stage and preview suffixes, grant check are done on the main app path
	appPathDomain.Path = strings.TrimSuffix(appPathDomain.Path, types.STAGE_SUFFIX)
	appPathDomain.Path = strings.TrimSuffix(appPathDomain.Path, types.PREVIEW_SUFFIX)

	return h.checkGrants(user, appPathDomain, permission, groups, isAppLevelPermission)
}

// GetCustomPermissions returns the custom permissions set for the user for the given app path domain and app auth setting
// Values in returned list do not have the custom: prefix
func (h *RBACManager) GetCustomPermissions(user string, appPathDomain types.AppPathDomain, appAuthSetting string,
	groups []string) ([]string, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.customPerms) == 0 {
		return nil, nil
	}

	if !h.rbacConfig.Enabled {
		// rbac is not enabled, authorize all requests
		return h.customPerms, nil
	}

	if user != "" && user == types.ADMIN_USER {
		// admin user is always authorized if enabled
		return h.customPerms, nil
	}

	customPerms := make([]string, 0)
	for _, perm := range h.customPerms {
		authorized, err := h.Authorize(user, appPathDomain, appAuthSetting, types.RBACPermission(perm), groups, true)
		if err != nil {
			return nil, err
		}
		if authorized {
			customPerms = append(customPerms, perm)
		}
	}

	h.Trace().Msgf("User %s has custom permissions: %v on app %s with auth setting %s groups %v", user,
		customPerms, appPathDomain.String(), appAuthSetting, groups)
	return customPerms, nil
}

func (h *RBACManager) checkGrants(inputUser string, appPathDomain types.AppPathDomain,
	inputPermission types.RBACPermission, groups []string, isAppLevelPermission bool) (bool, error) {
	for _, grant := range h.rbacConfig.Grants {
		match, err := h.checkGrant(grant, inputUser, appPathDomain, inputPermission, groups, isAppLevelPermission)
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
	h.Debug().Msgf("Denied user %s access to app %s with permission %s app level %t",
		inputUser, appPathDomain.String(), inputPermission, isAppLevelPermission)
	return false, nil
}

func (h *RBACManager) checkGrant(grant types.RBACGrant, inputUser string, appPathDomain types.AppPathDomain,
	inputPermission types.RBACPermission, groups []string, isAppLevelPermission bool) (bool, error) {
	userMatched := false
	for _, user := range grant.Users {
		if strings.HasPrefix(user, RBAC_GROUP_PREFIX) {
			refGroupName := user[len(RBAC_GROUP_PREFIX):]
			if slices.Contains(groups, refGroupName) {
				// granted group name matched group as found from SSO login
				userMatched = true
				break
			}
			refGroup, ok := h.groups[refGroupName]
			if ok {
				// Check for direct user match
				if slices.Contains(refGroup, inputUser) {
					userMatched = true
					break
				}
				// Check for regex patterns in the group
				for _, groupMember := range refGroup {
					if strings.HasPrefix(groupMember, RBAC_REGEX_PREFIX) {
						regex, ok := h.regexCache[groupMember[len(RBAC_REGEX_PREFIX):]]
						if ok && regex.MatchString(inputUser) {
							userMatched = true
							break
						}
					}
				}
				if userMatched {
					break
				}
			}
		} else if strings.HasPrefix(user, RBAC_REGEX_PREFIX) {
			// user in grant  is a regex, match it against the input user
			regex, ok := h.regexCache[user[len(RBAC_REGEX_PREFIX):]]
			if !ok {
				return false, fmt.Errorf("regex not found for user: %s", user)
			}
			if regex.MatchString(inputUser) {
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
	if isAppLevelPermission {
		// app level permission, look for grant with custom: prefix
		inputPermission = types.RBACPermission(RBAC_CUSTOM_PREFIX + string(inputPermission))
	}
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
				if strings.HasPrefix(user, RBAC_REGEX_PREFIX) {
					regexPattern := user[len(RBAC_REGEX_PREFIX):]
					regex, err := regexp.Compile(regexPattern)
					if err != nil {
						return nil, err
					}
					h.regexCache[regexPattern] = regex
				}
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

	// Keep track of all custom perms (deduplicated)
	customPermsMap := make(map[string]bool)
	for _, role := range roles {
		for _, permission := range role {
			if strings.HasPrefix(string(permission), RBAC_CUSTOM_PREFIX) {
				perm := string(permission)[len(RBAC_CUSTOM_PREFIX):]
				customPermsMap[perm] = true
			}
		}
	}

	// Convert map to slice
	for perm := range customPermsMap {
		h.customPerms = append(h.customPerms, perm)
	}

	return roles, nil
}
func (h *RBACManager) validateGrants(rbacConfig *types.RBACConfig) error {
	// Skip validation if RBAC is disabled
	if !rbacConfig.Enabled {
		return nil
	}

	for i, grant := range rbacConfig.Grants {
		// groups can be passed dynamically (for SSO login), so we don't need to validate them
		// Validate role references in Roles
		for _, user := range grant.Users {
			if strings.HasPrefix(user, RBAC_REGEX_PREFIX) {
				regexPattern := user[len(RBAC_REGEX_PREFIX):]
				regex, err := regexp.Compile(regexPattern)
				if err != nil {
					return fmt.Errorf("error compiling regex: %w", err)
				}
				h.regexCache[regexPattern] = regex
			}
		}
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
	h.regexCache = make(map[string]*regexp.Regexp)
	h.customPerms = make([]string, 0)

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
