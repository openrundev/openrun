// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/openrundev/openrun/internal/types"
)

const RBAC_AUTH_PREFIX = "rbac:"
const RBAC_GROUP_PREFIX = "group:"
const RBAC_ROLE_PREFIX = "role:"
const RBAC_CUSTOM_PREFIX = "custom:" // used for app level custom permissions
const RBAC_REGEX_PREFIX = "regex:"   // used for regex matching in users list

type RBACManager struct {
	*types.Logger
	RbacConfig   *types.RBACConfig
	serverConfig *types.ServerConfig
	mu           sync.RWMutex

	groups      map[string][]string                      // group name to user ids (with group hierarchy resolved)
	roles       map[string]*resolvedRole                 // role name to resolved permissions (hierarchy and implications resolved)
	regexCache  map[string]*regexp.Regexp                // cache of compiled regex patterns
	customPerms []string                                 // custom permissions are permissions defined by the user. This list does not have the custom: prefix
	ownerPerms  map[string]map[types.RBACPermission]bool // resource name to permissions granted to the asset owner
	enabled     atomic.Bool                              // RbacConfig.Enabled, readable without taking mu (hot path checks)
}

func NewRBACHandler(logger *types.Logger, rbacConfig *types.RBACConfig, serverConfig *types.ServerConfig) (*RBACManager, error) {
	rbacManager := &RBACManager{
		Logger:       logger,
		RbacConfig:   rbacConfig,
		serverConfig: serverConfig,
	}

	err := rbacManager.UpdateRBACConfig(rbacConfig)
	if err != nil {
		return nil, err
	}
	return rbacManager, nil
}

func (h *RBACManager) AuthorizeInt(user string, appPathDomain types.AppPathDomain,
	permission types.RBACPermission, groups []string, isAppLevelPermission bool) (bool, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.authorizeIntLocked(user, appPathDomain, permission, groups, isAppLevelPermission)
}

// authorizeIntLocked is AuthorizeInt without the read lock; the caller must
// already hold h.mu (RWMutex read locks are not reentrant - re-acquiring one
// while a writer waits deadlocks, so shared callers like GetCustomPermissionsInt
// take the lock once and call this)
func (h *RBACManager) authorizeIntLocked(user string, appPathDomain types.AppPathDomain,
	permission types.RBACPermission, groups []string, isAppLevelPermission bool) (bool, error) {
	if !h.RbacConfig.Enabled {
		// rbac is not enabled, authorize all requests
		return true, nil
	}

	if isAdmin, err := h.hasAdminPermLocked(user, groups); err != nil || isAdmin {
		// the admin super-user permission passes every check
		return isAdmin, err
	}

	// Callers resolve stage/preview apps to their main app path before this point, so
	// grant checks run against the main app path directly.
	return h.checkGrants(user, appPathDomain, permission, groups, isAppLevelPermission)
}

// GetCustomPermissions returns the custom permissions set for the user for the given app path domain
// Values in returned list do not have the custom: prefix
func (h *RBACManager) GetCustomPermissionsInt(user string, appPathDomain types.AppPathDomain,
	groups []string) ([]string, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.customPerms) == 0 {
		return nil, nil
	}

	if !h.RbacConfig.Enabled {
		// rbac is not enabled, authorize all requests
		return h.customPerms, nil
	}

	if isAdmin, err := h.hasAdminPermLocked(user, groups); err != nil {
		return nil, err
	} else if isAdmin {
		// the admin super-user permission passes every check
		return h.customPerms, nil
	}

	customPerms := make([]string, 0)
	for _, perm := range h.customPerms {
		// authorizeIntLocked, not AuthorizeInt: we already hold h.mu.RLock and
		// re-acquiring it here can deadlock against a waiting config-update writer
		authorized, err := h.authorizeIntLocked(user, appPathDomain, types.RBACPermission(perm), groups, true)
		if err != nil {
			return nil, err
		}
		if authorized {
			customPerms = append(customPerms, perm)
		}
	}

	h.Trace().Msgf("User %s has custom permissions: %v on app %s groups %v", user,
		customPerms, appPathDomain.String(), groups)
	return customPerms, nil
}

// ConfigEnabled reports whether RBAC is enabled at the config level. Lock
// free (atomic load), safe on the per-request paths
func (h *RBACManager) ConfigEnabled() bool {
	return h.enabled.Load()
}

// hasAdminPermLocked reports whether the user holds the "admin" super-user
// permission, which passes every RBAC check. The admin user holds it
// implicitly; other users hold it through a grant of the literal permission
// or the openrun-admin role (a global target is required, and permission
// globs never match it). Callers must hold h.mu
func (h *RBACManager) hasAdminPermLocked(user string, groups []string) (bool, error) {
	if user != "" && user == types.ADMIN_USER {
		return true, nil
	}
	return h.checkGrants(user, types.AppPathDomain{}, types.PermissionAdmin, groups, false)
}

func (h *RBACManager) checkGrants(inputUser string, appPathDomain types.AppPathDomain,
	inputPermission types.RBACPermission, groups []string, isAppLevelPermission bool) (bool, error) {
	for _, grant := range h.RbacConfig.Grants {
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

// grantUserMatchesLocked reports whether the grant's Users list matches
// inputUser: a direct user id, a group: reference (matched against the SSO
// context groups and the resolved config groups, including regex: members) or
// a regex: pattern. Callers must hold h.mu
func (h *RBACManager) grantUserMatchesLocked(grant types.RBACGrant, inputUser string, groups []string) (bool, error) {
	for _, user := range grant.Users {
		if strings.HasPrefix(user, RBAC_GROUP_PREFIX) {
			refGroupName := user[len(RBAC_GROUP_PREFIX):]
			if slices.Contains(groups, refGroupName) {
				// granted group name matched group as found from SSO login
				return true, nil
			}
			refGroup, ok := h.groups[refGroupName]
			if ok {
				// Check for direct user match
				if slices.Contains(refGroup, inputUser) {
					return true, nil
				}
				// Check for regex patterns in the group
				for _, groupMember := range refGroup {
					if strings.HasPrefix(groupMember, RBAC_REGEX_PREFIX) {
						regex, ok := h.regexCache[groupMember[len(RBAC_REGEX_PREFIX):]]
						if ok && regex.MatchString(inputUser) {
							return true, nil
						}
					}
				}
			}
		} else if strings.HasPrefix(user, RBAC_REGEX_PREFIX) {
			// user in grant  is a regex, match it against the input user
			regex, ok := h.regexCache[user[len(RBAC_REGEX_PREFIX):]]
			if !ok {
				return false, fmt.Errorf("regex not found for user: %s", user)
			}
			if regex.MatchString(inputUser) {
				return true, nil
			}
		} else if user == inputUser {
			return true, nil
		}
	}
	return false, nil
}

func (h *RBACManager) checkGrant(grant types.RBACGrant, inputUser string, appPathDomain types.AppPathDomain,
	inputPermission types.RBACPermission, groups []string, isAppLevelPermission bool) (bool, error) {
	userMatched, err := h.grantUserMatchesLocked(grant, inputUser, groups)
	if err != nil {
		return false, err
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
		if resolved, ok := h.roles[role]; ok && resolved.matches(inputPermission) {
			roleMatched = true
			break
		}
	}

	if !roleMatched {
		return false, nil
	}

	return permWithinTargets(inputPermission, isAppLevelPermission, grant.Targets, appPathDomain)
}

// permWithinTargets reports whether a permission a role confers applies to the
// app at appPathDomain given the grant's targets. app:* (and
// app-level custom permissions) are scoped to the grant's target glob. Every
// other permission is global: the grant confers it regardless of its targets.
// Shared by live grant checks and the frozen sync snapshot evaluation, so the
// scoping semantics cannot diverge between them
func permWithinTargets(perm types.RBACPermission, isAppLevelPermission bool,
	targets []string, appPathDomain types.AppPathDomain) (bool, error) {
	if !isAppLevelPermission && !scopedPermissions[perm] {
		return true, nil
	}
	for _, target := range targets {
		match, err := MatchGlob(target, appPathDomain)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
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

func (h *RBACManager) initRoleInfo(rbacConfig *types.RBACConfig) (map[string]*resolvedRole, error) {
	// Permission name validation only applies when RBAC is enabled, so that a
	// disabled config never blocks server startup
	validate := rbacConfig.Enabled
	if validate {
		for name := range rbacConfig.Roles {
			if isBuiltinRole(name) || strings.HasPrefix(name, ReservedRolePrefix) {
				return nil, fmt.Errorf("role name %q is reserved: the %q prefix is reserved for built-in roles",
					name, ReservedRolePrefix)
			}
		}
	}

	// Helper function to recursively resolve role permissions. User roles take
	// precedence in lookup, then the built-in predefined roles, so a user role
	// or grant can reference a predefined role like role:openrun-developer
	var resolveRole func(roleName string, visited map[string]bool) ([]types.RBACPermission, error)
	resolveRole = func(roleName string, visited map[string]bool) ([]types.RBACPermission, error) {
		if visited[roleName] {
			return nil, fmt.Errorf("circular role reference detected for role: %s", roleName)
		}

		perms, exists := rbacConfig.Roles[roleName]
		if !exists {
			perms, exists = predefinedRoles[roleName]
		}
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
				perm = normalizePermission(perm)
				if validate {
					if err := validatePermission(perm); err != nil {
						return nil, fmt.Errorf("role %s: %w", roleName, err)
					}
				}
				permissions = append(permissions, perm)
			}
		}

		return permissions, nil
	}

	// Resolve all roles into fast lookup structures. Implications (app:update
	// implying reload/apply/read, app:manage implying all app permissions except
	// approve) are expanded here so grant checks stay a map lookup
	roles := make(map[string]*resolvedRole, len(rbacConfig.Roles)+1)
	customPermsMap := make(map[string]bool)
	for role := range rbacConfig.Roles {
		visited := make(map[string]bool)
		permissions, err := resolveRole(role, visited)
		if err != nil {
			return nil, err
		}
		roles[role] = newResolvedRole(permissions)

		// Keep track of all custom perms (deduplicated)
		for _, permission := range permissions {
			if strings.HasPrefix(string(permission), RBAC_CUSTOM_PREFIX) && !hasGlobMeta(string(permission)) {
				customPermsMap[string(permission)[len(RBAC_CUSTOM_PREFIX):]] = true
			}
		}
	}

	// Built-in predefined roles (openrun-*), always available. Resolved after
	// the user roles so a user role may reference them; each is expanded with
	// implications like any other role
	for role := range predefinedRoles {
		visited := make(map[string]bool)
		permissions, err := resolveRole(role, visited)
		if err != nil {
			return nil, err
		}
		roles[role] = newResolvedRole(permissions)
	}

	for perm := range customPermsMap {
		h.customPerms = append(h.customPerms, perm)
	}

	return roles, nil
}

// initOwnerPerms resolves the owner permission sets: built-in defaults overridden by
// the owner_permissions config, with implications expanded
func (h *RBACManager) initOwnerPerms(rbacConfig *types.RBACConfig) (map[string]map[types.RBACPermission]bool, error) {
	validate := rbacConfig.Enabled
	ownerPerms := make(map[string]map[types.RBACPermission]bool, len(defaultOwnerPermissions))
	for resource, perms := range defaultOwnerPermissions {
		if configured, ok := rbacConfig.OwnerPermissions[resource]; ok {
			perms = configured
		}
		normalized := make([]types.RBACPermission, 0, len(perms))
		for _, perm := range perms {
			normalized = append(normalized, normalizePermission(perm))
		}
		perms = normalized
		for _, perm := range perms {
			if !validate {
				break
			}
			if hasGlobMeta(string(perm)) {
				return nil, fmt.Errorf("owner_permissions.%s: glob patterns are not allowed, got %q", resource, perm)
			}
			if err := validatePermission(perm); err != nil {
				return nil, fmt.Errorf("owner_permissions.%s: %w", resource, err)
			}
			if perm == types.PermissionApprove {
				return nil, fmt.Errorf("owner_permissions.%s: %s cannot be granted to owners, it requires an explicit grant", resource, types.PermissionApprove)
			}
			if PermissionResource(perm) != resource {
				return nil, fmt.Errorf("owner_permissions.%s: permission %q does not belong to resource %s", resource, perm, resource)
			}
		}
		expanded := expandImplications(perms)
		permSet := make(map[types.RBACPermission]bool, len(expanded))
		for _, perm := range expanded {
			permSet[perm] = true
		}
		ownerPerms[resource] = permSet
	}

	if validate {
		for resource := range rbacConfig.OwnerPermissions {
			if _, ok := defaultOwnerPermissions[resource]; !ok {
				return nil, fmt.Errorf("owner_permissions: unknown resource %q, valid resources are app, sync", resource)
			}
		}
	}

	return ownerPerms, nil
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
			if isBuiltinRole(role) {
				continue // built-in role, always defined
			}
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

	h.RbacConfig = rbacConfig
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

	h.ownerPerms, err = h.initOwnerPerms(rbacConfig)
	if err != nil {
		return fmt.Errorf("error initializing rbac owner permissions: %w", err)
	}

	err = h.validateGrants(rbacConfig)
	if err != nil {
		return fmt.Errorf("error validating rbac grants: %w", err)
	}

	// Published last, after the config validated: ConfigEnabled readers see
	// the new state only once the update is going to succeed
	h.enabled.Store(rbacConfig.Enabled)
	return nil
}
