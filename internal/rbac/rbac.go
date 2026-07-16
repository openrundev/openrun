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

	groups         map[string]*resolvedGroup                // group name to resolved membership (group hierarchy resolved)
	roles          map[string]*resolvedRole                 // role name to resolved permissions (hierarchy and implications resolved)
	resolvedGrants []resolvedGrant                          // per grant resolved state, aligned with RbacConfig.Grants
	hasAdminGrant  bool                                     // whether any grant's roles confer the admin super-user permission
	regexCache     map[string]*regexp.Regexp                // cache of compiled regex patterns
	customPerms    []string                                 // custom permissions are permissions defined by the user. This list does not have the custom: prefix
	ownerPerms     map[string]map[types.RBACPermission]bool // resource name to permissions granted to the asset owner
	enabled        atomic.Bool                              // RbacConfig.Enabled, readable without taking mu (hot path checks)
}

// resolvedGroup is a group's membership resolved into lookup structures at
// config update time: direct user ids as a set, regex: members precompiled
type resolvedGroup struct {
	members map[string]bool
	regexes []*regexp.Regexp
}

// resolvedGrant is the per-grant state resolved at config update time, so
// grant checks do not re-parse target globs on every authorization
type resolvedGrant struct {
	targets []parsedTarget
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
	if !h.enabled.Load() {
		// rbac is not enabled, authorize all requests. Checked through the
		// atomic so the per-request hot path (every app access check) does not
		// touch the RWMutex when RBAC is disabled
		return true, nil
	}
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

	if user == "" {
		// Fail closed: enforcement is active and every request is authenticated
		// to a user id (or the anonymous principal). An empty user is a context
		// propagation bug and must not match grants (a regex user pattern could
		// otherwise match the empty string)
		return false, nil
	}

	if isAdmin, err := h.hasAdminPermLocked(user, groups); err != nil || isAdmin {
		// the admin super-user permission passes every check
		return isAdmin, err
	}

	// Callers resolve stage/preview apps to their main app path before this point, so
	// grant checks run against the main app path directly.
	return h.checkGrants(user, appPathDomain, "", permission, groups, isAppLevelPermission)
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
// or the openrun-admin role (admin is a global permission, conferred
// regardless of the grant's targets, and permission globs never match it).
// Callers must hold h.mu
func (h *RBACManager) hasAdminPermLocked(user string, groups []string) (bool, error) {
	if user != "" && user == types.ADMIN_USER {
		return true, nil
	}
	if !h.hasAdminGrant {
		// No grant's roles confer the admin permission (computed at config
		// update time), so the grant scan below cannot match: skip it. This
		// runs on every authorization, before the actual permission check
		return false, nil
	}
	return h.checkGrants(user, types.AppPathDomain{}, "", types.PermissionAdmin, groups, false)
}

// checkGrants evaluates the grants for inputPermission. appPathDomain is the
// app being checked for app scoped permissions; resourceId is the service id
// or binding path for service/binding scoped permissions ("" otherwise)
func (h *RBACManager) checkGrants(inputUser string, appPathDomain types.AppPathDomain, resourceId string,
	inputPermission types.RBACPermission, groups []string, isAppLevelPermission bool) (bool, error) {
	if isAppLevelPermission {
		// app level permission, look for grant with custom: prefix
		inputPermission = types.RBACPermission(RBAC_CUSTOM_PREFIX + string(inputPermission))
	}
	for i, grant := range h.RbacConfig.Grants {
		match, err := h.checkGrant(grant, h.resolvedGrants[i].targets, inputUser, appPathDomain,
			resourceId, inputPermission, groups, isAppLevelPermission)
		if err != nil {
			return false, err
		}
		if match {
			// User, role and target matched. This is a valid grant.
			if trace := h.Trace(); trace.Enabled() {
				trace.Msgf("Allowed user %s access to %s%s with permission %s using grant %s",
					inputUser, appPathDomain.String(), resourceId, inputPermission, grant.Description)
			}
			return true, nil
		}
	}
	if debug := h.Debug(); debug.Enabled() {
		debug.Msgf("Denied user %s access to %s%s with permission %s app level %t",
			inputUser, appPathDomain.String(), resourceId, inputPermission, isAppLevelPermission)
	}
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
				if refGroup.members[inputUser] {
					return true, nil
				}
				// Check the group's regex members
				for _, regex := range refGroup.regexes {
					if regex.MatchString(inputUser) {
						return true, nil
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

// checkGrant reports whether one grant confers inputPermission (already
// custom: prefixed for app level permissions) on the app or resource. Roles
// are checked before users: role matching is a map lookup while user matching
// may run regexes, so grants that cannot confer the permission are skipped cheaply
func (h *RBACManager) checkGrant(grant types.RBACGrant, targets []parsedTarget, inputUser string,
	appPathDomain types.AppPathDomain, resourceId string, inputPermission types.RBACPermission,
	groups []string, isAppLevelPermission bool) (bool, error) {
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

	userMatched, err := h.grantUserMatchesLocked(grant, inputUser, groups)
	if err != nil || !userMatched {
		return false, err
	}

	return permWithinTargets(inputPermission, isAppLevelPermission, targets, appPathDomain, resourceId)
}

// permWithinTargets reports whether a permission a role confers applies to the
// checked app or resource given the grant's targets. Scoped permissions are
// matched against target entries of their kind: app:* (and app-level custom
// permissions) against app path targets, service:*/binding:* against
// service:/binding: target entries (matched against resourceId). Every other
// permission is global: the grant confers it regardless of its targets.
// Shared by live grant checks and the frozen sync snapshot evaluation, so the
// scoping semantics cannot diverge between them
func permWithinTargets(perm types.RBACPermission, isAppLevelPermission bool,
	targets []parsedTarget, appPathDomain types.AppPathDomain, resourceId string) (bool, error) {
	kind, scoped := scopedKind(perm, isAppLevelPermission)
	if !scoped {
		return true, nil
	}
	for _, target := range targets {
		var match bool
		var err error
		if kind == targetKindApp {
			match, err = target.matchesApp(appPathDomain)
		} else {
			match, err = target.matchesResource(kind, resourceId)
		}
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// compileUserRegex compiles a regex: pattern from a users list and stores it
// in cache, keyed by the raw pattern. Patterns are anchored (\A...\z) so they
// must match the entire user id: with an unanchored substring search, a
// pattern like .*@example\.com would also match evil@example.com.attacker.io,
// silently over-granting
func compileUserRegex(cache map[string]*regexp.Regexp, pattern string) error {
	if _, ok := cache[pattern]; ok {
		return nil
	}
	regex, err := regexp.Compile(`\A(?:` + pattern + `)\z`)
	if err != nil {
		return fmt.Errorf("error compiling regex %q: %w", pattern, err)
	}
	cache[pattern] = regex
	return nil
}

// initGroupInfo resolves the group hierarchy into membership lookup
// structures, compiling regex: members into regexCache. Pure: on error no
// state has been published to the manager
func (h *RBACManager) initGroupInfo(rbacConfig *types.RBACConfig, regexCache map[string]*regexp.Regexp) (map[string]*resolvedGroup, error) {
	groupMembers := make(map[string]*resolvedGroup)

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
					if err := compileUserRegex(regexCache, user[len(RBAC_REGEX_PREFIX):]); err != nil {
						return nil, err
					}
				}
				members = append(members, user)
			}
		}

		return members, nil
	}

	// Resolve all groups into lookup structures: user ids as a set, regex
	// members precompiled, so per-request membership checks avoid scanning
	// the member list and re-looking up the regex cache
	for group := range rbacConfig.Groups {
		visited := make(map[string]bool)
		members, err := resolveGroup(group, visited)
		if err != nil {
			return nil, err
		}
		resolved := &resolvedGroup{members: make(map[string]bool, len(members))}
		for _, member := range members {
			if strings.HasPrefix(member, RBAC_REGEX_PREFIX) {
				resolved.regexes = append(resolved.regexes, regexCache[member[len(RBAC_REGEX_PREFIX):]])
			} else {
				resolved.members[member] = true
			}
		}
		groupMembers[group] = resolved
	}

	return groupMembers, nil
}

// initRoleInfo resolves the roles (hierarchy and implications flattened) and
// collects the custom permissions the roles define (without the custom:
// prefix, sorted). Pure: on error no state has been published to the manager
func (h *RBACManager) initRoleInfo(rbacConfig *types.RBACConfig) (map[string]*resolvedRole, []string, error) {
	// Permission name validation only applies when RBAC is enabled, so that a
	// disabled config never blocks server startup
	validate := rbacConfig.Enabled
	if validate {
		for name := range rbacConfig.Roles {
			if isBuiltinRole(name) || strings.HasPrefix(name, ReservedRolePrefix) {
				return nil, nil, fmt.Errorf("role name %q is reserved: the %q prefix is reserved for built-in roles",
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
			return nil, nil, err
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
			return nil, nil, err
		}
		roles[role] = newResolvedRole(permissions)
	}

	// Sorted so surfaces reporting custom permissions (headers, request data)
	// are stable across requests and restarts
	customPerms := make([]string, 0, len(customPermsMap))
	for perm := range customPermsMap {
		customPerms = append(customPerms, perm)
	}
	slices.Sort(customPerms)

	return roles, customPerms, nil
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

// validateGrants validates grant user regexes (compiled into regexCache),
// role references and target globs. Pure: on error no state has been
// published to the manager
func (h *RBACManager) validateGrants(rbacConfig *types.RBACConfig, regexCache map[string]*regexp.Regexp) error {
	// Skip validation if RBAC is disabled
	if !rbacConfig.Enabled {
		return nil
	}

	for i, grant := range rbacConfig.Grants {
		// groups can be passed dynamically (for SSO login), so we don't need to validate them
		for _, user := range grant.Users {
			if strings.HasPrefix(user, RBAC_REGEX_PREFIX) {
				if err := compileUserRegex(regexCache, user[len(RBAC_REGEX_PREFIX):]); err != nil {
					return err
				}
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
		// A malformed target glob would otherwise error every authorization
		// check that evaluates the grant, denying unrelated valid grants
		for _, target := range grant.Targets {
			if err := ValidateGlob(target); err != nil {
				return fmt.Errorf("grant %d ('%s'): invalid target %q: %w", i, grant.Description, target, err)
			}
		}
	}
	return nil
}

// UpdateRBACConfig resolves and validates rbacConfig and swaps it in
// atomically: everything is built into locals first and published only when
// the whole update has succeeded, so a rejected config never leaves partial
// state behind (mixed old/new groups and roles, or the enabled flag out of
// sync with the resolved state)
func (h *RBACManager) UpdateRBACConfig(rbacConfig *types.RBACConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	regexCache := make(map[string]*regexp.Regexp)

	groups, err := h.initGroupInfo(rbacConfig, regexCache)
	if err != nil {
		return fmt.Errorf("error initializing rbac group info: %w", err)
	}

	roles, customPerms, err := h.initRoleInfo(rbacConfig)
	if err != nil {
		return fmt.Errorf("error initializing rbac role info: %w", err)
	}

	ownerPerms, err := h.initOwnerPerms(rbacConfig)
	if err != nil {
		return fmt.Errorf("error initializing rbac owner permissions: %w", err)
	}

	if err := h.validateGrants(rbacConfig, regexCache); err != nil {
		return fmt.Errorf("error validating rbac grants: %w", err)
	}

	// Per grant resolved state: pre-parsed target globs, and whether any
	// grant confers the admin super-user permission (when none does, the
	// admin pre-check on every authorization skips the grant scan)
	resolvedGrants := make([]resolvedGrant, len(rbacConfig.Grants))
	hasAdminGrant := false
	for i, grant := range rbacConfig.Grants {
		targets := make([]parsedTarget, 0, len(grant.Targets))
		for _, target := range grant.Targets {
			targets = append(targets, parseTarget(target))
		}
		resolvedGrants[i].targets = targets
		for _, role := range grant.Roles {
			if resolved, ok := roles[role]; ok && resolved.matches(types.PermissionAdmin) {
				hasAdminGrant = true
			}
		}
	}

	h.RbacConfig = rbacConfig
	h.regexCache = regexCache
	h.groups = groups
	h.roles = roles
	h.resolvedGrants = resolvedGrants
	h.hasAdminGrant = hasAdminGrant
	h.customPerms = customPerms
	h.ownerPerms = ownerPerms
	h.enabled.Store(rbacConfig.Enabled)
	return nil
}
