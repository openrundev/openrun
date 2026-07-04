// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/openrundev/openrun/internal/types"
)

// AdminRoleName is the built-in role that grants every permission (including
// app:approve). It is always defined and cannot be redefined in the config.
const AdminRoleName = "admin"

// Resource names used for owner permission lookup
const (
	ResourceApp  = "app"
	ResourceSync = "sync"
)

// appPermissions are all app scoped permissions
var appPermissions = []types.RBACPermission{
	types.PermissionAccess,
	types.PermissionRead,
	types.PermissionCreate,
	types.PermissionUpdate,
	types.PermissionReload,
	types.PermissionApply,
	types.PermissionDelete,
	types.PermissionApprove,
	types.PermissionPromote,
	types.PermissionPreview,
	types.PermissionTokenRead,
	types.PermissionTokenManage,
	types.PermissionAppAdmin,
}

// globalPermissions are permissions with no app path target. Grants confer these
// only when the grant targets include all apps ("all" or "*:**")
var globalPermissions = map[types.RBACPermission]bool{
	types.PermissionSyncCreate:        true,
	types.PermissionSyncRun:           true,
	types.PermissionSyncDelete:        true,
	types.PermissionSyncRead:          true,
	types.PermissionServiceCreate:     true,
	types.PermissionServiceUpdate:     true,
	types.PermissionServiceDelete:     true,
	types.PermissionServiceRead:       true,
	types.PermissionBindingCreate:     true,
	types.PermissionBindingUpdate:     true,
	types.PermissionBindingDelete:     true,
	types.PermissionBindingRead:       true,
	types.PermissionBindingRunCommand: true,
	types.PermissionConfigRead:        true,
	types.PermissionConfigUpdate:      true,
	types.PermissionServerStop:        true,
}

// builtinPermissions is the set of all valid permission names
var builtinPermissions = func() map[types.RBACPermission]bool {
	perms := make(map[types.RBACPermission]bool, len(appPermissions)+len(globalPermissions))
	for _, p := range appPermissions {
		perms[p] = true
	}
	for p := range globalPermissions {
		perms[p] = true
	}
	return perms
}()

// legacyPermissions maps the old public permission names to their current
// names. Configs using the old names keep working: they are normalized to the
// new names when the config is resolved
var legacyPermissions = map[string]types.RBACPermission{
	"list":   types.PermissionRead,
	"access": types.PermissionAccess,
}

// normalizePermission maps legacy permission names to their current names
func normalizePermission(perm types.RBACPermission) types.RBACPermission {
	if replacement, ok := legacyPermissions[string(perm)]; ok {
		return replacement
	}
	return perm
}

// appAdminPermissions is what app:admin expands to: every app permission except
// app:approve (approving plugin permissions is operator-only) and app:admin itself
var appAdminPermissions = func() []types.RBACPermission {
	perms := make([]types.RBACPermission, 0, len(appPermissions))
	for _, p := range appPermissions {
		if p == types.PermissionApprove || p == types.PermissionAppAdmin {
			continue
		}
		perms = append(perms, p)
	}
	return perms
}()

// permissionImplications: holding the key permission implies the value permissions.
// app:approve is never implied
var permissionImplications = map[types.RBACPermission][]types.RBACPermission{
	types.PermissionUpdate:   {types.PermissionReload, types.PermissionApply, types.PermissionRead},
	types.PermissionAppAdmin: appAdminPermissions,
}

// defaultOwnerPermissions are the permissions the creator of an asset gets on that
// asset when owner_permissions is not configured for the resource
var defaultOwnerPermissions = map[string][]types.RBACPermission{
	ResourceApp:  {types.PermissionAppAdmin},
	ResourceSync: {types.PermissionSyncRun, types.PermissionSyncDelete, types.PermissionSyncRead},
}

// expandImplications returns perms with all implied permissions appended (deduplicated).
// Only exact builtin permissions are expanded; glob and custom entries pass through
func expandImplications(perms []types.RBACPermission) []types.RBACPermission {
	seen := make(map[types.RBACPermission]bool, len(perms)*2)
	ret := make([]types.RBACPermission, 0, len(perms)*2)
	var add func(p types.RBACPermission)
	add = func(p types.RBACPermission) {
		if seen[p] {
			return
		}
		seen[p] = true
		ret = append(ret, p)
		for _, implied := range permissionImplications[p] {
			add(implied)
		}
	}
	for _, p := range perms {
		add(p)
	}
	return ret
}

func hasGlobMeta(s string) bool {
	return strings.ContainsAny(s, "*?[{")
}

// validatePermission checks that a (non role:, non-glob) permission entry in a role
// or owner permission list is valid. Callers normalize legacy names first
func validatePermission(perm types.RBACPermission) error {
	permStr := string(perm)
	if strings.HasPrefix(permStr, RBAC_CUSTOM_PREFIX) {
		return nil // custom permissions are user defined, not validated
	}
	if hasGlobMeta(permStr) {
		if !doublestar.ValidatePattern(permStr) {
			return fmt.Errorf("invalid permission glob pattern %q", permStr)
		}
		return nil
	}
	if !builtinPermissions[perm] {
		return fmt.Errorf("unknown permission %q", permStr)
	}
	return nil
}

// resolvedRole is a role with hierarchy and implications resolved into fast
// lookup structures at config update time
type resolvedRole struct {
	exact    map[types.RBACPermission]bool // exact permission names, implications expanded
	globs    []string                      // glob pattern entries, matched only on exact miss
	matchAll bool                          // built-in admin role: matches every permission
}

// matches reports whether the role grants perm. app:approve is only ever matched
// by its literal name (or the built-in admin role), never by glob entries. custom:
// permissions are matched by glob entries only when the pattern itself has the
// custom: prefix
func (r *resolvedRole) matches(perm types.RBACPermission) bool {
	if r.matchAll {
		return true
	}
	if r.exact[perm] {
		return true
	}
	if perm == types.PermissionApprove {
		return false
	}
	permStr := string(perm)
	isCustom := strings.HasPrefix(permStr, RBAC_CUSTOM_PREFIX)
	for _, glob := range r.globs {
		if isCustom != strings.HasPrefix(glob, RBAC_CUSTOM_PREFIX) {
			continue
		}
		if match, err := doublestar.Match(glob, permStr); err == nil && match {
			return true
		}
	}
	return false
}

func newResolvedRole(perms []types.RBACPermission) *resolvedRole {
	exact := make([]types.RBACPermission, 0, len(perms))
	globs := make([]string, 0)
	for _, perm := range perms {
		if hasGlobMeta(string(perm)) {
			globs = append(globs, string(perm))
		} else {
			exact = append(exact, perm)
		}
	}
	exact = expandImplications(exact)
	exactMap := make(map[types.RBACPermission]bool, len(exact))
	for _, perm := range exact {
		exactMap[perm] = true
	}
	return &resolvedRole{exact: exactMap, globs: globs}
}

// allPermissionNames is the shared, immutable list of every permission name,
// returned by GetAPIPermissions when enforcement is not active
var allPermissionNames = func() []string {
	perms := make([]string, 0, len(appPermissions)+len(globalPermissions))
	for _, p := range appPermissions {
		perms = append(perms, string(p))
	}
	for p := range globalPermissions {
		perms = append(perms, string(p))
	}
	return perms
}()

// isGlobalTarget reports whether a grant target matches everything, which is the
// requirement for global (non app path) permissions
func isGlobalTarget(target string) bool {
	return target == "" || strings.EqualFold(target, "all") || target == "*:**"
}

// PermissionResource returns the resource part of a permission name (app, sync, ...)
func PermissionResource(perm types.RBACPermission) string {
	permStr := string(perm)
	if idx := strings.Index(permStr, ":"); idx > 0 {
		return permStr[:idx]
	}
	return permStr
}
