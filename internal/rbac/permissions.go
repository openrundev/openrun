// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/openrundev/openrun/internal/types"
)

// predefinedRoles are built-in convenience roles, always available in every
// RBAC config. Their names are reserved (cannot be redefined) and grants and
// user roles may reference them. openrun-admin is the super-user role (it
// holds the "admin" permission, which bypasses every check). Permissions are
// expanded through the normal implication rules (app:manage -> all app perms,
// app:update -> reload/apply/read). openrun-builder composes openrun-developer.
// A role mixes scoped (app:*) and global permissions; the scoped ones
// apply to the grant's target apps, the global ones apply regardless of targets
// (see the RBAC docs on scope)
var predefinedRoles = map[string][]types.RBACPermission{
	// Full super-user (bypasses every check). Equivalent to the built-in
	// admin role; provided under the openrun- naming for discoverability
	"openrun-admin": {types.PermissionAdmin},

	// Runs the platform: full app lifecycle plus plugin approval, sync,
	// services, bindings, container management, config, secrets, audit,
	// server stop and the builder. No secret:reveal — reading back stored
	// secret values is admin-only (openrun-admin or an explicit grant)
	"openrun-operator": {
		types.PermissionAppManage, types.PermissionApprove,
		types.PermissionSyncCreate, types.PermissionSyncRun, types.PermissionSyncDelete, types.PermissionSyncRead,
		types.PermissionServiceCreate, types.PermissionServiceUpdate, types.PermissionServiceDelete, types.PermissionServiceRead,
		types.PermissionBindingCreate, types.PermissionBindingUpdate, types.PermissionBindingDelete, types.PermissionBindingRead, types.PermissionBindingRunCommand,
		types.PermissionContainerManage,
		types.PermissionConfigRead, types.PermissionConfigUpdate,
		types.PermissionSecretCreate, types.PermissionSecretRead, types.PermissionSecretDelete,
		types.PermissionAuditRead, types.PermissionServerStop,
		types.PermissionBuilderList, types.PermissionBuilderCreate, types.PermissionBuilderPublish,
	},

	// App lifecycle and supporting resources, minus operator-only controls
	// (no approve, full config, secret delete, server stop, sync
	// create/delete, container manage, builder) and no secret:reveal
	// (admin-only). Gets config:basic_read so the app create/update forms
	// can list specs and auth/git-auth entry names.
	"openrun-developer": {
		types.PermissionAppManage,
		types.PermissionServiceCreate, types.PermissionServiceUpdate, types.PermissionServiceRead,
		types.PermissionBindingCreate, types.PermissionBindingUpdate, types.PermissionBindingRead, types.PermissionBindingRunCommand,
		types.PermissionContainerRead,
		types.PermissionSyncRun, types.PermissionSyncRead,
		types.PermissionSecretCreate, types.PermissionSecretRead,
		types.PermissionConfigBasicRead,
	},

	// A developer who also gets the AI app builder
	"openrun-builder": {
		types.RBACPermission(RBAC_ROLE_PREFIX + "openrun-developer"),
		types.PermissionBuilderList, types.PermissionBuilderCreate, types.PermissionBuilderPublish,
	},

	// Baseline authenticated user: reach served apps and browse the app list
	"openrun-user": {
		types.PermissionAccess, types.PermissionRead,
	},

	// Read-only observability across the platform (no writes, no secret reveal)
	"openrun-monitor": {
		types.PermissionRead,
		types.PermissionAuditRead, types.PermissionContainerRead,
		types.PermissionSyncRead, types.PermissionServiceRead, types.PermissionBindingRead,
		types.PermissionConfigRead, types.PermissionSecretRead,
	},
}

// ReservedRolePrefix is reserved for built-in roles; user-defined role names
// may not use it
const ReservedRolePrefix = "openrun-"

// isBuiltinRole reports whether name is a predefined built-in role
func isBuiltinRole(name string) bool {
	_, ok := predefinedRoles[name]
	return ok
}

// BuiltinRoleNames returns the predefined built-in role names, sorted. UIs
// list these alongside user-defined roles so they can be selected in grants
func BuiltinRoleNames() []string {
	names := make([]string, 0, len(predefinedRoles))
	for name := range predefinedRoles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Resource names used for owner permission lookup
const (
	ResourceApp  = "app"
	ResourceSync = "sync"
)

// appPermissions are the app (app:*) scoped permissions
var appPermissions = []types.RBACPermission{
	types.PermissionAccess,
	types.PermissionRead,
	types.PermissionCreate,
	types.PermissionUpdate,
	types.PermissionReload,
	types.PermissionApply,
	types.PermissionDelete,
	types.PermissionPromote,
	types.PermissionPreview,
	types.PermissionTokenRead,
	types.PermissionTokenManage,
	types.PermissionAppManage,
	types.PermissionApprove,
}

// scopedPermissions are matched against the grant's target glob (the app path).
// These are the app:* permissions. App-level custom permissions are scoped too,
// handled via the isAppLevelPermission flag in checkGrant. Every permission not
// in this set is global: a grant confers it regardless of its targets.
var scopedPermissions = func() map[types.RBACPermission]bool {
	perms := make(map[types.RBACPermission]bool, len(appPermissions))
	for _, p := range appPermissions {
		perms[p] = true
	}
	return perms
}()

// globalPermissions are the permissions with no app path target: a grant confers
// them regardless of its targets. Everything except app:*. The builder:*
// permissions are global (a builder session is not bound to an app path until
// it publishes); the app the session publishes or edits is separately enforced
// with the app permissions (app:create/app:update/app:delete) on that path.
var globalPermissions = map[types.RBACPermission]bool{
	types.PermissionBuilderList:       true,
	types.PermissionBuilderCreate:     true,
	types.PermissionBuilderPublish:    true,
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
	types.PermissionContainerRead:     true,
	types.PermissionContainerManage:   true,
	types.PermissionConfigBasicRead:   true,
	types.PermissionConfigRead:        true,
	types.PermissionConfigUpdate:      true,
	types.PermissionServerStop:        true,
	types.PermissionAuditRead:         true,
	types.PermissionSecretCreate:      true,
	types.PermissionSecretRead:        true,
	types.PermissionSecretDelete:      true,
	types.PermissionSecretReveal:      true,
	types.PermissionAdmin:             true,
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

// appManagePermissions is what app:manage expands to: every app permission except
// app:manage itself and app:approve. Approving plugin permissions is operator-only:
// app:approve always needs an explicit grant, it is never implied
var appManagePermissions = func() []types.RBACPermission {
	perms := make([]types.RBACPermission, 0, len(appPermissions))
	for _, p := range appPermissions {
		if p == types.PermissionAppManage || p == types.PermissionApprove {
			continue
		}
		perms = append(perms, p)
	}
	return perms
}()

// permissionImplications: holding the key permission implies the value permissions.
// approve is never implied
var permissionImplications = map[types.RBACPermission][]types.RBACPermission{
	types.PermissionUpdate:          {types.PermissionReload, types.PermissionApply, types.PermissionRead},
	types.PermissionAppManage:       appManagePermissions,
	types.PermissionContainerManage: {types.PermissionContainerRead},
	types.PermissionConfigRead:      {types.PermissionConfigBasicRead},
}

// defaultOwnerPermissions are the permissions the creator of an asset gets on that
// asset when owner_permissions is not configured for the resource
var defaultOwnerPermissions = map[string][]types.RBACPermission{
	ResourceApp:  {types.PermissionAppManage},
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
	exact map[types.RBACPermission]bool // exact permission names, implications expanded
	globs []string                      // glob pattern entries, matched only on exact miss
}

// matches reports whether the role grants perm. approve and the admin
// super-user permission are only ever matched by their literal names, never by
// glob entries. custom: permissions are matched by glob entries only when the
// pattern itself has the custom: prefix
func (r *resolvedRole) matches(perm types.RBACPermission) bool {
	if r.exact[perm] {
		return true
	}
	if perm == types.PermissionApprove || perm == types.PermissionAdmin {
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

// permissions returns the role's entries in serializable form: sorted exact
// permission names (implications already expanded) plus the glob entries.
// Rebuilding with newResolvedRole yields identical matching, since
// expandImplications is idempotent over an already expanded set
func (r *resolvedRole) permissions() []types.RBACPermission {
	perms := make([]types.RBACPermission, 0, len(r.exact)+len(r.globs))
	for perm := range r.exact {
		perms = append(perms, perm)
	}
	slices.Sort(perms)
	for _, glob := range r.globs {
		perms = append(perms, types.RBACPermission(glob))
	}
	return perms
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

// PermissionResource returns the resource part of a permission name (app, sync, ...)
func PermissionResource(perm types.RBACPermission) string {
	permStr := string(perm)
	if idx := strings.Index(permStr, ":"); idx > 0 {
		return permStr[:idx]
	}
	return permStr
}
