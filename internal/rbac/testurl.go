// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// UrlDirectives holds the parsed _cl_ test URL directives for a request. Set
// in the request context (types.TESTURL_DIRECTIVES) only when
// security.unsafe_enable_testurl_rbac is on and the request is for a dev mode app
// with none auth (anonymous user) and RBAC inactive for the app. In that
// state every permission check is allow-all, so the simulated permissions
// replace allow-all and can only narrow access, never widen it.
type UrlDirectives struct {
	// Perms is the simulated permission set, in the same form apps see in
	// X-Openrun-Perms (custom permissions without the custom: prefix): the
	// explicit _cl_perm values plus the custom permissions conferred by any
	// _cl_role roles. nil means no simulated permission set.
	Perms []string
	// ExtendedPrefix is the app path plus the raw directive segments, e.g.
	// "/abc/_cl_perm=app:read". Used as the effective app path when
	// generating app-absolute URLs so directive URLs stay sticky.
	ExtendedPrefix string

	permsRole *resolvedRole   // explicit _cl_perm values resolved for matching
	roles     []*resolvedRole // _cl_role roles, resolved at config update time
}

// NewUrlDirectives builds the directives with the permission matcher
// resolved. Matching follows the same rules as real grants: app:admin
// expands to all app permissions except app:approve, app:approve matches
// only by its literal name, glob entries match, and entries that are not
// builtin permissions are treated as custom permissions (matched with or
// without the custom: prefix).
func NewUrlDirectives(perms []string, extendedPrefix string) *UrlDirectives {
	dirs := &UrlDirectives{Perms: perms, ExtendedPrefix: extendedPrefix}
	if perms != nil {
		rolePerms := make([]types.RBACPermission, 0, len(perms)*2)
		for _, permStr := range perms {
			perm := normalizePermission(types.RBACPermission(permStr))
			rolePerms = append(rolePerms, perm)
			if !builtinPermissions[perm] && !hasGlobMeta(permStr) &&
				!strings.HasPrefix(permStr, RBAC_CUSTOM_PREFIX) {
				// Custom permissions are simulated without the custom: prefix
				// (X-Openrun-Perms form); add the prefixed form so app level
				// permission checks (which match custom:<name>) also match
				rolePerms = append(rolePerms, types.RBACPermission(RBAC_CUSTOM_PREFIX+permStr))
			}
		}
		dirs.permsRole = newResolvedRole(rolePerms)
	}
	return dirs
}

// HasPerms reports whether a simulated permission set is present. Safe on nil.
func (d *UrlDirectives) HasPerms() bool {
	return d != nil && d.Perms != nil
}

// MatchesPerm reports whether the simulated permission set grants perm:
// either an explicit _cl_perm value or any _cl_role role grants it. Used for
// builtin management API permissions. Safe on nil.
func (d *UrlDirectives) MatchesPerm(perm types.RBACPermission) bool {
	if d == nil {
		return false
	}
	// The admin permission is the super-user permission: in the real system it
	// bypasses every check (hasAdminPermLocked) rather than being matched like
	// a normal permission, so a simulated set that grants admin grants all
	if d.matchesAny(types.PermissionAdmin) {
		return true
	}
	return d.matchesAny(perm)
}

// matchesAny reports whether the explicit perms or any simulated role grants
// perm, by the normal resolvedRole matching rules (no admin super-user bypass)
func (d *UrlDirectives) matchesAny(perm types.RBACPermission) bool {
	if d.permsRole != nil && d.permsRole.matches(perm) {
		return true
	}
	for _, role := range d.roles {
		if role.matches(perm) {
			return true
		}
	}
	return false
}

// MatchesCustomPerm reports whether the simulated permission set grants the
// app level custom permission perm (given without the custom: prefix, as in
// plugin permit lists). Safe on nil.
func (d *UrlDirectives) MatchesCustomPerm(perm string) bool {
	if !strings.HasPrefix(perm, RBAC_CUSTOM_PREFIX) {
		perm = RBAC_CUSTOM_PREFIX + perm
	}
	return d.MatchesPerm(types.RBACPermission(perm))
}

// testUrlDirectivesKey is the context key pre-boxed as an any value, see the
// note on the key list in system/thread_local.go
var testUrlDirectivesKey any = types.TESTURL_DIRECTIVES

// GetUrlDirectives returns the test URL directives from the request context,
// nil when not present
func GetUrlDirectives(ctx context.Context) *UrlDirectives {
	value := ctx.Value(testUrlDirectivesKey)
	if value == nil {
		return nil
	}
	dirs, ok := value.(*UrlDirectives)
	if !ok {
		return nil
	}
	return dirs
}

// HasTestUrlPerms reports whether the request carries a simulated permission set
func HasTestUrlPerms(ctx context.Context) bool {
	return GetUrlDirectives(ctx).HasPerms()
}

// GetTestUrlPerms returns the simulated permission set, false when not present
func GetTestUrlPerms(ctx context.Context) ([]string, bool) {
	dirs := GetUrlDirectives(ctx)
	if !dirs.HasPerms() {
		return nil, false
	}
	return dirs.Perms, true
}

// GetTestUrlPrefix returns the extended app path prefix (app path plus
// directive segments), "" when no directives are present
func GetTestUrlPrefix(ctx context.Context) string {
	dirs := GetUrlDirectives(ctx)
	if dirs == nil {
		return ""
	}
	return dirs.ExtendedPrefix
}

// AppRBACActive reports whether app level surfaces (X-Openrun-Rbac-Enabled
// header, request data, plugin permit checks) should treat RBAC as active for
// this request: the real per-request RBAC state, or a _cl_perm test URL
// directive (the simulated permission set then replaces allow-all, so apps
// exercise their permission gated paths against it)
func AppRBACActive(ctx context.Context) bool {
	return system.IsAppRBACEnabled(ctx) || HasTestUrlPerms(ctx)
}

// BuildUrlDirectives builds the test URL directives for a request, resolving
// _cl_role names against the configured roles (roles are resolved at config
// update time even when RBAC is disabled, with hierarchy and implications
// flattened; the built-in openrun-* roles are always defined). Unknown role
// names are an error (fail closed). The app visible permission list (Perms) is
// the explicit _cl_perm values plus the custom permissions the roles confer,
// mirroring what GetCustomPermissions computes for a user granted those roles
// (a role granting the admin permission confers every custom permission). The
// resolved roles are immutable snapshots, so a concurrent config update does
// not affect an in-flight request.
func (h *RBACManager) BuildUrlDirectives(perms, roleNames []string, extendedPrefix string) (*UrlDirectives, error) {
	dirs := NewUrlDirectives(perms, extendedPrefix)
	if len(roleNames) == 0 {
		return dirs, nil
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	dirs.roles = make([]*resolvedRole, 0, len(roleNames))
	for _, name := range roleNames {
		role, ok := h.roles[name]
		if !ok {
			return nil, fmt.Errorf("unknown role %q in _cl_role directive", name)
		}
		dirs.roles = append(dirs.roles, role)
	}

	// Perms is always non-nil when roles are simulated (the simulation is
	// active even when the roles confer no custom permissions)
	permsList := make([]string, 0, len(perms)+len(h.customPerms))
	seen := make(map[string]bool, len(perms))
	for _, perm := range perms {
		if !seen[perm] {
			seen[perm] = true
			permsList = append(permsList, perm)
		}
	}
	// A role granting the admin permission is super-user: it confers every
	// custom permission, matching what GetCustomPermissions returns for an
	// admin user (hasAdminPermLocked short-circuit)
	adminRole := false
	for _, role := range dirs.roles {
		if role.matches(types.PermissionAdmin) {
			adminRole = true
			break
		}
	}
	for _, custom := range h.customPerms {
		if seen[custom] {
			continue
		}
		customPerm := types.RBACPermission(RBAC_CUSTOM_PREFIX + custom)
		granted := adminRole
		for _, role := range dirs.roles {
			if granted || role.matches(customPerm) {
				granted = true
				break
			}
		}
		if granted {
			seen[custom] = true
			permsList = append(permsList, custom)
		}
	}
	dirs.Perms = permsList
	return dirs, nil
}
