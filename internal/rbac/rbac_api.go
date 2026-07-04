// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"strings"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// AuthorizeAny checks if the user has access to any of the specified custom permissions
// Used for app level permissions, like actions access
func (h *RBACManager) AuthorizeAny(ctx context.Context, permissions []string) (bool, error) {
	userId := ctx.Value(types.USER_ID).(string)
	groups := ctx.Value(types.GROUPS).([]string)
	appPathDomain := ctx.Value(types.APP_PATH_DOMAIN).(types.AppPathDomain)
	appAuth := string(ctx.Value(types.APP_AUTH).(types.AppAuthnType))
	for _, permission := range permissions {
		authorized, err := h.AuthorizeInt(userId, appPathDomain, appAuth, types.RBACPermission(permission), groups, true)
		if err != nil {
			return false, err
		}
		if authorized {
			return true, nil
		}
	}
	return false, nil
}

// Authorize checks if the user has access to the specified permission
func (h *RBACManager) Authorize(ctx context.Context, permission types.RBACPermission, isCustomPermission bool) (bool, error) {
	userId := ctx.Value(types.USER_ID).(string)
	groups := ctx.Value(types.GROUPS).([]string)
	appPathDomain := ctx.Value(types.APP_PATH_DOMAIN).(types.AppPathDomain)
	appAuth := string(ctx.Value(types.APP_AUTH).(types.AppAuthnType))
	return h.AuthorizeInt(userId, appPathDomain, appAuth, permission, groups, isCustomPermission)
}

// GetCustomPermissions returns the custom permissions for the user on the current app
func (h *RBACManager) GetCustomPermissions(ctx context.Context) ([]string, error) {
	userId := ctx.Value(types.USER_ID).(string)
	groups := ctx.Value(types.GROUPS).([]string)
	appPathDomain := ctx.Value(types.APP_PATH_DOMAIN).(types.AppPathDomain)
	appAuth := string(ctx.Value(types.APP_AUTH).(types.AppAuthnType))
	return h.GetCustomPermissionsInt(userId, appPathDomain, appAuth, groups)
}

// IsAppRBACEnabled checks if the RBAC is enabled for the current app
func (h *RBACManager) IsAppRBACEnabled(ctx context.Context) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if !h.RbacConfig.Enabled {
		// rbac is not enabled at the config level
		return false
	}

	appAuth := string(ctx.Value(types.APP_AUTH).(types.AppAuthnType))
	if !strings.HasPrefix(appAuth, RBAC_AUTH_PREFIX) {
		// app auth does not have rbac enabled
		return false
	}

	return true
}

// APIEnforced reports whether management API RBAC enforcement is active for this
// request: the RBAC config is enabled AND the calling app's auth has the rbac:
// prefix. The combined bool is computed once at request setup and stored in the
// context, so this is a single context lookup with no locking or allocation.
// Calls with no app context (unix socket / admin over TCP) are never enforced.
func (h *RBACManager) APIEnforced(ctx context.Context) bool {
	return system.IsAppRBACEnabled(ctx)
}

// AuthorizeAPI checks if the user can perform the management API operation needing
// permission perm on the app at target. target must be resolved to the main app
// path for stage/preview apps. owner is the app creator ("" if not known); the
// owner of an app holds the configured owner permissions on it without any grant.
// Returns true without any evaluation when enforcement is not active (see APIEnforced)
func (h *RBACManager) AuthorizeAPI(ctx context.Context, perm types.RBACPermission,
	target types.AppPathDomain, owner string) (bool, error) {
	if !system.IsAppRBACEnabled(ctx) {
		return true, nil
	}
	return h.authorizeAPIInt(system.GetContextUserId(ctx), system.GetContextGroups(ctx), perm, target, owner)
}

// AuthorizeGlobalAPI checks a global (non app path) permission like sync:create or
// binding:read. owner is the creator of the specific entry being operated on ("" when
// not applicable); the owner holds the configured owner permissions on their entries
func (h *RBACManager) AuthorizeGlobalAPI(ctx context.Context, perm types.RBACPermission, owner string) (bool, error) {
	if !system.IsAppRBACEnabled(ctx) {
		return true, nil
	}
	return h.authorizeAPIInt(system.GetContextUserId(ctx), system.GetContextGroups(ctx), perm, types.AppPathDomain{}, owner)
}

func (h *RBACManager) authorizeAPIInt(user string, groups []string, perm types.RBACPermission,
	target types.AppPathDomain, owner string) (bool, error) {
	if user == "" || user == types.ADMIN_USER {
		// admin (and calls with no user context) are always authorized
		return true, nil
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	if owner != "" && user == owner {
		// Owner virtual grant: the creator of an asset holds the owner permission
		// set on it (never includes app:approve)
		if h.ownerPerms[PermissionResource(perm)][perm] {
			return true, nil
		}
	}

	return h.checkGrants(user, target, perm, groups, false)
}

// GetAPIPermissions returns the management API permissions the user holds: app
// permissions evaluated against target/owner plus the global permissions the user
// holds. When enforcement is not active, all permissions are returned
func (h *RBACManager) GetAPIPermissions(ctx context.Context, target types.AppPathDomain, owner string) ([]string, error) {
	if !system.IsAppRBACEnabled(ctx) {
		return allPermissionNames, nil
	}

	user := system.GetContextUserId(ctx)
	groups := system.GetContextGroups(ctx)
	if user == "" || user == types.ADMIN_USER {
		return allPermissionNames, nil
	}

	perms := make([]string, 0)
	for _, perm := range appPermissions {
		if perm == types.PermissionAppAdmin {
			continue // composite permission, reported through its expansion
		}
		authorized, err := h.authorizeAPIInt(user, groups, perm, target, owner)
		if err != nil {
			return nil, err
		}
		if authorized {
			perms = append(perms, string(perm))
		}
	}
	for perm := range globalPermissions {
		authorized, err := h.authorizeAPIInt(user, groups, perm, types.AppPathDomain{}, "")
		if err != nil {
			return nil, err
		}
		if authorized {
			perms = append(perms, string(perm))
		}
	}
	return perms, nil
}

// RBACAPI is the interface used by the app package for app level (custom
// permission) checks. The management API enforcement methods (AuthorizeAPI,
// AuthorizeGlobalAPI, GetAPIPermissions) are used through the concrete
// RBACManager by the server package and are not part of this interface
type RBACAPI interface {
	AuthorizeAny(ctx context.Context, permissions []string) (bool, error)
	Authorize(ctx context.Context, permission types.RBACPermission, isAppLevelPermission bool) (bool, error)
	GetCustomPermissions(ctx context.Context) ([]string, error)
	IsAppRBACEnabled(ctx context.Context) bool
}

var _ RBACAPI = (*RBACManager)(nil)

// RequestHasRBACAuth reports whether the calling app's auth uses the rbac:
// prefix. Enforcement is two-level: the config enabled flag AND the app auth.
// Used for lockout checks: publishing an enabled config only affects callers
// whose app auth opts into rbac
func RequestHasRBACAuth(ctx context.Context) bool {
	authVal := ctx.Value(types.APP_AUTH)
	if authVal == nil {
		return false
	}
	appAuth, ok := authVal.(types.AppAuthnType)
	if !ok {
		return false
	}
	return strings.HasPrefix(string(appAuth), RBAC_AUTH_PREFIX)
}

// AuthorizeUserPerm evaluates a global permission for the given user and groups
// directly against this manager's config, without request context. Used for
// lockout checks when publishing a candidate config
func (h *RBACManager) AuthorizeUserPerm(user string, groups []string, perm types.RBACPermission) (bool, error) {
	return h.authorizeAPIInt(user, groups, perm, types.AppPathDomain{}, "")
}

// ValidatePermissionName checks that a permission entry is a valid resource:verb
// permission or permission glob. Used for local validation of draft edits
func ValidatePermissionName(perm types.RBACPermission) error {
	if strings.HasPrefix(string(perm), RBAC_ROLE_PREFIX) {
		return nil
	}
	if strings.ContainsAny(string(perm), "*?[") {
		return nil // permission glob, validated on apply
	}
	return validatePermission(perm)
}
