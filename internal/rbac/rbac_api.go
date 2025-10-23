// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"strings"

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

type RBACAPI interface {
	AuthorizeAny(ctx context.Context, permissions []string) (bool, error)
	Authorize(ctx context.Context, permission types.RBACPermission, isAppLevelPermission bool) (bool, error)
	GetCustomPermissions(ctx context.Context) ([]string, error)
	IsAppRBACEnabled(ctx context.Context) bool
}

var _ RBACAPI = (*RBACManager)(nil)
