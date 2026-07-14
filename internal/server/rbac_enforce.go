// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// RBAC enforcement for the management APIs. Enforcement is active whenever the
// RBAC config is enabled - it then applies to every app (the RBAC_ENABLED context
// bool, computed once per request in authenticateAndServeApp). All API calls made
// over the unix socket or with admin over TCP have no app context and are never
// enforced. The operation to permission mapping is documented in
// design/rbac-api-design.md.
//
// App scoped operations resolve stage/preview apps to the main app path and pass
// the app creator (AppInfo.UserID / AppEntry.UserID) as the owner; global
// operations (sync, service, binding, config, server) have no app target and
// require a grant targeting all apps, or ownership of the specific entry.

// rbacDenied builds the 403 error returned on an RBAC authorization failure.
// Denials during a sync run name the sync entry, so the sync status error
// identifies which entry's frozen creator authorization was insufficient
func (s *Server) rbacDenied(ctx context.Context, perm types.RBACPermission, target string) error {
	userId := system.GetContextUserId(ctx)
	syncMsg := ""
	if syncId := system.GetContextValue(ctx, types.SYNC_ID); syncId != "" {
		syncMsg = fmt.Sprintf(" (sync %s)", syncId)
	}
	s.Warn().Msgf("RBAC denied: user %s does not have %s on %s%s", userId, perm, target, syncMsg)
	return types.CreateRequestError(
		fmt.Sprintf("unauthorized: user %s does not have permission %s on %s%s", userId, perm, target, syncMsg),
		http.StatusForbidden)
}

// enforceAppPerm authorizes perm on one app path. owner is the app creator ("" if
// not known). Fast path: returns nil immediately when enforcement is not active
func (s *Server) enforceAppPerm(ctx context.Context, perm types.RBACPermission,
	target types.AppPathDomain, owner string) error {
	if !s.rbacManager.APIEnforced(ctx) {
		return nil
	}
	authorized, err := s.rbacManager.AuthorizeAPI(ctx, perm, target, owner)
	if err != nil {
		return err
	}
	if !authorized {
		return s.rbacDenied(ctx, perm, target.String())
	}
	return nil
}

// enforceAppPermInfos authorizes perm on every app in the list. Mutating glob
// operations are atomic: the first unauthorized app fails the whole call
func (s *Server) enforceAppPermInfos(ctx context.Context, perm types.RBACPermission, apps []types.AppInfo) error {
	if !s.rbacManager.APIEnforced(ctx) {
		return nil
	}
	for _, appInfo := range apps {
		target := mainAppPathDomain(appInfo.AppPathDomain, appInfo.MainApp, appInfo.LinkedAppPath)
		authorized, err := s.rbacManager.AuthorizeAPI(ctx, perm, target, appInfo.UserID)
		if err != nil {
			return err
		}
		if !authorized {
			return s.rbacDenied(ctx, perm, target.String())
		}
	}
	return nil
}

// enforceAppPermEntry authorizes perm on a loaded app entry (main app resolved,
// owner from the entry)
func (s *Server) enforceAppPermEntry(ctx context.Context, perm types.RBACPermission, appEntry *types.AppEntry) error {
	if !s.rbacManager.APIEnforced(ctx) {
		return nil
	}
	target := mainAppPathDomain(appEntry.AppPathDomain(), appEntry.MainApp, appEntry.LinkedAppPath)
	authorized, err := s.rbacManager.AuthorizeAPI(ctx, perm, target, appEntry.UserID)
	if err != nil {
		return err
	}
	if !authorized {
		return s.rbacDenied(ctx, perm, target.String())
	}
	return nil
}

// enforceGlobalPerm authorizes a global (non app path) permission. owner is the
// creator of the specific entry being operated on ("" when not applicable)
func (s *Server) enforceGlobalPerm(ctx context.Context, perm types.RBACPermission, owner string) error {
	if !s.rbacManager.APIEnforced(ctx) {
		return nil
	}
	authorized, err := s.rbacManager.AuthorizeGlobalAPI(ctx, perm, owner)
	if err != nil {
		return err
	}
	if !authorized {
		return s.rbacDenied(ctx, perm, "server")
	}
	return nil
}

// enforceGlobalApprove requires the global approve permission (granted with
// target "all"). approve is a global permission, so this is a plain global
// check; kept as a named helper for the approve-flag call sites
func (s *Server) enforceGlobalApprove(ctx context.Context) error {
	return s.enforceGlobalPerm(ctx, types.PermissionApprove, "")
}

// stagedUpdatePerms maps the StagedUpdate op name to the required permission
var stagedUpdatePerms = map[string]types.RBACPermission{
	"approve":         types.PermissionApprove,
	"update-param":    types.PermissionUpdate,
	"account-link":    types.PermissionUpdate,
	"update_metadata": types.PermissionUpdate,
}
