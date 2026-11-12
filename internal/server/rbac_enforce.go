// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// RBAC enforcement for the management APIs. Enforcement is active whenever the
// RBAC config is enabled - it then applies to every app (the RBAC_ENABLED context
// bool, computed once per request in authenticateAndServeApp). All API calls made
// over the unix socket are trusted and never enforced. Authenticated admin over
// TCP is attributed to the built-in admin principal and still traverses these
// checks. The operation to permission mapping is documented in
// design/rbac-api-design.md.
//
// App scoped operations resolve stage/preview apps to the main app path and pass
// the main app creator as the owner. Service and binding operations match
// their own resource targets. Global permissions (sync, config, server, etc.)
// apply independently of grant targets.

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

// enforceHoldsAppPermSomewhere refuses a caller who holds the app permission
// on no app at all: no grant confers it on any target and the caller owns no
// app with it. Used ahead of work which is done before the affected apps are
// known (fetching an apply file); the per app checks still follow. A sync is
// not checked here, its url is authorized by sync:create
func (s *Server) enforceHoldsAppPermSomewhere(ctx context.Context, perm types.RBACPermission,
	resourcePerms ...types.RBACPermission) error {
	if !s.rbacManager.APIEnforced(ctx) || rbac.HasSyncAuthorizer(ctx) ||
		system.GetContextValue(ctx, types.SYNC_ID) != "" {
		// A sync create or run: fetching the sync's url is covered by
		// sync:create, the apps it declares are checked per app
		return nil
	}
	perms, err := s.rbacManager.GetAPIPermissions(ctx, types.AppPathDomain{}, "")
	if err != nil {
		return err
	}
	if slices.Contains(perms, string(perm)) {
		return nil
	}
	// A file which declares only bindings needs no app permission: holding
	// one of the binding permissions the operation checks is enough here
	for _, resourcePerm := range resourcePerms {
		if slices.Contains(perms, string(resourcePerm)) {
			return nil
		}
	}
	if userId := system.GetContextUserId(ctx); userId != "" {
		apps, err := s.apps.GetAllAppsInfo()
		if err != nil {
			return err
		}
		for _, appInfo := range apps {
			if appInfo.UserID != userId {
				continue
			}
			target := mainAppPathDomain(appInfo.AppPathDomain, appInfo.MainApp, appInfo.LinkedAppPath)
			if authorized, err := s.rbacManager.AuthorizeAPI(ctx, perm, target, appInfo.UserID); err == nil && authorized {
				return nil
			}
		}
		// The owner of a binding holds the binding permissions on it
		// without a grant
		if len(resourcePerms) > 0 {
			// A short read only transaction, closed before the caller
			// starts any git work
			tx, err := s.db.BeginTransaction(ctx)
			if err != nil {
				return err
			}
			allBindings, err := s.db.ListBindings(ctx, tx, "")
			_ = tx.Rollback()
			if err != nil {
				return err
			}
			for _, binding := range allBindings {
				if binding.CreatedBy != userId {
					continue
				}
				for _, resourcePerm := range resourcePerms {
					if authorized, err := s.rbacManager.AuthorizeResourceAPI(ctx, resourcePerm, binding.Path, binding.CreatedBy); err == nil && authorized {
						return nil
					}
				}
			}
		}
	}
	return s.rbacDenied(ctx, perm, "any app")
}

// appDetailAllowed reports whether the caller holds app:read_detail on the app
// (the full app info, see types.AppEntry.BasicInfo for the app:read view).
// Always true when RBAC enforcement is not active for the call. Errors from
// the authorizer count as not allowed: the caller already passed the app:read
// check, so the basic view is the safe fallback
func (s *Server) appDetailAllowed(ctx context.Context, target types.AppPathDomain, owner string) bool {
	return s.appPermAllowed(ctx, types.PermissionReadDetail, target, owner)
}

// appPermAllowed reports whether the caller holds perm on the app, for
// shaping a response rather than refusing a call (an error counts as denied)
func (s *Server) appPermAllowed(ctx context.Context, perm types.RBACPermission, target types.AppPathDomain, owner string) bool {
	if !s.rbacManager.APIEnforced(ctx) {
		return true
	}
	authorized, err := s.rbacManager.AuthorizeAPI(ctx, perm, target, owner)
	return err == nil && authorized
}

// appEntryView returns the app entry as the caller may see it: the full
// entry with app:read_detail, identity and status only without it. The
// webhook tokens in the settings are the credentials of the app's webhook
// endpoints, gated by app:token_read like the token list API, so they are
// cleared for a detail reader without it. The entry itself is never
// modified, it may be a cached one
func (s *Server) appEntryView(ctx context.Context, appEntry *types.AppEntry, target types.AppPathDomain, owner string) *types.AppEntry {
	if !s.appPermAllowed(ctx, types.PermissionReadDetail, target, owner) {
		basic := appEntry.BasicInfo()
		return &basic
	}
	if s.appPermAllowed(ctx, types.PermissionTokenRead, target, owner) {
		return appEntry
	}
	view := *appEntry
	view.Settings.WebhookTokens = types.WebhookTokens{}
	return &view
}

// appDetailAllowedEntry is appDetailAllowed for a loaded app entry (main app
// resolved, owner from the entry)
func (s *Server) appDetailAllowedEntry(ctx context.Context, appEntry *types.AppEntry) bool {
	return s.appDetailAllowed(ctx, mainAppPathDomain(appEntry.AppPathDomain(), appEntry.MainApp, appEntry.LinkedAppPath), appEntry.UserID)
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

// enforceGlobalPerm authorizes a global (untargeted) permission. owner is the
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

// enforceServicePerm authorizes a service:* permission on one service, matched
// against the grants' service:<glob> target entries. serviceId is
// <type>/<name>; owner is the service creator ("" if not known)
func (s *Server) enforceServicePerm(ctx context.Context, perm types.RBACPermission, serviceId, owner string) error {
	return s.enforceResourcePerm(ctx, perm, serviceId, owner)
}

// enforceBindingPerm authorizes a binding:* permission on one binding, matched
// against the grants' binding:<glob> target entries. owner is the binding
// creator ("" if not known)
func (s *Server) enforceBindingPerm(ctx context.Context, perm types.RBACPermission, bindingPath, owner string) error {
	return s.enforceResourcePerm(ctx, perm, bindingPath, owner)
}

func (s *Server) enforceResourcePerm(ctx context.Context, perm types.RBACPermission, resourceId, owner string) error {
	if !s.rbacManager.APIEnforced(ctx) {
		return nil
	}
	authorized, err := s.rbacManager.AuthorizeResourceAPI(ctx, perm, resourceId, owner)
	if err != nil {
		return err
	}
	if !authorized {
		return s.rbacDenied(ctx, perm, resourceId)
	}
	return nil
}

// enforceApproveAllApps requires app:approve granted on all apps: the check
// runs with an empty app target, which only a grant targeting "all" (or the
// equivalent *:** glob) matches. Used by the sync entry paths, where the
// entry's glob can match apps created in the future, so a path-scoped grant
// is not sufficient
func (s *Server) enforceApproveAllApps(ctx context.Context) error {
	return s.enforceGlobalPerm(ctx, types.PermissionApprove, "")
}

// stagedUpdatePerms maps the StagedUpdate op name to the required permission
var stagedUpdatePerms = map[string]types.RBACPermission{
	"approve":         types.PermissionApprove,
	"update-param":    types.PermissionUpdate,
	"account-link":    types.PermissionUpdate,
	"update_metadata": types.PermissionUpdate,
}
