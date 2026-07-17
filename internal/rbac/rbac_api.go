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
	if dirs := GetUrlDirectives(ctx); dirs.HasPerms() {
		// _cl_perm test URL directive: match against the simulated set, see AuthorizeAPI
		for _, permission := range permissions {
			if dirs.MatchesCustomPerm(permission) {
				return true, nil
			}
		}
		return false, nil
	}
	// nil-safe getters: a context missing these values (a propagation bug)
	// yields an empty user, which fails closed in the grant evaluation
	// instead of panicking the request
	userId := system.GetContextUserId(ctx)
	groups := system.GetContextGroups(ctx)
	appPathDomain := system.GetContextAppPathDomain(ctx)
	for _, permission := range permissions {
		authorized, err := h.AuthorizeInt(userId, appPathDomain, types.RBACPermission(permission), groups, true)
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
	if dirs := GetUrlDirectives(ctx); dirs.HasPerms() {
		// _cl_perm test URL directive: match against the simulated set, see AuthorizeAPI
		if isCustomPermission {
			return dirs.MatchesCustomPerm(string(permission)), nil
		}
		return dirs.MatchesPerm(permission), nil
	}
	return h.AuthorizeInt(system.GetContextUserId(ctx), system.GetContextAppPathDomain(ctx),
		permission, system.GetContextGroups(ctx), isCustomPermission)
}

// GetCustomPermissions returns the custom permissions for the user on the current app
func (h *RBACManager) GetCustomPermissions(ctx context.Context) ([]string, error) {
	if simPerms, ok := GetTestUrlPerms(ctx); ok {
		// _cl_perm test URL directive: the simulated set replaces the computed
		// custom permissions, see AuthorizeAPI
		return simPerms, nil
	}
	return h.GetCustomPermissionsInt(system.GetContextUserId(ctx),
		system.GetContextAppPathDomain(ctx), system.GetContextGroups(ctx))
}

// IsAppRBACEnabled checks if RBAC is enabled. When enabled, RBAC applies to
// every app (the ctx is unused, kept for the RBACAPI interface)
func (h *RBACManager) IsAppRBACEnabled(_ context.Context) bool {
	return h.ConfigEnabled()
}

// APIEnforced reports whether management API RBAC enforcement is active for this
// request: the RBAC config is enabled (it then applies to every app). The bool is
// computed once at request setup and stored in the context, so the common case is
// a single context lookup with no locking or allocation. When that lookup misses,
// enforcement is still active for a _cl_perm test URL directive (only set on dev
// apps where enforcement is otherwise inactive; the simulated permission set
// replaces allow-all, so simulation can only narrow access) and for a background
// sync run carrying the frozen creator snapshot (SyncAuthorizer).
//
// Trusted administrative paths (authenticated admin/UDS management API requests,
// token authenticated webhooks, internal background operations) carry the
// TRUSTED_OPERATION marker and are never enforced. A context with NO marker at
// all is a propagation bug: enforcement is reported active when RBAC is enabled,
// and AuthorizeAPI then fails closed for it
func (h *RBACManager) APIEnforced(ctx context.Context) bool {
	if system.IsAppRBACEnabled(ctx) || HasTestUrlPerms(ctx) || HasSyncAuthorizer(ctx) {
		return true
	}
	// An app request that computed enforcement off at request start (the RBAC
	// marker is present with value false) stays unenforced for its lifetime,
	// even if a config publish enables RBAC mid-request
	return !system.IsTrustedOperation(ctx) && !system.AppRBACMarkerPresent(ctx) && h.ConfigEnabled()
}

// AuthorizeAPI checks if the user can perform the management API operation needing
// permission perm on the app at target. target must be resolved to the main app
// path for stage/preview apps. owner is the app creator ("" if not known); the
// owner of an app holds the configured owner permissions on it without any grant.
// Returns true without any evaluation when enforcement is not active (see APIEnforced)
func (h *RBACManager) AuthorizeAPI(ctx context.Context, perm types.RBACPermission,
	target types.AppPathDomain, owner string) (bool, error) {
	return h.authorizeAPICtx(ctx, perm, target, "", owner)
}

// AuthorizeResourceAPI checks a service or binding scoped permission against the
// resource identity: the service id (<type>/<name>) for service:* permissions,
// the binding path for binding:* permissions. owner is the entry's creator ("" if
// not known); the owner holds the configured owner permissions on their entries
func (h *RBACManager) AuthorizeResourceAPI(ctx context.Context, perm types.RBACPermission,
	resourceId string, owner string) (bool, error) {
	return h.authorizeAPICtx(ctx, perm, types.AppPathDomain{}, resourceId, owner)
}

// AuthorizeGlobalAPI checks a global (untargeted) permission like sync:create
// or config:read. owner is the creator of the specific entry being operated on
// ("" when not applicable); the owner holds the configured owner permissions on
// their entries
func (h *RBACManager) AuthorizeGlobalAPI(ctx context.Context, perm types.RBACPermission, owner string) (bool, error) {
	return h.authorizeAPICtx(ctx, perm, types.AppPathDomain{}, "", owner)
}

// authorizeAPICtx is the shared context gating for the management API checks,
// see AuthorizeAPI
func (h *RBACManager) authorizeAPICtx(ctx context.Context, perm types.RBACPermission,
	target types.AppPathDomain, resourceId string, owner string) (bool, error) {
	if system.IsAppRBACEnabled(ctx) {
		// live config enforcement; test URL directives and sync snapshots are
		// only ever attached to contexts where this is not set
		return h.authorizeAPIInt(system.GetContextUserId(ctx), system.GetContextGroups(ctx), perm, target, resourceId, owner)
	}
	if dirs := GetUrlDirectives(ctx); dirs.HasPerms() {
		// _cl_perm test URL directive: only set when enforcement is otherwise
		// inactive (this call would have returned true), so the simulated set
		// replaces allow-all. Real grants and the owner rule are not consulted
		return dirs.MatchesPerm(perm), nil
	}
	if sa := GetSyncAuthorizer(ctx); sa != nil {
		// background sync run: evaluate against the creator authorization
		// frozen on the sync entry, not the live config
		return sa.Authorize(perm, target, resourceId, owner)
	}
	if system.IsTrustedOperation(ctx) || system.AppRBACMarkerPresent(ctx) || !h.ConfigEnabled() {
		// Trusted administrative path (authenticated admin/UDS API, token
		// authenticated webhook, internal background operation), an app request
		// whose per-request enforcement state was computed off (stable for the
		// request even if a config publish enables RBAC mid-request), or RBAC
		// disabled
		return true, nil
	}
	// Fail closed: RBAC is enabled and the context carries no marker at all.
	// That is a context propagation bug (e.g. a missing Starlark thread
	// context), not a trusted internal call - it must not silently run with
	// admin authority
	h.Warn().Msgf("Denying management API call with unattributed context: perm %s target %s%s", perm, target, resourceId)
	return false, nil
}

func (h *RBACManager) authorizeAPIInt(user string, groups []string, perm types.RBACPermission,
	target types.AppPathDomain, resourceId string, owner string) (bool, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.authorizeAPIIntLocked(user, groups, perm, target, resourceId, owner)
}

// authorizeAPIIntLocked is authorizeAPIInt without the read lock, for callers
// that evaluate several permissions under one lock acquisition (RWMutex read
// locks are not reentrant). Callers must hold h.mu
func (h *RBACManager) authorizeAPIIntLocked(user string, groups []string, perm types.RBACPermission,
	target types.AppPathDomain, resourceId string, owner string) (bool, error) {
	if user == "" {
		// Fail closed. This is only reached with enforcement active (the
		// ctx-taking callers short-circuit to allow-all when it is not), where
		// the request has already been authenticated to a user or the anonymous
		// principal. An empty user here is a context-propagation bug, not a
		// trusted internal/CLI call (those have no app context and never reach
		// this path), so it must not be granted access - and it must not match
		// the owner rule via an empty owner id.
		return false, nil
	}

	if isAdmin, err := h.hasAdminPermLocked(user, groups); err != nil || isAdmin {
		// the admin super-user permission passes every check
		return isAdmin, err
	}

	if owner != "" && user == owner && perm != types.PermissionApprove {
		// Owner virtual grant: the creator of an asset holds the owner
		// permission set on it. app:approve shares the app resource prefix
		// but is never granted through ownership (config validation also
		// rejects it in owner_permissions; this keeps the exclusion
		// structural)
		if h.ownerPerms[PermissionResource(perm)][perm] {
			return true, nil
		}
	}

	return h.checkGrants(user, target, resourceId, perm, groups, false)
}

// GetAPIPermissions returns the management API permissions the user holds: app
// permissions evaluated against target/owner plus the global permissions the user
// holds. With no target (empty AppPathDomain, no owner) scoped permissions are
// reported when held on at least one target of their kind ("can the user do
// this somewhere"), so UIs can gate chrome for users whose grants are all
// scoped; enforcement stays per resource at action time. When enforcement is
// not active, all permissions are returned
func (h *RBACManager) GetAPIPermissions(ctx context.Context, target types.AppPathDomain, owner string) ([]string, error) {
	if dirs := GetUrlDirectives(ctx); dirs.HasPerms() {
		// _cl_perm test URL directive: report the simulated permission set, see AuthorizeAPI
		perms := make([]string, 0, len(dirs.Perms))
		for _, perm := range allPermissionNames {
			if dirs.MatchesPerm(types.RBACPermission(perm)) {
				perms = append(perms, perm)
			}
		}
		return perms, nil
	}
	if sa := GetSyncAuthorizer(ctx); sa != nil {
		// background sync run: report the frozen snapshot's permission set, see AuthorizeAPI
		return collectAPIPermissions(sa.Authorize, target, owner)
	}
	if !system.IsAppRBACEnabled(ctx) {
		if system.IsTrustedOperation(ctx) || system.AppRBACMarkerPresent(ctx) || !h.ConfigEnabled() {
			return allPermissionNames, nil
		}
		// unattributed context with RBAC enabled: fail closed, see AuthorizeAPI
		return []string{}, nil
	}

	user := system.GetContextUserId(ctx)
	groups := system.GetContextGroups(ctx)
	if user == "" {
		// Fail closed, consistent with authorizeAPIInt: enforcement is active,
		// so a missing user id is a context propagation bug and the report must
		// not claim permissions that every actual operation would deny
		return []string{}, nil
	}

	// One lock acquisition for the whole enumeration instead of one per
	// permission; the config state is consistent across the report
	h.mu.RLock()
	defer h.mu.RUnlock()

	isAdmin, err := h.hasAdminPermLocked(user, groups)
	if err != nil {
		return nil, err
	}
	if isAdmin {
		return allPermissionNames, nil
	}

	anyTarget := target == (types.AppPathDomain{}) && owner == ""
	return collectAPIPermissions(func(perm types.RBACPermission, target types.AppPathDomain, resourceId string, owner string) (bool, error) {
		if anyTarget {
			if kind, scoped := scopedKind(perm, false); scoped {
				return h.holdsPermSomewhereLocked(user, groups, perm, kind)
			}
		}
		return h.authorizeAPIIntLocked(user, groups, perm, target, resourceId, owner)
	}, target, owner)
}

// holdsPermSomewhereLocked reports whether any grant confers the scoped
// permission to the user on at least one target entry of the permission's
// kind (or an all target). Used by the no-target GetAPIPermissions report;
// which specific resources match is not evaluated here (list APIs and
// per-resource enforcement handle that). The owner virtual grant does not
// feed this report: it would require scanning every resource's creator.
// Callers must hold h.mu
func (h *RBACManager) holdsPermSomewhereLocked(user string, groups []string, perm types.RBACPermission, kind targetKind) (bool, error) {
	if user == "" {
		return false, nil // fail closed, consistent with authorizeAPIIntLocked
	}
	for i, grant := range h.RbacConfig.Grants {
		roleMatched := false
		for _, role := range grant.Roles {
			if resolved, ok := h.roles[role]; ok && resolved.matches(perm) {
				roleMatched = true
				break
			}
		}
		if !roleMatched {
			continue
		}
		userMatched, err := h.grantUserMatchesLocked(grant, user, groups)
		if err != nil {
			return false, err
		}
		if !userMatched {
			continue
		}
		for _, target := range h.resolvedGrants[i].targets {
			if target.err == nil && (target.all || target.kind == kind) {
				return true, nil
			}
		}
	}
	return false, nil
}

// collectAPIPermissions enumerates the permissions granted by authorize: app
// permissions evaluated against the target app and owner, service/binding
// permissions with no resource identity (so only grants targeting all
// services/bindings, ownership aside, report them), global permissions
// (including builder:*) with no target
func collectAPIPermissions(authorize func(perm types.RBACPermission, target types.AppPathDomain, resourceId string, owner string) (bool, error),
	target types.AppPathDomain, owner string) ([]string, error) {
	perms := make([]string, 0)
	appendGranted := func(perm types.RBACPermission, target types.AppPathDomain, owner string) error {
		authorized, err := authorize(perm, target, "", owner)
		if err != nil {
			return err
		}
		if authorized {
			perms = append(perms, string(perm))
		}
		return nil
	}
	for _, perm := range appPermissions {
		if perm == types.PermissionAppManage {
			continue // composite permission, reported through its expansion
		}
		if err := appendGranted(perm, target, owner); err != nil {
			return nil, err
		}
	}
	for _, perm := range servicePermissions {
		if perm == types.PermissionServiceManage {
			continue // composite permission, reported through its expansion
		}
		if err := appendGranted(perm, types.AppPathDomain{}, ""); err != nil {
			return nil, err
		}
	}
	for _, perm := range bindingPermissions {
		if perm == types.PermissionBindingManage {
			continue // composite permission, reported through its expansion
		}
		if err := appendGranted(perm, types.AppPathDomain{}, ""); err != nil {
			return nil, err
		}
	}
	for _, perm := range globalPermissionNames {
		if err := appendGranted(perm, types.AppPathDomain{}, ""); err != nil {
			return nil, err
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
}

var _ RBACAPI = (*RBACManager)(nil)

// AuthorizeUserPerm evaluates a global permission for the given user and groups
// directly against this manager's config, without request context. Used for
// lockout checks when publishing a candidate config
func (h *RBACManager) AuthorizeUserPerm(user string, groups []string, perm types.RBACPermission) (bool, error) {
	return h.authorizeAPIInt(user, groups, perm, types.AppPathDomain{}, "", "")
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
