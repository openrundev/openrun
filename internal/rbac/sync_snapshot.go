// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"slices"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// SnapshotUserGrants builds the frozen authorization snapshot for the calling
// user, stored on a sync entry at create time and enforced on its background
// runs. Returns nil (no snapshot, runs stay unrestricted) when API enforcement
// is not active for this call: RBAC disabled, or a unix socket / admin over TCP
// call with no app context. Group membership (config groups and SSO context
// groups) is resolved now, so the snapshot stays valid without live group data.
// Under a _cl_perm test URL directive the real grants of the (anonymous) user
// are snapshotted, not the simulated set: simulation is a narrowing debug aid
// and must never mint durable authority.
func (h *RBACManager) SnapshotUserGrants(ctx context.Context) (*types.RBACSnapshot, error) {
	if !h.APIEnforced(ctx) {
		return nil, nil
	}
	user := system.GetContextUserId(ctx)
	groups := system.GetContextGroups(ctx)

	h.mu.RLock()
	defer h.mu.RUnlock()

	isAdmin, err := h.hasAdminPermLocked(user, groups)
	if err != nil {
		return nil, err
	}
	if isAdmin {
		// the admin super-user permission passes every check, no grants needed
		return &types.RBACSnapshot{UserId: user, Admin: true}, nil
	}

	snap := &types.RBACSnapshot{UserId: user}
	for _, grant := range h.RbacConfig.Grants {
		matched, err := h.grantUserMatchesLocked(grant, user, groups)
		if err != nil {
			return nil, err
		}
		if !matched {
			continue
		}
		// Flatten the grant's roles into their permission entries. Unknown role
		// names never match at enforcement time, so they are skipped here too.
		// The newResolvedRole round trip deduplicates and sorts the union
		perms := make([]types.RBACPermission, 0)
		for _, role := range grant.Roles {
			if resolved, ok := h.roles[role]; ok {
				perms = append(perms, resolved.permissions()...)
			}
		}
		snap.Grants = append(snap.Grants, types.RBACSnapshotGrant{
			Description: grant.Description,
			Permissions: newResolvedRole(perms).permissions(),
			Targets:     append([]string(nil), grant.Targets...),
		})
	}

	snap.OwnerPermissions = make(map[string][]types.RBACPermission, len(h.ownerPerms))
	for resource, permSet := range h.ownerPerms {
		perms := make([]types.RBACPermission, 0, len(permSet))
		for perm := range permSet {
			perms = append(perms, perm)
		}
		slices.Sort(perms)
		snap.OwnerPermissions[resource] = perms
	}
	return snap, nil
}

// syncGrant is one snapshot grant with its role permissions resolved for matching
type syncGrant struct {
	role    *resolvedRole
	targets []string
}

// SyncAuthorizer evaluates management API permissions against a frozen
// RBACSnapshot, independent of the live RBAC config. Immutable after
// construction, safe for concurrent use.
type SyncAuthorizer struct {
	userId     string
	admin      bool
	grants     []syncGrant
	ownerPerms map[string]map[types.RBACPermission]bool
}

// NewSyncAuthorizer builds the authorizer for a stored snapshot, nil in -> nil out
func NewSyncAuthorizer(snap *types.RBACSnapshot) *SyncAuthorizer {
	if snap == nil {
		return nil
	}
	a := &SyncAuthorizer{
		userId:     snap.UserId,
		admin:      snap.Admin,
		grants:     make([]syncGrant, 0, len(snap.Grants)),
		ownerPerms: make(map[string]map[types.RBACPermission]bool, len(snap.OwnerPermissions)),
	}
	for _, grant := range snap.Grants {
		a.grants = append(a.grants, syncGrant{
			role:    newResolvedRole(grant.Permissions),
			targets: grant.Targets,
		})
	}
	for resource, perms := range snap.OwnerPermissions {
		permSet := make(map[types.RBACPermission]bool, len(perms))
		for _, perm := range perms {
			permSet[perm] = true
		}
		a.ownerPerms[resource] = permSet
	}
	return a
}

// Authorize mirrors authorizeAPIInt against the snapshot: empty user fails
// closed, admin bypasses every check, the snapshot user holds the snapshotted
// owner permissions on assets they own (never approve), and otherwise a grant
// must match the permission with scoped permissions (app:*) matched
// against the grant's target globs and every other permission global
func (a *SyncAuthorizer) Authorize(perm types.RBACPermission, target types.AppPathDomain, owner string) (bool, error) {
	if a.userId == "" {
		// Fail closed, same as authorizeAPIInt: a snapshot without a user id
		// (e.g. created under a test URL simulation with no authenticated user)
		// confers nothing
		return false, nil
	}
	if a.admin {
		return true, nil
	}
	if owner != "" && a.userId == owner && perm != types.PermissionApprove {
		// app:approve shares the app resource prefix but is never granted
		// through ownership, even by a hand-crafted snapshot
		if a.ownerPerms[PermissionResource(perm)][perm] {
			return true, nil
		}
	}
	for _, grant := range a.grants {
		if !grant.role.matches(perm) {
			continue
		}
		match, err := permWithinTargets(perm, false, grant.targets, target)
		if err != nil || match {
			return match, err
		}
	}
	return false, nil
}

// syncRBACKey is the context key pre-boxed as an any value, see the
// note on the key list in system/thread_local.go
var syncRBACKey any = types.SYNC_RBAC

// WithSyncAuthorizer attaches the frozen sync run authorization to the
// background run context, activating API enforcement against it
func WithSyncAuthorizer(ctx context.Context, a *SyncAuthorizer) context.Context {
	if a == nil {
		return ctx
	}
	return context.WithValue(ctx, syncRBACKey, a)
}

// GetSyncAuthorizer returns the sync run authorizer from the context, nil when
// not present
func GetSyncAuthorizer(ctx context.Context) *SyncAuthorizer {
	value := ctx.Value(syncRBACKey)
	if value == nil {
		return nil
	}
	a, ok := value.(*SyncAuthorizer)
	if !ok {
		return nil
	}
	return a
}

// HasSyncAuthorizer reports whether the context carries a sync run authorizer
func HasSyncAuthorizer(ctx context.Context) bool {
	return GetSyncAuthorizer(ctx) != nil
}
