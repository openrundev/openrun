// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/openrundev/openrun/internal/types"
)

// AdminSurface is the part of an RBAC config that decides who holds the admin
// super-user permission, or admin:manage (the permission to change that): the
// roles that resolve to either, the grants using those roles (their users and
// roles), and the membership of every config group those grants reference,
// through the whole group hierarchy. Two configs with equal surfaces confer
// admin and admin:manage on exactly the same principals. config:update is not
// enough to change the surface: a config editor could otherwise add themselves
// to an admin group or grant, or grant themselves admin:manage first and admin
// next. Changing it requires the admin permission or admin:manage (see
// Server.enforceAdminSurfaceChange).
//
// The surface is computed syntactically, tolerating dangling role references
// and cycles, so it can be evaluated on a draft config before validation
type AdminSurface struct {
	Roles  []string            // sorted "role=permission" entries for roles resolving to admin or admin:manage
	Grants []string            // sorted canonical keys of the grants using those roles
	Groups map[string][]string // config group name to sorted members, for every group reachable from an admin grant

	// GroupNames holds every group name a protected grant references,
	// directly or through a group: member of a referenced config group,
	// whether or not the name is a config group: a sign-in group of that
	// name (builtin user groups included) confers admin or admin:manage
	GroupNames map[string]bool
}

// ComputeAdminSurface extracts the admin surface of config. Grant
// descriptions and targets are not part of the surface: admin is a global
// permission, so neither affects who holds it
func ComputeAdminSurface(config *types.RBACConfig) *AdminSurface {
	surface := &AdminSurface{Groups: map[string][]string{}, GroupNames: map[string]bool{}}
	if config == nil {
		config = &types.RBACConfig{}
	}

	// Roles are tracked per protected permission: a role switching from
	// admin:manage to admin changes who holds admin although the set of
	// protected roles stays the same
	adminRoles := map[string]bool{}
	for _, perm := range []types.RBACPermission{types.PermissionAdmin, types.PermissionAdminManage} {
		for name := range rolesConferring(config, perm) {
			adminRoles[name] = true
			surface.Roles = append(surface.Roles, name+"="+string(perm))
		}
	}
	sort.Strings(surface.Roles)

	for _, grant := range config.Grants {
		confersAdmin := false
		for _, role := range grant.Roles {
			if adminRoles[role] {
				confersAdmin = true
				break
			}
		}
		if !confersAdmin {
			continue
		}
		users := slices.Clone(grant.Users)
		sort.Strings(users)
		roles := slices.Clone(grant.Roles)
		sort.Strings(roles)
		surface.Grants = append(surface.Grants, fmt.Sprintf("users=%q roles=%q", users, roles))
		for _, user := range grant.Users {
			if strings.HasPrefix(user, RBAC_GROUP_PREFIX) {
				surface.collectGroup(config, user[len(RBAC_GROUP_PREFIX):])
			}
		}
	}
	sort.Strings(surface.Grants)
	return surface
}

// collectGroup records the group name and, when it is a config group, its
// members and the groups they reference
func (a *AdminSurface) collectGroup(config *types.RBACConfig, name string) {
	if a.GroupNames[name] {
		return
	}
	a.GroupNames[name] = true
	members, ok := config.Groups[name]
	if !ok {
		return
	}
	sorted := slices.Clone(members)
	sort.Strings(sorted)
	a.Groups[name] = sorted
	for _, member := range members {
		if strings.HasPrefix(member, RBAC_GROUP_PREFIX) {
			a.collectGroup(config, member[len(RBAC_GROUP_PREFIX):])
		}
	}
}

// rolesConferring returns the roles (predefined or from config) that resolve
// to the literal permission perm (admin or admin:manage), directly or through
// role: composition. Permission globs never match either. Computed as a fixed
// point over the role graph: a role confers perm when it lists it or composes
// a role that does. Every pass is linear in the config and at most one pass
// per role is needed, so a dense cyclic role graph (which publish validation
// rejects separately) stays cheap to evaluate. Undefined roles confer nothing
func rolesConferring(config *types.RBACConfig, perm types.RBACPermission) map[string]bool {
	rolePerms := make(map[string][]types.RBACPermission, len(predefinedRoles)+len(config.Roles))
	for name, perms := range predefinedRoles {
		rolePerms[name] = perms
	}
	for name, perms := range config.Roles {
		rolePerms[name] = perms
	}

	protected := map[string]bool{}
	for name, perms := range rolePerms {
		if slices.Contains(perms, perm) {
			protected[name] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for name, perms := range rolePerms {
			if protected[name] {
				continue
			}
			for _, perm := range perms {
				if strings.HasPrefix(string(perm), RBAC_ROLE_PREFIX) && protected[string(perm)[len(RBAC_ROLE_PREFIX):]] {
					protected[name] = true
					changed = true
					break
				}
			}
		}
	}
	return protected
}

// Diff describes the first difference between two surfaces, or returns ""
// when they confer admin identically
func (a *AdminSurface) Diff(b *AdminSurface) string {
	if a == nil {
		a = ComputeAdminSurface(nil)
	}
	if b == nil {
		b = ComputeAdminSurface(nil)
	}
	if !slices.Equal(a.Roles, b.Roles) {
		return fmt.Sprintf("the roles conferring the admin or admin:manage permission change from %v to %v", a.Roles, b.Roles)
	}
	if !slices.Equal(a.Grants, b.Grants) {
		return "the grants conferring the admin or admin:manage permission change"
	}
	names := make([]string, 0, len(a.GroupNames)+len(b.GroupNames))
	for name := range a.GroupNames {
		names = append(names, name)
	}
	for name := range b.GroupNames {
		if !a.GroupNames[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		membersA, okA := a.Groups[name]
		membersB, okB := b.Groups[name]
		if okA != okB || !slices.Equal(membersA, membersB) {
			return fmt.Sprintf("the membership of group %q, which confers the admin or admin:manage permission, changes", name)
		}
	}
	return ""
}

// AdminSurface returns the admin surface of the live config
func (h *RBACManager) AdminSurface() *AdminSurface {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.adminSurface
}

// AdminGroupsIn returns the groups among the given names that confer the
// admin or admin:manage permission under the live config: a principal
// signing in with any of them (or a builtin user placed in one) is an admin
// or can make themselves one
func (h *RBACManager) AdminGroupsIn(groups []string) []string {
	surface := h.AdminSurface()
	var matched []string
	for _, group := range groups {
		if surface.GroupNames[group] {
			matched = append(matched, group)
		}
	}
	sort.Strings(matched)
	return matched
}
