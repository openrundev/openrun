// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/openrundev/openrun/internal/types"
)

// Credential scopes reuse the RBAC permission vocabulary: a scope is a
// permission name or glob (app:read, app:*, *:read, *). Scopes are a CEILING
// over RBAC, checked before grant evaluation: the credential must cover the
// permission AND the user's grants must allow it.
//
// The scope matcher is deliberately stricter than the RBAC role glob matcher
// (which excludes only app:approve and admin): reveal-class permissions must
// be named literally in a scope. A bearer credential is a weaker artifact
// than an RBAC grant, so reveal authority must be visible in the token itself.

// scopeLiteralOnly are the permissions a scope glob never matches; a
// credential must name them literally to cover them
var scopeLiteralOnly = map[types.RBACPermission]bool{
	types.PermissionSecretReveal:  true,
	types.PermissionBindingReveal: true,
	types.PermissionApprove:       true,
	types.PermissionAdmin:         true,
}

// ScopesAllow reports whether the scope ceiling covers perm. A nil/empty
// scope list covers nothing; callers represent "unscoped" by not attaching
// scopes to the context at all
func ScopesAllow(scopes []string, perm types.RBACPermission) bool {
	permStr := string(perm)
	for _, scope := range scopes {
		if scope == permStr {
			return true
		}
	}
	if scopeLiteralOnly[perm] {
		return false
	}
	for _, scope := range scopes {
		if !hasGlobMeta(scope) {
			continue
		}
		if match, err := doublestar.Match(scope, permStr); err == nil && match {
			return true
		}
	}
	return false
}

// ScopeCovered reports whether the parent scope ceiling covers the child
// scope entry, for credential attenuation (a credential may only mint
// credentials at most as powerful as itself). A child scope is covered when
// it exactly matches a parent entry, or when it is a literal permission the
// parent ceiling allows. A child GLOB that is not an exact parent entry is
// conservatively not covered (glob-implication is not evaluated)
func ScopeCovered(parent []string, child string) bool {
	for _, scope := range parent {
		if scope == child {
			return true
		}
	}
	if hasGlobMeta(child) {
		return false
	}
	return ScopesAllow(parent, types.RBACPermission(child))
}

// ValidateScopes checks that every scope is a known permission name or a
// syntactically valid glob pattern. Custom (custom:) and role (role:)
// entries are not valid scopes: scopes bound management API permissions only
func ValidateScopes(scopes []string) error {
	for _, scope := range scopes {
		if strings.HasPrefix(scope, RBAC_CUSTOM_PREFIX) || strings.HasPrefix(scope, RBAC_ROLE_PREFIX) {
			return fmt.Errorf("invalid scope %q: custom permissions and roles are not valid scopes", scope)
		}
		if hasGlobMeta(scope) {
			if !doublestar.ValidatePattern(scope) {
				return fmt.Errorf("invalid scope glob %q", scope)
			}
			continue
		}
		if err := validatePermission(types.RBACPermission(scope)); err != nil {
			return fmt.Errorf("invalid scope %q: %w", scope, err)
		}
	}
	return nil
}
