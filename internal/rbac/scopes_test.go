// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func TestScopesAllow(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		perm   types.RBACPermission
		want   bool
	}{
		{"exact match", []string{"app:read"}, types.PermissionRead, true},
		{"no match", []string{"app:read"}, types.PermissionCreate, false},
		{"resource glob", []string{"app:*"}, types.PermissionDelete, true},
		{"verb glob", []string{"*:read"}, types.PermissionSyncRead, true},
		{"star", []string{"*"}, types.PermissionServerStop, true},
		{"empty covers nothing", []string{}, types.PermissionRead, false},
		{"multiple scopes", []string{"sync:read", "app:*"}, types.PermissionPromote, true},

		// The scope matcher is stricter than the RBAC role glob matcher
		// (which excludes only app:approve and admin): reveal-class
		// permissions are literal-only in scopes
		{"secret glob does not match reveal", []string{"secret:*"}, types.PermissionSecretReveal, false},
		{"star does not match secret reveal", []string{"*"}, types.PermissionSecretReveal, false},
		{"literal secret reveal", []string{"secret:reveal"}, types.PermissionSecretReveal, true},
		{"binding glob does not match reveal", []string{"binding:*"}, types.PermissionBindingReveal, false},
		{"literal binding reveal", []string{"binding:reveal"}, types.PermissionBindingReveal, true},
		{"star does not match approve", []string{"*"}, types.PermissionApprove, false},
		{"app glob does not match approve", []string{"app:*"}, types.PermissionApprove, false},
		{"literal approve", []string{"app:approve"}, types.PermissionApprove, true},
		{"star does not match admin", []string{"*"}, types.PermissionAdmin, false},
		{"literal admin", []string{"admin"}, types.PermissionAdmin, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScopesAllow(tt.scopes, tt.perm); got != tt.want {
				t.Fatalf("ScopesAllow(%v, %s) = %v, want %v", tt.scopes, tt.perm, got, tt.want)
			}
		})
	}
}

func TestValidateScopes(t *testing.T) {
	if err := ValidateScopes([]string{"app:read", "app:*", "*:read", "*", "secret:reveal"}); err != nil {
		t.Fatalf("valid scopes rejected: %v", err)
	}
	for _, invalid := range [][]string{
		{"app:bogus"},          // unknown permission
		{"role:openrun-admin"}, // roles are not scopes
		{"custom:something"},   // custom permissions are not scopes
		{"app:[invalid"},       // malformed glob
	} {
		if err := ValidateScopes(invalid); err == nil {
			t.Fatalf("invalid scopes %v accepted", invalid)
		}
	}
}
