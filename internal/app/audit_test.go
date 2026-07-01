// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func TestNeedsApprovalWithServerConfigAllowsGlobalBindingSources(t *testing.T) {
	t.Parallel()

	result := &types.ApproveResult{
		NewBindingSourcePerms: []string{"postgres", "custom/source"},
	}

	if !needsApprovalWithServerConfig(result, nil, []string{"postgres"}) {
		t.Fatal("expected approval for binding source not covered by server config")
	}

	result.ApprovedBindingSourcePerms = []string{"custom/source"}
	if needsApprovalWithServerConfig(result, nil, []string{"postgres"}) {
		t.Fatal("did not expect approval when binding sources are approved or globally allowed")
	}

	result.ApprovedBindingSourcePerms = nil
	if needsApprovalWithServerConfig(result, nil, []string{"postgres", "regex:custom/.*"}) {
		t.Fatal("did not expect approval when binding source is covered by server regex")
	}
}

func TestNeedsApprovalChecksPermissionPermit(t *testing.T) {
	t.Parallel()

	result := &types.ApproveResult{
		NewPermissions: []types.Permission{
			{Plugin: "http.in", Method: "get", Permit: []string{"net:read"}},
		},
		ApprovedPermissions: []types.Permission{
			{Plugin: "http.in", Method: "get", Permit: []string{"net:read"}},
		},
	}
	if needsApproval(result) {
		t.Fatal("did not expect approval when permit list is unchanged")
	}

	result.ApprovedPermissions[0].Permit = []string{"net:write"}
	if !needsApproval(result) {
		t.Fatal("expected approval when permit list changes")
	}
}

func TestServerConfigCoverageChecksPermissionPermit(t *testing.T) {
	t.Parallel()

	result := &types.ApproveResult{
		NewPermissions: []types.Permission{
			{Plugin: "http.in", Method: "get", Permit: []string{"net:read"}},
		},
	}
	serverPerms := []types.Permission{{Plugin: "http.in", Method: "get"}}
	if !needsApprovalWithServerConfig(result, serverPerms, nil) {
		t.Fatal("expected approval when app permission permit is not covered by server config")
	}

	serverPerms[0].Permit = []string{"net:read"}
	if needsApprovalWithServerConfig(result, serverPerms, nil) {
		t.Fatal("did not expect approval when permit list is covered by server config")
	}
}
