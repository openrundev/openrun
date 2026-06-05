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
