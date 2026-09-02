// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/types"
)

// TestRBACEmptyGrantsRejected: a dynamic RBAC update with no grants is
// rejected while RBAC is enforced (the staged publish/restore path validates
// it here; the file upload path is covered by test_rbac.yaml rbac0188); a
// config with one grant passes
func TestRBACEmptyGrantsRejected(t *testing.T) {
	server, _, _ := newRemoteApiTestServer(t)
	if !server.rbacManager.ConfigEnabled() {
		t.Fatal("test server must enforce RBAC")
	}

	err := server.validateRBACCandidate(context.Background(), &types.RBACConfig{}, false)
	if err == nil || !strings.Contains(err.Error(), "at least one grant is required") {
		t.Fatalf("empty grants must be rejected, got %v", err)
	}
	if err := server.validateRBACCandidate(context.Background(), rbac.DefaultConfig(), false); err != nil {
		t.Fatalf("the default config must validate, got %v", err)
	}
}
