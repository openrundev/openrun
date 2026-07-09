// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/system"
)

func TestNewBackgroundOperationContext(t *testing.T) {
	// Background runs (the sync scheduler) get a synthesized request id so
	// their audit events share a trace id; the id uses the same per-process
	// prefix as HTTP requests and must be unique per call
	ctx1 := newBackgroundOperationContext("scheduler")
	ctx2 := newBackgroundOperationContext("scheduler")

	rid1 := system.GetContextRequestId(ctx1)
	rid2 := system.GetContextRequestId(ctx2)
	if rid1 == "" || rid2 == "" {
		t.Fatalf("background context has no request id: %q %q", rid1, rid2)
	}
	if !strings.HasPrefix(rid1, "rid_") {
		t.Fatalf("request id %q does not use the rid prefix", rid1)
	}
	if rid1 == rid2 {
		t.Fatalf("background runs share the request id %q", rid1)
	}
	if user := system.GetContextUserId(ctx1); user != "scheduler" {
		t.Fatalf("background context user id %q, want scheduler", user)
	}
}
