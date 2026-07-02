// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/types"
)

func testServer() *Server {
	return &Server{Logger: types.NewLogger(&types.LogConfig{Level: "ERROR"})}
}

// When a caller owns the DB transaction (ownsDB=true), finish rolls back the
// stack if the operation did not commit.
func TestDeployScopeOwnerRollsBack(t *testing.T) {
	s := testServer()
	ctx, scope := s.beginDeployScope(context.Background(), true)

	rolled := false
	container.DeployTxnFromContext(ctx).Register("app1", "clc-app1", func(context.Context) error { rolled = true; return nil }, nil)

	origErr := errors.New("verify failed")
	got := scope.finish(ctx, origErr)
	if !rolled {
		t.Fatal("owner scope did not roll back on a non-committed failure")
	}
	if !errors.Is(got, origErr) {
		t.Fatalf("finish returned %v, want it to wrap origErr", got)
	}
}

// A committed owner does not roll back.
func TestDeployScopeCommittedDoesNotRollBack(t *testing.T) {
	s := testServer()
	ctx, scope := s.beginDeployScope(context.Background(), true)
	rolled := false
	container.DeployTxnFromContext(ctx).Register("app1", "clc-app1", func(context.Context) error { rolled = true; return nil }, nil)

	if err := scope.commit(context.Background()); err != nil {
		t.Fatalf("commit error: %v", err)
	}
	if got := scope.finish(ctx, nil); got != nil {
		t.Fatalf("finish returned %v, want nil after commit", got)
	}
	if rolled {
		t.Fatal("committed scope should not roll back")
	}
}

// A scope that reuses a parent's stack (ownsDB=false because a stack already
// exists, or because it does not own the DB transaction) must not roll back;
// only the owner does. This is the apply-with-passed-in-transaction case.
func TestDeployScopeNonOwnerDefersToOwner(t *testing.T) {
	s := testServer()
	// Owner creates the stack.
	ctx, owner := s.beginDeployScope(context.Background(), true)
	// Inner call is handed the same context but does not own the DB tx.
	ctx2, inner := s.beginDeployScope(ctx, false)

	rolled := 0
	container.DeployTxnFromContext(ctx2).Register("app1", "clc-app1", func(context.Context) error { rolled++; return nil }, nil)

	// Inner finishing (e.g. Apply returning under a sync transaction) must not
	// roll back; the owner is still responsible.
	if got := inner.finish(ctx2, errors.New("inner failure")); got == nil {
		t.Fatal("inner.finish should pass the error through")
	}
	if rolled != 0 {
		t.Fatal("non-owner scope must not roll back")
	}

	// The owner rolls back the shared stack.
	owner.finish(ctx, errors.New("operation failed")) //nolint:errcheck
	if rolled != 1 {
		t.Fatalf("owner should have rolled back once, got %d", rolled)
	}
}

// A rollback failure is surfaced in the returned error, not just logged.
func TestDeployScopeRollbackErrorSurfaced(t *testing.T) {
	s := testServer()
	ctx, scope := s.beginDeployScope(context.Background(), true)
	container.DeployTxnFromContext(ctx).Register("app1", "clc-app1", func(context.Context) error { return errors.New("restore boom") }, nil)

	origErr := errors.New("verify failed")
	got := scope.finish(ctx, origErr)
	if got == nil || !strings.Contains(got.Error(), "restore boom") {
		t.Fatalf("finish=%v, want it to include the rollback failure", got)
	}
	if !strings.Contains(got.Error(), "verify failed") {
		t.Fatalf("finish=%v, want it to retain the original error", got)
	}

	// With no original error, a rollback failure still becomes the result.
	ctx2, scope2 := s.beginDeployScope(context.Background(), true)
	container.DeployTxnFromContext(ctx2).Register("app1", "clc-app1", func(context.Context) error { return errors.New("restore boom2") }, nil)
	got2 := scope2.finish(ctx2, nil)
	if got2 == nil || !strings.Contains(got2.Error(), "restore boom2") {
		t.Fatalf("finish=%v, want the rollback failure surfaced", got2)
	}
}

// Containers registered by an in-flight operation are reported as in use, and
// stop being reported once the owning scope commits or finishes.
func TestDeployScopeInFlightContainerNames(t *testing.T) {
	s := testServer()
	ctx, scope := s.beginDeployScope(context.Background(), true)
	container.DeployTxnFromContext(ctx).Register("app1", "clc-app1", nil, nil)

	if names := s.inFlightContainerNames(); !names["clc-app1"] {
		t.Fatalf("in-flight names=%v, want clc-app1 while operation is running", names)
	}
	if err := scope.commit(ctx); err != nil {
		t.Fatalf("commit error: %v", err)
	}
	if names := s.inFlightContainerNames(); len(names) != 0 {
		t.Fatalf("in-flight names=%v, want none after commit", names)
	}

	// The failure path unregisters through finish
	ctx2, scope2 := s.beginDeployScope(context.Background(), true)
	container.DeployTxnFromContext(ctx2).Register("app2", "clc-app2", nil, nil)
	if names := s.inFlightContainerNames(); !names["clc-app2"] {
		t.Fatalf("in-flight names=%v, want clc-app2 while operation is running", names)
	}
	scope2.finish(ctx2, errors.New("operation failed")) //nolint:errcheck
	if names := s.inFlightContainerNames(); len(names) != 0 {
		t.Fatalf("in-flight names=%v, want none after finish", names)
	}
}

// A commit-action failure (e.g. a deferred traffic switch) is returned to the
// caller, not only logged: the DB is committed but the cluster may still serve
// the previous version.
func TestDeployScopeCommitErrorSurfaced(t *testing.T) {
	s := testServer()
	ctx, scope := s.beginDeployScope(context.Background(), true)
	container.DeployTxnFromContext(ctx).Register("app1", "clc-app1", nil,
		func(context.Context) error { return errors.New("flip boom") })

	err := scope.commit(ctx)
	if err == nil || !strings.Contains(err.Error(), "flip boom") {
		t.Fatalf("commit=%v, want the commit-action failure surfaced", err)
	}
	// finish after a failed commit must not roll back: partial traffic
	// switches may have happened and the DB transaction is committed
	if got := scope.finish(ctx, nil); got != nil {
		t.Fatalf("finish after commit = %v, want nil", got)
	}
}

func TestDeployScopeRollbackUsesDetachedContext(t *testing.T) {
	s := testServer()
	ctx, cancel := context.WithCancel(context.Background())
	ctx, scope := s.beginDeployScope(ctx, true)

	rolled := false
	container.DeployTxnFromContext(ctx).Register("app1", "clc-app1", func(c context.Context) error {
		if err := c.Err(); err != nil {
			t.Fatalf("rollback context should not inherit request cancellation: %v", err)
		}
		rolled = true
		return nil
	}, nil)

	cancel()
	if got := scope.finish(ctx, errors.New("operation failed")); got == nil {
		t.Fatal("finish should return the original operation failure")
	}
	if !rolled {
		t.Fatal("rollback did not run")
	}
}
