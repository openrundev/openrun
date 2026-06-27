// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/openrundev/openrun/internal/container"
)

// deployScope manages an operation-level cluster rollback stack tied to the
// lifecycle of a DB-transaction owner. Apps that mutate their Kubernetes
// deployment in-place register a rollback closure on the stack; if the
// operation fails (or its DB transaction is not committed), every such app is
// rolled back so the cluster matches the rolled-back DB state.
//
// Ownership follows the DB transaction: the function that begins and commits
// the DB transaction owns the rollback and marks the scope committed only after
// CompleteTransaction succeeds. Nested calls reuse the parent's stack and do
// not roll back independently.
type deployScope struct {
	s         *Server
	txn       *container.DeployTxn
	own       bool
	committed bool
}

// beginDeployScope returns a context carrying the rollback stack and a scope.
// It reuses a parent stack already present in the context. ownsDB must be true
// only when this caller owns the DB transaction it will commit; a caller that
// was handed a transaction must pass ownsDB=false so the real owner performs
// the rollback.
func (s *Server) beginDeployScope(ctx context.Context, ownsDB bool) (context.Context, *deployScope) {
	txn := container.DeployTxnFromContext(ctx)
	own := false
	if txn == nil {
		txn = container.NewDeployTxn()
		ctx = container.ContextWithDeployTxn(ctx, txn)
		own = ownsDB
	}
	return ctx, &deployScope{s: s, txn: txn, own: own}
}

// commit marks the operation as successfully committed (so finish becomes a
// no-op) and, for the owning scope, runs the registered commit actions —
// garbage-collecting superseded blue-green versions. Call it only after
// CompleteTransaction succeeds. GC failures are logged, not propagated: the new
// version is already live, and a leftover old version is harmless.
func (d *deployScope) commit(ctx context.Context) {
	d.committed = true
	if !d.own {
		return
	}
	gcCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	if err := d.txn.CommitAll(gcCtx); err != nil {
		d.s.Error().Err(err).Msg("operation-level cleanup of superseded versions failed; they may need manual removal")
	}
}

// finish rolls back the cluster if this scope owns the stack and the operation
// did not commit. It returns retErr augmented with the rollback failure (if
// any) so the failure is surfaced to the caller, not only logged. Intended to
// be called from a deferred closure that assigns the result back to the named
// return value.
func (d *deployScope) finish(ctx context.Context, retErr error) error {
	if !d.own || d.committed {
		return retErr
	}
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	rbErr := d.txn.RollbackAll(rbCtx)
	if rbErr == nil {
		return retErr
	}
	d.s.Error().Err(rbErr).Msg("operation-level Kubernetes rollback failed; manual intervention may be required")
	if retErr == nil {
		return fmt.Errorf("operation failed and the Kubernetes rollback of earlier apps also failed: %w", rbErr)
	}
	return fmt.Errorf("%w; additionally, the Kubernetes rollback of earlier apps failed: %v", retErr, rbErr)
}
