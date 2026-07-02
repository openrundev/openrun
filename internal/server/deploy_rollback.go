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
// lifecycle of a DB-transaction owner. Apps that mutate their container
// deployment register rollback/commit closures on the stack; if the operation
// fails (or its DB transaction is not committed), every such app is rolled
// back so the cluster matches the rolled-back DB state. On success the commit
// closures run: deferred blue-green traffic switches and cleanup of superseded
// versions.
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
// the rollback. The owning scope's transaction is registered on the server so
// its in-flight containers are visible (e.g. to the stale container sweeper)
// until commit or finish unregisters it.
func (s *Server) beginDeployScope(ctx context.Context, ownsDB bool) (context.Context, *deployScope) {
	txn := container.DeployTxnFromContext(ctx)
	own := false
	if txn == nil {
		txn = container.NewDeployTxn()
		ctx = container.ContextWithDeployTxn(ctx, txn)
		own = ownsDB
		if own {
			s.registerDeployTxn(txn)
		}
	}
	return ctx, &deployScope{s: s, txn: txn, own: own}
}

// opTimeout scales the commit/rollback time budget with the operation size:
// each app's commit can wait on endpoint convergence after a traffic switch,
// and each rollback on a pod rollout.
func (d *deployScope) opTimeout() time.Duration {
	return 2*time.Minute + time.Duration(d.txn.Len())*time.Minute
}

// commit marks the operation as successfully committed (so finish becomes a
// no-op) and, for the owning scope, runs the registered commit actions:
// deferred blue-green traffic switches and cleanup of superseded versions.
// Call it only after CompleteTransaction succeeds. A commit-action failure is
// returned (not only logged) because it can mean a traffic switch did not
// happen: the metadata is committed but an app may still serve its previous
// version until a forced reload.
func (d *deployScope) commit(ctx context.Context) error {
	d.committed = true
	if !d.own {
		return nil
	}
	defer d.s.unregisterDeployTxn(d.txn)
	gcCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.opTimeout())
	defer cancel()
	if err := d.txn.CommitAll(gcCtx); err != nil {
		d.s.Error().Err(err).Msg("post-commit deployment actions failed; an app may still be serving its previous version")
		return fmt.Errorf("apps were updated, but post-commit deployment actions failed (a traffic switch may not have completed; reload with --force-reload to retry): %w", err)
	}
	return nil
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
	defer d.s.unregisterDeployTxn(d.txn)
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.opTimeout())
	defer cancel()
	rbErr := d.txn.RollbackAll(rbCtx)
	if rbErr == nil {
		return retErr
	}
	d.s.Error().Err(rbErr).Msg("operation-level deployment rollback failed; manual intervention may be required")
	if retErr == nil {
		return fmt.Errorf("operation failed and the deployment rollback of earlier apps also failed: %w", rbErr)
	}
	return fmt.Errorf("%w; additionally, the deployment rollback of earlier apps failed: %v", retErr, rbErr)
}

// registerDeployTxn tracks an owning operation's deploy transaction so its
// containers count as in use while the operation is in flight.
func (s *Server) registerDeployTxn(txn *container.DeployTxn) {
	s.deployTxnMu.Lock()
	defer s.deployTxnMu.Unlock()
	if s.activeDeployTxns == nil {
		s.activeDeployTxns = make(map[*container.DeployTxn]bool)
	}
	s.activeDeployTxns[txn] = true
}

func (s *Server) unregisterDeployTxn(txn *container.DeployTxn) {
	s.deployTxnMu.Lock()
	defer s.deployTxnMu.Unlock()
	delete(s.activeDeployTxns, txn)
}

// inFlightContainerNames returns the containers registered by operations
// currently in progress. Such containers are not yet referenced by the app
// store (their operation's DB transaction has not committed), so the stale
// container sweeper must not treat them as stale.
func (s *Server) inFlightContainerNames() map[container.ContainerName]bool {
	s.deployTxnMu.Lock()
	defer s.deployTxnMu.Unlock()
	names := make(map[container.ContainerName]bool)
	for txn := range s.activeDeployTxns {
		for _, name := range txn.ContainerNames() {
			names[name] = true
		}
	}
	return names
}
