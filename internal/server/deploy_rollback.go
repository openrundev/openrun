// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/openrundev/openrun/internal/container"
)

// operationScope manages the operation-level side effects tied to the lifecycle of
// a DB-transaction owner:
//   - the cluster rollback stack: apps that mutate their container deployment
//     register rollback/commit closures on it
//   - the binding account manager: binding operations record the artifacts and
//     grants they create on external services
//
// If the operation fails (or its DB transaction is not committed), finish
// reverts both so the cluster and the external services match the rolled-back
// DB state. On success commit keeps the binding side effects, runs the deferred
// blue-green traffic switches and finally executes the deferred grant revokes.
//
// Ownership follows the DB transaction: the function that begins and commits
// the DB transaction owns the scope and calls commit only after
// CompleteTransaction succeeds. Nested calls reuse the parent's stack and
// account manager and do not commit or roll back independently.
type operationScope struct {
	s         *Server
	txn       *container.DeployTxn
	accounts  *bindingAccountManager
	own       bool
	committed bool
}

// bindingEffectsCtxKey carries the operation's bindingAccountManager in the
// context, alongside the container.DeployTxn, so nested scopes share it.
type bindingEffectsCtxKey struct{}

// bindingEffectsFromContext returns the operation's binding account manager
// attached by beginDeployScope, or nil when no scope has been started.
func bindingEffectsFromContext(ctx context.Context) *bindingAccountManager {
	accounts, _ := ctx.Value(bindingEffectsCtxKey{}).(*bindingAccountManager)
	return accounts
}

// beginDeployScope returns a context carrying the operation's rollback stack
// and binding account manager, and a scope handle. It reuses a parent stack
// already present in the context. ownsDB must be true only when this caller
// owns the DB transaction it will commit; a caller that was handed a
// transaction must pass ownsDB=false so the real owner performs the commit and
// rollback. dryRun is used when a new binding account manager is created; on
// dry run the manager touches no external services. The owning scope's
// transaction is registered on the server so its in-flight containers are
// visible (e.g. to the stale container sweeper) until commit or finish
// unregisters it.
func (s *Server) beginDeployScope(ctx context.Context, ownsDB, dryRun bool) (context.Context, *operationScope) {
	txn := container.DeployTxnFromContext(ctx)
	accounts, _ := ctx.Value(bindingEffectsCtxKey{}).(*bindingAccountManager)
	own := false
	if txn == nil {
		txn = container.NewDeployTxn()
		ctx = container.ContextWithDeployTxn(ctx, txn)
		accounts = s.newBindingAccountManager(dryRun)
		ctx = context.WithValue(ctx, bindingEffectsCtxKey{}, accounts)
		own = ownsDB
		if own {
			s.registerDeployTxn(txn)
		}
	} else if accounts == nil {
		// A parent attached only the deploy transaction (not expected); still
		// provide a manager so binding operations have something to record on.
		accounts = s.newBindingAccountManager(dryRun)
		ctx = context.WithValue(ctx, bindingEffectsCtxKey{}, accounts)
	}
	return ctx, &operationScope{s: s, txn: txn, accounts: accounts, own: own}
}

// opTimeout scales the commit/rollback time budget with the operation size:
// each app's commit can wait on endpoint convergence after a traffic switch,
// and each rollback on a pod rollout.
func (d *operationScope) opTimeout() time.Duration {
	return 2*time.Minute + time.Duration(d.txn.Len())*time.Minute
}

// commit marks the operation as successfully committed (so finish becomes a
// no-op) and, for the owning scope, runs the post-commit work in order: the
// binding artifacts and grants created on external services are kept, the
// deferred blue-green traffic switches and cleanup of superseded versions run,
// and finally the deferred grant revokes execute (last, so no running app
// loses a grant before its traffic has switched). Call it only after
// CompleteTransaction succeeds. A failure is returned (not only logged): a
// failed traffic switch can mean an app still serves its previous version, and
// a failed revoke leaves extra grants applied until a later apply retries them.
func (d *operationScope) commit(ctx context.Context) error {
	d.committed = true
	if !d.own {
		return nil
	}
	defer d.s.unregisterDeployTxn(d.txn)
	gcCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.opTimeout())
	defer cancel()

	// The metadata transaction has committed: keep the binding accounts and
	// grants created on the services, whatever happens below.
	d.accounts.commit()
	defer d.accounts.closeServices(gcCtx)

	if err := d.txn.CommitAll(gcCtx); err != nil {
		d.s.Error().Err(err).Msg("post-commit deployment actions failed; an app may still be serving its previous version")
		return fmt.Errorf("apps were updated, but post-commit deployment actions failed (a traffic switch may not have completed; reload with --force-reload to retry): %w", err)
	}
	return d.accounts.finalizeRevokes(gcCtx)
}

// finish rolls back the operation's side effects if this scope owns them and
// the operation did not commit: the grants applied and binding accounts created
// on external services are undone first, then the cluster changes are rolled
// back so restored deployments run against the restored grants. It returns
// retErr augmented with the rollback failure (if any) so the failure is
// surfaced to the caller, not only logged. Intended to be called from a
// deferred closure that assigns the result back to the named return value.
func (d *operationScope) finish(ctx context.Context, retErr error) error {
	if !d.own || d.committed {
		return retErr
	}
	defer d.s.unregisterDeployTxn(d.txn)
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.opTimeout())
	defer cancel()
	d.accounts.rollbackAndClose(rbCtx)
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
