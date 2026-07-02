// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/openrundev/openrun/internal/types"
)

// DeployTxn is an operation-level deploy stack for container deployments. A
// single reload/apply command may deploy several apps before a later app fails.
// Because the control-plane DB transaction commits or rolls back as a whole,
// the cluster must follow: each app that successfully deploys registers an
// onRollback and an onCommit closure here, and the server invokes RollbackAll
// on failure or CommitAll on success.
type DeployTxn struct {
	mu      sync.Mutex
	entries []deployEntry
	names   []ContainerName
}

type deployEntry struct {
	appId      types.AppId
	onRollback func(ctx context.Context) error
	onCommit   func(ctx context.Context) error
}

func NewDeployTxn() *DeployTxn {
	return &DeployTxn{}
}

func (d *DeployTxn) Register(appId types.AppId, containerName ContainerName, onRollback, onCommit func(ctx context.Context) error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries = append(d.entries, deployEntry{appId: appId, onRollback: onRollback, onCommit: onCommit})
	if containerName != "" {
		d.names = append(d.names, containerName)
	}
}

// Len returns the number of registered deploy entries. Callers use it to scale
// commit/rollback time budgets with the operation size; it must be read before
// CommitAll/RollbackAll drain the entries.
func (d *DeployTxn) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

// ContainerNames returns the containers touched by this operation. Unlike the
// entries, names are not drained by CommitAll/RollbackAll: they must keep
// protecting the operation's containers (e.g. from the stale container
// sweeper) until the owning scope unregisters the whole transaction.
func (d *DeployTxn) ContainerNames() []ContainerName {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.names)
}

func (d *DeployTxn) drain() []deployEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	entries := d.entries
	d.entries = nil
	return entries
}

func (d *DeployTxn) RollbackAll(ctx context.Context) error {
	entries := d.drain()
	var errs []error
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].onRollback == nil {
			continue
		}
		if err := entries[i].onRollback(ctx); err != nil {
			errs = append(errs, fmt.Errorf("rollback app %s: %w", entries[i].appId, err))
		}
	}
	return errors.Join(errs...)
}

func (d *DeployTxn) CommitAll(ctx context.Context) error {
	entries := d.drain()
	var errs []error
	for i := range entries {
		if entries[i].onCommit == nil {
			continue
		}
		if err := entries[i].onCommit(ctx); err != nil {
			errs = append(errs, fmt.Errorf("commit app %s: %w", entries[i].appId, err))
		}
	}
	return errors.Join(errs...)
}

type deployTxnKeyType struct{}

var deployTxnKey = deployTxnKeyType{}

func ContextWithDeployTxn(ctx context.Context, d *DeployTxn) context.Context {
	return context.WithValue(ctx, deployTxnKey, d)
}

func DeployTxnFromContext(ctx context.Context) *DeployTxn {
	d, _ := ctx.Value(deployTxnKey).(*DeployTxn)
	return d
}

// DeployRollbackError wraps a verification failure with the status of the
// cluster-side rollback, so callers can report accurately instead of always
// claiming "all changes have been reverted".
type DeployRollbackError struct {
	Err         error
	Available   bool
	RollbackErr error
}

func (e *DeployRollbackError) Error() string {
	switch {
	case !e.Available:
		return fmt.Sprintf("%v (the Kubernetes deployment was NOT rolled back: no snapshot was captured; manual intervention may be required)", e.Err)
	case e.RollbackErr != nil:
		return fmt.Sprintf("%v (the Kubernetes rollback FAILED: %v; manual intervention required)", e.Err, e.RollbackErr)
	default:
		return e.Err.Error()
	}
}

func (e *DeployRollbackError) Unwrap() error { return e.Err }

func ClusterRollbackClean(err error) bool {
	var de *DeployRollbackError
	if errors.As(err, &de) {
		return de.Available && de.RollbackErr == nil
	}
	return true
}
