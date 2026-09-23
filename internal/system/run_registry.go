// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/segmentio/ksuid"
)

// RunRegistry tracks the background runs (job runs, async action runs)
// executing on this node, by run id, so a cancel request can stop them and
// the server shutdown can refuse new runs and wait for the active ones.
// Runs are grouped (by app id for action runs) so admission limits can count
// the active runs of a group
type RunRegistry struct {
	mu        sync.Mutex
	active    map[string]registeredRun
	reserved  map[string]int // admitted runs of a group not yet added, see Reserve
	ctx       context.Context
	cancelAll context.CancelFunc
	closed    bool
	wg        sync.WaitGroup
}

type registeredRun struct {
	group      string
	cancel     context.CancelFunc
	canceledBy string // who requested the cancel, for the run record
}

// Begin registers work before it can touch the database, so shutdown can
// reject new runs and wait for every claimed run to finish cleanup. The
// returned context is canceled by Stop; done must be called when the work
// ends
func (r *RunRegistry) Begin() (context.Context, func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, nil, errors.New("run registry is stopped")
	}
	if r.ctx == nil {
		r.ctx, r.cancelAll = context.WithCancel(context.Background())
	}
	r.wg.Add(1)
	return r.ctx, r.wg.Done, nil
}

// Stop refuses new runs and cancels the active ones
func (r *RunRegistry) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.cancelAll != nil {
		r.cancelAll()
	}
}

// Wait blocks until every begun run has called done
func (r *RunRegistry) Wait() { r.wg.Wait() }

// Add registers an executing run with its cancel function
func (r *RunRegistry) Add(id, group string, cancel context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		r.active = map[string]registeredRun{}
	}
	r.active[id] = registeredRun{group: group, cancel: cancel}
}

// Remove drops a finished run
func (r *RunRegistry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.active, id)
}

// Cancel cancels the run when it is executing here, reporting whether it
// was; by names who asked (recorded with the run)
func (r *RunRegistry) Cancel(id, by string) bool {
	r.mu.Lock()
	entry, ok := r.active[id]
	if ok && entry.canceledBy == "" {
		entry.canceledBy = by
		r.active[id] = entry
	}
	r.mu.Unlock()
	if ok {
		entry.cancel()
	}
	return ok
}

// CanceledBy returns who canceled the run: the user who asked, "server
// shutdown" when the registry was stopped, empty otherwise
func (r *RunRegistry) CanceledBy(id string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.active[id]; ok && entry.canceledBy != "" {
		return entry.canceledBy
	}
	if r.closed {
		return "server shutdown"
	}
	return ""
}

// Has reports whether the run is executing on this node
func (r *RunRegistry) Has(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.active[id]
	return ok
}

// CountGroup returns the number of active and reserved runs of the group
func (r *RunRegistry) CountGroup(group string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.countGroupLocked(group)
}

func (r *RunRegistry) countGroupLocked(group string) int {
	count := r.reserved[group]
	for _, entry := range r.active {
		if entry.group == group {
			count++
		}
	}
	return count
}

// Reserve admits a run of the group when fewer than limit runs of it are
// active or reserved, atomically with the check, so concurrent submissions
// cannot all pass the limit. The reservation is released by the returned
// function: after Add registered the run (it counts as active then), or
// when the submission fails
func (r *RunRegistry) Reserve(group string, limit int) (func(), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.countGroupLocked(group) >= limit {
		return nil, false
	}
	if r.reserved == nil {
		r.reserved = map[string]int{}
	}
	r.reserved[group]++
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.reserved[group] > 0 {
				r.reserved[group]--
			}
		})
	}, true
}

// NewPrefixedId returns a random, time ordered id with the prefix (run_ for
// job runs; async action run ids have no prefix)
func NewPrefixedId(prefix string) (string, error) {
	genId, err := ksuid.NewRandom()
	if err != nil {
		return "", err
	}
	return prefix + strings.ToLower(genId.String()), nil
}
