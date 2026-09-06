// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"time"
)

// BackgroundTask owns one cancellable goroutine. Stop cancels its work and
// waits for cleanup to finish; it is safe to call more than once.
type BackgroundTask struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func StartBackgroundTask(parent context.Context, run func(context.Context)) *BackgroundTask {
	ctx, cancel := context.WithCancel(parent)
	task := &BackgroundTask{cancel: cancel, done: make(chan struct{})}
	go func() { defer close(task.done); defer cancel(); run(ctx) }()
	return task
}

func (t *BackgroundTask) Stop() {
	if t == nil {
		return
	}
	t.cancel()
	<-t.done
}

// StartPeriodicTask serializes passes and checks cancellation before each one.
func StartPeriodicTask(parent context.Context, interval time.Duration, immediate bool, pass func(context.Context)) *BackgroundTask {
	return StartBackgroundTask(parent, func(ctx context.Context) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if !immediate {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
			if ctx.Err() != nil {
				return
			}
			pass(ctx)
			immediate = false
		}
	})
}
