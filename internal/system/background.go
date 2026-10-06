// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
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
	go func() {
		defer close(task.done)
		defer cancel()
		defer recoverBackgroundPanic()
		run(ctx)
	}()
	return task
}

// recoverBackgroundPanic keeps a panic in a background goroutine from taking
// down the process
func recoverBackgroundPanic() {
	if r := recover(); r != nil {
		fmt.Fprintf(os.Stderr, "panic in background task: %v\n%s\n", r, debug.Stack())
	}
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
			// A panic in one pass must not end the periodic task
			func() {
				defer recoverBackgroundPanic()
				pass(ctx)
			}()
			immediate = false
		}
	})
}
