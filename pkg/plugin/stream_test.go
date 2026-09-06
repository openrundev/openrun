// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"testing"
	"time"
)

func TestPushCursorCloseBeforeNext(t *testing.T) {
	started := make(chan struct{}, 1)
	cursor := PushCursor(context.Background(), "test", "test", true, func(ctx context.Context, yield func(any, error) bool) { started <- struct{}{} })
	if err := cursor.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, done, err := cursor.Next(context.Background(), 1)
	if err != nil || !done {
		t.Fatalf("Next after close = done %v, err %v", done, err)
	}
	select {
	case <-started:
		t.Fatal("closed cursor started producer")
	default:
	}
}

func TestPushCursorParentCancellationUnblocksYield(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exited := make(chan struct{})
	cursor := PushCursor(ctx, "test", "test", true, func(ctx context.Context, yield func(any, error) bool) {
		defer close(exited)
		if yield("first", nil) {
			yield("second", nil)
		}
	})
	defer cursor.Close(context.Background()) //nolint:errcheck
	if _, _, err := cursor.Next(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("parent cancellation did not unblock yield")
	}
}

func TestPushCursorCloseUnblocksNext(t *testing.T) {
	started, exited := make(chan struct{}), make(chan struct{})
	cursor := PushCursor(context.Background(), "test", "test", true, func(ctx context.Context, yield func(any, error) bool) {
		defer close(exited)
		close(started)
		<-ctx.Done() // Block outside yield until the cursor cancels its context.
	})
	defer func() { <-exited }()
	nextDone := make(chan struct{})
	go func() {
		defer close(nextDone)
		_, _, _ = cursor.Next(context.Background(), 1)
	}()
	<-started
	if err := cursor.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-nextDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Next")
	}
}
