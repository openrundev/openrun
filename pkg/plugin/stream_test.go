// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"errors"
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

// An error produced right after some items must not drop those items: they
// are delivered first, the error on the following Next
func TestPushCursorErrorAfterItems(t *testing.T) {
	boom := errors.New("boom")
	cursor := PushCursor(context.Background(), "test", "leak", true, func(ctx context.Context, yield func(any, error) bool) {
		if !yield("a", nil) {
			return
		}
		if !yield("b", nil) {
			return
		}
		yield(nil, boom)
	})
	var items []any
	var err error
	for err == nil {
		var batch []any
		var done bool
		batch, done, err = cursor.Next(context.Background(), 100)
		items = append(items, batch...)
		if done {
			t.Fatal("stream reported done without the error")
		}
	}
	if !errors.Is(err, boom) {
		t.Fatalf("expected boom, got %v", err)
	}
	if len(items) != 2 || items[0] != "a" || items[1] != "b" {
		t.Fatalf("items lost before the error: %v", items)
	}
}
