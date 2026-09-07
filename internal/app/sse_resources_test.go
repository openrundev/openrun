// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

func TestAppCloseReleasesSSEClients(t *testing.T) {
	a := &App{Logger: types.NewLogger(&types.LogConfig{Level: "ERROR"})}
	client := make(chan SSEMessage, 1)
	a.addSSEClient(client)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			a.notifyClients()
		}
	}()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	// Any queued notification may precede the close.
	select {
	case <-client:
	default:
	}
	select {
	case _, ok := <-client:
		if ok {
			t.Fatal("unexpected notification after Close")
		}
	default:
		t.Fatal("App.Close left its SSE client open")
	}
	if len(a.sseListeners) != 0 {
		t.Fatal("closed app retained listeners")
	}
	// A handler that captured the old app before removal must also exit.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.sseHandler(httptest.NewRecorder(), httptest.NewRequest("GET", "/events", nil).WithContext(ctx))
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("late SSE handler retained closed app")
	}
}
