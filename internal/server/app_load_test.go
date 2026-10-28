// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// Concurrent requests to an app which is not in the store (after an idle
// stop, a deploy or a restart) share one load: a single App instance is
// built, cached and returned to every caller
func TestGetAppConcurrentColdStartSharesOneLoad(t *testing.T) {
	server, _, _ := newMCPAppTestServer(t)
	createActionsTestApp(t, server, "/apps/one", "builtin", "")
	pathDomain := types.CreateAppPathDomain("/apps/one", "")
	server.apps.ClearAppsNoNotify([]types.AppPathDomain{pathDomain})

	var loads atomic.Int32
	server.appLoadHook = func(types.AppPathDomain) {
		loads.Add(1)
		time.Sleep(200 * time.Millisecond) // let the other callers pile up on the load
	}

	const callers = 16
	results := make([]*app.App, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = server.GetApp(system.WithTrustedOperation(t.Context()), pathDomain, false)
		}()
	}
	wg.Wait()

	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if results[i] != results[0] {
			t.Fatalf("caller %d got a different App instance than caller 0", i)
		}
	}
	if got := loads.Load(); got != 1 {
		t.Fatalf("expected one load, got %d", got)
	}
	cached, err := server.apps.GetApp(pathDomain)
	if err != nil || cached != results[0] {
		t.Fatalf("store holds %p (err %v), callers got %p", cached, err, results[0])
	}

	// The next cold load is a new load, the singleflight key is released
	server.apps.ClearAppsNoNotify([]types.AppPathDomain{pathDomain})
	if _, err := server.GetApp(system.WithTrustedOperation(t.Context()), pathDomain, false); err != nil {
		t.Fatalf("second load: %v", err)
	}
	if got := loads.Load(); got != 2 {
		t.Fatalf("expected two loads, got %d", got)
	}
}

// AddAppIfUnchanged keeps the instance already cached for the path, so a
// second build of the same app is discarded by its caller
func TestAddAppIfUnchangedKeepsExistingInstance(t *testing.T) {
	store := NewAppStore(testutil.TestLogger(), &Server{Logger: testutil.TestLogger()})
	pathDomain := types.CreateAppPathDomain("/app1", "example.com")
	first, second := testStoreApp("/app1"), testStoreApp("/app1")

	generation := store.Generation()
	if cached, ok := store.AddAppIfUnchanged(first, generation); !ok || cached != first {
		t.Fatalf("first add: ok %v cached %p want %p", ok, cached, first)
	}
	if cached, ok := store.AddAppIfUnchanged(second, generation); !ok || cached != first {
		t.Fatalf("second add: ok %v cached %p want the first instance %p", ok, cached, first)
	}
	if cached, _ := store.GetApp(pathDomain); cached != first {
		t.Fatalf("store holds %p, want %p", cached, first)
	}

	// A store change since the generation read rejects the add
	store.ClearAppsNoNotify([]types.AppPathDomain{pathDomain})
	if cached, ok := store.AddAppIfUnchanged(second, generation); ok || cached != nil {
		t.Fatalf("stale add: ok %v cached %p, want rejected", ok, cached)
	}
}
