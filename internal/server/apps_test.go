// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func testStoreApp(path string) *app.App {
	return &app.App{
		Logger:   testutil.TestLogger(),
		AppEntry: &types.AppEntry{Path: path, Domain: "example.com"},
	}
}

// AddAppIfUnchanged must reject an insert when apps were removed from the
// store after the generation was read: the App may have been built from a DB
// read that the concurrent clear (e.g. a committed reload) made stale.
func TestAppStoreAddAppIfUnchanged(t *testing.T) {
	store := NewAppStore(testutil.TestLogger(), &Server{Logger: testutil.TestLogger()})

	gen := store.Generation()
	if _, ok := store.AddAppIfUnchanged(testStoreApp("/app1"), gen); !ok {
		t.Fatal("insert with current generation rejected")
	}
	// Adding apps does not invalidate concurrent loads of other apps
	if _, ok := store.AddAppIfUnchanged(testStoreApp("/app2"), gen); !ok {
		t.Fatal("insert rejected although no apps were removed")
	}

	gen = store.Generation()
	store.ClearAppsNoNotify([]types.AppPathDomain{{Domain: "example.com", Path: "/app1"}})
	if store.Generation() == gen {
		t.Fatal("clearing an app did not bump the store generation")
	}
	if _, ok := store.AddAppIfUnchanged(testStoreApp("/app3"), gen); ok {
		t.Fatal("insert with stale generation accepted")
	}
	if _, err := store.GetApp(types.CreateAppPathDomain("/app3", "example.com")); err == nil {
		t.Fatal("rejected app was added to the store")
	}

	// Clearing a path that is not cached must still bump the generation: the
	// concurrent GetApp may be building exactly that app.
	gen = store.Generation()
	store.ClearAppsNoNotify([]types.AppPathDomain{{Domain: "example.com", Path: "/not-cached"}})
	if store.Generation() == gen {
		t.Fatal("clearing an uncached path did not bump the store generation")
	}
}

// A close request from a retired instance (replaced while an action run kept
// it alive) must not evict the replacement cached under the same path
func TestClearAppIfCurrentIgnoresRetiredInstance(t *testing.T) {
	server, _, _ := newAppAPIMetadataTestServer(t)
	store := server.apps
	pathDomain := types.CreateAppPathDomain("/app1", "example.com")
	retired, replacement := testStoreApp("/app1"), testStoreApp("/app1")

	if _, ok := store.AddAppIfUnchanged(replacement, store.Generation()); !ok {
		t.Fatal("adding the replacement failed")
	}
	if store.ClearAppIfCurrent(retired) {
		t.Fatal("a retired instance's close request cleared the app")
	}
	if cached, _ := store.GetApp(pathDomain); cached != replacement {
		t.Fatalf("store holds %p, want the replacement %p", cached, replacement)
	}

	if !store.ClearAppIfCurrent(replacement) {
		t.Fatal("the cached instance's close request did not clear the app")
	}
	if cached, _ := store.GetApp(pathDomain); cached != nil {
		t.Fatalf("store still holds %p after the close", cached)
	}
	// Nothing cached: a late duplicate request is ignored
	if store.ClearAppIfCurrent(replacement) {
		t.Fatal("a close request for an uncached instance reported a clear")
	}
}
