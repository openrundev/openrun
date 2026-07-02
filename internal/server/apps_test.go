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
	if !store.AddAppIfUnchanged(testStoreApp("/app1"), gen) {
		t.Fatal("insert with current generation rejected")
	}
	// Adding apps does not invalidate concurrent loads of other apps
	if !store.AddAppIfUnchanged(testStoreApp("/app2"), gen) {
		t.Fatal("insert rejected although no apps were removed")
	}

	gen = store.Generation()
	store.ClearAppsNoNotify([]types.AppPathDomain{{Domain: "example.com", Path: "/app1"}})
	if store.Generation() == gen {
		t.Fatal("clearing an app did not bump the store generation")
	}
	if store.AddAppIfUnchanged(testStoreApp("/app3"), gen) {
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
