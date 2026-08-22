// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

// A coded error response from an external plugin must carry the thread, so
// an explicit error check by the app clears the thread-local failure state
// and later plugin calls are not blocked.
func TestErrorCodeResponseClearsThreadState(t *testing.T) {
	thread := &starlark.Thread{}
	err := errors.New("rate limited")
	thread.SetLocal(types.TL_PLUGIN_API_FAILED_ERROR, err)

	resp := NewErrorCodeResponseThread(429, err, nil, thread)
	resp.Truth() // the app checking `if not ret` clears the failure state
	if got := thread.Local(types.TL_PLUGIN_API_FAILED_ERROR); got != nil {
		t.Errorf("thread failure state not cleared: %v", got)
	}

	// Without the thread (the bug this guards against), the state stays set
	thread.SetLocal(types.TL_PLUGIN_API_FAILED_ERROR, err)
	NewErrorCodeResponse(429, err, nil).Truth()
	if got := thread.Local(types.TL_PLUGIN_API_FAILED_ERROR); got == nil {
		t.Error("expected thread failure state to remain without a thread")
	}
}

// After shutdown (app close), the process manager must refuse to launch new
// provider processes: a request racing App.Close must not leave a provider
// process running.
func TestExtProcsShutdownBlocksRelaunch(t *testing.T) {
	a := &App{extProcs: newExtPluginProcs()}
	a.AppEntry = &types.AppEntry{Path: "/testapp"}
	a.extProcs.shutdown()

	if _, err := a.getExtProc(context.Background(), "someprovider"); err == nil ||
		!strings.Contains(err.Error(), "closed") {
		t.Errorf("expected closed error, got %v", err)
	}

	// stopAll (reload) must keep the manager usable; the error here is the
	// unregistered provider, not a closed manager
	b := &App{extProcs: newExtPluginProcs()}
	b.AppEntry = &types.AppEntry{Path: "/testapp"}
	b.extProcs.stopAll()
	if _, err := b.getExtProc(context.Background(), "someprovider"); err == nil ||
		!strings.Contains(err.Error(), "not registered") {
		t.Errorf("expected not-registered error after stopAll, got %v", err)
	}
}

func deferEntries(thread *starlark.Thread, modulePath string) map[string]apptype.DeferEntry {
	deferMap, _ := thread.Local(types.TL_DEFER_MAP).(map[string]map[string]apptype.DeferEntry)
	if deferMap == nil {
		return nil
	}
	return deferMap[modulePath]
}

// The provider session's strict deferred-cleanup keys are mirrored as strict
// host-side cleanup entries after every call, and removed when the provider
// clears them (e.g. after a commit).
func TestSyncExtStrictDefers(t *testing.T) {
	thread := &starlark.Thread{}

	syncExtStrictDefers(thread, "prov", "mymod.ex", []string{"tx_1"})
	entries := deferEntries(thread, "mymod.ex")
	if entry, ok := entries["tx_1"]; !ok || !entry.Strict {
		t.Fatalf("expected strict mirrored entry tx_1, got %#v", entries)
	}

	// A second call reporting the same key must not duplicate anything
	syncExtStrictDefers(thread, "prov", "mymod.ex", []string{"tx_1", "cursor_2"})
	entries = deferEntries(thread, "mymod.ex")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %#v", entries)
	}

	// Cleared provider-side (e.g. commit): the mirrored entry is removed,
	// under the module that registered it
	syncExtStrictDefers(thread, "prov", "othermod.ex", []string{"cursor_2"})
	entries = deferEntries(thread, "mymod.ex")
	if _, ok := entries["tx_1"]; ok {
		t.Errorf("expected tx_1 to be cleared, got %#v", entries)
	}
	if _, ok := entries["cursor_2"]; !ok {
		t.Errorf("expected cursor_2 to remain under mymod.ex, got %#v", entries)
	}

	syncExtStrictDefers(thread, "prov", "othermod.ex", nil)
	if entries := deferEntries(thread, "mymod.ex"); len(entries) != 0 {
		t.Errorf("expected all mirrored entries cleared, got %#v", entries)
	}
}
