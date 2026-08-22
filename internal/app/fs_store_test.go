// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"path/filepath"
	"testing"
)

func TestCloseFileStoreStopsAndResetsSingleton(t *testing.T) {
	// Keep this global singleton isolated if another test failed after opening
	// it, and ensure this test never leaves its cleanup worker behind.
	if err := CloseFileStore(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = CloseFileStore() })

	connectString := "sqlite:" + filepath.Join(t.TempDir(), "files.db")
	if err := InitFileStore(connectString); err != nil {
		t.Fatal(err)
	}
	mu.RLock()
	openedDB := fsDB
	mu.RUnlock()
	if openedDB == nil {
		t.Fatal("file store database was not initialized")
	}

	if err := CloseFileStore(); err != nil {
		t.Fatal(err)
	}
	mu.RLock()
	defer mu.RUnlock()
	if fsDB != nil || fsCancel != nil || fsDone != nil {
		t.Fatal("file store singleton retained resources after close")
	}
	if err := openedDB.Ping(); err == nil {
		t.Fatal("file store database pool remained usable after close")
	}
}
