// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirSizeMissingRootIgnoreError(t *testing.T) {
	// WalkDir invokes the callback with a nil DirEntry when the root cannot
	// be statted; with ignoreError this used to nil-panic (issue seen when a
	// dir was deleted between the listing and the recursive size walk)
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	size, err := dirSize(context.Background(), missing, 4096, true)
	if err != nil {
		t.Errorf("dirSize with ignoreError: unexpected error %v", err)
	}
	if size != 0 {
		t.Errorf("dirSize with ignoreError: expected size 0, got %d", size)
	}

	if _, err = dirSize(context.Background(), missing, 4096, false); err == nil {
		t.Error("dirSize without ignoreError: expected error for missing root")
	}
}

func TestMatchFilesMissingRootIgnoreError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	files, err := matchFiles(context.Background(), missing, "*", 10, 0, true)
	if err != nil {
		t.Errorf("matchFiles with ignoreError: unexpected error %v", err)
	}
	if len(files) != 0 {
		t.Errorf("matchFiles with ignoreError: expected no files, got %d", len(files))
	}

	if _, err = matchFiles(context.Background(), missing, "*", 10, 0, false); err == nil {
		t.Error("matchFiles without ignoreError: expected error for missing root")
	}
}

func TestRecoverToError(t *testing.T) {
	err := recoverToError(nil, "test goroutine", func() error {
		panic("boom")
	})()
	if err == nil || !strings.Contains(err.Error(), "panic in test goroutine") {
		t.Errorf("expected panic converted to error, got %v", err)
	}

	if err := recoverToError(nil, "test goroutine", func() error { return nil }); err() != nil {
		t.Error("expected nil error when no panic")
	}

	wantErr := fmt.Errorf("plain error")
	if err := recoverToError(nil, "test goroutine", func() error { return wantErr })(); err != wantErr {
		t.Errorf("expected error passthrough, got %v", err)
	}
}
