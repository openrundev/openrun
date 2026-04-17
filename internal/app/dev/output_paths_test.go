// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureSourceOutputDirRejectsSymlinkEscape(t *testing.T) {
	baseDir := t.TempDir()
	sourceRoot := filepath.Join(baseDir, "source")
	outsideRoot := filepath.Join(baseDir, "outside")
	if err := os.MkdirAll(sourceRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideRoot, 0700); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(outsideRoot, filepath.Join(sourceRoot, "static")); err != nil {
		t.Skipf("symlink not available: %v", err)
	}

	if _, err := ensureSourceOutputDir(sourceRoot, STYLE_FILE_PATH, 0700); err == nil {
		t.Fatal("ensureSourceOutputDir should reject output directory symlink escapes")
	}

	if _, err := os.Stat(filepath.Join(outsideRoot, "gen")); err == nil {
		t.Fatal("ensureSourceOutputDir created directories outside the source root")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
