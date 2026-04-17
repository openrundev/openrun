// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package appfs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestDiskFSRejectsSymlinkEscape(t *testing.T) {
	baseDir := t.TempDir()
	rootDir := filepath.Join(baseDir, "root")
	outsideDir := filepath.Join(baseDir, "outside")
	if err := os.MkdirAll(rootDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0700); err != nil {
		t.Fatal(err)
	}

	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(rootDir, "escape")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("symlink not available: %v", err)
	}

	logger := testutil.TestLogger()
	readFS := NewDiskReadFS(logger, rootDir, nil)
	writeFS := &DiskWriteFS{DiskReadFS: readFS}
	escapedName := filepath.ToSlash(filepath.Join("escape", "secret.txt"))

	if _, err := readFS.ReadFile(escapedName); err == nil {
		t.Fatalf("ReadFile(%q) should reject symlink escape", escapedName)
	}
	if f, err := readFS.Open(escapedName); err == nil {
		_ = f.Close()
		t.Fatalf("Open(%q) should reject symlink escape", escapedName)
	}
	if _, err := readFS.Stat(escapedName); err == nil {
		t.Fatalf("Stat(%q) should reject symlink escape", escapedName)
	}
	if err := writeFS.Write(escapedName, []byte("changed")); err == nil {
		t.Fatalf("Write(%q) should reject symlink escape", escapedName)
	}
	if err := writeFS.Remove(escapedName); err == nil {
		t.Fatalf("Remove(%q) should reject symlink escape", escapedName)
	}

	got, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("outside file was modified: got %q", got)
	}
}

func TestDiskFSGlobRejectsTraversalPattern(t *testing.T) {
	rootDir := t.TempDir()
	logger := testutil.TestLogger()
	readFS := NewDiskReadFS(logger, rootDir, nil)

	if _, err := readFS.Glob("../*.txt"); err == nil {
		t.Fatal("Glob should reject traversal patterns")
	}
}
