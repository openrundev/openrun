// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package appfs

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
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

func TestDiskFSCloseReleasesCachedRoot(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "file.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	readFS := NewDiskReadFS(testutil.TestLogger(), rootDir, nil)

	// Close with no cached root is a no-op
	if err := readFS.Close(); err != nil {
		t.Fatalf("Close on unopened FS returned error: %v", err)
	}

	if _, err := readFS.ReadFile("file.txt"); err != nil {
		t.Fatal(err)
	}
	if readFS.openRoot == nil {
		t.Fatal("root was not cached after read")
	}

	if err := readFS.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if readFS.openRoot != nil {
		t.Fatal("cached root was not released by Close")
	}

	// FS stays usable, a later operation reopens the root
	if _, err := readFS.ReadFile("file.txt"); err != nil {
		t.Fatalf("ReadFile after Close returned error: %v", err)
	}
	if err := readFS.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
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

func TestDiskFSCleanNameRejectsAbsoluteAndTraversalPaths(t *testing.T) {
	readFS := NewDiskReadFS(testutil.TestLogger(), t.TempDir(), nil)

	for _, name := range []string{
		"/secret.txt",
		"../secret.txt",
		`..\secret.txt`,
		`C:\secret.txt`,
	} {
		if _, _, err := readFS.cleanName(name); err == nil {
			t.Fatalf("cleanName(%q) should reject invalid path", name)
		}
	}
}

func TestDiskFSGlobIncludesSpecFiles(t *testing.T) {
	rootDir := t.TempDir()
	for _, name := range []string{"b.go.html", "other.txt"} {
		if err := os.WriteFile(filepath.Join(rootDir, name), []byte("disk"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	specFiles := types.SpecFiles{
		"a.go.html": "spec",
		"b.go.html": "spec", // also on disk, the disk file wins
		"c.go.html": "spec",
		"c.txt":     "spec",
	}
	readFS := NewDiskReadFS(testutil.TestLogger(), rootDir, specFiles)

	matches, err := readFS.Glob("*.go.html")
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"a.go.html", "b.go.html", "c.go.html"}
	if !slices.Equal(matches, expected) {
		t.Fatalf("expected %v, got %v", expected, matches)
	}

	// Disk content wins for files present in both
	data, err := readFS.ReadFile("b.go.html")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "disk" {
		t.Fatalf("expected disk content for b.go.html, got %s", data)
	}

	// No spec match leaves the disk results unchanged
	matches, err = readFS.Glob("other.*")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(matches, []string{"other.txt"}) {
		t.Fatalf("expected [other.txt], got %v", matches)
	}
}
