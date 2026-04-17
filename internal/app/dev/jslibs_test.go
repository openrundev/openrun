// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestSetupEsbuildWritesOutputThroughSourceFSRelativePath(t *testing.T) {
	logger := testutil.TestLogger()
	sourceDir := t.TempDir()
	workDir := t.TempDir()

	moduleDir := filepath.Join(workDir, "node_modules", "mylib")
	if err := os.MkdirAll(moduleDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "index.js"), []byte(`export const value = "ok";`), 0600); err != nil {
		t.Fatal(err)
	}

	sourceDiskFS := &appfs.DiskWriteFS{DiskReadFS: appfs.NewDiskReadFS(logger, sourceDir, nil)}
	sourceFS, err := appfs.NewSourceFs(sourceDir, sourceDiskFS, true)
	if err != nil {
		t.Fatal(err)
	}
	writableSourceFS := &appfs.WritableSourceFs{SourceFs: sourceFS}
	workFS := appfs.NewWorkFs(workDir, &appfs.DiskWriteFS{DiskReadFS: appfs.NewDiskReadFS(logger, workDir, nil)})
	appDev := NewAppDev(logger, writableSourceFS, workFS, &AppStyle{}, &types.SystemConfig{})

	lib := NewLibraryESM("mylib", "1.0.0", nil)
	target, err := (&JsLibManager{JSLibrary: *lib}).Setup(appDev, writableSourceFS, workFS)
	if err != nil {
		t.Fatal(err)
	}

	wantTarget := path.Join(types.ESM_PATH, "mylib-1.0.0.js")
	if target != wantTarget {
		t.Fatalf("target = %q, want %q", target, wantTarget)
	}

	got, err := os.ReadFile(filepath.Join(sourceDir, filepath.FromSlash(wantTarget)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `value = "ok"`) {
		t.Fatalf("bundled output missing module contents: %s", got)
	}
}

func TestCleanSourceRelativeOutputHandlesResolvedSymlinkRoot(t *testing.T) {
	baseDir := t.TempDir()
	realRoot := filepath.Join(baseDir, "real")
	linkRoot := filepath.Join(baseDir, "link")
	if err := os.MkdirAll(realRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlink not available: %v", err)
	}

	outputPath := filepath.Join(realRoot, "static", "gen", "esm", "bundle.js")
	got, err := cleanSourceRelativeOutput(linkRoot, outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := path.Join(types.ESM_PATH, "bundle.js"); got != want {
		t.Fatalf("relative output = %q, want %q", got, want)
	}
}

func TestGenerateSourceFileQuotesAndValidatesPackageName(t *testing.T) {
	logger := testutil.TestLogger()
	workDir := t.TempDir()
	workFS := appfs.NewWorkFs(workDir, &appfs.DiskWriteFS{DiskReadFS: appfs.NewDiskReadFS(logger, workDir, nil)})

	lib := NewLibraryESM("@scope/pkg/subpath", "1.0.0", nil)
	sourceFile, err := (&JsLibManager{JSLibrary: *lib}).generateSourceFile(workFS)
	if err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(sourceFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := `export * from "@scope/pkg/subpath"`; string(got) != want {
		t.Fatalf("source = %q, want %q", got, want)
	}

	unsafeLib := NewLibraryESM(`bad"; console.log("x")`, "1.0.0", nil)
	if _, err := (&JsLibManager{JSLibrary: *unsafeLib}).generateSourceFile(workFS); err == nil {
		t.Fatal("generateSourceFile should reject unsafe package names")
	}
}
