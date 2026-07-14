// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadWorkspaceFileJail verifies the workspace read boundary: the agent
// controls workspace content, so symlinks it creates must not expose host
// files through the console file viewer
func TestReadWorkspaceFileJail(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()

	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, name string) {
		t.Helper()
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}

	write(filepath.Join(workspace, "app.star"), "ok")
	write(filepath.Join(workspace, "sub", "inner.txt"), "inner")
	write(filepath.Join(outside, "secret.txt"), "host secret")
	link(filepath.Join(outside, "secret.txt"), filepath.Join(workspace, "leak.txt"))
	link(outside, filepath.Join(workspace, "leakdir"))
	link(filepath.Join(workspace, "app.star"), filepath.Join(workspace, "selflink.star"))

	if content, err := readWorkspaceFile(workspace, "app.star"); err != nil || content != "ok" {
		t.Errorf("plain file read failed: %q %v", content, err)
	}
	if content, err := readWorkspaceFile(workspace, "sub/inner.txt"); err != nil || content != "inner" {
		t.Errorf("nested file read failed: %q %v", content, err)
	}
	// A symlink that resolves inside the workspace is harmless
	if content, err := readWorkspaceFile(workspace, "selflink.star"); err != nil || content != "ok" {
		t.Errorf("in-workspace symlink read failed: %q %v", content, err)
	}

	if content, err := readWorkspaceFile(workspace, "leak.txt"); err == nil {
		t.Errorf("symlink to a host file was readable: %q", content)
	}
	if content, err := readWorkspaceFile(workspace, "leakdir/secret.txt"); err == nil {
		t.Errorf("path through a symlinked directory was readable: %q", content)
	}
	if _, err := readWorkspaceFile(workspace, "../secret.txt"); err == nil {
		t.Error("dot-dot path escaped the workspace")
	}
	if _, err := readWorkspaceFile(workspace, "sub"); err == nil {
		t.Error("directory read should be rejected")
	}
}
