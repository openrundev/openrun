// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveExistingPath(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "missing"), filepath.Join(base, "dangling")); err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		filepath.Join(base, "real", "sub"):         filepath.Join(real, "sub"),
		filepath.Join(base, "link", "sub"):         filepath.Join(real, "sub"),
		filepath.Join(base, "link", "new", "leaf"): filepath.Join(real, "new", "leaf"),
		filepath.Join(base, "none", "leaf"):        filepath.Join(base, "none", "leaf"),
	}
	for in, want := range tests {
		got, err := ResolveExistingPath(in)
		if err != nil || got != want {
			t.Errorf("ResolveExistingPath(%s) = %s, %v; want %s", in, got, err, want)
		}
	}
	if got, err := ResolveExistingPath(filepath.Join(base, "dangling", "leaf")); err == nil {
		t.Errorf("expected an error for a dangling symlink, got %s", got)
	}
}
