// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestValidGitCommit(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		commit string
		valid  bool
	}{
		"full sha":    {commit: "0e23273f82701c7ecb4f9f6b4e2a4c6ea154c0ec", valid: true},
		"uppercase":   {commit: "0E23273F82701C7ECB4F9F6B4E2A4C6EA154C0EC", valid: true},
		"short sha":   {commit: "0e23273f", valid: false},
		"not hex":     {commit: "zz23273f82701c7ecb4f9f6b4e2a4c6ea154c0ec", valid: false},
		"placeholder": {commit: "invalid", valid: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := validGitCommit(tc.commit); got != tc.valid {
				t.Fatalf("validGitCommit(%q) = %t, want %t", tc.commit, got, tc.valid)
			}
		})
	}
}

func TestSharedRepoCacheEvictsOnlyReleasedEntries(t *testing.T) {
	t.Parallel()
	cache, err := newSharedRepoCache(1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cache.close)

	key1 := sharedRepoKey{url: "https://example.com/one", commit: "111"}
	dir1, err := cache.newCheckoutDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, leader := cache.acquireOrStart(key1); !leader {
		t.Fatal("first checkout was not elected leader")
	}
	cache.finish(key1, CacheDir{dir: dir1, hash: key1.commit}, false, nil)

	key2 := sharedRepoKey{url: "https://example.com/two", commit: "222"}
	dir2, err := cache.newCheckoutDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, leader := cache.acquireOrStart(key2); !leader {
		t.Fatal("second checkout was not elected leader")
	}
	cache.finish(key2, CacheDir{dir: dir2, hash: key2.commit}, false, nil)

	if _, err := os.Stat(dir1); err != nil {
		t.Fatalf("active checkout was evicted: %v", err)
	}
	cache.release(key1)
	if _, err := os.Stat(dir1); !os.IsNotExist(err) {
		t.Fatalf("released least-recent checkout still exists, stat err = %v", err)
	}
	if _, err := os.Stat(dir2); err != nil {
		t.Fatalf("new checkout was evicted: %v", err)
	}
	cache.release(key2)
}

func TestSharedRepoCacheBranchHeadExpiry(t *testing.T) {
	t.Parallel()
	cache, err := newSharedRepoCache(1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cache.close)

	key := sharedRepoBranchKey{url: "https://example.com/repo", branch: "main"}
	cache.putBranchHead(key, "abc")
	if hash, ok := cache.getBranchHead(key, time.Minute); !ok || hash != "abc" {
		t.Fatalf("fresh branch head = %q, %t; want abc, true", hash, ok)
	}
	if _, ok := cache.getBranchHead(key, -time.Second); ok {
		t.Fatal("disabled branch-head cache returned a value")
	}
}

func TestMaterializeGitCommitFolder(t *testing.T) {
	t.Parallel()
	sourceDir := t.TempDir()
	repo, err := git.PlainInit(sourceDir, false)
	if err != nil {
		t.Fatal(err)
	}
	appDir := filepath.Join(sourceDir, "apps", "one")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "app.star"), []byte("app = 1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "outside.txt"), []byte("outside\n"), 0644); err != nil {
		t.Fatal(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("apps/one/app.star"); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("outside.txt"); err != nil {
		t.Fatal(err)
	}
	hash, err := worktree.Commit("fixture", &git.CommitOptions{
		Author: &object.Signature{Name: "OpenRun Test", Email: "test@openrun.dev", When: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}

	targetDir := t.TempDir()
	message, gotHash, err := materializeGitCommit(sourceDir, targetDir, hash.String(), "apps/one/")
	if err != nil {
		t.Fatal(err)
	}
	if message != "fixture" || gotHash != hash.String() {
		t.Fatalf("materialized commit = %q, %q; want fixture, %q", message, gotHash, hash)
	}
	contents, err := os.ReadFile(filepath.Join(targetDir, "apps", "one", "app.star"))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "app = 1\n" {
		t.Fatalf("materialized contents = %q", contents)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "outside.txt")); !os.IsNotExist(err) {
		t.Fatalf("file outside requested folder was materialized, stat err = %v", err)
	}
}
