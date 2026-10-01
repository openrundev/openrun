// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

func TestGitOperationContextTimeout(t *testing.T) {
	tests := []struct {
		name         string
		configured   int
		want         time.Duration
		wantDeadline bool
	}{
		{name: "disabled", configured: 0, wantDeadline: false},
		{name: "configured", configured: 2, want: 2 * time.Second, wantDeadline: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := &Server{staticConfig: &types.ServerConfig{System: types.SystemConfig{
				GitOperationTimeoutSecs: tc.configured,
			}}}
			cache := &RepoCache{server: server}
			ctx, cancel := cache.gitOperationContext(context.Background())
			defer cancel()
			deadline, ok := ctx.Deadline()
			if ok != tc.wantDeadline {
				t.Fatalf("deadline present = %t, want %t", ok, tc.wantDeadline)
			}
			if !ok {
				return
			}
			remaining := time.Until(deadline)
			if remaining > tc.want || remaining < tc.want-time.Second {
				t.Fatalf("timeout = %s, want approximately %s", remaining, tc.want)
			}
		})
	}
}

func TestSharedGitCloneDetachesFromLeaderRequest(t *testing.T) {
	server := &Server{stopRequested: make(chan struct{})}
	cache := &RepoCache{server: server}
	parent, cancelParent := context.WithCancel(context.Background())

	sharedParent, cancelShared := cache.gitCloneOperationParent(parent, true)
	defer cancelShared()
	cancelParent()
	select {
	case <-sharedParent.Done():
		t.Fatal("shared clone inherited leader request cancellation")
	default:
	}
	requestParent, cancelRequest := cache.gitCloneOperationParent(parent, false)
	defer cancelRequest()
	select {
	case <-requestParent.Done():
	default:
		t.Fatal("non-shared clone did not inherit request cancellation")
	}

	server.RequestStop()
	select {
	case <-sharedParent.Done():
	case <-time.After(time.Second):
		t.Fatal("shared clone did not inherit server shutdown cancellation")
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
