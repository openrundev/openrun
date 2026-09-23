// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"sync"
	"testing"
)

func TestRunRegistryReserveIsAtomic(t *testing.T) {
	var r RunRegistry
	admitted := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	releases := []func(){}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, ok := r.Reserve("app1", 3)
			if ok {
				mu.Lock()
				admitted++
				releases = append(releases, release)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 3 {
		t.Fatalf("admitted %d runs with a limit of 3", admitted)
	}
	if r.CountGroup("app1") != 3 {
		t.Fatalf("count %d", r.CountGroup("app1"))
	}
	// A registered run keeps its slot once its reservation is released
	r.Add("run1", "app1", func() {})
	releases[0]()
	releases[0]() // idempotent
	if r.CountGroup("app1") != 3 {
		t.Fatalf("count after add %d", r.CountGroup("app1"))
	}
	if _, ok := r.Reserve("app1", 3); ok {
		t.Fatal("admitted over the limit")
	}
	releases[1]()
	releases[2]()
	r.Remove("run1")
	if r.CountGroup("app1") != 0 {
		t.Fatalf("count after release %d", r.CountGroup("app1"))
	}
	if _, ok := r.Reserve("other", 1); !ok {
		t.Fatal("other group refused")
	}
}

func TestRunRegistryCanceledBy(t *testing.T) {
	var r RunRegistry
	ctx, cancel := context.WithCancel(context.Background())
	r.Add("run1", "app1", cancel)
	if r.CanceledBy("run1") != "" {
		t.Fatal("canceled before a cancel")
	}
	if !r.Cancel("run1", "alice") {
		t.Fatal("cancel of a registered run failed")
	}
	if ctx.Err() == nil {
		t.Fatal("cancel did not cancel the context")
	}
	r.Cancel("run1", "bob") // the first requester is kept
	if by := r.CanceledBy("run1"); by != "alice" {
		t.Fatalf("canceled by %q", by)
	}
	r.Add("run2", "app1", func() {})
	r.Stop()
	if by := r.CanceledBy("run2"); by != "server shutdown" {
		t.Fatalf("canceled by %q after stop", by)
	}
}
