// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"strings"
	"testing"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

func runGuarded(t *testing.T, src string) error {
	t.Helper()
	thread := &starlark.Thread{Name: "guard"}
	GuardStarlarkThread(thread)
	_, err := starlark.ExecFileOptions(&syntax.FileOptions{While: true, Recursion: true}, thread, "guard.star", src, nil)
	return err
}

func TestThreadGuardCallDepth(t *testing.T) {
	err := runGuarded(t, "def f(n):\n\treturn f(n + 1)\nf(0)\n")
	if err == nil || !strings.Contains(err.Error(), "call depth") {
		t.Fatalf("expected the call depth cancel, got %v", err)
	}
	// Depth within the limit runs
	if err := runGuarded(t, "def f(n):\n\tif n == 0:\n\t\treturn 0\n\treturn f(n - 1)\nf(5000)\n"); err != nil {
		t.Fatalf("recursion within the limit failed: %v", err)
	}
}

func TestThreadGuardMemoryHighWater(t *testing.T) {
	SetMemoryHighWater(1) // any memory in use is over the mark
	t.Cleanup(func() { SetMemoryHighWater(0); resetMemoryReading() })
	resetMemoryReading()
	err := runGuarded(t, "def f():\n\tx = 0\n\twhile True:\n\t\tx += 1\nf()\n")
	if err == nil || !strings.Contains(err.Error(), "high water mark") {
		t.Fatalf("expected the memory cancel, got %v", err)
	}

	// No mark, the loop runs to its end
	SetMemoryHighWater(0)
	resetMemoryReading()
	if MemoryHighWater() != 0 {
		t.Skip("a Go memory limit is set in this environment")
	}
	if err := runGuarded(t, "def f():\n\tx = 0\n\tfor i in range(30000):\n\t\tx += 1\nf()\n"); err != nil {
		t.Fatalf("loop under no mark failed: %v", err)
	}
}

func TestMemoryInUseCached(t *testing.T) {
	SetMemoryHighWater(1) // the reading is taken only under a mark
	t.Cleanup(func() { SetMemoryHighWater(0); resetMemoryReading() })
	resetMemoryReading()
	first := MemoryInUse()
	if first <= 0 {
		t.Fatalf("memory in use %d", first)
	}
	if again := MemoryInUse(); again != first {
		t.Fatalf("reading within the interval changed: %d then %d", first, again)
	}
}

func resetMemoryReading() {
	memoryReadMu.Lock()
	defer memoryReadMu.Unlock()
	memoryReadAt = time.Time{}
	memoryReadLast = 0
	memoryMarkLast = 0
}
