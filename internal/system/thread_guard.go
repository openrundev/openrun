// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"fmt"
	"math"
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"

	"go.starlark.net/starlark"
)

// The Starlark thread guard: a periodic check installed on the threads which
// run app code (handlers, actions, jobs, the app load) through the
// interpreter's step limit callback, every guardStepInterval instructions.
// It cancels the thread when
//   - the call depth exceeds MaxStarlarkCallDepth. The interpreter's own
//     guard allows 100 000 frames, about 460MB of goroutine stack per
//     request: a recursion driven by a request value must fail well below
//   - the Go runtime's memory in use is over the memory high water mark
//     (see MemoryHighWater). The interpreter has no allocation accounting:
//     this bounds app code which grows memory gradually (a loop appending
//     to a list) before the process is killed, at the cost of the handler
//     running when the mark is reached
//
// Builtins and template rendering run between checks (a request cancel
// cannot reach inside them either), so the guard bounds interpreted code,
// and the caps on the builtins and the template functions bound the rest
const (
	guardStepInterval    = 10_000
	MaxStarlarkCallDepth = 10_000
	// memoryReadInterval bounds the runtime metrics reads: one reading is
	// shared by all threads for this long
	memoryReadInterval = 10 * time.Millisecond
)

// memoryHighWater is the configured mark, 0 derives it from the Go memory limit
var memoryHighWater atomic.Int64

// SetMemoryHighWater sets the memory high water mark from the config, see
// MemoryHighWater
func SetMemoryHighWater(bytes int64) {
	memoryHighWater.Store(bytes)
}

// MemoryHighWater returns the memory in use (as the Go memory limit counts
// it) over which running Starlark threads are canceled: the configured
// system.memory_high_water_bytes, else 90% of the Go memory limit (GOMEMLIMIT
// or debug.SetMemoryLimit) when one is set, else 0 (no check)
func MemoryHighWater() int64 {
	if mark := memoryHighWater.Load(); mark > 0 {
		return mark
	}
	limit := debug.SetMemoryLimit(-1)
	if limit <= 0 || limit == math.MaxInt64 {
		return 0
	}
	return limit / 10 * 9
}

var (
	memoryReadMu   sync.Mutex
	memoryReadAt   time.Time
	memoryReadLast int64
	memoryMarkLast int64
	memorySamples  = []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
)

// MemoryInUse returns the Go runtime's memory in use, as the memory limit
// counts it (all memory mapped by the runtime, less what is released to the
// OS), read at most every memoryReadInterval
func MemoryInUse() int64 {
	inUse, _ := memoryReading()
	return inUse
}

// memoryReading returns the memory in use and the high water mark, both
// re-read at most every memoryReadInterval: the mark's derivation from the
// Go memory limit takes the runtime's heap lock, and the metrics read is
// not free either, while the checks run every few thousand instructions
// on every thread
func memoryReading() (inUse, mark int64) {
	memoryReadMu.Lock()
	defer memoryReadMu.Unlock()
	now := time.Now()
	if now.Sub(memoryReadAt) < memoryReadInterval {
		return memoryReadLast, memoryMarkLast
	}
	memoryMarkLast = MemoryHighWater()
	if memoryMarkLast > 0 {
		metrics.Read(memorySamples)
		var total, released uint64
		if memorySamples[0].Value.Kind() == metrics.KindUint64 {
			total = memorySamples[0].Value.Uint64()
		}
		if memorySamples[1].Value.Kind() == metrics.KindUint64 {
			released = memorySamples[1].Value.Uint64()
		}
		memoryReadLast = int64(total - released)
	}
	memoryReadAt = now
	return memoryReadLast, memoryMarkLast
}

// GuardStarlarkThread installs the periodic check on a thread about to run
// app code. It must be called before the thread runs
func GuardStarlarkThread(thread *starlark.Thread) {
	thread.OnMaxSteps = guardCheck
	thread.SetMaxExecutionSteps(thread.ExecutionSteps() + guardStepInterval)
}

// guardCheck is the step limit callback: it runs the checks and arms the
// next check
func guardCheck(thread *starlark.Thread) {
	thread.SetMaxExecutionSteps(thread.ExecutionSteps() + guardStepInterval)
	if depth := thread.CallStackDepth(); depth > MaxStarlarkCallDepth {
		thread.Cancel(fmt.Sprintf("call depth %d exceeds the limit of %d", depth, MaxStarlarkCallDepth))
		return
	}
	if inUse, mark := memoryReading(); mark > 0 && inUse > mark {
		thread.Cancel(fmt.Sprintf("server memory in use (%d bytes) is over the high water mark (%d bytes)", inUse, mark))
	}
}
