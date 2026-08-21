// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingModule tracks instance creation and Close calls, with an optional
// init delay to widen race windows and an optional init failure.
type countingModule struct {
	initDelay time.Duration
	initErr   error
	inited    *atomic.Int64
	closed    *atomic.Int64
}

func (m *countingModule) InitModule(ctx context.Context, init ModuleInit) error {
	if m.inited != nil {
		m.inited.Add(1)
	}
	if m.initDelay > 0 {
		time.Sleep(m.initDelay)
	}
	return m.initErr
}

func (m *countingModule) Close(ctx context.Context) error {
	if m.closed != nil {
		m.closed.Add(1)
	}
	return nil
}

func (m *countingModule) Ping(ctx context.Context, call *Call) (any, error) {
	return "pong", nil
}

func (m *countingModule) NilCursor(ctx context.Context, call *Call) (any, error) {
	return (*Cursor)(nil), nil
}

func newCountingHost(t *testing.T, inited *atomic.Int64, closed *atomic.Int64, initErr error) *Host {
	t.Helper()
	host, err := NewHost(&ServeConfig{
		Modules: map[string]ModuleDef{
			"mod": {
				// NewHost's validateConfig builds one probe instance, so tests
				// count InitModule invocations, not builds
				Builder: func() Module {
					return &countingModule{initDelay: 10 * time.Millisecond, initErr: initErr, inited: inited, closed: closed}
				},
				Functions: []FuncDef{
					{Name: "ping", Type: READ, Method: "Ping"},
					{Name: "nil_cursor", Type: READ, Method: "NilCursor"},
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.InitApp(AppInfo{AppId: "test", AppPath: "/test"}); err != nil {
		t.Fatal(err)
	}
	return host
}

func TestHostTypedNilCursorIsNilValue(t *testing.T) {
	var inited, closed atomic.Int64
	host := newCountingHost(t, &inited, &closed, nil)
	if err := host.InitModule(context.Background(), "mod", "", nil); err != nil {
		t.Fatal(err)
	}

	result, err := host.Call(context.Background(), &HostCall{
		Module: "mod", Function: "nil_cursor", SessionId: "s1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Cursor != nil || result.Value != nil {
		t.Fatalf("typed nil cursor became %#v", result)
	}
	if err := host.EndSession(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
}

// Concurrent first calls for the same (module, account) must build exactly
// one instance: a second instance would overwrite the first without Close,
// leaking its resources.
func TestHostInitModuleConcurrent(t *testing.T) {
	var inited, closed atomic.Int64
	host := newCountingHost(t, &inited, &closed, nil)

	var wg sync.WaitGroup
	errs := make([]error, 16)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = host.InitModule(context.Background(), "mod", "", nil)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("init %d: %v", i, err)
		}
	}
	if inited.Load() != 1 {
		t.Fatalf("expected exactly 1 instance initialized, got %d", inited.Load())
	}
}

// A failed first init is not cached: waiters get the error, and a later call
// retries fresh.
func TestHostInitModuleFailureRetries(t *testing.T) {
	var inited, closed atomic.Int64
	initErr := errors.New("init failed")
	host := newCountingHost(t, &inited, &closed, initErr)

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = host.InitModule(context.Background(), "mod", "", nil)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if !errors.Is(err, initErr) {
			t.Fatalf("init %d: expected init error, got %v", i, err)
		}
	}

	// The failure was not cached: the next attempt builds a fresh instance
	if err := host.InitModule(context.Background(), "mod", "", nil); !errors.Is(err, initErr) {
		t.Fatalf("retry: expected init error, got %v", err)
	}
	if inited.Load() < 2 {
		t.Fatalf("expected a fresh init on retry, inited=%d", inited.Load())
	}
}

// A session registered at acquisition time (StartSession), before any call
// is made, pins a retiring host open: this closes the window where a reload
// between host acquisition and the first call could close the modules while
// the request is preparing its call.
func TestHostStartSessionPinsRetire(t *testing.T) {
	var inited, closed atomic.Int64
	host := newCountingHost(t, &inited, &closed, nil)
	if err := host.InitModule(context.Background(), "mod", "", nil); err != nil {
		t.Fatal(err)
	}

	host.StartSession("s1") // request acquired the host, no call made yet
	host.Retire()
	if closed.Load() != 0 {
		t.Fatal("retire closed modules while an acquired session was pending")
	}

	// The pending request's first call still works on the retired host
	if result, err := host.Call(context.Background(), &HostCall{
		Module: "mod", Function: "ping", SessionId: "s1",
	}); err != nil || result.Value != "pong" {
		t.Fatalf("call on retired host: %v, %v", result, err)
	}

	if err := host.EndSession(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	if closed.Load() != 1 {
		t.Fatalf("expected close after the pinned session ended, closed=%d", closed.Load())
	}
}

// Retire with no active sessions closes the modules immediately; with an
// active session, modules stay usable until the session ends.
func TestHostRetireDrainsSessions(t *testing.T) {
	var inited, closed atomic.Int64
	host := newCountingHost(t, &inited, &closed, nil)
	if err := host.InitModule(context.Background(), "mod", "", nil); err != nil {
		t.Fatal(err)
	}

	// Open a session by making a call
	result, err := host.Call(context.Background(), &HostCall{
		Module: "mod", Function: "ping", SessionId: "s1",
	})
	if err != nil || result.Value != "pong" {
		t.Fatalf("call: %v, %v", result, err)
	}

	host.Retire()
	if closed.Load() != 0 {
		t.Fatal("retire closed modules while a session was active")
	}

	// The retired host still serves the in-flight request's calls
	if result, err = host.Call(context.Background(), &HostCall{
		Module: "mod", Function: "ping", SessionId: "s1",
	}); err != nil || result.Value != "pong" {
		t.Fatalf("call on retired host: %v, %v", result, err)
	}

	if err := host.EndSession(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	if closed.Load() != 1 {
		t.Fatalf("expected modules closed after last session ended, closed=%d", closed.Load())
	}

	// Retire with no sessions closes immediately
	host2 := newCountingHost(t, &inited, &closed, nil)
	if err := host2.InitModule(context.Background(), "mod", "", nil); err != nil {
		t.Fatal(err)
	}
	before := closed.Load()
	host2.Retire()
	if closed.Load() != before+1 {
		t.Fatal("expected immediate close when no sessions are active")
	}
}
