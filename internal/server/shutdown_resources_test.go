// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/app"
	app_test "github.com/openrundev/openrun/internal/app/tests"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func TestListAppsRetirementWaitsForRequest(t *testing.T) {
	s := newBenchServer("")
	a, _, err := app_test.CreateTestApp(s.Logger, map[string]string{"app.star": `
app = ace.app("listing", routes=[ace.api("/")])
def handler(req):
    return {"ok": True}
`})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	s.listAppsApp = a
	// Hold the same request lease used by the listing route.
	s.listAppsMu.RLock()
	retired := make(chan struct{})
	go func() { s.closeListAppsApp(); close(retired) }()
	response := httptest.NewRecorder()
	a.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/test", nil))
	s.listAppsMu.RUnlock()
	if response.Code != http.StatusOK {
		t.Fatalf("in-flight listing failed: %d %s", response.Code, response.Body.String())
	}
	select {
	case <-retired:
	case <-time.After(5 * time.Second):
		t.Fatal("listing was not retired after request completion")
	}
	if s.listAppsApp != nil {
		t.Fatal("retired listing remained cached")
	}
	if _, err := a.Reload(context.Background(), true, true, types.DryRunFalse, app.ReloadOptions{}); err == nil {
		t.Fatal("retired listing was not closed")
	}
}

func TestShutdownClosesActiveRequestsOnTimeout(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		defer close(stopped)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		response, err := server.Client().Get(server.URL)
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := shutdownHTTPServer(ctx, server.Config); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown error = %v, want cancellation", err)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("active request was not canceled")
	}
	select {
	case <-clientDone:
	case <-time.After(5 * time.Second):
		t.Fatal("client connection was not closed")
	}
}

func TestStopAuditWriterCancelsAndJoinsCleanup(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	db.SetMaxOpenConns(1)
	held, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close() //nolint:errcheck
	server := newBenchServer("")
	server.staticConfig.System.HttpEventRetentionDays = 1
	server.auditDB, server.auditDbType = db, system.DB_TYPE_SQLITE
	server.auditEvents = make(chan *types.AuditEvent)
	server.auditStop, server.auditDone = make(chan struct{}), make(chan struct{})
	cleanupDone := make(chan struct{})
	var cleanupCtx context.Context
	server.auditCleanup = system.StartBackgroundTask(context.Background(), func(ctx context.Context) {
		defer close(cleanupDone)
		cleanupCtx = ctx
		server.auditCleanupPass(ctx)
	})
	go server.auditWriterLoop()
	defer func() {
		// Also unblock an implementation that accidentally drops ctx.
		_ = held.Close()
		server.stopAuditWriter()
	}()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for db.Stats().WaitCount == 0 {
		select {
		case <-deadline:
			t.Fatal("cleanup did not wait for a connection")
		case <-ticker.C:
		}
	}
	stopped := make(chan struct{})
	go func() { server.stopAuditWriter(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("audit shutdown did not cancel pending SQL")
	}
	select {
	case <-cleanupDone:
	default:
		t.Fatal("audit shutdown returned before cleanup exited")
	}
	if cleanupCtx.Err() == nil {
		t.Fatal("audit cleanup context was not canceled")
	}
}
