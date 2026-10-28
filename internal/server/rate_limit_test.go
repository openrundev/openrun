// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/crypto/bcrypt"
)

func TestIPRateLimiterWindow(t *testing.T) {
	limiter := newIPRateLimiter(time.Minute, 2)
	now := time.Now()
	for i := range 3 {
		if !limiter.allowAt("a", 3, now) {
			t.Fatalf("hit %d of a refused", i)
		}
	}
	if limiter.allowAt("a", 3, now.Add(30*time.Second)) {
		t.Fatal("fourth hit within the window allowed")
	}
	if !limiter.allowAt("b", 3, now) {
		t.Fatal("another IP refused")
	}
	if !limiter.allowAt("a", 3, now.Add(61*time.Second)) {
		t.Fatal("hit after the window refused")
	}
	// A limit of 0 disables the limiter
	for range 10 {
		if !limiter.allowAt("a", 0, now) {
			t.Fatal("hit refused with the limit disabled")
		}
	}
}

// Past maxIPs the stale IPs are pruned, once per window, so the map is
// bounded by the hit rate over a window
func TestIPRateLimiterPrunesStaleIPs(t *testing.T) {
	limiter := newIPRateLimiter(time.Minute, 5)
	now := time.Now()
	for i := range 10 {
		limiter.allowAt(fmt.Sprintf("ip%d", i), 1, now)
	}
	if len(limiter.hits) != 10 {
		t.Fatalf("expected 10 tracked IPs, got %d", len(limiter.hits))
	}
	// Within the window nothing is stale, the prune keeps everything
	limiter.allowAt("fresh", 1, now.Add(30*time.Second))
	if len(limiter.hits) != 11 {
		t.Fatalf("expected 11 tracked IPs, got %d", len(limiter.hits))
	}
	// A window later the first IPs are stale and are dropped
	limiter.allowAt("later", 1, now.Add(61*time.Second))
	if _, ok := limiter.hits["ip0"]; ok {
		t.Fatal("stale IP not pruned")
	}
	if _, ok := limiter.hits["fresh"]; !ok {
		t.Fatal("IP within the window pruned")
	}
	if len(limiter.hits) != 2 {
		t.Fatalf("expected 2 tracked IPs after the prune, got %d", len(limiter.hits))
	}
}

// A form login start past security.login_start_rate_limit per IP is refused
// with 429 and writes no login state
func TestFormLoginStartRateLimited(t *testing.T) {
	db := NewInmemoryKVStore()
	store := NewKVSessionStore(db,
		[]byte("test-session-key-32bytes-long!!!"),
		[]byte("test-session-block-32bytes-key!!"),
	)
	store.Options.Secure = false

	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &types.ServerConfig{}
	cfg.AdminUser = "admin"
	cfg.Security.AdminPasswordBcrypt = string(hash)
	cfg.Security.AuthCallbackDomain = "auth."
	cfg.Security.LoginStartRateLimit = 2
	cfg.System.DefaultDomain = "localhost"

	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	manager, err := NewFormLoginManager(logger, func() *types.ServerConfig { return cfg },
		store, db, NewAdminBasicAuth(logger, cfg), nil, false)
	if err != nil {
		t.Fatalf("NewFormLoginManager failed: %v", err)
	}
	manager.loginRate = newIPRateLimiter(time.Minute, rateLimiterMaxIPs)

	start := func(remote string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://localhost:25222/app1", nil)
		req.RemoteAddr = remote
		if !manager.beginLogin(rec, req, "system") {
			t.Fatal("beginLogin did not handle the request")
		}
		return rec
	}
	for i := range 2 {
		if rec := start("10.0.0.1:1234"); rec.Code != 302 {
			t.Fatalf("start %d: code %d, want a login redirect", i, rec.Code)
		}
	}
	rows := len(db.store)
	rec := start("10.0.0.1:1234")
	if rec.Code != 429 {
		t.Fatalf("third start: code %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After %q", rec.Header().Get("Retry-After"))
	}
	if len(db.store) != rows {
		t.Fatalf("refused start wrote keystore rows: %d, was %d", len(db.store), rows)
	}
	// Another client is not affected
	if rec := start("10.0.0.2:1234"); rec.Code != 302 {
		t.Fatalf("other IP: code %d, want a login redirect", rec.Code)
	}
	// 0 disables the limit
	cfg.Security.LoginStartRateLimit = 0
	if rec := start("10.0.0.1:1234"); rec.Code != 302 {
		t.Fatalf("limit disabled: code %d, want a login redirect", rec.Code)
	}
}
