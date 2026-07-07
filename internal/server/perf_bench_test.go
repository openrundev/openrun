// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	app_test "github.com/openrundev/openrun/internal/app/tests"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
)

func newBenchServer(defaultDomain string) *Server {
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{
		System: types.SystemConfig{
			DefaultDomain: defaultDomain,
		},
		Security: types.SecurityConfig{
			AppDefaultAuthType: "none",
		},
	}
	return &Server{
		Logger:       logger,
		staticConfig: config,
		authHandler:  NewAdminBasicAuth(logger, config),
		rbacManager: &rbac.RBACManager{
			Logger:     logger,
			RbacConfig: &types.RBACConfig{},
		},
		csrfMiddleware: http.NewCrossOriginProtection(),
	}
}

func newBenchAppStore(server *Server, numApps int, numDomains int) *AppStore {
	apps := make([]types.AppInfo, 0, numApps)
	allDomains := map[string]bool{"example.com": true}
	for i := range numApps {
		domain := ""
		if numDomains > 1 {
			domain = fmt.Sprintf("domain%d.example.com", i%numDomains)
			allDomains[domain] = true
		}
		apps = append(apps, types.AppInfo{
			AppPathDomain: types.AppPathDomain{Path: fmt.Sprintf("/app%d", i), Domain: domain},
		})
	}
	return &AppStore{
		Logger:     server.Logger,
		server:     server,
		allApps:    apps,
		domainApps: buildDomainApps(apps, "example.com"),
		allDomains: allDomains,
	}
}

// BenchmarkMatchApp measures the per-request app matching cost. Matching
// scans the apps installed on the request's domain, so single-domain setups
// scale with total app count while multi-domain setups scan only the
// per-domain bucket. The request matches the last app in scan order (worst case).
func BenchmarkMatchApp(b *testing.B) {
	for _, tc := range []struct {
		numApps    int
		numDomains int
	}{
		{10, 1}, {100, 1}, {1000, 1}, {1000, 100},
	} {
		b.Run(fmt.Sprintf("apps=%d/domains=%d", tc.numApps, tc.numDomains), func(b *testing.B) {
			server := newBenchServer("example.com")
			server.apps = newBenchAppStore(server, tc.numApps, tc.numDomains)
			matchApp := tc.numApps - 1
			matchDomain := "example.com"
			if tc.numDomains > 1 {
				matchDomain = fmt.Sprintf("domain%d.example.com", matchApp%tc.numDomains)
			}
			matchPath := fmt.Sprintf("/app%d/api/endpoint", matchApp)

			b.ReportAllocs()
			for b.Loop() {
				if _, err := server.MatchApp(matchDomain, matchPath); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkAuthenticateAndServeApp measures the server-side per-request path
// after app matching: auth resolution, RBAC check, context setup, CSRF wrap
// and the in-app handler (starlark JSON API).
func BenchmarkAuthenticateAndServeApp(b *testing.B) {
	server := newBenchServer("example.com")

	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	fileData := map[string]string{
		"app.star": `
app = ace.app("benchApp", routes = [ace.api("/", type="json")])

def handler(req):
	return {"key": "myvalue", "count": 42}
`,
	}
	a, _, err := app_test.CreateTestApp(logger, fileData)
	if err != nil {
		b.Fatalf("error creating app: %s", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		w := httptest.NewRecorder()
		server.authenticateAndServeApp(w, req, a)
		if w.Code != 200 {
			b.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
		}
	}
}

func newBenchAuditServer(b *testing.B) *Server {
	server := newBenchServer("example.com")
	dbPath := filepath.Join(b.TempDir(), "audit.db")
	if err := server.initAuditDB("sqlite:" + dbPath); err != nil {
		b.Fatalf("error initializing audit db: %s", err)
	}
	return server
}

// BenchmarkInsertAuditEvent measures the audit event write cost paid by every
// non-GET app/API request (handleStatus middleware) and admin API call.
// "sync" is the direct SQLite insert; "async" is the queued path used by the
// request handlers (batched writes on a background goroutine).
func BenchmarkInsertAuditEvent(b *testing.B) {
	benchEvent := func() types.AuditEvent {
		return types.AuditEvent{
			RequestId:  "rid_bench_1",
			CreateTime: time.Now(),
			UserId:     "admin",
			EventType:  types.EventTypeHTTP,
			Operation:  "POST",
			Target:     "example.com:/app1/api",
			Status:     "200",
			Detail:     "POST example.com /app1/api 200 1",
		}
	}

	b.Run("sync", func(b *testing.B) {
		server := newBenchAuditServer(b)
		b.Cleanup(server.stopAuditWriter)

		b.ReportAllocs()
		for b.Loop() {
			event := benchEvent()
			if err := server.insertAuditEventDB(&event); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("async", func(b *testing.B) {
		server := newBenchAuditServer(b)
		b.Cleanup(server.stopAuditWriter)

		b.ReportAllocs()
		for b.Loop() {
			event := benchEvent()
			if err := server.InsertAuditEvent(&event); err != nil {
				b.Fatal(err)
			}
		}
		server.FlushAuditEvents()
	})
}

// BenchmarkAccessLog compares the per-request cost of the zerolog-based
// access logger against the chi default request logger it replaced. Both
// write to io.Discard so only the formatting/allocation cost is measured.
func BenchmarkAccessLog(b *testing.B) {
	noop := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK")) //nolint:errcheck
	})

	runBench := func(b *testing.B, handler http.Handler) {
		b.ReportAllocs()
		for b.Loop() {
			req := httptest.NewRequest("GET", "http://example.com/app0/api", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	}

	b.Run("zerolog", func(b *testing.B) {
		server := newBenchServer("example.com")
		logger := zerolog.New(io.Discard).With().Timestamp().Logger()
		server.accessLogger = &logger
		runBench(b, server.accessLogMiddleware(noop))
	})

	b.Run("chi-default", func(b *testing.B) {
		chiLogger := middleware.RequestLogger(&middleware.DefaultLogFormatter{
			Logger: log.New(io.Discard, "", log.LstdFlags), NoColor: true})
		runBench(b, chiLogger(noop))
	})
}

// BenchmarkHandleStatus measures the handleStatus middleware overhead around a
// no-op handler: GET skips the audit insert, POST performs it inline.
func BenchmarkHandleStatus(b *testing.B) {
	server := newBenchAuditServer(b)
	b.Cleanup(server.stopAuditWriter)
	server.apps = newBenchAppStore(server, 1, 1)
	handler := server.handleStatus(types.ADMIN_USER)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	for _, method := range []string{"GET", "POST"} {
		b.Run(method, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				req := httptest.NewRequest(method, "http://example.com/app0/api", nil)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				if w.Code != 200 {
					b.Fatalf("unexpected status %d", w.Code)
				}
			}
		})
	}
}
