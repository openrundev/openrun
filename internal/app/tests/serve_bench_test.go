// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/types"
)

func newBenchApp(b *testing.B) *app.App {
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	fileData := map[string]string{
		"app.star": `
app = ace.app("benchApp", routes = [ace.api("/", type="json")])

def handler(req):
	return {"key": "myvalue", "count": 42}
`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		b.Fatalf("error creating app: %s", err)
	}
	return a
}

// BenchmarkAppServeJSONAPI measures the full in-app API request path:
// App.ServeHTTP -> chi router -> starlark handler -> JSON encode.
func BenchmarkAppServeJSONAPI(b *testing.B) {
	a := newBenchApp(b)

	b.ReportAllocs()
	for b.Loop() {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
		}
	}
}

func BenchmarkAppServeJSONAPIParallel(b *testing.B) {
	a := newBenchApp(b)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, req)
			if w.Code != 200 {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})
}

// BenchmarkAppProxy measures the proxy route path used by containerized apps:
// App.ServeHTTP -> permsHandler (host/header work) -> Tracker (byte counting)
// -> httputil.ReverseProxy -> backend. Response sizes exercise the per-chunk
// byte counting (the proxy copies in 32KB chunks).
func BenchmarkAppProxy(b *testing.B) {
	for _, size := range []int{1024, 256 * 1024} {
		b.Run(fmt.Sprintf("resp=%dKB", size/1024), func(b *testing.B) {
			payload := make([]byte, size)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(payload) //nolint:errcheck
			}))
			defer backend.Close()

			logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
			fileData := map[string]string{
				"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("benchProxy", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, backend.URL),
			}
			a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
				[]types.Permission{{Plugin: "proxy.in", Method: "config"}}, map[string]types.PluginSettings{})
			if err != nil {
				b.Fatalf("error creating app: %s", err)
			}

			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				req := httptest.NewRequest("GET", "/test/data", nil)
				req.Host = "localhost:25222"
				w := httptest.NewRecorder()
				a.ServeHTTP(w, req)
				if w.Code != 200 || w.Body.Len() != size {
					b.Fatalf("unexpected status %d len %d", w.Code, w.Body.Len())
				}
			}
		})
	}
}

// BenchmarkAppInitializeFastPath measures the already-initialized fast path of
// App.Initialize, which server.GetApp calls on every request. Run with
// RunParallel it exposes the exclusive initMutex.Lock() taken per request.
func BenchmarkAppInitializeFastPath(b *testing.B) {
	a := newBenchApp(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := a.Initialize(ctx, types.DryRunFalse); err != nil {
				b.Fatal(err)
			}
		}
	})
}
