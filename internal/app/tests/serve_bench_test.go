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

// newBenchHTMLApp serves an HTML page: the handler returns a data map that a
// template renders, exercising App.ServeHTTP -> starlark handler ->
// UnmarshalStarlark -> html/template execution (the console's actual workload).
func newBenchHTMLApp(b *testing.B) *app.App {
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	fileData := map[string]string{
		"app.star": `
app = ace.app("benchApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return {
		"title": "Dashboard",
		"user": "alice@example.com",
		"count": 42,
		"rows": [
			{"name": "app-one", "status": "running", "version": 3},
			{"name": "app-two", "status": "stopped", "version": 1},
			{"name": "app-three", "status": "running", "version": 7},
			{"name": "app-four", "status": "running", "version": 2},
		],
	}
`,
		"index.go.html": `<!doctype html>
<html><head><title>{{ .Data.title }}</title></head>
<body>
<h1>{{ .Data.title }}</h1>
<p>Signed in as {{ .Data.user }} ({{ .Data.count }} apps)</p>
<table>
{{ range .Data.rows }}
  <tr><td>{{ .name }}</td><td>{{ .status }}</td><td>v{{ .version }}</td></tr>
{{ end }}
</table>
</body></html>`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		b.Fatalf("error creating app: %s", err)
	}
	return a
}

// BenchmarkAppServeHTML measures the HTML page path: starlark handler ->
// UnmarshalStarlark -> html/template render.
func BenchmarkAppServeHTML(b *testing.B) {
	a := newBenchHTMLApp(b)

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

// setBrowserHeaders adds a realistic browser header set (~15 headers). The
// handler never reads req.Headers, so this measures whether the per-request
// path pays to clone/process headers it does not use.
func setBrowserHeaders(req *http.Request) {
	h := req.Header
	h.Set("Host", "app.example.com")
	h.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	h.Set("Cache-Control", "max-age=0")
	h.Set("Cookie", "session=abcdef0123456789; theme=dark; sidebar=collapsed")
	h.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	h.Set("Sec-Ch-Ua-Mobile", "?0")
	h.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	h.Set("Sec-Fetch-Dest", "document")
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-Site", "same-origin")
	h.Set("Upgrade-Insecure-Requests", "1")
	h.Set("Referer", "https://app.example.com/apps")
}

// BenchmarkAppServeJSONAPIWithHeaders is the realistic-request variant: the
// same handler, but the request carries a full browser header set. The handler
// does not read headers, so with lazy header materialization this should cost
// no more than the header-less benchmark.
func BenchmarkAppServeJSONAPIWithHeaders(b *testing.B) {
	a := newBenchApp(b)

	b.ReportAllocs()
	for b.Loop() {
		req := httptest.NewRequest("GET", "/test", nil)
		setBrowserHeaders(req)
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
