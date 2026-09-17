// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestAppHeaderHtmx4(t *testing.T) {
	files := map[string]string{
		"app.star":      `app = ace.app("htmx4", custom_layout=True, routes=[ace.html("/")])`,
		"index.go.html": `<!doctype html><html><head>{{ template "openrun_gen_import" . }}</head><body>htmx4 app</body></html>`,
	}
	a, _, err := CreateDevModeTestApp(testutil.TestLogger(), files)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	a.ServeHTTP(response, httptest.NewRequest("GET", "/test", nil))
	if response.Code != 200 {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	html := response.Body.String()
	for _, want := range []string{`hx-sse:connect="/test/_openrun_app/sse"`, `.addEventListener("openrun_reload"`, `htmx4 app`} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
	if strings.Contains(html, `hx-ext=`) || strings.Contains(html, `sse:openrun_reload`) {
		t.Error("rendered htmx 4 page contains legacy reload markup")
	}
	if strings.Contains(html, `htmx-config`) || strings.Contains(html, `htmx:before:swap`) {
		t.Error("rendered page overrides htmx 4 defaults")
	}
	if !strings.Contains(files["static/gen/lib/htmx.min.js"], `4.0.0`) {
		t.Error("generated runtime is not htmx 4.0.0")
	}
	if !strings.Contains(files["static/gen/lib/sse.js"], `registerExtension`) {
		t.Error("generated SSE library does not use the htmx 4 extension API")
	}
}

// An explicit htmx 2 library pins the runtime: the reload markup and SSE
// extension follow it even though new apps are configured for htmx 4.
func TestAppHeaderExplicitHtmx2(t *testing.T) {
	files := map[string]string{
		"app.star": `app = ace.app("htmx2", custom_layout=True, routes=[ace.html("/")],
    libraries=["https://unpkg.com/htmx.org@2.0.3/dist/htmx.min.js"])`,
		"index.go.html": `<!doctype html><html><head>{{ template "openrun_gen_import" . }}</head><body>htmx2 app</body></html>`,
	}
	a, _, err := CreateDevModeTestApp(testutil.TestLogger(), files)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	a.ServeHTTP(response, httptest.NewRequest("GET", "/test", nil))
	if response.Code != 200 {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	html := response.Body.String()
	for _, want := range []string{`hx-ext="sse"`, `sse-connect="/test/_openrun_app/sse"`, `.addEventListener("sse:openrun_reload"`, `htmx2 app`} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
	if strings.Contains(html, `hx-sse:connect`) {
		t.Error("rendered htmx 2 page contains htmx 4 reload markup")
	}
	if !strings.Contains(files["static/gen/lib/htmx.min.js"], `2.0.3`) {
		t.Error("explicit htmx 2.0.3 runtime was not served")
	}
	if strings.Contains(files["static/gen/lib/sse.js"], `registerExtension`) {
		t.Error("htmx 4 SSE extension generated for an htmx 2 runtime")
	}
}
