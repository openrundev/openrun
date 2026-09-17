// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"bytes"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

type htmxRoundTripper func(*http.Request) (*http.Response, error)

func (f htmxRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newHtmxTestDev(t *testing.T) *AppDev {
	t.Helper()
	logger := testutil.TestLogger()
	dir := t.TempDir()
	disk := &appfs.DiskWriteFS{DiskReadFS: appfs.NewDiskReadFS(logger, dir, nil)}
	source, err := appfs.NewSourceFs(dir, disk, true)
	if err != nil {
		t.Fatal(err)
	}
	workDir := t.TempDir()
	work := appfs.NewWorkFs(workDir, &appfs.DiskWriteFS{DiskReadFS: appfs.NewDiskReadFS(logger, workDir, nil)})
	a := NewAppDev(logger, &appfs.WritableSourceFs{SourceFs: source}, work, &AppStyle{}, &types.SystemConfig{})
	a.Config = apptype.NewCodeConfig()
	a.CustomLayout = true
	return a
}

func mockHtmxDownloads(t *testing.T) *[]string {
	t.Helper()
	var urls []string
	old := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = old })
	http.DefaultClient = &http.Client{Transport: htmxRoundTripper(func(r *http.Request) (*http.Response, error) {
		urls = append(urls, r.URL.String())
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("// " + r.URL.String())), Request: r}, nil
	})}
	return &urls
}

func TestHtmxLibrariesAcrossVersionChanges(t *testing.T) {
	urls := mockHtmxDownloads(t)
	a := newHtmxTestDev(t)
	for _, version := range []string{"1.9.2", "2.0.3", "4.0.0", "2.0.3", "4.0.0"} {
		t.Run(version, func(t *testing.T) {
			a.Config.Htmx.Version = version
			a.JsLibs = nil // Reload rebuilds the app's explicit library list.
			if err := a.SetupJsLibs(); err != nil {
				t.Fatal(err)
			}
			wantRuntime := "https://unpkg.com/htmx.org@" + version + "/dist/htmx.min.js"
			wantSSE := "https://unpkg.com/htmx-ext-sse@2.2.2/sse.js"
			if strings.HasPrefix(version, "4.") {
				wantSSE = "https://unpkg.com/htmx.org@" + version + "/dist/ext/hx-sse.min.js"
			}
			for name, want := range map[string]string{"htmx.min.js": wantRuntime, "sse.js": wantSSE} {
				data, err := a.sourceFS.ReadFile("static/gen/lib/" + name)
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != "// "+want {
					t.Fatalf("%s after switching to %s: got %q, want %q", name, version, data, want)
				}
			}
			before := len(*urls)
			if err := a.SetupJsLibs(); err != nil {
				t.Fatal(err)
			}
			if len(*urls) != before {
				t.Fatal("unchanged libraries were downloaded again")
			}
			if len(a.JsLibs) != 2 || len(a.jsCache) != 2 {
				t.Fatalf("duplicate or stale libraries: %d libs, %d cached", len(a.JsLibs), len(a.jsCache))
			}
		})
	}
}

func TestExplicitHtmxSSELibrary(t *testing.T) {
	for _, test := range []struct{ version, url string }{
		{"4.0.0", "https://cdn.jsdelivr.net/npm/htmx.org@4.0.0/dist/ext/hx-sse.min.js"},
		{"4.0.0", "https://cdn.jsdelivr.net/npm/htmx.org@4.0.0/dist/ext/hx-sse.js"},
		{"2.0.3", "https://unpkg.com/htmx-ext-sse@2.2.2/sse.js"},
		{"1.9.2", "https://unpkg.com/htmx.org@1.9.2/dist/ext/sse.js"},
		// Mismatched generations are the app's choice: set up with a warning
		{"4.0.0", "https://unpkg.com/htmx-ext-sse@2.2.2/sse.js"},
		{"2.0.3", "https://unpkg.com/htmx.org@4.0.0/dist/ext/hx-sse.min.js"},
	} {
		t.Run(test.url, func(t *testing.T) {
			urls := mockHtmxDownloads(t)
			a := newHtmxTestDev(t)
			a.Config.Htmx.Version = test.version
			a.JsLibs = []types.JSLibrary{*NewLibrary(test.url)}
			if err := a.SetupJsLibs(); err != nil {
				t.Fatal(err)
			}
			if len(*urls) != 2 {
				t.Fatalf("got downloads %v, want runtime and explicit SSE only", *urls)
			}
			data, err := a.sourceFS.ReadFile("static/gen/lib/sse.js")
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "// "+test.url {
				t.Fatalf("explicit extension not available at the generated import path: %s", data)
			}
		})
	}
}

// The SSE extension follows the runtime the app serves, which an explicit
// htmx library pins regardless of the configured version.
func TestExplicitHtmxRuntimeSelectsExtension(t *testing.T) {
	for _, test := range []struct{ version, url, wantSSE, wantVersion string }{
		{"4.0.0", "https://unpkg.com/htmx.org@2.0.3/dist/htmx.min.js", "https://unpkg.com/htmx-ext-sse@2.2.2/sse.js", "2.0.3"},
		{"2.0.3", "https://cdn.jsdelivr.net/npm/htmx.org@4.0.1/dist/htmx.min.js", "https://unpkg.com/htmx.org@4.0.1/dist/ext/hx-sse.min.js", "4.0.1"},
		{"4.0.0", "https://unpkg.com/htmx.org@latest/dist/htmx.min.js", "https://unpkg.com/htmx-ext-sse@2.2.2/sse.js", "latest"},
	} {
		t.Run(test.url, func(t *testing.T) {
			urls := mockHtmxDownloads(t)
			a := newHtmxTestDev(t)
			a.Config.Htmx.Version = test.version
			a.JsLibs = []types.JSLibrary{*NewLibrary(test.url)}
			if err := a.SetupJsLibs(); err != nil {
				t.Fatal(err)
			}
			if got := a.HtmxVersion(); got != test.wantVersion {
				t.Fatalf("resolved version %q, want %q", got, test.wantVersion)
			}
			if len(*urls) != 2 || (*urls)[0] != test.url || (*urls)[1] != test.wantSSE {
				t.Fatalf("got downloads %v, want [%s %s]", *urls, test.url, test.wantSSE)
			}
		})
	}
}

func TestHtmx4(t *testing.T) {
	for version, want := range map[string]bool{"4": true, "4.0.0": true, "4.1": true, "2.0.3": false, "1.9.2": false, "latest": false, "": false, "40.1": false} {
		if got := Htmx4(version); got != want {
			t.Errorf("Htmx4(%q) = %v, want %v", version, got, want)
		}
	}
}

func TestGeneratedHtmxImport(t *testing.T) {
	for _, version := range []string{"1.9.2", "2.0.3", "4.0.0"} {
		for _, base := range []string{"", "base_templates", "custom_templates"} {
			t.Run(version+"/"+base, func(t *testing.T) {
				a := newHtmxTestDev(t)
				a.Config.Htmx.Version = version
				a.Config.Routing.BaseTemplates = base
				if base != "" {
					if err := a.sourceFS.Write(base+"/layout.go.html", []byte(`{{define "layout"}}test{{end}}`)); err != nil {
						t.Fatal(err)
					}
				}
				if err := a.sourceFS.Write(apptype.CLACE_GEN_FILE, []byte("stale template")); err != nil {
					t.Fatal(err)
				}
				if err := a.GenerateHTML(); err != nil {
					t.Fatal(err)
				}
				name := filepath.Join(base, apptype.CLACE_GEN_FILE)
				data, err := a.sourceFS.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if base != "" {
					if _, err := a.sourceFS.Stat(apptype.CLACE_GEN_FILE); !os.IsNotExist(err) {
						t.Fatalf("stale root import remains: %v", err)
					}
				}
				// The app FuncMap (sprig, so hasPrefix takes the prefix first) plus
				// the app-specific helpers
				funcMap := system.GetFuncMap()
				funcMap["static"] = func(s string) string { return "/test/static/" + s }
				funcMap["fileNonEmpty"] = func(s string) bool { return strings.HasSuffix(s, ".js") }
				tmpl, err := template.New("import").Funcs(funcMap).Parse(string(data))
				if err != nil {
					t.Fatal(err)
				}
				for _, dev := range []bool{false, true} {
					var out bytes.Buffer
					if err := tmpl.Execute(&out, map[string]any{"IsDev": dev, "PushEvents": dev, "AppPath": "/test", "HtmxVersion": version}); err != nil {
						t.Fatal(err)
					}
					html := out.String()
					if !strings.Contains(html, `src="/test/static/gen/lib/htmx.min.js"`) {
						t.Fatal("missing runtime import")
					}
					// htmx 4 defaults apply (error responses swap, hx-status opts out):
					// the block must not claim the single htmx-config meta or cancel swaps
					if strings.Contains(html, "htmx-config") || strings.Contains(html, "htmx:before:swap") {
						t.Fatal("generated import overrides htmx defaults")
					}
					if strings.Contains(html, "cl_reload_listener") != dev {
						t.Fatalf("dev listener for IsDev=%v: %s", dev, html)
					}
					if dev {
						if !strings.Contains(html, `src="/test/static/gen/lib/sse.js"`) {
							t.Fatal("missing SSE import")
						}
						if version == "4.0.0" {
							for _, want := range []string{`hx-sse:connect="/test/_openrun_app/sse"`, `.addEventListener("openrun_reload"`} {
								if !strings.Contains(html, want) {
									t.Errorf("missing %s", want)
								}
							}
							if strings.Contains(html, "hx-ext") || strings.Contains(html, "sse:openrun_reload") {
								t.Fatal("legacy SSE markup in htmx 4 template")
							}
						} else if !strings.Contains(html, `hx-ext="sse"`) || !strings.Contains(html, `sse:openrun_reload`) {
							t.Fatal("legacy SSE behavior changed")
						}
					}
				}
				before, err := a.sourceFS.Stat(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := a.GenerateHTML(); err != nil {
					t.Fatal(err)
				}
				after, err := a.sourceFS.Stat(name)
				if err != nil {
					t.Fatal(err)
				}
				if !before.ModTime().Equal(after.ModTime()) {
					t.Fatal("unchanged template rewritten, causing a reload loop")
				}
			})
		}
	}
}
