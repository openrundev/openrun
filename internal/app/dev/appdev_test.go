// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	source, err := appfs.NewSourceFs(logger, dir, disk, true)
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

// stubDownloads replaces both download transports for the test
func stubDownloads(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	oldApp, oldServer := appDownloadTransport, serverDownloadTransport
	t.Cleanup(func() { appDownloadTransport, serverDownloadTransport = oldApp, oldServer })
	appDownloadTransport, serverDownloadTransport = rt, rt
}

func mockHtmxDownloads(t *testing.T) *[]string {
	t.Helper()
	var urls []string
	stubDownloads(t, htmxRoundTripper(func(r *http.Request) (*http.Response, error) {
		urls = append(urls, r.URL.String())
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("// " + r.URL.String())), Request: r}, nil
	}))
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

// TestFetchUrlRetriesTransientFailures verifies a library download retries
// a connection failure and a 5xx response, and gives up at once on a 4xx
func TestFetchUrlRetriesTransientFailures(t *testing.T) {
	var calls int
	responses := []func() (*http.Response, error){
		func() (*http.Response, error) { return nil, errors.New("tls handshake timeout") },
		func() (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
		func() (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("lib"))}, nil
		},
	}
	transport := htmxRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		return responses[calls-1]()
	})
	data, err := fetchUrl(transport, "https://unpkg.com/htmx.org@4.0.0/dist/htmx.min.js")
	if err != nil || string(data) != "lib" || calls != 3 {
		t.Fatalf("fetch after transient failures: data=%q err=%v calls=%d", data, err, calls)
	}

	calls = 0
	transport = htmxRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if _, err := fetchUrl(transport, "https://unpkg.com/htmx.org@nosuch/dist/htmx.min.js"); err == nil || calls != 1 {
		t.Fatalf("a 404 must fail at once: err=%v calls=%d", err, calls)
	}
}

// TestFetchUrlLimitsSize verifies a download over downloadMaxBytes fails
// without retrying, instead of being buffered whole
func TestFetchUrlLimitsSize(t *testing.T) {
	var calls int
	transport := htmxRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		body := io.LimitReader(zeroReader{}, downloadMaxBytes+10)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(body)}, nil
	})
	if _, err := fetchUrl(transport, "https://example.com/huge.js"); err == nil ||
		!strings.Contains(err.Error(), "larger than") || calls != 1 {
		t.Fatalf("oversized download must fail at once: err=%v calls=%d", err, calls)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// TestAppDownloadsRefusePrivateHosts verifies the app download transport
// refuses a loopback target (redirect hops are dialed through the same
// transport), the server config transport does not, and the redirect policy
// refuses an https to http downgrade and long chains
func TestAppDownloadsRefusePrivateHosts(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "internal")
	}))
	defer local.Close()
	if _, err := fetchUrl(appDownloadTransport, local.URL+"/lib.js"); err == nil ||
		!strings.Contains(err.Error(), "private or local address") {
		t.Fatalf("loopback download must be refused: %v", err)
	}
	// The server transport (daisyui_url from the server config) may reach
	// an internal mirror
	if data, err := fetchUrl(serverDownloadTransport, local.URL+"/lib.js"); err != nil || string(data) != "internal" {
		t.Fatalf("server config download of a local mirror failed: %q %v", data, err)
	}

	req := func(scheme string) *http.Request { return &http.Request{URL: &url.URL{Scheme: scheme, Host: "x"}} }
	if err := checkDownloadRedirect(req("http"), []*http.Request{req("https")}); err == nil {
		t.Error("https to http redirect downgrade allowed")
	}
	if err := checkDownloadRedirect(req("https"), []*http.Request{req("https")}); err != nil {
		t.Errorf("https redirect refused: %v", err)
	}
	// The downgrade is checked against the preceding hop, not the original
	// request: http -> https -> http is refused
	if err := checkDownloadRedirect(req("http"), []*http.Request{req("http"), req("https")}); err == nil {
		t.Error("https to http downgrade after an http start allowed")
	}
	if err := checkDownloadRedirect(req("https"), []*http.Request{req("http")}); err != nil {
		t.Errorf("http to https upgrade refused: %v", err)
	}
	// via includes the original request: the fifth redirect is allowed,
	// the sixth is not
	chain := func(n int) []*http.Request {
		via := make([]*http.Request, n)
		for i := range via {
			via[i] = req("https")
		}
		return via
	}
	if err := checkDownloadRedirect(req("https"), chain(downloadMaxRedirects)); err != nil {
		t.Errorf("redirect %d refused: %v", downloadMaxRedirects, err)
	}
	if err := checkDownloadRedirect(req("https"), chain(downloadMaxRedirects+1)); err == nil {
		t.Error("redirect limit not enforced")
	}
}

// TestAppDownloadsThroughProxy verifies the app download transport uses the
// operator's proxy, which may be on a private address, refuses a proxied
// target which is or resolves to a private address before reaching the
// proxy, and checks a direct download of the proxy's own address like any
// other direct download
func TestAppDownloadsThroughProxy(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.String())
		mu.Unlock()
		_, _ = io.WriteString(w, "via proxy")
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := newAppDownloadTransport(func(r *http.Request) (*url.URL, error) {
		if r.URL.Port() == proxyURL.Port() {
			return nil, nil // like NO_PROXY, or a loopback host the env proxy skips
		}
		return proxyURL, nil
	})

	// A public IP literal, no DNS lookup needed
	const public = "http://93.184.216.34/lib.js"
	if data, err := fetchUrl(transport, public); err != nil || string(data) != "via proxy" {
		t.Fatalf("proxied download failed: %q %v", data, err)
	}
	for _, target := range []string{"http://10.1.2.3/lib.js", "http://169.254.169.254/latest/meta-data",
		"http://[::1]:8080/lib.js", "http://localhost:8080/lib.js",
		// fullwidth spellings, which the transport normalizes to 10.1.2.3
		"http://１０.１.２.３/lib.js", "https://１０.１.２.３/admin"} {
		if _, err := fetchUrl(transport, target); !errors.Is(err, system.ErrPrivateAddress) {
			t.Errorf("proxied download of %s must be refused: %v", target, err)
		}
	}
	if _, err := fetchUrl(transport, proxy.URL+"/lib.js"); !errors.Is(err, system.ErrPrivateAddress) {
		t.Errorf("direct download of the proxy address must be refused: %v", err)
	}
	// A fullwidth spelling of the proxy host, which the transport normalizes
	// to the proxy address when dialing
	fullwidth := "http://１２７.０.０.１:" + proxyURL.Port() + "/admin"
	if _, err := fetchUrl(transport, fullwidth); !errors.Is(err, system.ErrPrivateAddress) {
		t.Errorf("direct download of the fullwidth proxy address must be refused: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != public {
		t.Errorf("proxy requests: %v", seen)
	}
}

// TestAppDownloadsProxyConcurrent verifies direct downloads of the proxy's
// address, interleaved with proxied downloads which use it, never reach the
// proxy: whether a dial is checked does not depend on other requests
func TestAppDownloadsProxyConcurrent(t *testing.T) {
	var admin atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			admin.Add(1)
		}
		_, _ = io.WriteString(w, "via proxy")
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := newAppDownloadTransport(func(r *http.Request) (*url.URL, error) {
		if r.URL.Port() == proxyURL.Port() {
			return nil, nil
		}
		return proxyURL, nil
	})

	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for range 50 {
		wg.Go(func() {
			if _, err := fetchUrl(transport, "http://93.184.216.34/lib.js"); err != nil {
				errs <- fmt.Errorf("proxied download: %w", err)
			}
		})
		wg.Go(func() {
			if _, err := fetchUrl(transport, proxy.URL+"/admin"); !errors.Is(err, system.ErrPrivateAddress) {
				errs <- fmt.Errorf("direct download of the proxy address not refused: %v", err)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := admin.Load(); n != 0 {
		t.Errorf("proxy /admin reached %d times", n)
	}
}

// TestTailwindCommandNoArgs verifies system.tailwindcss_command is the
// executable only: a value with arguments is refused instead of passing
// them through to the watcher
func TestTailwindCommandNoArgs(t *testing.T) {
	style := &AppStyle{library: TailwindCSS}
	for _, command := range []string{"tailwindcss --config /tmp/evil.js", "npx tailwindcss", "tailwindcss\t-i x"} {
		err := style.startTailwindWatcher(testutil.TestLogger(), nil, nil, nil,
			&types.SystemConfig{TailwindCSSCommand: command})
		if err == nil || !strings.Contains(err.Error(), "arguments are not supported") {
			t.Errorf("%q: command with arguments accepted: %v", command, err)
		}
	}
}
