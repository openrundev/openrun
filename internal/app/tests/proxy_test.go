// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// testRBAC is a minimal RBACAPI implementation for tests
type testRBAC struct {
	perms []string
}

func (t *testRBAC) AuthorizeAny(ctx context.Context, permissions []string) (bool, error) {
	return true, nil
}

func (t *testRBAC) Authorize(ctx context.Context, permission types.RBACPermission, isAppLevelPermission bool) (bool, error) {
	return true, nil
}

func (t *testRBAC) GetCustomPermissions(ctx context.Context) ([]string, error) {
	return t.perms, nil
}

func (t *testRBAC) IsAppRBACEnabled(ctx context.Context) bool {
	return true
}
func TestProxyBasics(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())
}

func TestProxyBasicsRoot(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc/def" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPluginRoot(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/abc/def", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())
}

func TestProxyMultiPath(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pp/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

def handler(req):
    return "handler text"

app = ace.app("testApp", routes = [
	ace.api("/", type=ace.TEXT),
	ace.proxy("/pp", proxy.config("%s")),
	ace.api("/np", type=ace.TEXT)],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "handler text", response.Body.String())

	request = httptest.NewRequest("GET", "/test/pp/abc", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())

	request = httptest.NewRequest("GET", "/test/np", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "handler text", response.Body.String())
}

func TestProxyPermsSuccess(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config", ["%s"]),
]
)`, testServer.URL, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config", Arguments: []string{testServer.URL}},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())
}

func TestProxyPermsFailure(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config", ["example.com"]),
]
)`, testServer.URL),
	}

	_, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config", Arguments: []string{"example.com"}},
		}, map[string]types.PluginSettings{})

	testutil.AssertErrorContains(t, err, "is not permitted to call proxy.in.config with argument 0 having value \"http://127.0.0.1:")
	testutil.AssertErrorContains(t, err, "expected \"example.com\". Update the app or audit and approve permissions")
}

func TestProxyPermsFailureRegex(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config", ["regex:.*.example.com"]),
]
)`, testServer.URL),
	}

	_, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config", Arguments: []string{"regex:.*.example.com"}},
		}, map[string]types.PluginSettings{})

	testutil.AssertErrorContains(t, err, "is not permitted to call proxy.in.config with argument 0 having value \"http://127.0.0.1:")
	testutil.AssertErrorContains(t, err, "expected \"regex:.*.example.com\". Update the app or audit and approve permissions")
}

func TestProxyPermsRegex(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config", ["regex:http://127.0.0.1:.*"]),
]
)`, testServer.URL),
	}

	_, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config", Arguments: []string{"regex:http://127.0.0.1:.*"}},
		}, map[string]types.PluginSettings{})

	testutil.AssertNoError(t, err)
}

func TestProxyStripPath(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/ppp", proxy.config("%s", strip_path="/ppp"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/ppp/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())
}

func TestProxyPostPreview(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPluginId(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{}, "app_pre_testapp", types.AppSettings{PreviewWriteAccess: false})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// POST fails
	request := httptest.NewRequest("POST", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertEqualsString(t, "body", "Preview app does not have access to proxy write APIs\n", response.Body.String())

	// GET works
	request = httptest.NewRequest("GET", "/test/abc", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())

	// Enable write access, POST works
	a.Settings.PreviewWriteAccess = true

	request = httptest.NewRequest("POST", "/test/abc", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())
}

func TestProxyPostStage(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPluginId(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{}, "app_stg_testapp", types.AppSettings{StageWriteAccess: false})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("POST", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertEqualsString(t, "body", "Stage app does not have access to proxy write APIs\n", response.Body.String())

	// Enable write access
	a.Settings.StageWriteAccess = true

	request = httptest.NewRequest("POST", "/test/abc", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())
}

func TestProxyStatic(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/static/f1" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
		"static_root/f2": "static file contents",
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/static/f1", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String()) // goes to proxy instead of static

	request = httptest.NewRequest("GET", "/test/f2", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "static file contents", response.Body.String())
}

func TestProxyError(t *testing.T) {
	// Check error handling, proxy config is read in the route handler, error handler is not called
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config(abc="%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	_, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})

	testutil.AssertErrorContains(t, err, "error in proxy config: config: unexpected keyword argument \"abc\"")
}

func TestProxyNoPreserveHost(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Host) //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", testServer.URL[7:], response.Body.String())
}

func TestProxyPreserveHost(t *testing.T) {
	// Preserve host forwards the client Host header to the backend instead of
	// rewriting it to the upstream URL. Apps like Grafana require the original
	// Host so they can build absolute URLs (redirects, OAuth callbacks, etc.).
	// The app domain anchors what we are willing to forward — a client Host
	// that doesn't match the canonical authority is rewritten.
	var backendHost string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHost = r.Host
		io.WriteString(w, "ok") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s", preserve_host=True))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPluginDomain(logger, "grafana.example.com", fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	request.Host = "grafana.example.com"
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "backend host", "grafana.example.com", backendHost)
}

func TestProxyPreserveHostRequiresCanonicalDomain(t *testing.T) {
	// preserve_host requires a canonical authority so an attacker-controlled
	// Host header can't be forwarded blindly to the backend. The test harness
	// configures neither the app domain nor system.default_domain, so app load
	// should fail fast.
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Host) //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s", preserve_host=True))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	_, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err == nil {
		t.Fatal("expected error when preserve_host is true without a canonical domain")
	}
}

func TestProxyRejectsInvalidHost(t *testing.T) {
	called := false
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	request.Host = "example.com/health?x="
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", http.StatusBadRequest, response.Code)
	testutil.AssertEqualsBool(t, "backend called", false, called)
}

func TestProxyRewritesUpstreamLocationHeader(t *testing.T) {
	// The upstream issues a 307 trailing-slash redirect whose Location absolute
	// URL points at itself — exactly what uvicorn/Starlette does. The proxy's
	// ModifyResponse must rewrite it to a path-absolute URL so the upstream
	// authority doesn't leak to the client.
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mimic Starlette: redirect to the same path with a trailing slash,
		// using the upstream's Host to build an absolute URL.
		w.Header().Set("Location", "http://"+r.Host+r.URL.Path+"/")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPluginConfig(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{}, &types.AppConfig{Proxy: types.Proxy{RewriteLocation: true}})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", http.StatusTemporaryRedirect, response.Code)
	// Path should round-trip; scheme+host must not appear (no upstream leak).
	testutil.AssertEqualsString(t, "location", "/test/abc/", response.Header().Get("Location"))
}

func TestProxyRewritesUpstreamLocationWithStripApp(t *testing.T) {
	// With strip_app=True the upstream doesn't know the public path prefix.
	// Its Location must have the prefix restored on the way out, whether the
	// Location is absolute or path-absolute.
	var hits int
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			// Absolute URL pointing at upstream.
			w.Header().Set("Location", "http://"+r.Host+"/bar?x=1")
		} else {
			// Path-absolute Location from upstream's perspective.
			w.Header().Set("Location", "/bar?x=1")
		}
		w.WriteHeader(http.StatusFound)
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s", strip_app=True))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPluginConfig(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{}, &types.AppConfig{Proxy: types.Proxy{RewriteLocation: true}})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// First request: absolute Location.
	request := httptest.NewRequest("GET", "/test/foo", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code (absolute)", http.StatusFound, response.Code)
	testutil.AssertEqualsString(t, "location (absolute)", "/test/bar?x=1", response.Header().Get("Location"))

	// Second request: path-absolute Location, should be re-prefixed with /test.
	request = httptest.NewRequest("GET", "/test/foo", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code (path-absolute)", http.StatusFound, response.Code)
	testutil.AssertEqualsString(t, "location (path-absolute)", "/test/bar?x=1", response.Header().Get("Location"))
}

func TestProxyDoesNotRewriteExternalLocation(t *testing.T) {
	// A Location pointing at an unrelated host (an OAuth/SSO redirect, say)
	// must pass through untouched.
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://accounts.example.com/login?return=/foo")
		w.WriteHeader(http.StatusFound)
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", http.StatusFound, response.Code)
	testutil.AssertEqualsString(t, "location", "https://accounts.example.com/login?return=/foo", response.Header().Get("Location"))
}

func TestProxyWebSocketForwardsClientHost(t *testing.T) {
	// WebSocket upgrades always forward the client Host to the upstream, even
	// when preserve_host=false. Upstream WebSocket frameworks (Starlette/ASGI,
	// Tornado, etc.) reject the handshake as a "disallowed origin" when the
	// browser-supplied Origin's host doesn't match the request's Host, so the
	// proxy must leave Host alone for upgrades.
	//
	// This is safe in the live server: by the time a request hits this code,
	// Host has been constrained to a registered app domain by MatchApp and
	// validated by system.ValidHostHeader. The "attacker.example" value here
	// stands in for one of those registered domains; the test bypasses
	// MatchApp by calling ServeHTTP directly.
	var backendHost string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHost = r.Host
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	request.Host = "attacker.example"
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "backend host", "attacker.example", backendHost)
}

func TestProxyNoStripApp(t *testing.T) {
	// Used when proxying to apps like streamlit, which need the app path to be passed through
	// and a baseDir variable to be set in app config
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/test/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s", strip_app=False))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())
}

func TestProxyStripPathNoApp(t *testing.T) {
	// If strip_app is false, then strip_path needs to include the app path also
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc" {
			t.Fatalf("Invalid path %s", r.URL.Path)
		}
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/ppp", proxy.config("%s", strip_path="/test/ppp", strip_app=False))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/ppp/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())
}

func TestProxyRequestHeaders(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ALLOW", "ALLOWED")
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s", response_headers={"-AAA": "", "NEWH": "NEWVAL", "NEWTEMP": "aa/$urlbb"}))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPluginRoot(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/abc/def", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())
	testutil.AssertEqualsString(t, "header", "ALLOWED", response.Header().Get("ALLOW"))
	testutil.AssertEqualsString(t, "header", "NEWVAL", response.Header().Get("NEWH"))
	testutil.AssertEqualsString(t, "header", "aa/abc/defbb", response.Header().Get("NEWTEMP"))
}

func TestProxyUserAndPermsHeaders(t *testing.T) {
	// Test that X-Openrun-User and X-Openrun-Perms headers are passed to proxied endpoint
	var receivedUser string
	var receivedUserSubject string
	var receivedUserEmail string
	var receivedPerms string
	var receivedRBACEnabled string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUser = r.Header.Get("X-Openrun-User")
		receivedUserSubject = r.Header.Get("X-Openrun-User-Id")
		receivedUserEmail = r.Header.Get("X-Openrun-User-Email")
		receivedPerms = r.Header.Get("X-Openrun-Perms")
		receivedRBACEnabled = r.Header.Get("X-Openrun-Rbac-Enabled")
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppAuthorizer(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{}, &testRBAC{perms: []string{"read:data", "write:data", "admin"}})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	// Set user ID in context as it would be set by the server middleware
	ctx := context.WithValue(request.Context(), types.USER_ID, types.ANONYMOUS_USER)
	ctx = context.WithValue(ctx, types.USER_SUBJECT, "subject-123")
	ctx = context.WithValue(ctx, types.USER_EMAIL, "test@example.com")
	ctx = context.WithValue(ctx, types.CUSTOM_PERMS, []string{"read:data", "write:data", "admin"})
	ctx = context.WithValue(ctx, types.RBAC_ENABLED, true)
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())

	// Verify the headers were passed to the proxied endpoint
	testutil.AssertEqualsString(t, "X-Openrun-User", types.ANONYMOUS_USER, receivedUser)
	testutil.AssertEqualsString(t, "X-Openrun-User-Id", "subject-123", receivedUserSubject)
	testutil.AssertEqualsString(t, "X-Openrun-User-Email", "test@example.com", receivedUserEmail)
	testutil.AssertEqualsString(t, "X-Openrun-Perms", "read:data,write:data,admin", receivedPerms)
	testutil.AssertEqualsString(t, "X-Openrun-Rbac-Enabled", "true", receivedRBACEnabled)
}

func TestProxyUserHeaderWithAuthentication(t *testing.T) {
	// Test that X-Openrun-User header contains the authenticated user
	var receivedUser string
	var receivedExtra string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUser = r.Header.Get("X-Openrun-User")
		receivedExtra = r.Header.Get("X-Openrun-Extra")
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppAuthorizer(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{}, &testRBAC{perms: []string{}})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	request.Header.Set("X-Openrun-Extra", "testvalue")
	// Set authenticated user in context as it would be set by the server middleware
	ctx := context.WithValue(request.Context(), types.USER_ID, "testuser@example.com")
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())

	// Verify the user header was passed to the proxied endpoint
	testutil.AssertEqualsString(t, "X-Openrun-User", "testuser@example.com", receivedUser)
	testutil.AssertEqualsString(t, "X-Openrun-Extra", "", receivedExtra)
}

func TestProxyForwardHeadersSanitized(t *testing.T) {
	var forwardedFor string
	var realIP string
	var forwarded string
	var forwardedHost string
	var forwardedProto string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedFor = r.Header.Get("X-Forwarded-For")
		realIP = r.Header.Get("X-Real-IP")
		forwarded = r.Header.Get("Forwarded")
		forwardedHost = r.Header.Get("X-Forwarded-Host")
		forwardedProto = r.Header.Get("X-Forwarded-Proto")
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "http://example.com/test/abc", nil)
	request.RemoteAddr = "198.51.100.40:4242"
	request.Host = "example.com"
	request.Header.Set("X-Forwarded-For", "203.0.113.1")
	request.Header.Set("X-Real-IP", "203.0.113.2")
	request.Header.Set("Forwarded", "for=203.0.113.3")
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())
	testutil.AssertEqualsString(t, "forwarded for", "198.51.100.40", forwardedFor)
	testutil.AssertEqualsString(t, "real ip", "198.51.100.40", realIP)
	testutil.AssertEqualsString(t, "forwarded", "", forwarded)
	testutil.AssertEqualsString(t, "forwarded host", "example.com", forwardedHost)
	testutil.AssertEqualsString(t, "forwarded proto", "http", forwardedProto)
}

func TestProxyForwardHeadersSanitizedIPv6Host(t *testing.T) {
	var forwardedHost string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedHost = r.Header.Get("X-Forwarded-Host")
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

app = ace.app("testApp", routes = [ace.proxy("/", proxy.config("%s"))],
permissions=[
	ace.permission("proxy.in", "config"),
]
)`, testServer.URL),
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "http://[2001:db8::1]/test/abc", nil)
	request.RemoteAddr = "198.51.100.40:4242"
	request.Host = "[2001:db8::1]:8080"
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())
	testutil.AssertEqualsString(t, "forwarded host", "2001:db8::1", forwardedHost)
}
