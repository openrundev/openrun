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
	// Preserve host is false by default, the Host header is set to the target endpoint host.
	// Apps like Grafana require the origin host header to be preserved
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
	testutil.AssertEqualsString(t, "body", "example.com", response.Body.String()) // httptest uses example.com
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
	var receivedPerms string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUser = r.Header.Get("X-Openrun-User")
		receivedPerms = r.Header.Get("X-Openrun-Perms")
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

	// Create custom authorizer and perms func
	authorizer := func(ctx context.Context, permissions []string) (bool, error) {
		// Always allow
		return true, nil
	}

	customPermsFunc := func(ctx context.Context) ([]string, error) {
		// Return custom permissions
		return []string{"read:data", "write:data", "admin"}, nil
	}

	a, _, err := CreateTestAppAuthorizer(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{}, authorizer, customPermsFunc)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	// Set user ID in context as it would be set by the server middleware
	ctx := context.WithValue(request.Context(), types.USER_ID, types.ANONYMOUS_USER)
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())

	// Verify the headers were passed to the proxied endpoint
	testutil.AssertEqualsString(t, "X-Openrun-User", types.ANONYMOUS_USER, receivedUser)
	testutil.AssertEqualsString(t, "X-Openrun-Perms", "read:data,write:data,admin", receivedPerms)
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

	// Create custom authorizer that sets a user in context
	authorizer := func(ctx context.Context, permissions []string) (bool, error) {
		// Always allow
		return true, nil
	}

	customPermsFunc := func(ctx context.Context) ([]string, error) {
		// Return empty custom permissions
		return []string{}, nil
	}

	a, _, err := CreateTestAppAuthorizer(logger, fileData, []string{"proxy.in"},
		[]types.Permission{
			{Plugin: "proxy.in", Method: "config"},
		}, map[string]types.PluginSettings{}, authorizer, customPermsFunc)
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
