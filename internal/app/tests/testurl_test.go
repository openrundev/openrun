// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// testUrlContext builds the request context the server sets up for a request
// carrying _cl_perm test URL directives
func testUrlContext(perms []string, extendedPrefix string) context.Context {
	dirs := rbac.NewUrlDirectives(perms, extendedPrefix)
	ctx := context.WithValue(context.Background(), types.TESTURL_DIRECTIVES, dirs)
	ctx = context.WithValue(ctx, types.CUSTOM_PERMS, perms)
	ctx = context.WithValue(ctx, types.USER_ID, types.ANONYMOUS_USER)
	return ctx
}

func testUrlServerConfig() *types.ServerConfig {
	serverConfig := &types.ServerConfig{}
	serverConfig.Security.UnsafeEnableTestUrlRbac = true
	return serverConfig
}

const testUrlAppStar = `
app = ace.app("testApp", custom_layout=True, routes = [ace.api("/info", type="json")])

def handler(req):
	return {"app_path": req.AppPath, "page_url": req.PageUrl,
		"perms": req.CustomPerms, "rbac_enabled": req.AppRBACEnabled}
`

func TestTestUrlRequestSurfaces(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{"app.star": testUrlAppStar}
	a, _, err := CreateDevModeTestAppServerConfig(logger, fileData, testUrlServerConfig())
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// Request with directives: the server strips the directive segments and
	// stores the directives in the context before the app sees the request
	ctx := testUrlContext([]string{"app:read", "report_view"}, "/test/_cl_perm=app:read,report_view")
	request := httptest.NewRequest("GET", "/test/info", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "status", http.StatusOK, response.Code)

	var got struct {
		AppPath     string   `json:"app_path"`
		PageUrl     string   `json:"page_url"`
		Perms       []string `json:"perms"`
		RbacEnabled bool     `json:"rbac_enabled"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("Error %s, body %s", err, response.Body.String())
	}
	testutil.AssertEqualsString(t, "app path", "/test/_cl_perm=app:read,report_view", got.AppPath)
	testutil.AssertStringContains(t, got.PageUrl, "/test/_cl_perm=app:read,report_view")
	testutil.AssertEqualsBool(t, "rbac enabled", true, got.RbacEnabled)
	if len(got.Perms) != 2 || got.Perms[0] != "app:read" || got.Perms[1] != "report_view" {
		t.Fatalf("perms: got %v", got.Perms)
	}

	// Same app without directives: unchanged behavior
	request = httptest.NewRequest("GET", "/test/info", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "status", http.StatusOK, response.Code)
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("Error %s", err)
	}
	testutil.AssertEqualsString(t, "app path", "/test", got.AppPath)
	testutil.AssertEqualsBool(t, "rbac enabled", false, got.RbacEnabled)
}

func TestTestUrlRequestSurfacesFlagOff(t *testing.T) {
	// With the config flag off, the effective path stays the app path even if
	// directives were somehow present in the context (defense in depth; the
	// server never sets them when the flag is off)
	logger := testutil.TestLogger()
	fileData := map[string]string{"app.star": testUrlAppStar}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	ctx := testUrlContext([]string{"app:read"}, "/test/_cl_perm=app:read")
	request := httptest.NewRequest("GET", "/test/info", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "status", http.StatusOK, response.Code)

	var got struct {
		AppPath string `json:"app_path"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("Error %s", err)
	}
	testutil.AssertEqualsString(t, "app path", "/test", got.AppPath)
}

func TestTestUrlProxyHeaders(t *testing.T) {
	// Verify the proxy path: X-Forwarded-Prefix carries the extended prefix,
	// X-Openrun-Perms carries the simulated set, Rbac-Enabled reports true and
	// upstream Location redirects get the directive segments re-inserted
	var gotPrefix, gotPerms, gotRbacEnabled string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPrefix = r.Header.Get("X-Forwarded-Prefix")
		gotPerms = r.Header.Get("X-Openrun-Perms")
		gotRbacEnabled = r.Header.Get("X-Openrun-Rbac-Enabled")
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/test/foo")
			w.WriteHeader(http.StatusFound)
			return
		}
		io.WriteString(w, "backend response") //nolint:errcheck
	}))
	defer testServer.Close()

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

	appConfig := types.AppConfig{}
	appConfig.Proxy.RewriteLocation = true
	a, _, err := createTestAppFull(logger, "/test", "", fileData, true, []string{"proxy.in"},
		[]types.Permission{{Plugin: "proxy.in", Method: "config"}},
		map[string]types.PluginSettings{}, "app_dev_testapp", types.AppSettings{}, nil, &appConfig,
		nil, testSystemConfig(), testUrlServerConfig())
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	ctx := testUrlContext([]string{"app:read"}, "/test/_cl_perm=app:read")
	request := httptest.NewRequest("GET", "/test/page", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "status", http.StatusOK, response.Code)
	testutil.AssertEqualsString(t, "forwarded prefix", "/test/_cl_perm=app:read", gotPrefix)
	testutil.AssertEqualsString(t, "openrun perms", "app:read", gotPerms)
	testutil.AssertEqualsString(t, "rbac enabled header", "true", gotRbacEnabled)

	// Upstream redirect to an app-absolute path gets the directives re-inserted
	request = httptest.NewRequest("GET", "/test/redirect", nil).WithContext(ctx)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "status", http.StatusFound, response.Code)
	testutil.AssertEqualsString(t, "location", "/test/_cl_perm=app:read/foo", response.Header().Get("Location"))

	// Without directives, the proxy behaves as before
	request = httptest.NewRequest("GET", "/test/page", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "status", http.StatusOK, response.Code)
	testutil.AssertEqualsString(t, "forwarded prefix", "/test", gotPrefix)
	testutil.AssertEqualsString(t, "rbac enabled header", "false", gotRbacEnabled)

	request = httptest.NewRequest("GET", "/test/redirect", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "status", http.StatusFound, response.Code)
	testutil.AssertEqualsString(t, "location", "/test/foo", response.Header().Get("Location"))
}
