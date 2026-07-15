// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

type testSysPlugin struct{}

func (p *testSysPlugin) Ping(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.String("pong"), nil
}

func init() {
	c := &testSysPlugin{}
	app.RegisterSystemPlugin("testsys", func(pluginContext *types.PluginContext) (any, error) {
		return &testSysPlugin{}, nil
	}, []plugin.PluginFunc{
		app.CreatePluginApiName(c.Ping, app.READ, "ping"),
	})
}

// TestSystemPluginRequiresAuth verifies a privileged system plugin cannot be
// invoked by an anonymous caller unless security.unsafe_allow_system_plugins_anon
// is set, regardless of RBAC.
func TestSystemPluginRequiresAuth(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
load ("testsys.in", "testsys")
app = ace.app("testApp", routes = [ace.api("/", type=ace.TEXT)],
    permissions=[ace.permission("testsys.in", "ping")])

def handler(req):
	return testsys.ping().value
`,
	}
	plugins := []string{"testsys.in"}
	perms := []types.Permission{{Plugin: "testsys.in", Method: "ping"}}

	serve := func(a *app.App, userId string) *httptest.ResponseRecorder {
		request := httptest.NewRequest("GET", "/test", nil)
		if userId != "" {
			ctx := context.WithValue(request.Context(), types.USER_ID, userId)
			request = request.WithContext(ctx)
		}
		response := httptest.NewRecorder()
		a.ServeHTTP(response, request)
		return response
	}

	gate := func(anon bool) *types.ServerConfig {
		sc := &types.ServerConfig{}
		sc.Security.UnsafeAllowSystemPluginsAnon = anon
		return sc
	}

	// Gate on (default): one app covers all three caller cases
	a, _, err := CreateTestAppPluginServerConfig(logger, fileData, plugins, perms, gate(false))
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// Anonymous caller is blocked
	resp := serve(a, types.ANONYMOUS_USER)
	testutil.AssertEqualsInt(t, "anon blocked code", 500, resp.Code)
	testutil.AssertStringContains(t, resp.Body.String(), "plugin testsys.in requires an authenticated user")

	// Missing identity is also treated as anonymous
	resp = serve(a, "")
	testutil.AssertEqualsInt(t, "no-user blocked code", 500, resp.Code)
	testutil.AssertStringContains(t, resp.Body.String(), "requires an authenticated user")

	// An authenticated caller is allowed
	resp = serve(a, "alice@example.com")
	testutil.AssertEqualsInt(t, "authed code", 200, resp.Code)
	testutil.AssertEqualsString(t, "authed body", "pong", resp.Body.String())

	// Gate off (unsafe opt-in): anonymous caller is allowed
	a, _, err = CreateTestAppPluginServerConfig(logger, fileData, plugins, perms, gate(true))
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	resp = serve(a, types.ANONYMOUS_USER)
	testutil.AssertEqualsInt(t, "anon allowed code", 200, resp.Code)
	testutil.AssertEqualsString(t, "anon allowed body", "pong", resp.Body.String())
}
