// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

type testDisallowPlugin struct{}

func (p *testDisallowPlugin) Run(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.String("ran"), nil
}

func (p *testDisallowPlugin) Other(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.String("other"), nil
}

func init() {
	p := &testDisallowPlugin{}
	app.RegisterPlugin("testdis", func(pluginContext *types.PluginContext) (any, error) {
		return &testDisallowPlugin{}, nil
	}, []plugin.PluginFunc{
		app.CreatePluginApiName(p.Run, app.READ, "run"),
		app.CreatePluginApiName(p.Other, app.READ, "other"),
	})
}

// TestPluginDisallow verifies that a server config permissions.disallow entry
// blocks matching plugin calls even though the app's permissions approve them
func TestPluginDisallow(t *testing.T) {
	logger := testutil.TestLogger()
	appFile := func(call string) map[string]string {
		return map[string]string{
			"app.star": fmt.Sprintf(`
load ("testdis.in", "testdis")
app = ace.app("testApp", routes = [ace.api("/", type=ace.TEXT)],
    permissions=[
	ace.permission("testdis.in", "run"),
	ace.permission("testdis.in", "other"),
	])

def handler(req):
	return %s.value
`, call),
		}
	}
	plugins := []string{"testdis.in"}
	perms := []types.Permission{
		{Plugin: "testdis.in", Method: "run"},
		{Plugin: "testdis.in", Method: "other"},
	}

	config := func(disallow ...types.Permission) *types.ServerConfig {
		sc := &types.ServerConfig{}
		sc.Permissions.Disallow = disallow
		return sc
	}
	serve := func(a *app.App) *httptest.ResponseRecorder {
		request := httptest.NewRequest("GET", "/test", nil)
		response := httptest.NewRecorder()
		a.ServeHTTP(response, request)
		return response
	}

	tests := []struct {
		name     string
		call     string
		disallow []types.Permission
		blocked  bool
	}{
		{"no disallow entries", `testdis.run("ls")`, nil, false},
		{"plugin wide block, no method", `testdis.run("ls")`,
			[]types.Permission{{Plugin: "testdis.in"}}, true},
		{"plugin wide block covers every method", `testdis.other()`,
			[]types.Permission{{Plugin: "testdis.in"}}, true},
		{"method specific block", `testdis.run("ls")`,
			[]types.Permission{{Plugin: "testdis.in", Method: "run"}}, true},
		{"different method not blocked", `testdis.other()`,
			[]types.Permission{{Plugin: "testdis.in", Method: "run"}}, false},
		{"different plugin not blocked", `testdis.run("ls")`,
			[]types.Permission{{Plugin: "exec.in"}}, false},
		{"argument match blocks", `testdis.run("rm -rf /")`,
			[]types.Permission{{Plugin: "testdis.in", Method: "run", Arguments: []string{"regex:^rm.*"}}}, true},
		{"argument mismatch does not block", `testdis.run("ls")`,
			[]types.Permission{{Plugin: "testdis.in", Method: "run", Arguments: []string{"regex:^rm.*"}}}, false},
		{"more argument patterns than args does not block", `testdis.other()`,
			[]types.Permission{{Plugin: "testdis.in", Method: "other", Arguments: []string{"x"}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _, err := CreateTestAppPluginServerConfig(logger, appFile(tt.call), plugins, perms, config(tt.disallow...))
			if err != nil {
				t.Fatalf("Error %s", err)
			}
			resp := serve(a)
			if tt.blocked {
				testutil.AssertEqualsInt(t, "blocked code", 500, resp.Code)
				testutil.AssertStringContains(t, resp.Body.String(), "disallowed by the server config (permissions.disallow)")
			} else {
				testutil.AssertEqualsInt(t, "allowed code", 200, resp.Code)
			}
		})
	}
}
