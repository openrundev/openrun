// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

type testDisallowPlugin struct{}

func (p *testDisallowPlugin) InitModule(ctx context.Context, init sdk.ModuleInit) error { return nil }
func (p *testDisallowPlugin) Close(ctx context.Context) error                           { return nil }

func (p *testDisallowPlugin) Run(ctx context.Context, call *sdk.Call) (any, error) {
	return "ran", nil
}

func (p *testDisallowPlugin) Other(ctx context.Context, call *sdk.Call) (any, error) {
	return "other", nil
}

func init() {
	app.RegisterLocalProvider("testdis", &sdk.ServeConfig{
		ProviderVersion: "test",
		Modules: map[string]sdk.ModuleDef{
			"testdis": {
				Builder: func() sdk.Module { return &testDisallowPlugin{} },
				Functions: []sdk.FuncDef{
					{Name: "run", Type: sdk.READ, Method: "Run"},
					{Name: "other", Type: sdk.READ, Method: "Other"},
				},
			},
		},
	}, app.LocalProviderOptions{})
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
		// GHSA-qgqh-4fgp-rf5c: a restricted argument passed by keyword used to
		// skip the entry; the patterns cannot see keyword values, so block
		{"keyword argument in place of a patterned positional blocks", `testdis.run(cmd="ls")`,
			[]types.Permission{{Plugin: "testdis.in", Method: "run", Arguments: []string{"regex:^rm.*"}}}, true},
		{"keyword arguments beyond the patterned positionals are checked normally", `testdis.run("ls", env={"a": "b"})`,
			[]types.Permission{{Plugin: "testdis.in", Method: "run", Arguments: []string{"regex:^rm.*"}}}, false},
		{"regex method matches", `testdis.run("ls")`,
			[]types.Permission{{Plugin: "testdis.in", Method: "regex:^r.*"}}, true},
		{"regex method mismatch does not block", `testdis.other()`,
			[]types.Permission{{Plugin: "testdis.in", Method: "regex:^r.*"}}, false},
		// GHSA-qgqh-4fgp-rf5c: the raw text does not match, the resolved
		// template does (the dead-branch secret call makes the string a
		// template without needing a secret grant)
		{"template-resolved argument blocks", `testdis.run(ace.eval('r{{if false}}{{secret "x"}}{{end}}m -rf /'))`,
			[]types.Permission{{Plugin: "testdis.in", Method: "run", Arguments: []string{"regex:^rm.*"}}}, true},
		{"template-resolved list element blocks", `testdis.run("ls", [ace.eval('r{{if false}}{{secret "x"}}{{end}}m')])`,
			[]types.Permission{{Plugin: "testdis.in", Method: "run", Arguments: []string{"ls", "regex:rm"}}}, true},
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

// TestPluginArgRecheck verifies the approval side of GHSA-qgqh-4fgp-rf5c: the
// argument patterns of the permission that approved a call are re-checked on
// the template-resolved values, and a regex: method approves by pattern
func TestPluginArgRecheck(t *testing.T) {
	logger := testutil.TestLogger()
	appFile := func(call string) map[string]string {
		return map[string]string{
			"app.star": fmt.Sprintf(`
load ("testdis.in", "testdis")
app = ace.app("testApp", routes = [ace.api("/", type=ace.TEXT)],
    permissions=[
	ace.permission("testdis.in", "run", arguments=["regex:^[^;]*$"]),
	ace.permission("testdis.in", "other"),
	])

def handler(req):
	return %s.value
`, call),
		}
	}
	plugins := []string{"testdis.in"}
	serve := func(a *app.App) *httptest.ResponseRecorder {
		request := httptest.NewRequest("GET", "/test", nil)
		response := httptest.NewRecorder()
		a.ServeHTTP(response, request)
		return response
	}

	noSemicolon := []types.Permission{{Plugin: "testdis.in", Method: "run", Arguments: []string{"regex:^[^;]*$"}}}
	tests := []struct {
		name     string
		call     string
		perms    []types.Permission
		code     int
		contains string
	}{
		{"plain argument approved", `testdis.run("ls")`, noSemicolon, 200, "ran"},
		{"plain argument rejected", `testdis.run("ls; rm")`, noSemicolon, 500, "with argument 0 having value"},
		// The raw text has no ";" (the template writes one through a Go
		// string escape), the resolved value does
		{"template-resolved argument rejected", `testdis.run(ace.eval('ls{{if false}}{{secret "x"}}{{end}}{{"\\x3b"}} rm'))`,
			noSemicolon, 500, "template-resolved argument 0 does not match the approved pattern \"regex:^[^;]*$\""},
		{"template-resolved argument approved", `testdis.run(ace.eval('ls{{if false}}{{secret "x"}}{{end}} -l'))`,
			noSemicolon, 200, "ran"},
		{"regex method approves run", `testdis.run("ls")`,
			[]types.Permission{{Plugin: "testdis.in", Method: "regex:.*"}}, 200, "ran"},
		{"regex method approves other", `testdis.other()`,
			[]types.Permission{{Plugin: "testdis.in", Method: "regex:.*"}}, 200, "other"},
		{"regex method mismatch not approved", `testdis.other()`,
			[]types.Permission{{Plugin: "testdis.in", Method: "regex:^r.*"}}, 500, "is not permitted to call testdis.in.other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _, err := CreateTestAppPluginServerConfig(logger, appFile(tt.call), plugins, tt.perms, &types.ServerConfig{})
			if err != nil {
				t.Fatalf("Error %s", err)
			}
			resp := serve(a)
			testutil.AssertEqualsInt(t, "code", tt.code, resp.Code)
			testutil.AssertStringContains(t, resp.Body.String(), tt.contains)
		})
	}
}

// TestPluginDisallowAccountSuffix verifies that a disallow entry for a plugin
// also blocks the plugin when it is loaded with an account suffix
func TestPluginDisallowAccountSuffix(t *testing.T) {
	logger := testutil.TestLogger()
	files := map[string]string{
		"app.star": `
load ("testdis.in#acct", "testdis")
app = ace.app("testApp", routes = [ace.api("/", type=ace.TEXT)],
    permissions=[ace.permission("testdis.in#acct", "run")])

def handler(req):
	return testdis.run("ls").value
`,
	}
	plugins := []string{"testdis.in#acct"}
	perms := []types.Permission{{Plugin: "testdis.in#acct", Method: "run"}}
	serve := func(disallow ...types.Permission) *httptest.ResponseRecorder {
		t.Helper()
		sc := &types.ServerConfig{}
		sc.Permissions.Disallow = disallow
		a, _, err := CreateTestAppPluginServerConfig(logger, files, plugins, perms, sc)
		if err != nil {
			t.Fatalf("Error %s", err)
		}
		response := httptest.NewRecorder()
		a.ServeHTTP(response, httptest.NewRequest("GET", "/test", nil))
		return response
	}

	testutil.AssertEqualsInt(t, "no disallow", 200, serve().Code)
	testutil.AssertEqualsInt(t, "other account", 200, serve(types.Permission{Plugin: "testdis.in#other"}).Code)
	for _, entry := range []types.Permission{{Plugin: "testdis.in", Method: "run"}, {Plugin: "testdis.in#acct"}} {
		resp := serve(entry)
		testutil.AssertEqualsInt(t, "blocked code "+entry.Plugin, 500, resp.Code)
		testutil.AssertStringContains(t, resp.Body.String(), "disallowed by the server config (permissions.disallow)")
	}
}
