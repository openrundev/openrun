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
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// Tests for the actions.star and action_params.star convention files: an app
// built from a spec (a root proxy to the upstream, no app.star of its own)
// adds actions and the params they present without copying app.star

// specAppStar is what a proxy spec's app.star looks like: a root proxy and
// the spec's own params (port, app_name), no actions
func specAppStar(upstream string) string {
	return fmt.Sprintf(`
load("proxy.in", "proxy")
app = ace.app(param.app_name,
	routes=[ace.proxy("/", proxy.config(%q))],
	permissions=[ace.permission("proxy.in", "config")])
`, upstream)
}

const specParamsStar = `
param("port", type=INT, description="The port", default=5000)
param("app_name", description="The name for the app", default="Flask App")
`

const specActionsStar = `
load("http.in", "http")

# the param module has the spec params and the action params, with their
# effective values
port_seen = param.port
status_seen = param.status

def orders(dry_run, args):
	if dry_run:
		return ace.result("valid")
	body = http.get(%q + "/internal/orders").value.body()
	return ace.result("fetched", [",".join(sorted(dir(args))), str(port_seen), status_seen, body], ace.TEXT)

def cancel(dry_run, args):
	return ace.result("cancelled " + args.order_id)

actions = [
	ace.action("List Orders", "/orders", orders, description="List the orders"),
	ace.action("Cancel Order", "/orders/cancel", cancel, hidden=["status"]),
]
permissions = [ace.permission("http.in", "get")]
`

const specActionParamsStar = `
param("status", description="Order status", default="open")
param("options_status", type=LIST, default=["open", "closed"])
param("order_id", description="Order to cancel")
`

func newUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "upstream:"+r.URL.Path) //nolint:errcheck
	}))
	t.Cleanup(upstream.Close)
	return upstream
}

// specApp creates the spec-style test app with the given source files, param
// values and mcp document
func specApp(t *testing.T, fileData map[string]string, params map[string]string, mcpDoc string) (*app.App, error) {
	t.Helper()
	if mcpDoc != "" {
		mcpConfig, err := types.ParseMCPConfig(mcpDoc)
		if err != nil {
			t.Fatal(err)
		}
		testMetadataHook = func(metadata *types.AppMetadata) { metadata.MCP = mcpConfig }
		defer func() { testMetadataHook = nil }()
	}
	a, _, err := CreateTestAppInt(testutil.TestLogger(), "/test", "", fileData, false,
		[]string{"proxy.in", "http.in"},
		[]types.Permission{{Plugin: "proxy.in", Method: "config"}, {Plugin: "http.in", Method: "get"}},
		nil, "app_prd_testapp", types.AppSettings{}, params, nil, &testRBAC{})
	return a, err
}

func specFiles(upstream string) map[string]string {
	return map[string]string{
		"app.star":           specAppStar(upstream),
		"params.star":        specParamsStar,
		"actions.star":       fmt.Sprintf(specActionsStar, upstream),
		"action_params.star": specActionParamsStar,
	}
}

func getPath(t *testing.T, a *app.App, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req = req.WithContext(context.WithValue(req.Context(), types.USER_ID, "builtin:alice"))
	resp := httptest.NewRecorder()
	a.ServeHTTP(resp, req)
	return resp.Code, resp.Body.String()
}

func schemaParamNames(t *testing.T, a *app.App, actionPath string) []string {
	t.Helper()
	code, body := getPath(t, a, "/test/api/actions"+actionPath)
	testutil.AssertEqualsInt(t, "schema code", 200, code)
	var schema struct {
		Params []types.ActionParam `json:"params"`
	}
	if err := json.Unmarshal([]byte(body), &schema); err != nil {
		t.Fatalf("schema %s: %s: %s", actionPath, err, body)
	}
	names := []string{}
	for _, p := range schema.Params {
		names = append(names, p.Name)
	}
	return names
}

func TestSpecActionsRoutingAndParams(t *testing.T) {
	upstream := newUpstream(t)
	a, err := specApp(t, specFiles(upstream.URL), map[string]string{"status": "closed"}, `{"source":"actions"}`)
	testutil.AssertNoError(t, err)

	// The proxy keeps everything the actions do not claim; the action paths,
	// the actions API and the MCP region are served by OpenRun
	for path, want := range map[string]string{
		"/test/":            "upstream:/",
		"/test/api2/deep":   "upstream:/api2/deep",
		"/test/static/a.js": "upstream:/static/a.js",
		"/test/orders":      "<!DOCTYPE html>",
		"/test/api":         `"actions":[`,
	} {
		code, body := getPath(t, a, path)
		testutil.AssertEqualsInt(t, path, 200, code)
		if !strings.Contains(body, want) {
			t.Errorf("%s: want %q in %q", path, want, body[:min(len(body), 80)])
		}
	}
	code, _ := getPath(t, a, "/test/mcp")
	testutil.AssertEqualsInt(t, "mcp GET", 405, code)

	// Only the action_params.star params are presented, the spec params are
	// not; the app level value is the default; hidden narrows the visible set
	names := schemaParamNames(t, a, "/orders")
	slices.Sort(names)
	testutil.AssertEqualsString(t, "orders params", "order_id,status", strings.Join(names, ","))
	testutil.AssertEqualsString(t, "cancel params", "order_id", strings.Join(schemaParamNames(t, a, "/orders/cancel"), ","))
	_, body := getPath(t, a, "/test/api/actions/orders")
	if !strings.Contains(body, `"default":"closed"`) {
		t.Errorf("status default should be the app level value: %s", body)
	}
	if !strings.Contains(body, `"options":["open","closed"]`) {
		t.Errorf("options expected: %s", body)
	}

	// MCP tools: the input schema has the action params only; the run sees
	// the action params in args, the spec params through the param module
	// and reaches the upstream
	session := mcpSession(t, a, nil)
	tools, err := session.ListTools(context.Background(), nil)
	testutil.AssertNoError(t, err)
	toolNames := []string{}
	for _, tool := range tools.Tools {
		toolNames = append(toolNames, tool.Name)
		if tool.Name == "orders" {
			props, _ := tool.InputSchema.(map[string]any)["properties"].(map[string]any)
			keys := slices.Sorted(func(yield func(string) bool) {
				for k := range props {
					if !yield(k) {
						return
					}
				}
			})
			testutil.AssertEqualsString(t, "tool schema", "dry_run,order_id,status", strings.Join(keys, ","))
		}
	}
	testutil.AssertEqualsString(t, "tools", "orders orders_cancel", strings.Join(toolNames, " "))

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "orders", Arguments: map[string]any{"order_id": "o1"}})
	testutil.AssertNoError(t, err)
	if result.IsError {
		t.Fatalf("tool error: %s", toolText(result))
	}
	text := toolText(result)
	for _, want := range []string{"order_id,status", "5000", "closed", "upstream:/internal/orders"} {
		if !strings.Contains(text, want) {
			t.Errorf("want %q in tool result: %s", want, text)
		}
	}
	if strings.Contains(text, "port") && !strings.Contains(text, "5000") {
		t.Errorf("spec params should not be in args: %s", text)
	}
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "orders_cancel", Arguments: map[string]any{"order_id": "o7"}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "cancel", "cancelled o7", strings.TrimSpace(toolText(result)))
}

func TestSpecActionsAudit(t *testing.T) {
	upstream := newUpstream(t)
	a, err := specApp(t, specFiles(upstream.URL), nil, "")
	testutil.AssertNoError(t, err)

	// The permissions and plugin loads of actions.star are part of the
	// approval, after the app.star entries
	result, err := a.Audit()
	testutil.AssertNoError(t, err)
	perms := []string{}
	for _, p := range result.NewPermissions {
		perms = append(perms, p.Plugin+"."+p.Method)
	}
	testutil.AssertEqualsString(t, "permissions", "proxy.in.config http.in.get", strings.Join(perms, " "))
	slices.Sort(result.NewLoads)
	testutil.AssertEqualsString(t, "loads", "http.in proxy.in", strings.Join(result.NewLoads, " "))

	// Without the http.in permission approved, the audit asks for approval
	b, _, err := CreateTestAppInt(testutil.TestLogger(), "/test", "", specFiles(upstream.URL), false,
		[]string{"proxy.in", "http.in"}, []types.Permission{{Plugin: "proxy.in", Method: "config"}},
		nil, "app_prd_testapp2", types.AppSettings{}, nil, nil, &testRBAC{})
	testutil.AssertNoError(t, err)
	result, err = b.Audit()
	testutil.AssertNoError(t, err)
	if !result.NeedsApproval {
		t.Error("approval expected for the http.in permission of actions.star")
	}
}

// The actions in app.star are subject to action_params.star too: the visible
// set is an app wide rule
func TestActionParamsWithAppStarActions(t *testing.T) {
	fileData := map[string]string{
		"app.star": `
def orders(dry_run, args):
	return ace.result("ok", [",".join(sorted(dir(args)))], ace.TEXT)
app = ace.app("testApp", actions=[ace.action("Orders", "/orders", orders)])
`,
		"params.star":        `param("count", type=INT, default=2)`,
		"action_params.star": `param("status", default="open")`,
	}
	a, _, err := CreateTestAppPlugin(testutil.TestLogger(), fileData, nil, nil, nil)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "params", "status", strings.Join(schemaParamNames(t, a, "/orders"), ","))
}

// Without action_params.star nothing changes: every params.star param is an
// action param, and actions.star alone adds actions to an app.star app
func TestActionsFileWithoutActionParams(t *testing.T) {
	fileData := map[string]string{
		"app.star": `app = ace.app("testApp", actions=[ace.action("First", "/first", lambda dry_run, args: ace.result("first"))])`,
		"actions.star": `
def second(dry_run, args):
	return ace.result("second " + str(args.count))
actions = [ace.action("Second", "/second", second, hidden=["status"])]
`,
		"params.star": `
param("count", type=INT, default=2)
param("status", default="open")
`,
	}
	a, _, err := CreateTestAppPlugin(testutil.TestLogger(), fileData, nil, nil, nil)
	testutil.AssertNoError(t, err)
	names := schemaParamNames(t, a, "/first")
	slices.Sort(names)
	testutil.AssertEqualsString(t, "first params", "count,status", strings.Join(names, ","))
	testutil.AssertEqualsString(t, "second params", "count", strings.Join(schemaParamNames(t, a, "/second"), ","))
	code, body := getPath(t, a, "/test/api")
	testutil.AssertEqualsInt(t, "describe", 200, code)
	if !strings.Contains(body, `"name":"First"`) || !strings.Contains(body, `"name":"Second"`) {
		t.Errorf("both actions expected: %s", body)
	}
}

func TestSpecActionsErrors(t *testing.T) {
	upstream := newUpstream(t)
	base := specFiles(upstream.URL)
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no actions global", map[string]string{"actions.star": `x = 1`}, "actions.star must define actions = [...]"},
		{"actions not a list", map[string]string{"actions.star": `actions = 1`}, "actions.star: actions is not a list"},
		{"entry not an action", map[string]string{"actions.star": `actions = [ace.permission("http.in", "get")]`}, "actions entry 0 is not an ace.action"},
		{"permission not a permission", map[string]string{"actions.star": `
actions = [ace.action("A", "/a", lambda dry_run, args: ace.result("a"))]
permissions = [ace.action("A", "/a", lambda dry_run, args: ace.result("a"))]`}, "permissions entry 0 is not an ace.permission"},
		{"param in both files", map[string]string{"action_params.star": `param("port", type=INT, default=1)`}, "param port is defined in both params.star and action_params.star"},
		{"hidden outside action params", map[string]string{"actions.star": `
actions = [ace.action("A", "/a", lambda dry_run, args: ace.result("a"), hidden=["port"])]`}, "action A: hidden param port is not defined in action_params.star"},
		{"root action with root proxy", map[string]string{"actions.star": `
actions = [ace.action("A", "/", lambda dry_run, args: ace.result("a"))]`}, "a root action cannot share the app root with the proxy route at /"},
		{"load error", map[string]string{"actions.star": `actions = [undefined_name]`}, "error loading actions.star"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{}
			for k, v := range base {
				files[k] = v
			}
			for k, v := range c.files {
				files[k] = v
			}
			_, err := specApp(t, files, nil, "")
			testutil.AssertErrorContains(t, err, c.want)
		})
	}
}

// The load checks are applied by the audit too, so app create and update
// fail instead of the first request
func TestSpecActionsAuditChecks(t *testing.T) {
	upstream := newUpstream(t)
	base := specFiles(upstream.URL)
	for _, c := range []struct{ name, actions, want string }{
		{"hidden", `actions = [ace.action("A", "/a", lambda dry_run, args: ace.result("a"), hidden=["port"])]`,
			"action A: hidden param port is not defined in action_params.star"},
		{"root", `actions = [ace.action("A", "/", lambda dry_run, args: ace.result("a"))]`,
			"a root action cannot share the app root with the proxy route at /"},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{}
			for k, v := range base {
				files[k] = v
			}
			files["actions.star"] = c.actions
			// The app loads lazily in the test helper only when the definition
			// is valid, the audit runs on the source regardless
			a, _, err := CreateTestAppInt(testutil.TestLogger(), "/test", "", files, false,
				[]string{"proxy.in", "http.in"}, []types.Permission{{Plugin: "proxy.in", Method: "config"}},
				nil, "app_prd_testapp3", types.AppSettings{}, nil, nil, &testRBAC{})
			if err != nil {
				testutil.AssertErrorContains(t, err, c.want)
				return
			}
			_, err = a.Audit()
			testutil.AssertErrorContains(t, err, c.want)
		})
	}
}

// A required action param without a default and without an app level value
// is supplied per invocation, the app loads; the same for a params.star
// param is a load error as before
func TestRequiredActionParamLoads(t *testing.T) {
	upstream := newUpstream(t)
	files := specFiles(upstream.URL)
	files["action_params.star"] = `
param("status", default="open")
param("order_id", description="Order to cancel", required=True)
`
	_, err := specApp(t, files, nil, "")
	testutil.AssertNoError(t, err)

	files["params.star"] = specParamsStar + `param("region", required=True)`
	_, err = specApp(t, files, nil, "")
	testutil.AssertErrorContains(t, err, "param region is a required param")
}

// A required action param without a value is refused before the handler
// runs: a correctable tool error on MCP, 422 on the REST API (run and
// validate), never a None in args
func TestRequiredActionParamEnforced(t *testing.T) {
	upstream := newUpstream(t)
	files := specFiles(upstream.URL)
	files["action_params.star"] = `
param("status", default="open")
param("order_id", description="Order to cancel")
param("note", description="Optional note", required=False)
`
	a, err := specApp(t, files, nil, `{"source":"actions"}`)
	testutil.AssertNoError(t, err)

	session := mcpSession(t, a, nil)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "orders_cancel", Arguments: map[string]any{}})
	testutil.AssertNoError(t, err)
	if !result.IsError || !strings.Contains(toolText(result), "param order_id: param order_id is required") {
		t.Errorf("tool error expected for the missing order_id: %v %s", result.IsError, toolText(result))
	}
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "orders_cancel", Arguments: map[string]any{"order_id": "o9"}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "cancel", "cancelled o9", strings.TrimSpace(toolText(result)))

	post := func(path, body string) (int, string) {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), types.USER_ID, "builtin:alice"))
		resp := httptest.NewRecorder()
		a.ServeHTTP(resp, req)
		return resp.Code, resp.Body.String()
	}
	for _, path := range []string{"/test/api/actions/orders/cancel", "/test/api/validate/orders/cancel"} {
		code, body := post(path, `{}`)
		testutil.AssertEqualsInt(t, path, 422, code)
		if !strings.Contains(body, "param order_id is required") {
			t.Errorf("%s: %s", path, body)
		}
		code, body = post(path, `{"order_id": ""}`)
		testutil.AssertEqualsInt(t, path+" empty", 422, code)
		if !strings.Contains(body, "param order_id is required") {
			t.Errorf("%s empty: %s", path, body)
		}
	}
	code, body := post("/test/api/actions/orders/cancel", `{"order_id": "o3"}`)
	testutil.AssertEqualsInt(t, "run", 200, code)
	if !strings.Contains(body, "cancelled o3") {
		t.Errorf("run: %s", body)
	}
}

// The actions MCP validation at create time (auditActionsMCP) counts the
// actions of actions.star
func TestSpecActionsMCPAudit(t *testing.T) {
	upstream := newUpstream(t)
	a, err := specApp(t, specFiles(upstream.URL), nil, `{"source":"actions"}`)
	testutil.AssertNoError(t, err)
	_, err = a.Audit()
	testutil.AssertNoError(t, err)

	files := specFiles(upstream.URL)
	files["actions.star"] = `
actions = [ace.action("A", "/mcp", lambda dry_run, args: ace.result("a"))]`
	_, err = specApp(t, files, nil, `{"source":"actions"}`)
	testutil.AssertErrorContains(t, err, "action path /mcp is not allowed, /mcp is the MCP endpoint of the app")
}
