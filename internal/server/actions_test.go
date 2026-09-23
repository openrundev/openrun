// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// App actions through the management API (the openrun action commands) and
// through the per app MCP endpoint (mcp source actions)

const actionsTestAppStar = `
load("exec.in", "exec")

def orders(dry_run, args):
	if args.count < 1:
		return ace.result("Validation failed", param_errors={"count": "count must be positive"})
	if dry_run:
		return ace.result("valid")
	return ace.result("Listed %d orders" % args.count, [{"id": i, "status": args.status} for i in range(args.count)], ace.TABLE)

def orders_suggest(args):
	return {"status": "open"}

def restricted(dry_run, args):
	return ace.result("secret done")

def stream(dry_run, args):
	return ace.result("Streaming", stream=exec.run("sh", ["-c", "echo one; echo two; exit " + str(args.count)], stream=True))

app = ace.app("ops", actions=[
	ace.action("List Orders", "/", orders, suggest=orders_suggest, description="List the orders"),
	ace.action("Restricted", "/restricted", restricted, permit=["ops_admin"], hidden=["count", "status"]),
	ace.action("Stream", "/stream", stream, hidden=["status"]),
], permissions=[ace.permission("exec.in", "run")])
`

const actionsTestParamsStar = `
param("count", type=INT, description="Number of orders", default=2)
param("status", description="Order status", default="open")
`

func createActionsTestApp(t *testing.T, server *Server, appPath, auth, mcpDoc string) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"app.star": actionsTestAppStar, "params.star": actionsTestParamsStar} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	ctx := system.WithTrustedOperation(t.Context())
	if _, err := server.CreateApp(ctx, appPath, true, false, &types.CreateAppRequest{
		SourceUrl: dir, AppAuthn: types.AppAuthnType(auth), MCP: mcpDoc}); err != nil {
		t.Fatalf("create actions app: %v", err)
	}
	server.apps.ResetAllAppCache()
}

// newActionsTestServer: alice is a developer on /apps/**, carol a user with
// the ops_admin custom permission, dave (another login provider) a user, bob
// has no grant
func newActionsTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	server, ts, _ := newMCPAppTestServer(t)
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Roles: map[string][]types.RBACPermission{"ops": {"custom:ops_admin"}},
		Grants: []types.RBACGrant{
			{Description: "alice dev", Users: []string{"builtin:alice"}, Roles: []string{"openrun-developer"}, Targets: []string{"/apps/**"}},
			{Description: "carol user and ops", Users: []string{"builtin:carol"}, Roles: []string{"openrun-user", "ops"}, Targets: []string{"/apps/**"}},
			{Description: "dave user", Users: []string{"okta:dave"}, Roles: []string{"openrun-user"}, Targets: []string{"/apps/**"}},
		},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	return server, ts
}

// userApiCtx is the context of a remote management API call by the user
func userApiCtx(t *testing.T, server *Server, user string) context.Context {
	t.Helper()
	ctx, err := server.asUserRequestContext(t.Context(), user)
	if err != nil {
		// Not a builtin user known to the config: same context, no groups
		return &managementAPIContext{Context: t.Context(), userId: user, groups: []string{}, rbacEnabled: true}
	}
	return ctx
}

func actionTools(resp *types.ActionListResponse) string {
	names := []string{}
	for _, info := range resp.Actions {
		names = append(names, info.AppPath+":"+info.Tool)
	}
	return strings.Join(names, ",")
}

func requestErrorCode(t *testing.T, err error) int {
	t.Helper()
	reqErr, ok := err.(types.RequestError)
	if !ok {
		t.Fatalf("expected a request error, got %v", err)
	}
	return reqErr.Code
}

func TestActionsListAndAuthorization(t *testing.T) {
	server, _ := newActionsTestServer(t)
	createActionsTestApp(t, server, "/apps/ops", "builtin", "")
	createActionsTestApp(t, server, "/apps/sysops", "system", "")
	createActionsTestApp(t, server, "/apps/open", "none", "")

	// The trusted admin (unix socket) sees every action
	resp, err := server.ListActions(system.WithTrustedOperation(t.Context()), "/apps/**")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "admin actions", 9, len(resp.Actions))

	// alice: the builtin app and the auth none app, without the permit restricted
	// action; the system auth app is for the admin only
	resp, err = server.ListActions(userApiCtx(t, server, "builtin:alice"), "/apps/**")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "alice actions",
		"/apps/open:list_orders,/apps/open:stream,/apps/ops:list_orders,/apps/ops:stream", actionTools(resp))
	info := resp.Actions[2]
	testutil.AssertEqualsString(t, "name", "List Orders", info.Name)
	testutil.AssertEqualsString(t, "path", "/", info.Path)
	testutil.AssertEqualsBool(t, "suggest", true, info.Suggest)

	// carol holds the custom permission
	resp, err = server.ListActions(userApiCtx(t, server, "builtin:carol"), "/apps/ops")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "carol actions", "/apps/ops:list_orders,/apps/ops:restricted,/apps/ops:stream", actionTools(resp))

	// dave logs in through another provider: only the auth none app
	resp, err = server.ListActions(userApiCtx(t, server, "okta:dave"), "/apps/**")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "dave actions", "/apps/open:list_orders,/apps/open:stream", actionTools(resp))

	// bob has no app:access
	resp, err = server.ListActions(userApiCtx(t, server, "builtin:bob"), "/apps/**")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "bob actions", 0, len(resp.Actions))

	// The same checks are errors for a specific action
	_, err = server.GetAction(userApiCtx(t, server, "okta:dave"), "/apps/ops", "list_orders", false)
	testutil.AssertEqualsInt(t, "provider mismatch", http.StatusForbidden, requestErrorCode(t, err))
	testutil.AssertErrorContains(t, err, `app /apps/ops uses login builtin, you are logged in as okta:dave: run "openrun login --auth builtin"`)

	_, err = server.GetAction(userApiCtx(t, server, "builtin:alice"), "/apps/sysops", "list_orders", false)
	testutil.AssertEqualsInt(t, "system auth", http.StatusForbidden, requestErrorCode(t, err))
	testutil.AssertErrorContains(t, err, "by the admin user only")

	_, err = server.GetAction(userApiCtx(t, server, "builtin:bob"), "/apps/ops", "list_orders", false)
	testutil.AssertEqualsInt(t, "no app:access", http.StatusForbidden, requestErrorCode(t, err))
	testutil.AssertErrorContains(t, err, "app:access")

	// Without the permit the action is not found, as a missing one
	_, err = server.GetAction(userApiCtx(t, server, "builtin:alice"), "/apps/ops", "restricted", false)
	testutil.AssertEqualsInt(t, "no permit", http.StatusNotFound, requestErrorCode(t, err))
	_, err = server.GetAction(userApiCtx(t, server, "builtin:alice"), "/apps/ops", "nosuch", false)
	testutil.AssertEqualsInt(t, "missing action", http.StatusNotFound, requestErrorCode(t, err))
	_, err = server.GetAction(userApiCtx(t, server, "builtin:alice"), "/apps/ops", "", false)
	testutil.AssertEqualsInt(t, "selector needed", http.StatusBadRequest, requestErrorCode(t, err))

	detail, err := server.GetAction(userApiCtx(t, server, "builtin:alice"), "/apps/ops", "/", false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "detail tool", "list_orders", detail.Tool)
	testutil.AssertEqualsInt(t, "detail params", 2, len(detail.Params))
	if detail.InputSchema["properties"].(map[string]any)["count"] == nil {
		t.Fatalf("input schema: %v", detail.InputSchema)
	}

	// The OpenAPI spec leaves out what the caller cannot run
	spec, err := server.ActionsOpenAPI(userApiCtx(t, server, "builtin:alice"), "/apps/ops", false)
	testutil.AssertNoError(t, err)
	paths := spec.(map[string]any)["paths"].(map[string]any)
	if paths["/apps/ops/api/actions"] == nil || paths["/apps/ops/api/actions/restricted"] != nil {
		t.Fatalf("openapi paths: %v", paths)
	}
}

func TestActionsRunOverRest(t *testing.T) {
	server, ts := newActionsTestServer(t)
	createActionsTestApp(t, server, "/apps/ops", "builtin", "")
	mint := func(user string) *system.HttpClient {
		key, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
			&types.ApiKeyCreateRequest{User: user, Resources: []string{ApiResourceRest}})
		if err != nil {
			t.Fatalf("key for %s: %v", user, err)
		}
		return remoteClient(ts, key.Key)
	}
	alice, carol := mint("builtin:alice"), mint("builtin:carol")

	var list types.ActionListResponse
	testutil.AssertNoError(t, alice.Get("/_openrun/actions", url.Values{"appPathGlob": {"/apps/ops"}}, &list))
	testutil.AssertEqualsString(t, "rest list", "/apps/ops:list_orders,/apps/ops:stream", actionTools(&list))

	run := func(client *system.HttpClient, apiPath, body string) (*http.Response, string) {
		t.Helper()
		resp, err := client.PostRaw(t.Context(), apiPath, nil, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %s: %v", apiPath, err)
		}
		defer resp.Body.Close() //nolint:errcheck
		data, _ := io.ReadAll(resp.Body)
		return resp, string(data)
	}

	// String args are coerced, the result is the REST API document
	resp, body := run(alice, "/_openrun/actions/run", `{"app_path":"/apps/ops","action":"list_orders","args":{"count":"3","status":"closed"}}`)
	testutil.AssertEqualsInt(t, "run status", http.StatusOK, resp.StatusCode)
	var result types.ActionResult
	testutil.AssertNoError(t, json.Unmarshal([]byte(body), &result))
	testutil.AssertEqualsString(t, "status", "Listed 3 orders", result.Status)
	testutil.AssertEqualsString(t, "report", "TABLE", result.Report)
	testutil.AssertEqualsInt(t, "values", 3, len(result.Values))

	// Param errors: 422; dry_run validates
	resp, body = run(alice, "/_openrun/actions/run", `{"app_path":"/apps/ops","action":"list_orders","args":{"count":0}}`)
	testutil.AssertEqualsInt(t, "param error status", http.StatusUnprocessableEntity, resp.StatusCode)
	testutil.AssertStringContains(t, body, "count must be positive")
	resp, body = run(alice, "/_openrun/actions/run", `{"app_path":"/apps/ops","action":"list_orders","dry_run":true}`)
	testutil.AssertEqualsInt(t, "dry run status", http.StatusOK, resp.StatusCode)
	testutil.AssertStringContains(t, body, `"status":"valid"`)
	if strings.Contains(body, `"values"`) {
		t.Fatalf("dry run returned values: %s", body)
	}

	// Bad args and a missing permit
	resp, body = run(alice, "/_openrun/actions/run", `{"app_path":"/apps/ops","action":"list_orders","args":{"bogus":1}}`)
	testutil.AssertEqualsInt(t, "unknown arg", http.StatusBadRequest, resp.StatusCode)
	testutil.AssertStringContains(t, body, "unknown param bogus")
	resp, _ = run(alice, "/_openrun/actions/run", `{"app_path":"/apps/ops","action":"restricted"}`)
	testutil.AssertEqualsInt(t, "no permit", http.StatusNotFound, resp.StatusCode)
	resp, body = run(carol, "/_openrun/actions/run", `{"app_path":"/apps/ops","action":"restricted"}`)
	testutil.AssertEqualsInt(t, "with permit", http.StatusOK, resp.StatusCode)
	testutil.AssertStringContains(t, body, "secret done")

	// Suggest
	resp, body = run(alice, "/_openrun/actions/suggest", `{"app_path":"/apps/ops","action":"list_orders"}`)
	testutil.AssertEqualsInt(t, "suggest status", http.StatusOK, resp.StatusCode)
	testutil.AssertStringContains(t, body, `"status":"open"`)
	resp, _ = run(alice, "/_openrun/actions/suggest", `{"app_path":"/apps/ops","action":"stream"}`)
	testutil.AssertEqualsInt(t, "no suggest handler", http.StatusNotImplemented, resp.StatusCode)

	// A stream result: chunked text, the status header and the exit trailer
	resp, body = run(alice, "/_openrun/actions/run", `{"app_path":"/apps/ops","action":"stream","args":{"count":4}}`)
	testutil.AssertEqualsInt(t, "stream status", http.StatusOK, resp.StatusCode)
	testutil.AssertStringContains(t, resp.Header.Get("Content-Type"), "text/plain")
	testutil.AssertEqualsString(t, "stream body", "one\ntwo\n", body)
	testutil.AssertEqualsString(t, "status header", "Streaming", resp.Header.Get(types.ACTION_STATUS_HEADER))
	testutil.AssertEqualsString(t, "exit trailer", "4", resp.Trailer.Get(types.ACTION_EXIT_TRAILER))

	// The action audit event carries the caller and the mgmt operation (the
	// audit writer is asynchronous)
	found := false
	for i := 0; i < 100 && !found; i++ {
		var count int
		row := server.auditDB.QueryRow(`select count(*) from audit where event_type = 'action' and operation = 'mgmt_execute' and user_id = 'builtin:alice' and target = 'List Orders'`)
		testutil.AssertNoError(t, row.Scan(&count))
		found = count > 0
		if !found {
			time.Sleep(20 * time.Millisecond)
		}
	}
	testutil.AssertEqualsBool(t, "mgmt_execute audit event", true, found)
}

func TestActionsManagementMCPTool(t *testing.T) {
	server, _ := newActionsTestServer(t)
	createActionsTestApp(t, server, "/apps/ops", "builtin", "")
	ctx := userApiCtx(t, server, "builtin:alice")

	out, err := server.mcpInvokeAction(ctx, "/apps/ops", "list_orders", false, false, false, map[string]any{"count": 2}, 0)
	testutil.AssertNoError(t, err)
	doc := out.(map[string]any)
	testutil.AssertEqualsString(t, "status", "Listed 2 orders", doc["status"].(string))

	// Param errors are part of the result document
	out, err = server.mcpInvokeAction(ctx, "/apps/ops", "list_orders", false, false, false, map[string]any{"count": 0}, 0)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "param error", "count must be positive", out.(map[string]any)["param_errors"].(map[string]string)["count"])

	// A stream is consumed to completion
	out, err = server.mcpInvokeAction(ctx, "/apps/ops", "stream", false, false, false, map[string]any{"count": 1}, 0)
	testutil.AssertNoError(t, err)
	doc = out.(map[string]any)
	testutil.AssertEqualsString(t, "output", "one\ntwo\n", doc["output"].(string))
	testutil.AssertEqualsInt(t, "exit status", 1, doc["exit_status"].(int))

	out, err = server.mcpInvokeAction(ctx, "/apps/ops", "list_orders", false, false, true, nil, 0)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "suggest", "open", out.(map[string]any)["params"].(map[string]any)["status"].(string))

	_, err = server.mcpInvokeAction(ctx, "/apps/ops", "restricted", false, false, false, nil, 0)
	testutil.AssertEqualsInt(t, "no permit", http.StatusNotFound, requestErrorCode(t, err))
}

// bearerTransport adds the bearer token to the MCP client's requests
type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (b *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(req)
}

func TestActionsMCPEndpoint(t *testing.T) {
	server, ts := newActionsTestServer(t)
	createActionsTestApp(t, server, "/apps/ops", "builtin",
		`{"source":"actions","scopes":["orders:read","orders:admin"],"default_scope":"orders:read","tools":{"restricted":"orders:admin"}}`)

	// The form UI stays beside the endpoint: a human login, not a bearer challenge
	resp, err := ts.Client().Get(ts.URL + "/apps/ops/")
	testutil.AssertNoError(t, err)
	resp.Body.Close() //nolint:errcheck
	if resp.Header.Get("WWW-Authenticate") != "" && strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("the app root answered with a bearer challenge: %s", resp.Header.Get("WWW-Authenticate"))
	}

	// The endpoint is bearer only, the resource is the /mcp region
	tsURL, _ := url.Parse(ts.URL)
	resp = mcpCall(t, ts, "/apps/ops/mcp", "", nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "no token", http.StatusUnauthorized, resp.StatusCode)
	testutil.AssertStringContains(t, resp.Header.Get("WWW-Authenticate"),
		`resource_metadata="https://localhost:`+tsURL.Port()+`/.well-known/oauth-protected-resource/apps/ops/mcp"`)

	mintApp := func(user string, scopes ...string) string {
		key, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
			&types.ApiKeyCreateRequest{User: user, Resources: []string{"app:/apps/ops"}, Scopes: scopes})
		if err != nil {
			t.Fatalf("app key for %s: %v", user, err)
		}
		return key.Key
	}
	connect := func(token string) *mcp.ClientSession {
		httpClient := &http.Client{Transport: &bearerTransport{base: ts.Client().Transport, token: token}}
		client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
		session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: ts.URL + "/apps/ops/mcp", HTTPClient: httpClient}, nil)
		if err != nil {
			t.Fatalf("mcp connect: %v", err)
		}
		t.Cleanup(func() { session.Close() }) //nolint:errcheck
		return session
	}
	toolNames := func(session *mcp.ClientSession) string {
		tools, err := session.ListTools(t.Context(), nil)
		testutil.AssertNoError(t, err)
		names := []string{}
		for _, tool := range tools.Tools {
			names = append(names, tool.Name)
		}
		return strings.Join(names, ",")
	}

	// alice: the tools her permits allow, run as alice
	session := connect(mintApp("builtin:alice"))
	testutil.AssertEqualsString(t, "alice tools", "list_orders,list_orders_suggest,stream", toolNames(session))
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_orders", Arguments: map[string]any{"count": 1}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "isError", false, result.IsError)
	testutil.AssertStringContains(t, result.Content[0].(*mcp.TextContent).Text, "Listed 1 orders")

	// carol holds the permit
	session = connect(mintApp("builtin:carol"))
	testutil.AssertEqualsString(t, "carol tools", "list_orders,list_orders_suggest,restricted,stream", toolNames(session))
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "restricted"})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, result.Content[0].(*mcp.TextContent).Text, "secret done")

	// The app's tool scope map applies to the action tools: step-up challenge
	resp = mcpCall(t, ts, "/apps/ops/mcp", mintApp("builtin:carol", "orders:read"), nil,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"restricted","arguments":{}}}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "scope step-up", http.StatusForbidden, resp.StatusCode)
	testutil.AssertStringContains(t, resp.Header.Get("WWW-Authenticate"), `scope="orders:admin"`)

	// bob has no app:access
	resp = mcpCall(t, ts, "/apps/ops/mcp", mintApp("builtin:bob"), nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "no app:access", http.StatusForbidden, resp.StatusCode)
}

func TestActionsLoginMechanismHint(t *testing.T) {
	server, ts, client := newOAuthTestServer(t)
	_ = server
	// A mechanism which is not a federated login of the resource is ignored:
	// the login page is shown
	resp, err := client.Get(ts.URL + "/_openrun/oauth/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"}, "redirect_uri": {"http://127.0.0.1:9999/callback"},
		"code_challenge": {"abc"}, "code_challenge_method": {"S256"}, "resource": {ts.URL + "/_openrun/rest"},
		"mechanism": {"saml_nosuch"},
	}.Encode())
	testutil.AssertNoError(t, err)
	body := readBody(t, resp)
	testutil.AssertEqualsInt(t, "login page", http.StatusOK, resp.StatusCode)
	testutil.AssertStringContains(t, body, "or_username")
}

// The management MCP surface exposes the generic action tools
func TestActionsManagementMCPSession(t *testing.T) {
	server, connect := newMCPTestServer(t)
	createActionsTestApp(t, server, "/apps/ops", "builtin", "")
	session := connect(t, "builtin:alice", []string{"dev"}, nil)

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_actions", Arguments: map[string]any{"path_glob": "/apps/ops"}})
	testutil.AssertNoError(t, err)
	if result.IsError {
		t.Fatalf("list_actions tool error: %s", callToolText(t, result))
	}
	testutil.AssertStringContains(t, callToolText(t, result), `"tool":"list_orders"`)

	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "run_action",
		Arguments: map[string]any{"path": "/apps/ops", "action": "list_orders", "args": map[string]any{"count": 1}}})
	testutil.AssertNoError(t, err)
	if result.IsError {
		t.Fatalf("run_action tool error: %s", callToolText(t, result))
	}
	testutil.AssertStringContains(t, callToolText(t, result), "Listed 1 orders")

	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_action",
		Arguments: map[string]any{"path": "/apps/ops", "action": "list_orders"}})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, callToolText(t, result), `"input_schema"`)
}

// mcp source actions is validated against the app definition when the app is
// created, not at its first request
func TestActionsMCPCreateValidation(t *testing.T) {
	server, _ := newActionsTestServer(t)
	ctx := system.WithTrustedOperation(t.Context())

	emptyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(emptyDir, "app.star"), []byte(`app = ace.app("empty")`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := server.CreateApp(ctx, "/apps/empty", true, false, &types.CreateAppRequest{
		SourceUrl: emptyDir, AppAuthn: "builtin", MCP: `{"source":"actions"}`})
	testutil.AssertErrorContains(t, err, "mcp source actions needs the app to define actions")

	actionsDir := t.TempDir()
	for name, content := range map[string]string{"app.star": actionsTestAppStar, "params.star": actionsTestParamsStar} {
		if err := os.WriteFile(filepath.Join(actionsDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, err = server.CreateApp(ctx, "/apps/clash", true, false, &types.CreateAppRequest{
		SourceUrl: actionsDir, AppAuthn: "builtin", MCP: `{"source":"actions","path":"/stream"}`})
	testutil.AssertErrorContains(t, err, "action path /stream is not allowed, /stream is the MCP endpoint of the app")

	_, err = server.CreateApp(ctx, "/apps/rootmcp", true, false, &types.CreateAppRequest{
		SourceUrl: actionsDir, AppAuthn: "builtin", MCP: `{"source":"actions","path":"/"}`})
	testutil.AssertErrorContains(t, err, "needs a region path other than")
}

// The files of a download result are served through the management API, as
// the calling user: the CLI has no session with the app to fetch them with
func TestActionsResultFile(t *testing.T) {
	server, ts := newActionsTestServer(t)
	dir := t.TempDir()
	appStar := `
def report(dry_run, args):
	return ace.result("Report is ready", [{"name": "report.txt", "url": "static/report.txt"},
		{"name": "elsewhere", "url": "https://example.com/x"}], ace.DOWNLOAD)

def restricted(dry_run, args):
	return ace.result("done", [{"name": "report.txt", "url": "static/report.txt"}], ace.DOWNLOAD)

app = ace.app("files", actions=[ace.action("Report", "/", report),
	ace.action("Restricted", "/restricted", restricted, permit=["ops_admin"])])
`
	if err := os.MkdirAll(filepath.Join(dir, "static"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"app.star": appStar, "static/report.txt": "quarterly numbers\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server.CreateApp(system.WithTrustedOperation(t.Context()), "/apps/files", true, false,
		&types.CreateAppRequest{SourceUrl: dir, AppAuthn: "builtin", MCP: `{"source":"actions"}`}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	server.apps.ResetAllAppCache()

	client := func(user string) *system.HttpClient {
		key, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
			&types.ApiKeyCreateRequest{User: user, Resources: []string{ApiResourceRest}})
		if err != nil {
			t.Fatalf("key for %s: %v", user, err)
		}
		return remoteClient(ts, key.Key)
	}
	fetch := func(c *system.HttpClient, action, fileURL string) (int, string) {
		t.Helper()
		resp, err := c.GetRaw(t.Context(), "/_openrun/actions/file",
			url.Values{"appPath": {"/apps/files"}, "action": {action}, "url": {fileURL}})
		if err != nil {
			t.Fatalf("get file: %v", err)
		}
		defer resp.Body.Close() //nolint:errcheck
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}
	alice := client("builtin:alice")

	// The url is resolved as the action page resolves it, and served by the app
	code, body := fetch(alice, "report", "static/report.txt")
	testutil.AssertEqualsInt(t, "file status", http.StatusOK, code)
	testutil.AssertEqualsString(t, "file body", "quarterly numbers\n", body)
	code, body = fetch(alice, "report", "/apps/files/static/report.txt")
	testutil.AssertEqualsInt(t, "absolute path status", http.StatusOK, code)
	testutil.AssertEqualsString(t, "absolute path body", "quarterly numbers\n", body)
	code, _ = fetch(alice, "report", "static/nosuch.txt")
	testutil.AssertEqualsInt(t, "missing file", http.StatusNotFound, code)

	// Only urls within the app: no other app, no other host through the server
	for _, outside := range []string{"https://example.com/x", "//example.com/x", "/apps/ops/static/x", "../../_openrun/apps"} {
		code, body = fetch(alice, "report", outside)
		testutil.AssertEqualsInt(t, outside, http.StatusBadRequest, code)
		testutil.AssertStringContains(t, body, "is not within app /apps/files")
	}

	// The bearer only MCP region of the app is not reachable through this route
	for _, region := range []string{"mcp", "/apps/files/mcp/x"} {
		code, body = fetch(alice, "report", region)
		testutil.AssertEqualsInt(t, region, http.StatusBadRequest, code)
		testutil.AssertStringContains(t, body, "is in the MCP endpoint of app")
	}

	// The checks of the action apply: app:access, the permit
	code, _ = fetch(client("builtin:bob"), "report", "static/report.txt")
	testutil.AssertEqualsInt(t, "no app:access", http.StatusForbidden, code)
	code, _ = fetch(alice, "restricted", "static/report.txt")
	testutil.AssertEqualsInt(t, "no permit", http.StatusNotFound, code)
	code, _ = fetch(client("builtin:carol"), "restricted", "static/report.txt")
	testutil.AssertEqualsInt(t, "with permit", http.StatusOK, code)
}

// An action run through the management API does not pass through
// App.ServeHTTP: it has to count as app activity, or the idle shutdown stops
// the container of an app which is in use
func TestActionsRecordAppActivity(t *testing.T) {
	server, _ := newActionsTestServer(t)
	createActionsTestApp(t, server, "/apps/ops", "builtin", "")
	ctx := userApiCtx(t, server, "builtin:alice")

	// Listing and describing actions loads the app, it is not use of the app
	_, err := server.GetAction(ctx, "/apps/ops", "list_orders", false)
	testutil.AssertNoError(t, err)
	application, err := server.GetApp(t.Context(), types.AppPathDomain{Path: "/apps/ops"}, false)
	testutil.AssertNoError(t, err)
	if application.LastActivity() != 0 {
		t.Fatalf("activity recorded before any run: %d", application.LastActivity())
	}

	_, err = server.mcpInvokeAction(ctx, "/apps/ops", "list_orders", false, false, false, nil, 0)
	testutil.AssertNoError(t, err)
	if application.LastActivity() == 0 {
		t.Fatal("running an action must record app activity")
	}
}

// The subject and email of a federated caller reach the action context, as
// they do for a browser session and for the per app MCP endpoint
func TestActionsFederatedIdentityContext(t *testing.T) {
	server, _ := newActionsTestServer(t)
	createActionsTestApp(t, server, "/apps/open", "none", "")
	application, err := server.GetApp(t.Context(), types.AppPathDomain{Path: "/apps/open"}, true)
	testutil.AssertNoError(t, err)

	federated := &types.Identity{Provider: "okta", StableSubject: "00u1abc", Email: "dave@example.com"}
	apiCtx := server.apiTokenIdentityContext(t.Context(), "okta:dave", []string{"eng"}, nil, InvokerRest, nil, federated)
	testutil.AssertEqualsString(t, "api ctx subject", "00u1abc", system.GetContextUserSubject(apiCtx))

	appCtx, err := server.actionAppContext(apiCtx, actionTargetOfApp(application))
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "user", "okta:dave", system.GetContextUserId(appCtx))
	testutil.AssertEqualsString(t, "subject", "00u1abc", system.GetContextUserSubject(appCtx))
	testutil.AssertEqualsString(t, "email", "dave@example.com", system.GetContextUserEmail(appCtx))
	testutil.AssertEqualsString(t, "groups", "eng", strings.Join(system.GetContextGroups(appCtx), ","))

	// builtin and admin identities have neither
	for _, identity := range []*types.Identity{{Provider: "builtin", StableSubject: "alice", Email: "a@example.com"},
		{Provider: types.ADMIN_USER, StableSubject: "admin"}, nil} {
		apiCtx = server.apiTokenIdentityContext(t.Context(), "builtin:alice", nil, nil, InvokerRest, nil, identity)
		appCtx, err = server.actionAppContext(apiCtx, actionTargetOfApp(application))
		testutil.AssertNoError(t, err)
		testutil.AssertEqualsString(t, "no subject", "", system.GetContextUserSubject(appCtx))
		testutil.AssertEqualsString(t, "no email", "", system.GetContextUserEmail(appCtx))
	}
}

// A request the actions REST API cannot parse is still an attempt: it is
// recorded as a failed action event
func TestActionsAuditRejectedRequest(t *testing.T) {
	server, ts := newActionsTestServer(t)
	createActionsTestApp(t, server, "/apps/ops", "builtin", "")

	countFailed := func() int {
		var count int
		row := server.auditDB.QueryRow(`select count(*) from audit where event_type = 'action' and operation = 'api_execute' and target = 'List Orders' and status = ?`,
			string(types.EventStatusFailure))
		testutil.AssertNoError(t, row.Scan(&count))
		return count
	}
	post := func(contentType, body string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/apps/ops/api/actions", strings.NewReader(body))
		testutil.AssertNoError(t, err)
		req.Header.Set("Content-Type", contentType)
		req.SetBasicAuth("alice", "alicepw") // the app's own auth, as a REST API client uses it
		resp, err := ts.Client().Do(req)
		testutil.AssertNoError(t, err)
		readBody(t, resp)
		return resp.StatusCode
	}
	waitFor := func(want int) {
		t.Helper()
		for i := 0; i < 100 && countFailed() < want; i++ { // the audit writer is asynchronous
			time.Sleep(20 * time.Millisecond)
		}
		testutil.AssertEqualsInt(t, "failed action events", want, countFailed())
	}

	testutil.AssertEqualsInt(t, "malformed json", http.StatusBadRequest, post("application/json", `{"count": `))
	waitFor(1)
	testutil.AssertEqualsInt(t, "malformed multipart", http.StatusBadRequest, post("multipart/form-data; boundary=xyz", "--xyz\r\nbroken"))
	waitFor(2)
	// A handled request with bad args is recorded by invoke, once
	testutil.AssertEqualsInt(t, "unknown param", http.StatusBadRequest, post("application/json", `{"bogus": 1}`))
	waitFor(3)
}

// Listing actions must not initialize the apps it goes over: for a container
// app, initialization builds and starts the container
func TestActionsListDoesNotInitializeApps(t *testing.T) {
	server, _ := newActionsTestServer(t)
	createActionsTestApp(t, server, "/apps/ops", "builtin", "")
	pathDomain := types.AppPathDomain{Path: "/apps/ops"}
	ctx := userApiCtx(t, server, "builtin:alice")
	initialized := func() bool {
		application, err := server.apps.GetApp(pathDomain)
		if err != nil {
			return false // not even in the app store
		}
		_, loaded := application.LoadedActions()
		return loaded
	}

	resp, err := server.ListActions(ctx, "/apps/**")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "first list", "/apps/ops:list_orders,/apps/ops:stream", actionTools(resp))
	testutil.AssertEqualsBool(t, "initialized by the list", false, initialized())

	// The actions come from the version metadata, persisted when the app was
	// created: the app was not loaded at all, nothing went into the app store
	// or the in-memory lists
	entry, err := server.db.GetAppEntry(t.Context(), pathDomain)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "stored definitions, the restricted one too", 3, len(entry.Metadata.DefinitionActions))
	testutil.AssertEqualsString(t, "stored permit", "ops_admin", strings.Join(entry.Metadata.DefinitionActions[1].Permit, ","))
	testutil.AssertEqualsBool(t, "stored suggest", true, entry.Metadata.DefinitionActions[0].Suggest)
	if _, err := server.apps.GetApp(pathDomain); err == nil {
		t.Fatal("the list put the app in the app store")
	}
	if _, ok := server.actionLists.Load(entry.Id); ok {
		t.Fatal("the list loaded the definition of an app with stored actions")
	}
	// The stored permit is checked per caller
	resp, err = server.ListActions(userApiCtx(t, server, "builtin:carol"), "/apps/ops")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "carol", "/apps/ops:list_orders,/apps/ops:restricted,/apps/ops:stream", actionTools(resp))

	// The stage instance has them too, and an app without actions has an
	// empty list, which is not the same as unknown
	stageEntry, err := server.getStageAppNoTx(t.Context(), entry)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "stage definitions", 3, len(stageEntry.Metadata.DefinitionActions))
	plainDir := t.TempDir()
	testutil.AssertNoError(t, os.WriteFile(filepath.Join(plainDir, "app.star"), []byte(`app = ace.app("plain")`), 0600))
	_, err = server.CreateApp(system.WithTrustedOperation(t.Context()), "/apps/plain", true, false,
		&types.CreateAppRequest{SourceUrl: plainDir, AppAuthn: "builtin"})
	testutil.AssertNoError(t, err)
	plainEntry, err := server.db.GetAppEntry(t.Context(), types.AppPathDomain{Path: "/apps/plain"})
	testutil.AssertNoError(t, err)
	if plainEntry.Metadata.DefinitionActions == nil || len(plainEntry.Metadata.DefinitionActions) != 0 {
		t.Fatalf("an app without actions stores an empty list, got %#v", plainEntry.Metadata.DefinitionActions)
	}

	// A version stored before the field existed has no definitions: the
	// definition is loaded once (no container) and kept in memory for that version
	entry.Metadata.DefinitionActions = nil
	tx, err := server.db.BeginTransaction(t.Context())
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, server.db.UpdateAppMetadata(t.Context(), tx, entry))
	testutil.AssertNoError(t, server.db.CommitTransaction(tx))
	server.apps.ResetAllAppCache()
	resp, err = server.ListActions(ctx, "/apps/ops")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "legacy version", "/apps/ops:list_orders,/apps/ops:stream", actionTools(resp))
	testutil.AssertEqualsBool(t, "initialized by the legacy list", false, initialized())
	info, ok := server.apps.GetAppInfo(entry.Id)
	testutil.AssertEqualsBool(t, "app info", true, ok)
	cached, ok := server.actionLists.Load(info.Id)
	testutil.AssertEqualsBool(t, "cached", true, ok)
	testutil.AssertEqualsInt(t, "cached version", info.Version, cached.(*actionListEntry).version)
	testutil.AssertEqualsInt(t, "cached actions, the restricted one too", 3, len(cached.(*actionListEntry).actions))
	resp, err = server.ListActions(userApiCtx(t, server, "builtin:carol"), "/apps/ops")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "carol from the cache", "/apps/ops:list_orders,/apps/ops:restricted,/apps/ops:stream", actionTools(resp))
	testutil.AssertEqualsBool(t, "initialized by the cached list", false, initialized())

	// A cache entry of another version is not used
	cached.(*actionListEntry).version = info.Version + 100
	cached.(*actionListEntry).actions = nil
	resp, err = server.ListActions(ctx, "/apps/ops")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "stale cache ignored", "/apps/ops:list_orders,/apps/ops:stream", actionTools(resp))

	// Describing an action needs the definition only
	detail, err := server.GetAction(ctx, "/apps/ops", "list_orders", false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "detail params", 2, len(detail.Params))
	_, err = server.ActionsOpenAPI(ctx, "/apps/ops", false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "initialized by show/openapi", false, initialized())

	// A caller who may not use the app does not get it started: the checks
	// come before the app is loaded
	_, err = server.mcpInvokeAction(userApiCtx(t, server, "builtin:bob"), "/apps/ops", "list_orders", false, false, false, nil, 0)
	testutil.AssertEqualsInt(t, "bob refused", http.StatusForbidden, requestErrorCode(t, err))
	_, err = server.mcpInvokeAction(userApiCtx(t, server, "okta:dave"), "/apps/ops", "list_orders", false, false, false, nil, 0)
	testutil.AssertEqualsInt(t, "dave refused", http.StatusForbidden, requestErrorCode(t, err))
	testutil.AssertEqualsBool(t, "initialized by a refused run", false, initialized())

	// Running an action is what initializes the app; the list then reads the loaded app
	_, err = server.mcpInvokeAction(ctx, "/apps/ops", "list_orders", false, false, false, nil, 0)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "initialized by the run", true, initialized())
	server.actionLists.Delete(info.Id)
	resp, err = server.ListActions(ctx, "/apps/ops")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "list from the loaded app", "/apps/ops:list_orders,/apps/ops:stream", actionTools(resp))
	if _, ok := server.actionLists.Load(info.Id); ok {
		t.Fatal("the loaded app answers the list, nothing to cache")
	}
}

// A reload persists the actions of the new version. A dev app is listed from
// its live definition: its source changes without a deploy
func TestActionsDefinitionsFollowTheSource(t *testing.T) {
	server, _ := newActionsTestServer(t)
	ctx := system.WithTrustedOperation(t.Context())
	appStar := func(actions string) string {
		return "def handler(dry_run, args):\n\treturn ace.result(\"ok\")\n\napp = ace.app(\"src\", actions=[" + actions + "])\n"
	}
	one := `ace.action("One", "/one", handler)`
	two := one + `, ace.action("Two", "/two", handler, permit=["ops_admin"])`

	prodDir, devDir := t.TempDir(), t.TempDir()
	for _, dir := range []string{prodDir, devDir} {
		testutil.AssertNoError(t, os.WriteFile(filepath.Join(dir, "app.star"), []byte(appStar(one)), 0600))
	}
	_, err := server.CreateApp(ctx, "/apps/prod", true, false, &types.CreateAppRequest{SourceUrl: prodDir, AppAuthn: "builtin"})
	testutil.AssertNoError(t, err)
	_, err = server.CreateApp(ctx, "/apps/dev", true, false, &types.CreateAppRequest{SourceUrl: devDir, AppAuthn: "builtin", IsDev: true})
	testutil.AssertNoError(t, err)
	server.apps.ResetAllAppCache()

	list := func() string {
		t.Helper()
		resp, err := server.ListActions(ctx, "/apps/**")
		testutil.AssertNoError(t, err)
		return actionTools(resp)
	}
	testutil.AssertEqualsString(t, "created", "/apps/dev:one,/apps/prod:one", list())

	for _, dir := range []string{prodDir, devDir} {
		testutil.AssertNoError(t, os.WriteFile(filepath.Join(dir, "app.star"), []byte(appStar(two)), 0600))
	}
	// The dev app follows its source; the prod app lists what is deployed
	testutil.AssertEqualsString(t, "source changed", "/apps/dev:one,/apps/dev:two,/apps/prod:one", list())

	// Reload and promote: the new version's actions are stored with it
	_, err = server.ReloadApps(ctx, "/apps/prod", true, false, true, "", "", "", true, false)
	testutil.AssertNoError(t, err)
	server.apps.ResetAllAppCache()
	testutil.AssertEqualsString(t, "reloaded", "/apps/dev:one,/apps/dev:two,/apps/prod:one,/apps/prod:two", list())
	entry, err := server.db.GetAppEntry(t.Context(), types.AppPathDomain{Path: "/apps/prod"})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "stored after the reload", 2, len(entry.Metadata.DefinitionActions))
	testutil.AssertEqualsString(t, "stored permit", "ops_admin", strings.Join(entry.Metadata.DefinitionActions[1].Permit, ","))
}
