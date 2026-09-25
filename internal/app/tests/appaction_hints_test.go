// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// Side-effect hints (ace.action read_only/destructive/idempotent/open_world):
// tool annotations, the destructive confirmation of the MCP tools, the form
// badge; and the live MCP server of an app across reloads

const hintsTestApp = `
def handler(dry_run, args):
	if args.count < 1:
		return ace.result("Validation failed", param_errors={"count": "count must be positive"})
	if dry_run:
		return ace.result("would purge %d orders" % args.count)
	return ace.result("purged %d orders" % args.count)

def report(dry_run, args):
	return ace.result("report", ["row"], ace.TEXT)

app = ace.app("hintsApp", actions=[
	ace.action("Purge Orders", "/purge", handler, destructive=True, description="Removes orders", hidden=["token"]),
	ace.action("Report", "/report", report, read_only=True, hidden=["count", "token"]),
	ace.action("Set Flag", "/flag", report, destructive=False, idempotent=True, open_world=False, hidden=["count", "token"]),
	ace.action("Plain", "/plain", report, hidden=["count", "token"]),
	ace.action("Secret Purge", "/secret", handler, destructive=True, hidden=[]),
])
`

const hintsTestParams = `
param("count", type=INT, description="Number of orders", default=2)
param("token", description="API token", default="s3cret", display_type=PASSWORD)
`

func hintsApp(t *testing.T, mcpDoc string) *app.App {
	t.Helper()
	fileData := map[string]string{"app.star": hintsTestApp, "params.star": hintsTestParams}
	var a *app.App
	var err error
	if mcpDoc != "" {
		a, _, err = CreateTestAppMCP(testutil.TestLogger(), fileData, nil, nil, &testRBAC{}, mcpDoc)
	} else {
		a, _, err = CreateTestAppAuthorizer(testutil.TestLogger(), fileData, nil, nil, nil, &testRBAC{})
	}
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	return a
}

// mcpSessionOptions connects a go-sdk client with the given options
func mcpSessionOptions(t *testing.T, a *app.App, opts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), types.USER_ID, "builtin:alice")))
	}))
	t.Cleanup(server.Close)
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, opts)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: server.URL + "/test/mcp"}, nil)
	if err != nil {
		t.Fatalf("mcp connect: %s", err)
	}
	t.Cleanup(func() { session.Close() }) //nolint:errcheck
	return session
}

func TestActionHintsDefinition(t *testing.T) {
	a := hintsApp(t, "")
	defs := map[string]types.ActionDef{}
	for _, def := range action.Defs(a.Actions()) {
		defs[def.Path] = def
	}
	purge := defs["/purge"].Hints
	if purge == nil || !purge.IsDestructive() || purge.ReadOnly != nil || purge.Idempotent != nil {
		t.Fatalf("purge hints: %+v", purge)
	}
	report := defs["/report"].Hints
	if report == nil || !report.IsReadOnly() || report.Destructive != nil {
		t.Fatalf("report hints: %+v", report)
	}
	flag := defs["/flag"].Hints
	if flag == nil || *flag.Destructive || !*flag.Idempotent || *flag.OpenWorld {
		t.Fatalf("flag hints: %+v", flag)
	}
	if defs["/plain"].Hints != nil {
		t.Fatalf("an action without hint keywords declares no hints: %+v", defs["/plain"].Hints)
	}
	testutil.AssertEqualsString(t, "labels", "destructive", strings.Join(purge.Labels(), ","))
	testutil.AssertEqualsString(t, "flag labels", "idem", strings.Join(flag.Labels(), ","))
	testutil.AssertEqualsBool(t, "is destructive", true, findAction(t, a, "purge").IsDestructive())
	testutil.AssertEqualsBool(t, "not destructive", false, findAction(t, a, "plain").IsDestructive())

	// Invalid declarations fail the load
	for _, bad := range []string{
		`ace.action("Bad", "/bad", report, read_only=True, destructive=True)`,
		`ace.action("Bad", "/bad", report, read_only=True, idempotent=False)`,
		`ace.action("Bad", "/bad", report, destructive="yes")`,
	} {
		_, _, err := CreateTestAppAuthorizer(testutil.TestLogger(), map[string]string{
			"app.star":    "def report(dry_run, args):\n\treturn ace.result('r')\n\napp = ace.app('bad', actions=[" + bad + "])\n",
			"params.star": hintsTestParams}, nil, nil, nil, &testRBAC{})
		if err == nil {
			t.Fatalf("expected a load error for %s", bad)
		}
	}
}

func TestActionFormDestructiveBadge(t *testing.T) {
	a := hintsApp(t, "")
	page := func(path string) string {
		request := httptest.NewRequest(http.MethodGet, "/test"+path, nil)
		response := httptest.NewRecorder()
		a.ServeHTTP(response, request.WithContext(userCtx()))
		testutil.AssertEqualsInt(t, "status "+path, http.StatusOK, response.Code)
		return response.Body.String()
	}
	testutil.AssertStringContains(t, page("/purge"), `id="action_destructive_badge"`)
	if body := page("/plain"); strings.Contains(body, "action_destructive_badge") {
		t.Fatal("an action without the destructive hint has no badge")
	}
	if body := page("/report"); strings.Contains(body, "action_destructive_badge") {
		t.Fatal("a read only action has no badge")
	}
}

func TestActionsMCPAnnotationsAndCache(t *testing.T) {
	a := hintsApp(t, `{"source":"actions"}`)
	session := mcpSession(t, a, nil)

	tools, err := session.ListTools(context.Background(), nil)
	testutil.AssertNoError(t, err)
	// The list is filtered per caller: private to the caller's client,
	// fresh for the prod ttl
	testutil.AssertEqualsString(t, "cache scope", "private", tools.CacheScope)
	testutil.AssertEqualsInt(t, "default ttl", int(3*time.Minute/time.Millisecond), tools.TTLMs)

	byName := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}
	purge := byName["purge"].Annotations
	if purge == nil || purge.DestructiveHint == nil || !*purge.DestructiveHint || purge.ReadOnlyHint {
		t.Fatalf("purge annotations: %+v", purge)
	}
	report := byName["report"].Annotations
	if report == nil || !report.ReadOnlyHint || report.DestructiveHint == nil || *report.DestructiveHint || !report.IdempotentHint {
		t.Fatalf("report annotations: %+v", report)
	}
	flag := byName["flag"].Annotations
	if flag == nil || flag.DestructiveHint == nil || *flag.DestructiveHint || !flag.IdempotentHint || flag.OpenWorldHint == nil || *flag.OpenWorldHint {
		t.Fatalf("flag annotations: %+v", flag)
	}
	// Undeclared: no annotations block, as before hints existed
	if byName["plain"].Annotations != nil {
		t.Fatalf("plain annotations: %+v", byName["plain"].Annotations)
	}
}

func TestActionsMCPDestructiveConfirm(t *testing.T) {
	a := hintsApp(t, `{"source":"actions"}`)
	elicitSession := func(answer string, saw *string) *mcp.ClientSession {
		return mcpSessionOptions(t, a, &mcp.ClientOptions{
			ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				if saw != nil {
					*saw = req.Params.Message
				}
				return &mcp.ElicitResult{Action: answer}, nil
			},
		})
	}

	// Declined: nothing ran, the result says so and is not an error
	var declineMsg string
	result, err := elicitSession("decline", &declineMsg).CallTool(context.Background(),
		&mcp.CallToolParams{Name: "purge", Arguments: map[string]any{"count": 3}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "declined is not an error", false, result.IsError)
	testutil.AssertStringContains(t, toolText(result), "no changes were made")
	testutil.AssertEqualsBool(t, "confirmed", false, result.StructuredContent.(map[string]any)["confirmed"].(bool))
	// The prompt names the action, the app, the args and the validate status
	for _, want := range []string{"Confirm Purge Orders on /test", "Removes orders", "count=3", "would purge 3 orders", "Accept to run"} {
		testutil.AssertStringContains(t, declineMsg, want)
	}

	// Accepted: the action ran once, on the retry
	var acceptMsg string
	result, err = elicitSession("accept", &acceptMsg).CallTool(context.Background(),
		&mcp.CallToolParams{Name: "purge", Arguments: map[string]any{"count": 2}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "accepted is not an error", false, result.IsError)
	testutil.AssertStringContains(t, toolText(result), "purged 2 orders")
	testutil.AssertStringContains(t, acceptMsg, "count=2")

	// Password params are hidden in the prompt
	var secretMsg string
	_, err = elicitSession("decline", &secretMsg).CallTool(context.Background(),
		&mcp.CallToolParams{Name: "secret", Arguments: map[string]any{"count": 1, "token": "hunter2"}})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, secretMsg, "token=<hidden>")
	if strings.Contains(secretMsg, "hunter2") {
		t.Fatalf("password value in the prompt: %s", secretMsg)
	}

	// Param errors are reported for correction before any confirmation
	var unexpected string
	result, err = elicitSession("accept", &unexpected).CallTool(context.Background(),
		&mcp.CallToolParams{Name: "purge", Arguments: map[string]any{"count": 0}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "param error", true, result.IsError)
	testutil.AssertStringContains(t, toolText(result), "count must be positive")
	testutil.AssertEqualsString(t, "no prompt for a param error", "", unexpected)

	// dry_run needs no confirmation
	result, err = elicitSession("decline", &unexpected).CallTool(context.Background(),
		&mcp.CallToolParams{Name: "purge", Arguments: map[string]any{"count": 1, "dry_run": true}})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "would purge 1 orders")
	testutil.AssertEqualsString(t, "no prompt for dry_run", "", unexpected)

	// A non destructive action never asks
	result, err = elicitSession("decline", &unexpected).CallTool(context.Background(), &mcp.CallToolParams{Name: "plain"})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "report")
	testutil.AssertEqualsString(t, "no prompt for a plain action", "", unexpected)

	// A client without the elicitation capability runs at once, as before
	plain := mcpSession(t, a, nil)
	result, err = plain.CallTool(context.Background(), &mcp.CallToolParams{Name: "purge", Arguments: map[string]any{"count": 4}})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "purged 4 orders")

	// So does a client whose elicitation supports the url mode only: it
	// cannot answer the form the confirmation uses
	urlOnly := mcpSessionOptions(t, a, &mcp.ClientOptions{
		Capabilities: &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{URL: &mcp.URLElicitationCapabilities{}}},
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			t.Fatalf("a url only client must not be asked: %s", req.Params.Message)
			return nil, nil
		},
	})
	result, err = urlOnly.CallTool(context.Background(), &mcp.CallToolParams{Name: "purge", Arguments: map[string]any{"count": 5}})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "purged 5 orders")

	// A capability naming no mode is form support (clients from before modes)
	bare := mcpSessionOptions(t, a, &mcp.ClientOptions{
		Capabilities: &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{}},
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "decline"}, nil
		},
	})
	result, err = bare.CallTool(context.Background(), &mcp.CallToolParams{Name: "purge", Arguments: map[string]any{"count": 6}})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "no changes were made")
}

// A load of the app builds its MCP server anew: the list of a client on the
// new server reflects the new actions, and the list carries the freshness
// hint of the app config (action.mcp_list_ttl, default 3m). The go-sdk
// client caches the list for the ttl, so the dev app here sets it to zero
func TestActionsMCPReloadAndListTTL(t *testing.T) {
	appStar := func(extra string) string {
		return "def handler(dry_run, args):\n\treturn ace.result('ok')\n\napp = ace.app('live', actions=[ace.action('One', '/one', handler)" + extra + "])\n"
	}
	fileData := map[string]string{"app.star": appStar("")}
	mcpConfig, err := types.ParseMCPConfig(`{"source":"actions"}`)
	testutil.AssertNoError(t, err)
	testMetadataHook = func(metadata *types.AppMetadata) { metadata.MCP = mcpConfig }
	a, _, err := CreateTestAppInt(testutil.TestLogger(), "/test", "", fileData, true, nil, nil, nil, "app_dev_live", types.AppSettings{}, nil,
		&types.AppConfig{Action: types.ActionConfig{MCPListTTL: "0s"}}, &testRBAC{})
	testMetadataHook = nil
	testutil.AssertNoError(t, err)

	session := mcpSession(t, a, nil)
	tools, err := session.ListTools(context.Background(), nil)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "tools", 1, len(tools.Tools))
	testutil.AssertEqualsInt(t, "zero ttl", 0, tools.TTLMs)
	testutil.AssertEqualsString(t, "cache scope", "private", tools.CacheScope)
	if caps := session.InitializeResult().Capabilities; caps == nil || caps.Tools == nil || caps.Tools.ListChanged {
		t.Fatalf("list changes are not notified, capabilities %+v", caps)
	}

	fileData["app.star"] = appStar(", ace.action('Two', '/two', handler)")
	_, err = a.Reload(context.Background(), true, true, types.DryRunFalse, app.ReloadOptions{})
	testutil.AssertNoError(t, err)
	tools, err = session.ListTools(context.Background(), nil)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "listed after reload", 2, len(tools.Tools))
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "two"})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "ok")

	// The ttl is an app config setting; an invalid value fails the load
	testMetadataHook = func(metadata *types.AppMetadata) { metadata.MCP = mcpConfig }
	b, _, err := CreateTestAppInt(testutil.TestLogger(), "/test", "", fileData, false, nil, nil, nil, "app_prd_ttl", types.AppSettings{}, nil,
		&types.AppConfig{Action: types.ActionConfig{MCPListTTL: "45s"}}, &testRBAC{})
	testutil.AssertNoError(t, err)
	tools, err = mcpSession(t, b, nil).ListTools(context.Background(), nil)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "configured ttl", 45000, tools.TTLMs)
	testMetadataHook = func(metadata *types.AppMetadata) { metadata.MCP = mcpConfig }
	_, _, err = CreateTestAppInt(testutil.TestLogger(), "/test", "", fileData, false, nil, nil, nil, "app_prd_badttl", types.AppSettings{}, nil,
		&types.AppConfig{Action: types.ActionConfig{MCPListTTL: "soon"}}, &testRBAC{})
	testMetadataHook = nil
	if err == nil || !strings.Contains(err.Error(), "mcp_list_ttl") {
		t.Fatalf("expected an mcp_list_ttl error, got %v", err)
	}
}

// The confirmation switch is read from the effective server config at call
// time, not from the config the app was loaded with
func TestActionsMCPConfirmSkipIsDynamic(t *testing.T) {
	a := hintsApp(t, `{"source":"actions"}`)
	config := &types.ServerConfig{}
	a.SetConfigSource(func() *types.ServerConfig { return config })

	var prompted string
	session := mcpSessionOptions(t, a, &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			prompted = req.Params.Message
			return &mcp.ElicitResult{Action: "accept"}, nil
		},
	})
	call := func(count int) string {
		t.Helper()
		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "purge", Arguments: map[string]any{"count": count}})
		testutil.AssertNoError(t, err)
		return toolText(result)
	}
	testutil.AssertStringContains(t, call(1), "purged 1 orders")
	testutil.AssertStringContains(t, prompted, "count=1")

	config.Api.MCP.SkipDestructiveConfirm = true
	prompted = ""
	testutil.AssertStringContains(t, call(2), "purged 2 orders")
	testutil.AssertEqualsString(t, "no prompt when skipped", "", prompted)

	config.Api.MCP.SkipDestructiveConfirm = false
	testutil.AssertStringContains(t, call(3), "purged 3 orders")
	testutil.AssertStringContains(t, prompted, "count=3")
}
