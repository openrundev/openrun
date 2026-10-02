// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// The aggregate app actions MCP endpoint (/_openrun/app_mcp): the parts the
// commander suite (test_app_mcp.yaml) does not reach. Tool naming rules, the
// tool cap, the staging view, the run tools of async actions and the names
// tools refer to each other by, config validation

func TestAggMCPAppPart(t *testing.T) {
	// Plain form: reversible, no hash
	for appPath, want := range map[string]string{
		"/orders":      "orders",
		"/team/orders": "team_orders",
		"/my-app":      "my-app",
		"/Team/Orders": "Team_Orders",
		"/a/b-c/d1":    "a_b-c_d1",
	} {
		testutil.AssertEqualsString(t, appPath, want, aggMCPAppPart("", appPath))
	}

	// Hashed form: the slug, "--" and 8 hex chars of the app's own identity
	hashed := regexp.MustCompile(`^[A-Za-z0-9_]+--[0-9a-f]{8}$`)
	for _, tc := range []struct{ domain, path, slug string }{
		{"", "/team_orders", "team_orders"},
		{"", "/a.b", "a_b"},
		{"", "/a--b", "a_b"},
		{"", "/", "root"},
		{"example.com", "/x", "example_com_x"},
	} {
		part := aggMCPAppPart(tc.domain, tc.path)
		if !hashed.MatchString(part) || !strings.HasPrefix(part, tc.slug+aggMCPHashMark) {
			t.Fatalf("%s:%s: got %q, want %s--<hash>", tc.domain, tc.path, part, tc.slug)
		}
	}

	// Paths which slug alike never share a name, whatever other apps exist:
	// each name is derived from its app alone
	seen := map[string]string{}
	for _, app := range [][2]string{{"", "/a/b"}, {"", "/a-b"}, {"", "/a_b"}, {"", "/A/b"}, {"", "/a.b"}, {"", "/"}, {"", "/root"},
		{"example.com", "/x"}, {"", "/example/com/x"}, {"example.com", "/a/b"}} {
		part := aggMCPAppPart(app[0], app[1])
		if other, dup := seen[part]; dup {
			t.Fatalf("%s:%s and %s share the name %q", app[0], app[1], other, part)
		}
		seen[part] = app[0] + ":" + app[1]
	}

	// Bounded, for both forms; the tail of the slug with the hash, and
	// distinct for paths which share that tail
	long := "/" + strings.Repeat("x", 40) + "/orders"
	for _, appPath := range []string{long, long + "_v2", "/short", "/under_score_path_which_is_long"} {
		part := aggMCPAppPart("", appPath)
		if len(part) > aggMCPAppPartMax {
			t.Fatalf("%s: %q is %d chars, limit %d", appPath, part, len(part), aggMCPAppPartMax)
		}
		if strings.Contains(part, aggMCPNameSep) || strings.HasSuffix(part, "_") {
			t.Fatalf("%s: %q must not contain or end at the separator", appPath, part)
		}
	}
	a, b := aggMCPAppPart("", "/team1/"+strings.Repeat("y", 30)), aggMCPAppPart("", "/team2/"+strings.Repeat("y", 30))
	if a == b || !strings.Contains(a, aggMCPHashMark) {
		t.Fatalf("long paths with the same tail must differ by their hash: %q %q", a, b)
	}
}

func TestAggMCPActionPart(t *testing.T) {
	testutil.AssertEqualsString(t, "short", "cancel_order", aggMCPActionPart("cancel_order"))
	exact := strings.Repeat("a", aggMCPActionPartMax)
	testutil.AssertEqualsString(t, "at the limit", exact, aggMCPActionPart(exact))

	one, two := strings.Repeat("a", 60)+"_one", strings.Repeat("a", 60)+"_two"
	partOne, partTwo := aggMCPActionPart(one), aggMCPActionPart(two)
	if len(partOne) > aggMCPActionPartMax || len(partTwo) > aggMCPActionPartMax || partOne == partTwo {
		t.Fatalf("long action names must be bounded and distinct: %q %q", partOne, partTwo)
	}
	// The whole name fits the strictest client limit
	name := aggMCPNamer(aggMCPAppPart("", "/"+strings.Repeat("p", 50)))(one)
	if len(name) > 64 {
		t.Fatalf("tool name %q is %d chars", name, len(name))
	}
	app, action, _ := strings.Cut(name, aggMCPNameSep)
	if strings.Contains(app, aggMCPNameSep) || action != partOne {
		t.Fatalf("name %q does not split into its parts", name)
	}
}

func aggMCPTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	server, ts := newActionsTestServer(t)
	server.staticConfig.Api.AppMCP.Enable = true
	return server, ts
}

// aggCall posts a JSON-RPC request to the endpoint and returns the parsed
// response message
func aggCall(t *testing.T, ts *httptest.Server, query, token, body string) (int, map[string]any) {
	t.Helper()
	resp := mcpCall(t, ts, aggMCPEndpointPath+query, token, nil, body)
	data := readBody(t, resp)
	message := map[string]any{}
	for _, line := range strings.Split(data, "\n") {
		if payload, ok := strings.CutPrefix(line, "data: "); ok {
			if err := json.Unmarshal([]byte(payload), &message); err != nil {
				t.Fatalf("parse %s: %v", payload, err)
			}
		}
	}
	if len(message) == 0 && strings.HasPrefix(strings.TrimSpace(data), "{") {
		_ = json.Unmarshal([]byte(data), &message)
	}
	return resp.StatusCode, message
}

func aggToolNames(t *testing.T, message map[string]any) []string {
	t.Helper()
	result, _ := message["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	return names
}

func aggKey(t *testing.T, server *Server, user string) string {
	t.Helper()
	key, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
		&types.ApiKeyCreateRequest{User: user, Resources: []string{ApiResourceAppMCP + ":builtin"}, Scopes: []string{aggMCPScope}})
	testutil.AssertNoError(t, err)
	return key.Key
}

const aggList = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

func aggToolCall(name, args string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
}

func TestAggMCPAsyncToolsAndNames(t *testing.T) {
	server, ts := aggMCPTestServer(t)
	createActionsTestApp(t, server, "/apps/ops", "builtin", "")
	createAsyncActionsTestApp(t, server, "/apps/site")
	alice := aggKey(t, server, "builtin:alice")

	status, message := aggCall(t, ts, "?auth=builtin", alice, aggList)
	testutil.AssertEqualsInt(t, "list", http.StatusOK, status)
	names := strings.Join(aggToolNames(t, message), " ")
	// Every tool carries its app; the suggest tool and the run tools of the
	// app with async actions are listed under the aggregate names too. The
	// permit restricted actions are not listed for alice. The MCP server
	// lists by name
	testutil.AssertEqualsString(t, "tools",
		"apps_ops__list_orders apps_ops__list_orders_suggest apps_ops__stream apps_site__build apps_site__cancel_run "+
			"apps_site__get_run apps_site__list_runs apps_site__rows", names)

	// The names tools refer to each other by are the listed ones
	result := message["result"].(map[string]any)
	descriptions := map[string]string{}
	for _, tool := range result["tools"].([]any) {
		entry := tool.(map[string]any)
		descriptions[entry["name"].(string)], _ = entry["description"].(string)
	}
	testutil.AssertStringContains(t, descriptions["apps_site__rows"], "check it with apps_site__get_run")
	testutil.AssertStringContains(t, descriptions["apps_ops__list_orders"], "apps_ops__list_orders_suggest suggests argument values")
	testutil.AssertStringContains(t, descriptions["apps_site__rows"], "App /apps/site\n")
	testutil.AssertEqualsString(t, "cache scope", "private", result["cacheScope"].(string))

	// An async action through the endpoint: the run starts, and the run
	// tools (which are not bound to an action) are dispatched like the
	// action tools
	_, message = aggCall(t, ts, "?auth=builtin", alice, aggToolCall("apps_site__rows", `{"count":2,"wait_seconds":20}`))
	structured := message["result"].(map[string]any)["structuredContent"].(map[string]any)
	runId, _ := structured["run_id"].(string)
	if runId == "" {
		t.Fatalf("no run id in %v", structured)
	}
	_, message = aggCall(t, ts, "?auth=builtin", alice, aggToolCall("apps_site__get_run", `{"run_id":"`+runId+`","wait_seconds":20}`))
	structured = message["result"].(map[string]any)["structuredContent"].(map[string]any)
	testutil.AssertEqualsString(t, "run result", "Built 2 rows", structured["status"].(string))
	testutil.AssertEqualsString(t, "run id", runId, structured["run_id"].(string))

	// list_runs takes the action by its listed name and reports it by it
	_, message = aggCall(t, ts, "?auth=builtin", alice, aggToolCall("apps_site__list_runs", `{"action":"apps_site__rows"}`))
	runs := message["result"].(map[string]any)["structuredContent"].(map[string]any)["runs"].([]any)
	testutil.AssertEqualsInt(t, "runs", 1, len(runs))
	testutil.AssertEqualsString(t, "run action name", "apps_site__rows", runs[0].(map[string]any)["action"].(string))

	// The suggest tool
	_, message = aggCall(t, ts, "?auth=builtin", alice, aggToolCall("apps_ops__list_orders_suggest", `{}`))
	if text, _ := json.Marshal(message); !strings.Contains(string(text), "open") {
		t.Fatalf("suggest result: %s", text)
	}

	// The cap: over max_tools the list fails rather than hide tools; a
	// narrower view passes, and calls are not affected
	server.staticConfig.Api.AppMCP.MaxTools = 3
	_, message = aggCall(t, ts, "?auth=builtin", alice, aggList)
	errorMessage, _ := message["error"].(map[string]any)
	if errorMessage == nil || !strings.Contains(errorMessage["message"].(string), "max_tools") {
		t.Fatalf("expected the max_tools error, got %v", message)
	}
	_, message = aggCall(t, ts, "?auth=builtin&apps=/apps/ops", alice, aggList)
	testutil.AssertEqualsInt(t, "narrowed view", 3, len(aggToolNames(t, message)))
	_, message = aggCall(t, ts, "?auth=builtin", alice, aggToolCall("apps_ops__list_orders", `{"count":1}`))
	if message["error"] != nil {
		t.Fatalf("call under a capped list: %v", message)
	}
}

func TestAggMCPStagingView(t *testing.T) {
	server, ts := aggMCPTestServer(t)
	ctx := system.WithTrustedOperation(t.Context())
	appStar := func(status, actions string) string {
		return "def handler(dry_run, args):\n\treturn ace.result(\"" + status + "\")\n\napp = ace.app(\"stg\", actions=[" + actions + "])\n"
	}
	one := `ace.action("One", "/one", handler)`
	dir, devDir := t.TempDir(), t.TempDir()
	testutil.AssertNoError(t, os.WriteFile(filepath.Join(dir, "app.star"), []byte(appStar("prod", one)), 0600))
	testutil.AssertNoError(t, os.WriteFile(filepath.Join(devDir, "app.star"), []byte(appStar("dev", one)), 0600))
	_, err := server.CreateApp(ctx, "/apps/stg", true, false, &types.CreateAppRequest{SourceUrl: dir, AppAuthn: "builtin"})
	testutil.AssertNoError(t, err)
	_, err = server.CreateApp(ctx, "/apps/dev", true, false, &types.CreateAppRequest{SourceUrl: devDir, AppAuthn: "builtin", IsDev: true})
	testutil.AssertNoError(t, err)

	// A new version in staging only: another action, another result
	testutil.AssertNoError(t, os.WriteFile(filepath.Join(dir, "app.star"),
		[]byte(appStar("staging", one+`, ace.action("Two", "/two", handler)`)), 0600))
	_, err = server.ReloadApps(ctx, "/apps/stg", true, false, false, "", "", "", true, false)
	testutil.AssertNoError(t, err)
	server.apps.ResetAllAppCache()
	alice := aggKey(t, server, "builtin:alice")

	// The prod view lists what is deployed, the staging view the staging
	// version under the same names. A dev app has no staging instance
	_, message := aggCall(t, ts, "?auth=builtin", alice, aggList)
	testutil.AssertEqualsString(t, "prod view", "apps_dev__one apps_stg__one", strings.Join(aggToolNames(t, message), " "))
	_, message = aggCall(t, ts, "?auth=builtin&stage=true", alice, aggList)
	testutil.AssertEqualsString(t, "staging view", "apps_stg__one apps_stg__two", strings.Join(aggToolNames(t, message), " "))

	status := func(query, tool string) string {
		t.Helper()
		_, message := aggCall(t, ts, query, alice, aggToolCall(tool, `{}`))
		if message["error"] != nil {
			return "error: " + message["error"].(map[string]any)["message"].(string)
		}
		return message["result"].(map[string]any)["structuredContent"].(map[string]any)["status"].(string)
	}
	// A call runs the instance its view lists
	testutil.AssertEqualsString(t, "prod call", "prod", status("?auth=builtin", "apps_stg__one"))
	testutil.AssertEqualsString(t, "staging call", "staging", status("?auth=builtin&stage=true", "apps_stg__one"))
	testutil.AssertEqualsString(t, "staging only tool", "staging", status("?auth=builtin&stage=true", "apps_stg__two"))
	testutil.AssertStringContains(t, status("?auth=builtin", "apps_stg__two"), "unknown tool")
	testutil.AssertStringContains(t, status("?auth=builtin&stage=true", "apps_dev__one"), "unknown tool")
	testutil.AssertEqualsString(t, "dev app", "dev", status("?auth=builtin", "apps_dev__one"))
}

func TestAggMCPConfigAndResource(t *testing.T) {
	server, ts := aggMCPTestServer(t)

	// The canonical resource carries the mechanism, also for the default
	server.staticConfig.Security.AppDefaultAuthType = "builtin"
	resource := server.aggMCPResourceURI("builtin")
	testutil.AssertEqualsString(t, "resource", ts.URL+"/_openrun/app_mcp?auth=builtin", resource)
	for _, requested := range []string{resource, ts.URL + "/_openrun/app_mcp", ts.URL + "/_openrun/app_mcp?apps=/x/**&auth=default",
		ts.URL + "/_openrun/app_mcp/?stage=true"} {
		res, err := server.resolveOAuthResource(requested)
		testutil.AssertNoError(t, err)
		testutil.AssertEqualsString(t, requested, resource, res.URI)
	}
	res, err := server.resolveOAuthResource(ts.URL + "/_openrun/app_mcp?auth=system")
	testutil.AssertNoError(t, err)
	mechanisms, err := server.oauthLoginMechanisms(res)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "system logs in as admin", "admin", strings.Join(mechanisms, ","))
	testutil.AssertEqualsString(t, "default scope", aggMCPScope, strings.Join(server.oauthGrantScopes(res, nil), ","))

	// Not the endpoint: another origin, another path
	for _, requested := range []string{"https://other.example/_openrun/app_mcp", ts.URL + "/_openrun/app_mcpx", ts.URL + "/apps/app_mcp"} {
		if _, isAggMCP, _ := server.aggMCPResourceMechanism(requested); isAggMCP {
			t.Fatalf("%s must not resolve to the endpoint", requested)
		}
	}
	for _, auth := range []string{"cert", "cert_test1", "nosuchlogin"} {
		if _, err := server.aggMCPMechanism(auth); err == nil {
			t.Fatalf("auth %s must be refused", auth)
		}
	}
	// allowed_auth pins the mechanisms; a stored resource whose mechanism
	// is no longer allowed does not refresh
	server.staticConfig.Api.AppMCP.AllowedAuth = []string{"system"}
	if _, err := server.aggMCPMechanism("builtin"); err == nil {
		t.Fatal("builtin must be refused when not in allowed_auth")
	}
	if _, err := server.oauthStoredResource(resource); err == nil {
		t.Fatal("a stored resource of a mechanism no longer allowed must not resolve")
	}
	server.staticConfig.Api.AppMCP.AllowedAuth = nil
	_, err = server.oauthStoredResource(resource)
	testutil.AssertNoError(t, err)

	// Disabled: the endpoint, its document and its resource do not exist
	server.staticConfig.Api.AppMCP.Enable = false
	resp := mcpCall(t, ts, aggMCPEndpointPath+"?auth=builtin", "", nil, aggList)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "disabled endpoint", http.StatusNotFound, resp.StatusCode)
	if _, err := server.resolveOAuthResource(resource); err == nil {
		t.Fatal("the resource of a disabled endpoint must not resolve")
	}
	if _, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
		&types.ApiKeyCreateRequest{User: "builtin:alice", Resources: []string{ApiResourceAppMCP}}); err == nil {
		t.Fatal("no key for a disabled endpoint")
	}

	// The endpoint is on by default, so a server without RBAC enforcement
	// must still start: the config is valid, the endpoint is not served
	config := *server.staticConfig
	config.Api.AppMCP = types.ApiAppMCPConfig{Enable: true, ListTTL: "5m", MaxTools: 10, AllowedAuth: []string{"builtin", "none"}}
	testutil.AssertNoError(t, validateAggMCPConfig(&config))
	if !aggMCPEnabled(&config) {
		t.Fatal("enabled with RBAC enforced")
	}
	config.Security.UnsafeDisableRBAC = true
	testutil.AssertNoError(t, validateAggMCPConfig(&config))
	if aggMCPEnabled(&config) {
		t.Fatal("not served without RBAC enforcement")
	}
	config.Security.UnsafeDisableRBAC = false
	for field, appMCP := range map[string]types.ApiAppMCPConfig{
		"list_ttl":     {ListTTL: "soon"},
		"max_tools":    {MaxTools: -1},
		"allowed_auth": {AllowedAuth: []string{"nosuchlogin"}},
	} {
		config.Api.AppMCP = appMCP
		testutil.AssertErrorContains(t, validateAggMCPConfig(&config), field)
	}

	// A [saml.*] entry is named saml_<name> as a login mechanism, the name
	// it has at runtime; the bare config key is not a mechanism
	config.SAML = map[string]types.SAMLConfig{"corp": {}}
	config.Api.AppMCP = types.ApiAppMCPConfig{AllowedAuth: []string{"saml_corp", "builtin"}}
	testutil.AssertNoError(t, validateAggMCPConfig(&config))
	config.Api.AppMCP = types.ApiAppMCPConfig{AllowedAuth: []string{"corp"}}
	testutil.AssertErrorContains(t, validateAggMCPConfig(&config), "allowed_auth")
	config.Api.AppMCP = types.ApiAppMCPConfig{AllowedAuth: []string{"saml_other"}}
	testutil.AssertErrorContains(t, validateAggMCPConfig(&config), "allowed_auth")
	if !federatedMechanismConfigured(&config, "saml_corp") || federatedMechanismConfigured(&config, "corp") {
		t.Fatal("federatedMechanismConfigured: saml entries are named with the prefix")
	}

	// The auth param of a management surface: one of its logins, system is
	// the admin account
	server.staticConfig.Api.MCP.Auth = []string{"builtin", "admin"}
	for param, want := range map[string]string{"": "", "builtin": "builtin", "admin": "admin", "system": "admin"} {
		mechanism, err := server.surfaceAuthParam(ApiResourceMCP, param)
		testutil.AssertNoError(t, err)
		testutil.AssertEqualsString(t, "auth "+param, want, mechanism)
	}
	if _, err := server.surfaceAuthParam(ApiResourceMCP, "github"); err == nil {
		t.Fatal("a login outside api.mcp auth must be refused")
	}
	res, err = server.resolveOAuthResource(ts.URL + "/_openrun/mcp?auth=builtin")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "audience stays the surface", ApiResourceMCP, res.URI)
	mechanisms, err = server.oauthLoginMechanisms(res)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "only the named login", "builtin", strings.Join(mechanisms, ","))
}

func TestMCPImplicitEndpoint(t *testing.T) {
	server, _ := newActionsTestServer(t)
	// An app with actions and no mcp document is not a reason to pin the
	// issuer config; an app which asked for MCP is
	createActionsTestApp(t, server, "/apps/implicit", "builtin", "")
	createActionsTestApp(t, server, "/apps/off", "builtin", types.MCPValueDisable)
	if server.hasMCPAppsUncached() {
		t.Fatal("implicit and disabled apps must not count as MCP apps for the issuer check")
	}
	if !server.hasMCPApps() {
		t.Fatal("an app with the implicit endpoint needs the authorization server")
	}
	infos, err := server.FilterApps("/apps/**", false)
	testutil.AssertNoError(t, err)
	for _, info := range infos {
		switch info.Path {
		case "/apps/implicit":
			if info.MCP == nil || !info.MCPImplicit || info.MCP.Path != types.MCPActionsDefaultPath || !info.MCP.ServesActions() || storedMCPOfInfo(info) != nil {
				t.Fatalf("implicit app info: %+v", info)
			}
		case "/apps/off":
			if info.MCP != nil || !info.MCPDisabled || !types.MCPDisabled(storedMCPOfInfo(info)) {
				t.Fatalf("disabled app info: %+v", info)
			}
		}
	}
	createActionsTestApp(t, server, "/apps/explicit", "builtin", types.MCPSourceActions)
	if !server.hasMCPAppsUncached() {
		t.Fatal("an app with an mcp document counts")
	}

	// The loaded apps agree
	ctx := system.WithTrustedOperation(t.Context())
	for appPath, wantMCP := range map[string]bool{"/apps/implicit": true, "/apps/off": false, "/apps/explicit": true} {
		application, err := server.GetApp(ctx, types.AppPathDomain{Path: appPath}, true)
		testutil.AssertNoError(t, err)
		if (application.EffectiveMCP() != nil) != wantMCP {
			t.Fatalf("%s: effective mcp %v", appPath, application.EffectiveMCP())
		}
	}

	// A dev app's source changes without a deploy: the action definitions
	// stored with it can be behind, the metadata lookups (the protected
	// resource document, the OAuth resource) then take the effective config
	// from the loaded app
	devDir := t.TempDir()
	noActions := "app = ace.app(\"dev\")\n"
	withAction := "def handler(dry_run, args):\n\treturn ace.result(\"ok\")\n\napp = ace.app(\"dev\", actions=[ace.action(\"One\", \"/one\", handler)])\n"
	testutil.AssertNoError(t, os.WriteFile(filepath.Join(devDir, "app.star"), []byte(noActions), 0600))
	_, err = server.CreateApp(ctx, "/apps/devmcp", true, false, &types.CreateAppRequest{SourceUrl: devDir, AppAuthn: "builtin", IsDev: true})
	testutil.AssertNoError(t, err)
	server.apps.ResetAllAppCache()
	testutil.AssertNoError(t, os.WriteFile(filepath.Join(devDir, "app.star"), []byte(withAction), 0600))
	devApp, err := server.GetApp(ctx, types.AppPathDomain{Path: "/apps/devmcp"}, true)
	testutil.AssertNoError(t, err)
	if devApp.EffectiveMCP() == nil {
		t.Fatal("the loaded dev app serves its actions")
	}
	info, err := server.MatchApp("localhost", "/apps/devmcp/mcp")
	testutil.AssertNoError(t, err)
	if info.MCP != nil {
		t.Fatal("the stored definitions of the dev app are expected to be behind its source")
	}
	server.withLoadedMCP(&info)
	if info.MCP == nil || !info.MCPImplicit {
		t.Fatalf("the dev app's effective config must come from the loaded app: %+v", info)
	}

	// Export round trip of the disable document
	testutil.AssertEqualsString(t, "apply form", "False", formatMCPArg(`{"disable":true}`))
}

// A dev app's first action makes it an MCP endpoint without a deploy: the
// authorization server has to exist for it as soon as its protected
// resource document does, with every other surface off
func TestMCPDevAppEnablesOAuth(t *testing.T) {
	server, ts, client := newMCPAppTestServer(t)
	server.staticConfig.Api.Rest.Enable = false
	server.staticConfig.Api.MCP.Enable = false
	ctx := system.WithTrustedOperation(t.Context())
	devDir := t.TempDir()
	testutil.AssertNoError(t, os.WriteFile(filepath.Join(devDir, "app.star"), []byte("app = ace.app(\"dev\")\n"), 0600))
	_, err := server.CreateApp(ctx, "/apps/devmcp", true, false, &types.CreateAppRequest{SourceUrl: devDir, AppAuthn: "builtin", IsDev: true})
	testutil.AssertNoError(t, err)
	server.apps.ResetAllAppCache()

	asMetadata := func() int {
		t.Helper()
		resp, err := client.Get(ts.URL + "/.well-known/oauth-authorization-server")
		testutil.AssertNoError(t, err)
		readBody(t, resp)
		return resp.StatusCode
	}
	if server.hasMCPApps() {
		t.Fatal("no MCP app yet")
	}
	testutil.AssertEqualsInt(t, "no authorization server yet", http.StatusNotFound, asMetadata())

	withAction := "def handler(dry_run, args):\n\treturn ace.result(\"ok\")\n\napp = ace.app(\"dev\", actions=[ace.action(\"One\", \"/one\", handler)])\n"
	testutil.AssertNoError(t, os.WriteFile(filepath.Join(devDir, "app.star"), []byte(withAction), 0600))
	_, err = server.GetApp(ctx, types.AppPathDomain{Path: "/apps/devmcp"}, true)
	testutil.AssertNoError(t, err)
	if !server.hasMCPApps() {
		t.Fatal("the live endpoint of the dev app counts")
	}
	testutil.AssertEqualsInt(t, "authorization server metadata", http.StatusOK, asMetadata())
	resp, err := client.Get(ts.URL + "/.well-known/oauth-protected-resource/apps/devmcp/mcp")
	testutil.AssertNoError(t, err)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "protected resource document", http.StatusOK, resp.StatusCode)
}

// Every MCP call is recorded as an audit event of the mcp type, whichever
// endpoint it goes to: the management endpoint, an app's own endpoint and
// the aggregate one. The event names the JSON-RPC method, the tool, the
// endpoint, the client and, where the server knows it, the error
func TestMCPAuditEvents(t *testing.T) {
	server, ts := aggMCPTestServer(t)
	createActionsTestApp(t, server, "/apps/ops", "builtin", "")
	ctx := system.WithTrustedOperation(t.Context())
	mint := func(resource string, scopes ...string) *types.ApiKeyCreateResponse {
		t.Helper()
		key, err := server.CreateApiKey(ctx, &types.ApiKeyCreateRequest{User: "builtin:alice", Resources: []string{resource}, Scopes: scopes})
		testutil.AssertNoError(t, err)
		return key
	}
	mgmtKey, appKey, aggKey := mint(ApiResourceMCP, "*"), mint("app:/apps/ops"), mint(ApiResourceAppMCP+":builtin", aggMCPScope)

	post := func(path, token, body string) {
		t.Helper()
		resp := mcpCall(t, ts, path, token, nil, body)
		readBody(t, resp)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted { // 202 for a notification
			t.Fatalf("%s: status %d", path, resp.StatusCode)
		}
	}
	post("/_openrun/mcp", mgmtKey.Key, aggToolCall("list_apps", `{}`))
	post("/_openrun/mcp", mgmtKey.Key, aggToolCall("get_app", `{"path":"/apps/nosuch"}`))
	post("/_openrun/mcp", mgmtKey.Key, aggToolCall("list_versions", `{"path":"/apps/ops"}`))
	post("/_openrun/mcp", mgmtKey.Key, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	post("/apps/ops/mcp", appKey.Key, aggList)
	post("/apps/ops/mcp", appKey.Key, aggToolCall("list_orders", `{"count":1}`))
	post(aggMCPEndpointPath+"?auth=builtin&apps=/apps/**", aggKey.Key, aggToolCall("apps_ops__list_orders", `{"count":1}`))
	post(aggMCPEndpointPath+"?auth=builtin", aggKey.Key, aggToolCall("apps_ops__nosuch", `{}`))
	post(aggMCPEndpointPath+"?auth=builtin", aggKey.Key, aggToolCall("apps_ops__list_orders", `{"count":0}`))

	type event struct{ operation, target, status, detail, appId string }
	query := func(where string, args ...any) []event {
		t.Helper()
		rows, err := server.auditDB.Query("select operation, target, status, detail, app_id from audit where event_type = 'mcp' and user_id = 'builtin:alice' and "+where+" order by create_time", args...)
		testutil.AssertNoError(t, err)
		defer rows.Close() //nolint:errcheck
		events := []event{}
		for rows.Next() {
			var e event
			testutil.AssertNoError(t, rows.Scan(&e.operation, &e.target, &e.status, &e.detail, &e.appId))
			events = append(events, e)
		}
		return events
	}
	one := func(where string, args ...any) event {
		t.Helper()
		var events []event
		for i := 0; i < 100; i++ { // the audit writer is asynchronous
			if events = query(where, args...); len(events) > 0 {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if len(events) != 1 {
			t.Fatalf("%s %v: want one mcp event, got %d: %+v", where, args, len(events), events)
		}
		return events[0]
	}

	// The management endpoint: a call and a failed call
	e := one("target = 'list_apps'")
	testutil.AssertEqualsString(t, "operation", "tools/call", e.operation)
	testutil.AssertEqualsString(t, "status", string(types.EventStatusSuccess), e.status)
	for _, want := range []string{"POST ", "/_openrun/mcp 200", "endpoint=management", "tool=list_apps", "client=apikey cred=" + mgmtKey.Id} {
		testutil.AssertStringContains(t, e.detail, want)
	}
	e = one("target = 'get_app'")
	testutil.AssertEqualsString(t, "failed management call", string(types.EventStatusFailure), e.status)
	testutil.AssertStringContains(t, e.detail, "error=")
	// A management tool called for one app links its event to that app; a
	// call for no app, or for an app which does not exist, has none
	opsEntry, err := server.db.GetAppEntry(t.Context(), types.AppPathDomain{Path: "/apps/ops"})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "management call app", string(opsEntry.Id), one("target = 'list_versions'").appId)
	testutil.AssertEqualsString(t, "unknown app", "", e.appId)
	testutil.AssertEqualsString(t, "no app", "", one("target = 'list_apps'").appId)

	// An app's own endpoint: the list and a call, with the app
	e = one("detail like '%endpoint=app %' and operation = 'tools/list'")
	testutil.AssertStringContains(t, e.target, "/apps/ops/mcp")
	testutil.AssertStringContains(t, e.detail, "app=/apps/ops")
	if e.appId == "" {
		t.Fatal("the app endpoint event carries the app id")
	}
	e = one("detail like '%endpoint=app %' and target = 'list_orders'")
	testutil.AssertEqualsString(t, "app call", "tools/call", e.operation)
	testutil.AssertStringContains(t, e.detail, "cred="+appKey.Id)

	// The aggregate endpoint: the view, an unknown tool and a tool error
	events := query("detail like '%endpoint=apps %' and target = 'apps_ops__list_orders'")
	for i := 0; i < 100 && len(events) < 2; i++ {
		time.Sleep(20 * time.Millisecond)
		events = query("detail like '%endpoint=apps %' and target = 'apps_ops__list_orders'")
	}
	testutil.AssertEqualsInt(t, "aggregate calls", 2, len(events))
	testutil.AssertEqualsString(t, "aggregate call", string(types.EventStatusSuccess), events[0].status)
	// The endpoint serves many apps: each call's event links to its app
	testutil.AssertEqualsString(t, "aggregate call app", string(opsEntry.Id), events[0].appId)
	for _, want := range []string{"auth=builtin", "apps=/apps/**", "client=apikey cred=" + aggKey.Id} {
		testutil.AssertStringContains(t, events[0].detail, want)
	}
	testutil.AssertEqualsString(t, "tool error", string(types.EventStatusFailure), events[1].status)
	testutil.AssertStringContains(t, events[1].detail, "count must be positive")
	e = one("target = 'apps_ops__nosuch'")
	testutil.AssertEqualsString(t, "unknown tool", string(types.EventStatusFailure), e.status)
	testutil.AssertStringContains(t, e.detail, "unknown tool")

	// Notifications are not calls, and MCP requests leave no http event
	testutil.AssertEqualsInt(t, "notification events", 0, len(query("operation like 'notifications/%'")))
	var httpEvents int
	testutil.AssertNoError(t, server.auditDB.QueryRow(
		"select count(*) from audit where event_type = 'http' and (target like '%/mcp' or target like '%/app_mcp')").Scan(&httpEvents))
	testutil.AssertEqualsInt(t, "http events for mcp requests", 0, httpEvents)
}
