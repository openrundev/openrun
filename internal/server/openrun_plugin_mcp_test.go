// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/system"

	"github.com/openrundev/openrun/internal/types"
)

// TestApiStatus covers the api block of server_info: the transport
// prerequisites and the surface states the console's MCP page renders
func TestApiStatus(t *testing.T) {
	server, db, _ := newApplyTestServer(t)
	defer db.Close()
	config := server.staticConfig
	config.Https.Port = -1
	config.Api.AppMCP.Enable = true
	config.Api.MCP.Auth = []string{"admin"}
	config.Auth = map[string]types.AuthConfig{"google_test": {}}
	config.SAML = map[string]types.SAMLConfig{"corp": {}}
	config.ClientAuth = map[string]types.ClientCertConfig{"cert_team": {}}

	status := server.apiStatus()
	if status.ExternalUrl != "" || status.HttpsListener || status.TrustedProxies || !status.RBACEnforced {
		t.Fatalf("fresh plaintext server status = %+v", status)
	}
	if status.MCP.Enabled || status.MCP.Url != "" || !slices.Equal(status.MCP.Auth, []string{"admin"}) {
		t.Fatalf("mcp status = %+v", status.MCP)
	}
	if !status.AppMCP.Enabled || !status.AppMCP.Served || status.AppMCP.Url != "" || status.AppMCP.MaxTools != aggMCPDefaultMax {
		t.Fatalf("app_mcp status = %+v", status.AppMCP)
	}
	if status.Rest.Auth == nil || status.AppMCP.AllowedAuth == nil {
		t.Fatal("unset lists must serialize as empty lists, not null")
	}
	// Logins: the fixed accounts, then the federated entries by their
	// runtime names; client cert entries are not browser logins
	if want := []string{"none", "system", "builtin", "google_test", "saml_corp"}; !slices.Equal(status.Logins, want) {
		t.Fatalf("logins = %v, want %v", status.Logins, want)
	}

	// An HTTPS listener on the default domain gives the issuer origin and
	// with it the endpoint urls; disabling RBAC takes the app endpoint down
	config.Https.Port = 25223
	config.Api.MCP.Enable = true
	config.Security.UnsafeDisableRBAC = true
	status = server.apiStatus()
	if status.ExternalUrl != "https://localhost:25223" || !status.HttpsListener {
		t.Fatalf("https status = %+v", status)
	}
	if status.MCP.Url != "https://localhost:25223/_openrun/mcp" || !status.MCP.Enabled {
		t.Fatalf("mcp status = %+v", status.MCP)
	}
	if status.AppMCP.Url != "https://localhost:25223/_openrun/app_mcp" || !status.AppMCP.Enabled || status.AppMCP.Served || status.RBACEnforced {
		t.Fatalf("app_mcp status with rbac disabled = %+v (rbac %v)", status.AppMCP, status.RBACEnforced)
	}
}

// mcpValuesTestApp creates an app from an app.star source (with the actions
// fixture's params) and returns its stored entry
func mcpValuesTestApp(t *testing.T, server *Server, appPath, appStar, mcpDoc string) *types.AppEntry {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"app.star": appStar, "params.star": actionsTestParamsStar} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	ctx := system.WithTrustedOperation(t.Context())
	if _, err := server.CreateApp(ctx, appPath, DeployOptions{Approve: true}, &types.CreateAppRequest{SourceUrl: dir, MCP: mcpDoc}); err != nil {
		t.Fatalf("create app %s: %v", appPath, err)
	}
	server.apps.ResetAllAppCache()
	entry, err := server.db.GetAppEntry(ctx, types.CreateAppPathDomain(appPath, ""))
	if err != nil {
		t.Fatalf("get app entry %s: %v", appPath, err)
	}
	return entry
}

// An app with one action and an ordinary route: at /mcp the route takes the
// implicit endpoint's path, so does a param route (/{page}); /other does not
func mcpRouteAppStar(route string) string {
	return `
def run(dry_run, args):
	return ace.result("done")

def page(req):
	return {"ok": True}

app = ace.app("routed", actions=[ace.action("Run", "/run", run)],
	routes=[ace.api("` + route + `", page)])
`
}

// TestAppMCPValues covers the mcp_* fields of get_app: the stored setting,
// the effective endpoint as the app's load decides it (implicit for an app
// with actions, none when a route of the app takes the path), the url from
// the external origin, and the configuration document gated on detail
func TestAppMCPValues(t *testing.T) {
	server, _, _ := newMCPAppTestServer(t)
	ctx := system.WithTrustedOperation(t.Context())
	external := server.apiExternalUrl()
	if !strings.HasPrefix(external, "https://") {
		t.Fatalf("test server external url = %q, want an https origin", external)
	}

	// An app with actions and no document: the implicit endpoint, addressed
	// through the external origin
	actions := mcpValuesTestApp(t, server, "/apps/implicit", actionsTestAppStar, "")
	values := server.appMCPValues(ctx, actions, true)
	if values["mcp_setting"] != "default" || values["mcp_implicit"] != true || values["mcp_source"] != "actions" ||
		values["mcp_url"] != server.appMCPResource("/apps/implicit", "", &types.MCPConfig{Path: "/mcp"}) {
		t.Fatalf("app with actions = %v", values)
	}
	if url := values["mcp_url"].(string); !strings.HasPrefix(url, "https://localhost") || !strings.HasSuffix(url, "/apps/implicit/mcp") {
		t.Fatalf("implicit endpoint url = %q", url)
	}

	// A route of the app at the endpoint path: the load leaves the implicit
	// endpoint out (mountActionsMCP), so none is advertised. A param route
	// can match the path too; a route elsewhere does not matter
	for route, served := range map[string]bool{"/mcp": false, "/{page}": false, "/other": true} {
		name := strings.NewReplacer("/", "", "{", "", "}", "").Replace(route)
		entry := mcpValuesTestApp(t, server, "/apps/route_"+name, mcpRouteAppStar(route), "")
		values = server.appMCPValues(ctx, entry, true)
		if got := values["mcp_url"] != ""; got != served || values["mcp_implicit"] != served {
			t.Fatalf("app with a route at %s: served %v, want %v (%v)", route, got, served, values)
		}
		// The answer of a prod version is cached, and stays the same
		if again := server.appMCPValues(ctx, entry, true); again["mcp_url"] != values["mcp_url"] {
			t.Fatalf("route %s: cached answer %v differs from %v", route, again, values)
		}
	}

	// A stored document: explicit, its text only with detail
	explicit := mcpValuesTestApp(t, server, "/apps/explicit", actionsTestAppStar, `{"path":"/tools","source":"actions","scopes":["read"]}`)
	values = server.appMCPValues(ctx, explicit, true)
	if values["mcp_setting"] != "custom" || values["mcp_implicit"] != false || !strings.HasSuffix(values["mcp_url"].(string), "/apps/explicit/tools") ||
		!strings.Contains(values["mcp_doc"].(string), `"scopes":["read"]`) {
		t.Fatalf("explicit app with detail = %v", values)
	}
	values = server.appMCPValues(ctx, explicit, false)
	if values["mcp_doc"] != "" {
		t.Fatalf("mcp_doc returned without detail: %v", values["mcp_doc"])
	}
	if values["mcp_setting"] != "custom" || values["mcp_url"] == "" {
		t.Fatalf("endpoint status must stay available without detail: %v", values)
	}

	// Disabled: no endpoint
	disabled := &types.AppEntry{Path: "/apps/off", Metadata: types.AppMetadata{MCP: &types.MCPConfig{Disable: true}}}
	values = server.appMCPValues(ctx, disabled, true)
	if values["mcp_setting"] != "disable" || values["mcp_url"] != "" || values["mcp_disabled"] != true || values["mcp_doc"] != `{"disable":true}` {
		t.Fatalf("disabled app = %v", values)
	}

	// Behind a TLS terminating proxy the listener is plaintext on an internal
	// port: the url is the external origin's, not the listener's
	server.staticConfig.Https.Port = -1
	server.staticConfig.Http.Port = 25222
	server.staticConfig.Api.ExternalUrl = "https://openrun.example.com"
	server.staticConfig.Security.CallbackUrl = ""
	values = server.appMCPValues(ctx, explicit, true)
	if values["mcp_url"] != "https://localhost/apps/explicit/tools" {
		t.Fatalf("proxied url = %v", values["mcp_url"])
	}
	// No issuer origin at all (plaintext local development): the listener url
	server.staticConfig.Api.ExternalUrl = ""
	if server.apiExternalUrl() != "" {
		t.Skipf("external url still resolves to %q", server.apiExternalUrl())
	}
	values = server.appMCPValues(ctx, explicit, true)
	if values["mcp_url"] != "http://localhost:25222/apps/explicit/tools" {
		t.Fatalf("listener fallback url = %v", values["mcp_url"])
	}
}

// TestCreateAppPluginMCPArg checks that create_app validates its mcp arg
// before touching the server, and that update_mcp refuses an empty value
func TestCreateAppPluginMCPArg(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	plugin := &openrunAdminPlugin{server: server}

	_, err := plugin.CreateApp(ctx, pluginCall(types.ADMIN_USER, []any{"/orders", "/nosuch/source"}, "mcp", "bogus"))
	if err == nil || !strings.Contains(err.Error(), "mcp: invalid mcp value") {
		t.Fatalf("create_app with a bad mcp value: %v", err)
	}
	_, err = plugin.UpdateMCP(context.Background(), pluginCall(types.ADMIN_USER, []any{"/orders", "  "}))
	if err == nil || !strings.Contains(err.Error(), "mcp value is required") {
		t.Fatalf("update_mcp with an empty value: %v", err)
	}
}

// TestUpdateAuthPlugin checks that update_auth changes the app auth type: the
// auth type is versioned app metadata, staged and then promoted (it was
// silently ignored when routed through the app settings update)
func TestUpdateAuthPlugin(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	if err := server.initAuditDB("sqlite:" + filepath.Join(t.TempDir(), "audit.db")); err != nil {
		t.Fatalf("init audit db: %v", err)
	}
	plugin := &openrunAdminPlugin{server: server}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.star"), []byte("app = ace.app(\"authApp\")\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := server.CreateApp(ctx, "/authapp", DeployOptions{Approve: true}, &types.CreateAppRequest{SourceUrl: dir}); err != nil {
		t.Fatalf("create: %v", err)
	}
	authOf := func(stage bool) types.AppAuthnType {
		t.Helper()
		entry, err := db.GetAppEntry(ctx, types.AppPathDomain{Path: "/authapp"})
		if err == nil && stage {
			entry, err = server.getStageAppNoTx(ctx, entry)
		}
		if err != nil {
			t.Fatalf("get app (stage %t): %v", stage, err)
		}
		return entry.Metadata.AuthnType
	}

	if _, err := plugin.UpdateAuth(ctx, pluginCall(types.ADMIN_USER, []any{"/authapp", "system"}, "dry_run", true)); err != nil {
		t.Fatalf("update_auth dry run: %v", err)
	}
	if auth := authOf(false); auth == types.AppAuthnSystem {
		t.Fatalf("dry run must not change the prod auth, got %s", auth)
	}
	// dry_run is the third positional arg, as before promote was added
	if _, err := plugin.UpdateAuth(ctx, pluginCall(types.ADMIN_USER, []any{"/authapp", "system", true})); err != nil {
		t.Fatalf("update_auth positional dry run: %v", err)
	}
	if auth := authOf(false); auth == types.AppAuthnSystem {
		t.Fatalf("positional dry run must not change the prod auth, got %s", auth)
	}
	if auth := authOf(true); auth == types.AppAuthnSystem {
		t.Fatalf("positional dry run must not change the stage auth, got %s", auth)
	}

	if _, err := plugin.UpdateAuth(ctx, pluginCall(types.ADMIN_USER, []any{"/authapp", "system"})); err != nil {
		t.Fatalf("update_auth: %v", err)
	}
	if auth := authOf(false); auth != types.AppAuthnSystem {
		t.Fatalf("prod auth = %q, want system", auth)
	}
	if auth := authOf(true); auth != types.AppAuthnSystem {
		t.Fatalf("stage auth = %q, want system", auth)
	}

	if _, err := plugin.UpdateAuth(ctx, pluginCall(types.ADMIN_USER, []any{"/authapp", "none"}, "promote", false)); err != nil {
		t.Fatalf("update_auth without promote: %v", err)
	}
	if auth := authOf(true); auth != types.AppAuthnNone {
		t.Fatalf("stage auth = %q, want none", auth)
	}
	if auth := authOf(false); auth != types.AppAuthnSystem {
		t.Fatalf("prod auth must stay system without promote, got %q", auth)
	}
}
