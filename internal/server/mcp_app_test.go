// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/crypto/bcrypt"
)

// upstreamRecorder is the stand-in MCP server: an httptest upstream the app
// proxies to, recording the last request it received
type upstreamRecorder struct {
	mu      sync.Mutex
	path    string
	headers http.Header
	body    string
	server  *httptest.Server
}

func newUpstreamRecorder(t *testing.T) *upstreamRecorder {
	t.Helper()
	rec := &upstreamRecorder{}
	rec.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.path = r.URL.Path
		rec.headers = r.Header.Clone()
		rec.body = string(body)
		rec.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	t.Cleanup(rec.server.Close)
	return rec
}

func (u *upstreamRecorder) last() (string, http.Header, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.path, u.headers, u.body
}

// newMCPAppTestServer is newOAuthTestServer with the default domain set to
// localhost: MatchApp treats the test router's 127.0.0.1 host as localhost,
// so apps created without a domain are reachable through the router
func newMCPAppTestServer(t *testing.T) (*Server, *httptest.Server, *http.Client) {
	t.Helper()
	server, ts, client := newOAuthTestServer(t)
	server.staticConfig.System.DefaultDomain = "localhost"
	return server, ts, client
}

// createMCPTestApp creates an approved proxy app at appPath forwarding to
// the upstream, with the given mcp document and auth type
func createMCPTestApp(t *testing.T, server *Server, appPath, upstreamUrl, auth, mcp string) {
	t.Helper()
	dir := t.TempDir()
	appStar := fmt.Sprintf(`
load("proxy.in", "proxy")
app = ace.app("mcp test app", routes=[ace.proxy("/", proxy.config(%q))],
    permissions=[ace.permission("proxy.in", "config")])`, upstreamUrl)
	if err := os.WriteFile(filepath.Join(dir, "app.star"), []byte(appStar), 0600); err != nil {
		t.Fatalf("write app.star: %v", err)
	}
	ctx := system.WithTrustedOperation(t.Context())
	if _, err := server.CreateApp(ctx, appPath, true, false, &types.CreateAppRequest{
		SourceUrl: dir, AppAuthn: types.AppAuthnType(auth), MCP: mcp}); err != nil {
		t.Fatalf("create mcp app: %v", err)
	}
	server.apps.ResetAllAppCache()
}

// mcpCall POSTs a JSON-RPC request to the app through the TLS test router
func mcpCall(t *testing.T, ts *httptest.Server, path, token string, headers map[string]string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("mcp call: %v", err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// The test router is an httptest TLS server on 127.0.0.1 (matched as the
// localhost default domain); the canonical resource carries the server's
// port from api.external_url (= ts.URL)
func TestMCPAppBearerFlow(t *testing.T) {
	server, ts, _ := newMCPAppTestServer(t)
	upstream := newUpstreamRecorder(t)
	createMCPTestApp(t, server, "/apps/orders", upstream.server.URL, "builtin",
		`{"path":"/","container_path":"/mcp","scopes":["orders:read","orders:write"],"default_scope":"orders:read","tools":{"cancel_order":"orders:write"}}`)

	tsURL, _ := url.Parse(ts.URL)
	wantResource := "https://localhost:" + tsURL.Port() + "/apps/orders"

	// Protected resource metadata: path-inserted form on the app host
	resp, err := ts.Client().Get(ts.URL + "/.well-known/oauth-protected-resource/apps/orders")
	if err != nil {
		t.Fatalf("prm: %v", err)
	}
	var prm map[string]any
	decodeJSONBody(t, resp, &prm)
	testutil.AssertEqualsString(t, "prm resource", wantResource, prm["resource"].(string))
	testutil.AssertEqualsString(t, "prm as", ts.URL, prm["authorization_servers"].([]any)[0].(string))
	if scopes, _ := prm["scopes_supported"].([]any); len(scopes) != 2 {
		t.Fatalf("prm scopes_supported: %v", prm["scopes_supported"])
	}
	// No document for a non-MCP path
	resp, err = ts.Client().Get(ts.URL + "/.well-known/oauth-protected-resource/apps/remote-test")
	if err != nil {
		t.Fatalf("prm: %v", err)
	}
	resp.Body.Close() //nolint:errcheck
	testutil.AssertEqualsInt(t, "non-mcp prm", http.StatusNotFound, resp.StatusCode)

	// No token: 401 with the challenge pointing at the app's document
	resp = mcpCall(t, ts, "/apps/orders", "", nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "no token", http.StatusUnauthorized, resp.StatusCode)
	challenge := resp.Header.Get("WWW-Authenticate")
	for _, want := range []string{`resource_metadata="https://localhost:` + tsURL.Port() + `/.well-known/oauth-protected-resource/apps/orders"`, `scope="orders:read"`} {
		if !strings.Contains(challenge, want) {
			t.Fatalf("challenge %q must contain %s", challenge, want)
		}
	}

	// A management surface token is not valid at the app (resource binding)
	restKey, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
		&types.ApiKeyCreateRequest{User: "builtin:alice", Resources: []string{ApiResourceRest}})
	if err != nil {
		t.Fatalf("rest key: %v", err)
	}
	resp = mcpCall(t, ts, "/apps/orders", restKey.Key, nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "rest key at app", http.StatusUnauthorized, resp.StatusCode)

	// An app-bound API key (unscoped): the call reaches the upstream at the
	// rewritten container path, without the token, with identity headers
	appKey, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
		&types.ApiKeyCreateRequest{User: "builtin:alice", Resources: []string{"app:/apps/orders"}})
	if err != nil {
		t.Fatalf("app key: %v", err)
	}
	if appKey.Resources[0] != wantResource {
		t.Fatalf("app key resource %v", appKey.Resources)
	}
	resp = mcpCall(t, ts, "/apps/orders", appKey.Key, map[string]string{"Cookie": "openrun_session=x; other=y"},
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	body := readBody(t, resp)
	testutil.AssertEqualsInt(t, "app key call", http.StatusOK, resp.StatusCode)
	if !strings.Contains(body, `"tools"`) {
		t.Fatalf("upstream response not proxied: %s", body)
	}
	gotPath, gotHeaders, _ := upstream.last()
	testutil.AssertEqualsString(t, "rewritten path", "/mcp", gotPath)
	testutil.AssertEqualsString(t, "token stripped", "", gotHeaders.Get("Authorization"))
	testutil.AssertEqualsString(t, "cookies stripped", "", gotHeaders.Get("Cookie"))
	testutil.AssertEqualsString(t, "user header", "builtin:alice", gotHeaders.Get(types.OPENRUN_HEADER_USER))
	testutil.AssertEqualsString(t, "client header", "apikey", gotHeaders.Get(types.OPENRUN_HEADER_CLIENT_ID))
	testutil.AssertEqualsString(t, "scopes header (unscoped key)", "", gotHeaders.Get(types.OPENRUN_HEADER_SCOPES))

	// Sub-paths are rewritten under the container path too, and a trailing
	// slash the client sent is kept
	resp = mcpCall(t, ts, "/apps/orders/sub", appKey.Key, nil, `{}`)
	readBody(t, resp)
	gotPath, _, _ = upstream.last()
	testutil.AssertEqualsString(t, "rewritten sub path", "/mcp/sub", gotPath)
	resp = mcpCall(t, ts, "/apps/orders/", appKey.Key, nil, `{}`)
	readBody(t, resp)
	gotPath, gotHeaders, _ = upstream.last()
	testutil.AssertEqualsString(t, "trailing slash kept", "/mcp/", gotPath)
	// Builtin identities carry no provider subject or email
	testutil.AssertEqualsString(t, "no subject for builtin", "", gotHeaders.Get(types.OPENRUN_HEADER_USER_ID))

	// Unscoped keys pass tool scope checks; a scoped key must carry the
	// tool's scope (header form and legacy body form)
	readKey, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
		&types.ApiKeyCreateRequest{User: "builtin:alice", Resources: []string{"app:/apps/orders"}, Scopes: []string{"orders:read"}})
	if err != nil {
		t.Fatalf("scoped key: %v", err)
	}
	resp = mcpCall(t, ts, "/apps/orders", readKey.Key, map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "cancel_order"},
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cancel_order"}}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "scoped key denied (header)", http.StatusForbidden, resp.StatusCode)
	if ch := resp.Header.Get("WWW-Authenticate"); !strings.Contains(ch, `error="insufficient_scope"`) || !strings.Contains(ch, `scope="orders:write"`) {
		t.Fatalf("step-up challenge: %q", ch)
	}
	resp = mcpCall(t, ts, "/apps/orders", readKey.Key, nil,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cancel_order","arguments":{}}}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "scoped key denied (body sniff)", http.StatusForbidden, resp.StatusCode)
	// A header claiming a harmless method over a body that calls the
	// write tool is refused, as is a body too large to inspect
	resp = mcpCall(t, ts, "/apps/orders", readKey.Key, map[string]string{"Mcp-Method": "tools/list"},
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cancel_order"}}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "header/body mismatch", http.StatusBadRequest, resp.StatusCode)
	resp = mcpCall(t, ts, "/apps/orders", readKey.Key, nil,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cancel_order","arguments":{"pad":"`+strings.Repeat("x", mcpBodySniffLimit)+`"}}}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "oversized body", http.StatusRequestEntityTooLarge, resp.StatusCode)
	resp = mcpCall(t, ts, "/apps/orders", readKey.Key, nil,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_orders"}}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "unmapped tool allowed", http.StatusOK, resp.StatusCode)
	_, gotHeaders, gotBody := upstream.last()
	testutil.AssertEqualsString(t, "scopes header", "orders:read", gotHeaders.Get(types.OPENRUN_HEADER_SCOPES))
	if !strings.Contains(gotBody, `"list_orders"`) {
		t.Fatalf("sniffed body must be restored for the upstream, got %s", gotBody)
	}
	// Scopes outside the app's vocabulary are refused at key creation
	if _, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
		&types.ApiKeyCreateRequest{User: "builtin:alice", Resources: []string{"app:/apps/orders"}, Scopes: []string{"app:read"}}); err == nil {
		t.Fatal("rbac scope on an app key must be refused")
	}

	// RBAC app:access: bob has no grant on /apps/**
	bobKey, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
		&types.ApiKeyCreateRequest{User: "builtin:bob", Resources: []string{"app:/apps/orders"}})
	if err != nil {
		t.Fatalf("bob key: %v", err)
	}
	resp = mcpCall(t, ts, "/apps/orders", bobKey.Key, nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "no app:access", http.StatusForbidden, resp.StatusCode)

	// Browser origins are refused unless allowed
	resp = mcpCall(t, ts, "/apps/orders", appKey.Key, map[string]string{"Origin": "https://evil.example.com"}, `{}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "origin refused", http.StatusForbidden, resp.StatusCode)
}

// CORS preflight from an allowed origin reaches the app without a token so
// its CORS handler can answer; other origins are refused; preflight never
// carries credentials or identity
func TestMCPAppPreflight(t *testing.T) {
	server, ts, _ := newMCPAppTestServer(t)
	upstream := newUpstreamRecorder(t)
	createMCPTestApp(t, server, "/apps/web", upstream.server.URL, "builtin",
		`{"allowed_origins":["https://app.example.com"]}`)
	preflight := func(origin string) *http.Response {
		req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/apps/web", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Authorization", "Bearer bogus")
		req.Header.Set("Cookie", "a=b")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		readBody(t, resp)
		return resp
	}
	resp := preflight("https://app.example.com")
	testutil.AssertEqualsInt(t, "allowed preflight", http.StatusOK, resp.StatusCode)
	_, gotHeaders, _ := upstream.last()
	testutil.AssertEqualsString(t, "preflight token stripped", "", gotHeaders.Get("Authorization"))
	testutil.AssertEqualsString(t, "preflight cookie stripped", "", gotHeaders.Get("Cookie"))
	testutil.AssertEqualsString(t, "preflight origin forwarded", "https://app.example.com", gotHeaders.Get("Origin"))
	testutil.AssertEqualsString(t, "no identity on preflight", types.ANONYMOUS_USER, gotHeaders.Get(types.OPENRUN_HEADER_USER))
	resp = preflight("https://evil.example.com")
	testutil.AssertEqualsInt(t, "refused preflight", http.StatusForbidden, resp.StatusCode)

	// The actual call still needs a token, and the challenge is readable
	// by the browser client: CORS headers on OpenRun's own 401
	resp = mcpCall(t, ts, "/apps/web", "", map[string]string{"Origin": "https://app.example.com"}, `{}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "post needs token", http.StatusUnauthorized, resp.StatusCode)
	testutil.AssertEqualsString(t, "cors on 401", "https://app.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
	testutil.AssertEqualsString(t, "challenge exposed", "WWW-Authenticate", resp.Header.Get("Access-Control-Expose-Headers"))
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("401 must carry the challenge")
	}
	// Native clients (no Origin) get no CORS headers
	resp = mcpCall(t, ts, "/apps/web", "", nil, `{}`)
	readBody(t, resp)
	testutil.AssertEqualsString(t, "no cors without origin", "", resp.Header.Get("Access-Control-Allow-Origin"))
}

func TestMCPAppOAuthFlow(t *testing.T) {
	server, ts, client := newMCPAppTestServer(t)
	upstream := newUpstreamRecorder(t)
	createMCPTestApp(t, server, "/apps/orders", upstream.server.URL, "builtin",
		`{"path":"/","scopes":["orders:read","orders:write"],"default_scope":"orders:read"}`)
	tsURL, _ := url.Parse(ts.URL)
	resource := "https://localhost:" + tsURL.Port() + "/apps/orders"

	// The AS serves apps even with both management surfaces disabled
	server.staticConfig.Api.Rest.Enable = false
	server.staticConfig.Api.MCP.Enable = false
	resp, err := client.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("as metadata: %v", err)
	}
	resp.Body.Close() //nolint:errcheck
	testutil.AssertEqualsInt(t, "as metadata with surfaces off", http.StatusOK, resp.StatusCode)

	verifier := "mcp-app-verifier-0123456789-0123456789-0123456789"
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])

	// Consent page names the app; unknown scopes are dropped, the app
	// default is granted when nothing usable is requested
	form := url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"},
		"redirect_uri": {"http://127.0.0.1:39999/callback"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "resource": {resource}, "scope": {"openid"}}
	resp, err = client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	page := readBody(t, resp)
	testutil.AssertEqualsInt(t, "consent", http.StatusOK, resp.StatusCode)
	if !strings.Contains(page, "mcp test app") || !strings.Contains(page, resource) || !strings.Contains(page, `value="orders:read"`) {
		t.Fatalf("consent page must name the app, the resource and the default scope: %s", page)
	}

	// bob (no app:access) cannot obtain a token; the page reports it
	bobHash, err := bcrypt.GenerateFromPassword([]byte("bobpw"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	server.staticConfig.BuiltinAuth["bob"] = types.BuiltinAuthEntry{Password: string(bobHash)}
	form.Set("or_username", "bob")
	form.Set("or_password", "bobpw")
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize", form)
	if err != nil {
		t.Fatalf("bob authorize: %v", err)
	}
	page = readBody(t, resp)
	if resp.StatusCode == http.StatusFound || !strings.Contains(page, "does not have access") {
		t.Fatalf("bob must be refused at consent, got %d %s", resp.StatusCode, page)
	}

	// alice: code -> tokens bound to the app, usable at the app, not at REST
	code := runAuthorize(t, ts, client, "openrun-cli", "http://127.0.0.1:39999/callback",
		challenge, resource, "orders:read orders:write bogus", "alice", "alicepw")
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"http://127.0.0.1:39999/callback"},
		"client_id":    {"openrun-cli"}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var tokenResp system.OAuthTokenResponse
	decodeJSONBody(t, resp, &tokenResp)
	if tokenResp.AccessToken == "" {
		t.Fatalf("token exchange failed: %+v", tokenResp)
	}
	testutil.AssertEqualsString(t, "granted scopes (bogus dropped)", "orders:read orders:write", tokenResp.Scope)

	resp = mcpCall(t, ts, "/apps/orders", tokenResp.AccessToken, nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "oauth token at app", http.StatusOK, resp.StatusCode)
	_, gotHeaders, _ := upstream.last()
	testutil.AssertEqualsString(t, "client header", "openrun-cli", gotHeaders.Get(types.OPENRUN_HEADER_CLIENT_ID))
	testutil.AssertEqualsString(t, "scopes header", "orders:read,orders:write", gotHeaders.Get(types.OPENRUN_HEADER_SCOPES))
	testutil.AssertEqualsString(t, "user header", "builtin:alice", gotHeaders.Get(types.OPENRUN_HEADER_USER))

	server.staticConfig.Api.Rest.Enable = true
	var listResponse types.AppListResponse
	if err := remoteClient(ts, tokenResp.AccessToken).Get("/_openrun/apps", nil, &listResponse); err == nil {
		t.Fatal("an app token must not work at the management REST surface")
	}

	// Refresh keeps the app binding
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokenResp.RefreshToken}, "client_id": {"openrun-cli"}})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var refreshed system.OAuthTokenResponse
	decodeJSONBody(t, resp, &refreshed)
	resp = mcpCall(t, ts, "/apps/orders", refreshed.AccessToken, nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "refreshed token at app", http.StatusOK, resp.StatusCode)

	// A resource that is not an MCP endpoint is refused at authorize
	form.Set("resource", "https://localhost:"+tsURL.Port()+"/apps/remote-test")
	resp, err = client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	page = readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(page, "invalid_target") {
		t.Fatalf("non-mcp resource must be invalid_target, got %d %s", resp.StatusCode, page)
	}
}

func TestMCPAppRegionAndAuthNone(t *testing.T) {
	server, ts, client := newMCPAppTestServer(t)
	upstream := newUpstreamRecorder(t)
	// Mixed app: MCP under /mcp, the rest keeps the app's basic auth
	createMCPTestApp(t, server, "/apps/mixed", upstream.server.URL, "builtin", `{"path":"/mcp"}`)
	tsURL, _ := url.Parse(ts.URL)

	// Outside the region: normal app auth (basic); inside: bearer only
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/apps/mixed/ui", nil)
	req.SetBasicAuth("alice", "alicepw")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("ui: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "ui with basic auth", http.StatusOK, resp.StatusCode)
	gotPath, _, _ := upstream.last()
	testutil.AssertEqualsString(t, "ui path not rewritten", "/ui", gotPath)

	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/apps/mixed/mcp", strings.NewReader(`{}`))
	req.SetBasicAuth("alice", "alicepw")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("mcp basic: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "region refuses basic auth", http.StatusUnauthorized, resp.StatusCode)
	if !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer ") {
		t.Fatalf("region must challenge with Bearer, got %q", resp.Header.Get("WWW-Authenticate"))
	}

	// Alternate spellings of the region path get the same treatment:
	// routing cleans the path, so must the auth decision
	for _, alt := range []string{"/apps/mixed//mcp", "/apps/mixed/./mcp", "/apps/mixed/ui/../mcp", "/apps/mixed/mcp/../mcp/x"} {
		req, _ = http.NewRequest(http.MethodPost, ts.URL+alt, strings.NewReader(`{}`))
		req.SetBasicAuth("alice", "alicepw")
		resp, err = ts.Client().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", alt, err)
		}
		readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s must require a bearer token, got %d", alt, resp.StatusCode)
		}
	}

	// PRM is at the region path, the resource ends with it
	resp, err = client.Get(ts.URL + "/.well-known/oauth-protected-resource/apps/mixed/mcp")
	if err != nil {
		t.Fatalf("prm: %v", err)
	}
	var prm map[string]any
	decodeJSONBody(t, resp, &prm)
	testutil.AssertEqualsString(t, "region resource", "https://localhost:"+tsURL.Port()+"/apps/mixed/mcp", prm["resource"].(string))

	appKey, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
		&types.ApiKeyCreateRequest{User: "builtin:alice", Resources: []string{"app:/apps/mixed"}})
	if err != nil {
		t.Fatalf("app key: %v", err)
	}
	resp = mcpCall(t, ts, "/apps/mixed/mcp", appKey.Key, nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "region with app key", http.StatusOK, resp.StatusCode)
	gotPath, _, _ = upstream.last()
	testutil.AssertEqualsString(t, "region path forwarded as is", "/mcp", gotPath)

	// auth none: keys still work (an admin minted one for a user), but the
	// browser flow has no login mechanism
	createMCPTestApp(t, server, "/apps/anon", upstream.server.URL, "none", "true")
	form := url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"},
		"redirect_uri": {"http://127.0.0.1:39999/callback"}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "resource": {"https://localhost:" + tsURL.Port() + "/apps/anon"},
		"or_username": {"alice"}, "or_password": {"alicepw"}}
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize", form)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	page := readBody(t, resp)
	if resp.StatusCode == http.StatusFound || !strings.Contains(page, "auth none") {
		t.Fatalf("auth none app must not issue tokens, got %d %s", resp.StatusCode, page)
	}
}

func TestMCPAppConfigValidation(t *testing.T) {
	server, _, _ := newMCPAppTestServer(t)
	upstream := newUpstreamRecorder(t)
	dir := t.TempDir()
	appStar := fmt.Sprintf(`
load("proxy.in", "proxy")
app = ace.app("x", routes=[ace.proxy("/", proxy.config(%q))], permissions=[ace.permission("proxy.in", "config")])`, upstream.server.URL)
	if err := os.WriteFile(filepath.Join(dir, "app.star"), []byte(appStar), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	ctx := system.WithTrustedOperation(t.Context())
	for name, doc := range map[string]string{
		"container path with region": `{"path":"/mcp","container_path":"/other"}`,
		"default scope undeclared":   `{"scopes":["a"],"default_scope":"b"}`,
		"tool scope undeclared":      `{"scopes":["a"],"tools":{"t":"b"}}`,
		"bad origin":                 `{"allowed_origins":["example.com"]}`,
		"garbage":                    `nope`,
		"file reference at the api":  `@/etc/hostname`,
	} {
		if _, err := server.CreateApp(ctx, "/apps/bad", true, false, &types.CreateAppRequest{SourceUrl: dir, MCP: doc}); err == nil {
			t.Fatalf("%s: create must fail", name)
		}
	}
	// The management resources live under /_openrun, so an MCP app at
	// /rest or /mcp on the issuer host is fine: distinct audiences
	tsHost, _ := url.Parse(server.staticConfig.Api.ExternalUrl)
	for _, p := range []string{tsHost.Hostname() + ":/rest", tsHost.Hostname() + ":/mcp"} {
		if _, err := server.CreateApp(ctx, p, true, false, &types.CreateAppRequest{SourceUrl: dir, MCP: "true"}); err != nil {
			t.Fatalf("mcp app at %s must be allowed: %v", p, err)
		}
	}

	// Without an issuer origin an MCP app cannot be created
	external := server.staticConfig.Api.ExternalUrl
	server.staticConfig.Api.ExternalUrl = ""
	server.staticConfig.Security.CallbackUrl = ""
	if _, err := server.CreateApp(ctx, "/apps/noissuer", true, false, &types.CreateAppRequest{SourceUrl: dir, MCP: "true"}); err == nil ||
		!strings.Contains(err.Error(), "external_url") {
		t.Fatalf("mcp app without issuer must fail with a config hint, got %v", err)
	}
	server.staticConfig.Api.ExternalUrl = external

	// Metadata update: set, replace and clear
	if _, err := server.CreateApp(ctx, "/apps/upd", true, false, &types.CreateAppRequest{SourceUrl: dir}); err != nil {
		t.Fatalf("create: %v", err)
	}
	update := func(value string) error {
		_, err := server.StagedUpdate(ctx, "/apps/upd", false, true, server.updateMetadataHandler, map[string]any{
			"metadata": types.UpdateAppMetadataRequest{Spec: types.StringValueUndefined,
				ConfigType: types.AppMetadataMCP, ConfigEntries: []string{value}},
			"dryRun": false,
		}, "update_metadata")
		return err
	}
	if err := update("/mcp"); err != nil {
		t.Fatalf("update mcp: %v", err)
	}
	server.apps.ResetAllAppCache()
	info, _, err := server.resolveAppReference("app:/apps/upd")
	if err != nil {
		t.Fatalf("resolve after update: %v", err)
	}
	testutil.AssertEqualsString(t, "container path", "/mcp", info.MCP.ContainerPath)
	if err := update("-"); err != nil {
		t.Fatalf("clear mcp: %v", err)
	}
	server.apps.ResetAllAppCache()
	if _, _, err := server.resolveAppReference("app:/apps/upd"); err == nil {
		t.Fatal("cleared mcp must make the app a non-MCP app")
	}
}

func TestMCPHelpers(t *testing.T) {
	for req, want := range map[string]bool{"/apps/x": true, "/apps/x/mcp": true, "/apps/xy": false, "/apps": false} {
		testutil.AssertEqualsBool(t, req, want, inMCPRegion(req, "/apps/x"))
	}
	testutil.AssertEqualsBool(t, "root region", true, inMCPRegion("/anything", "/"))
	testutil.AssertEqualsString(t, "region join", "/apps/x/mcp", appMCPRegion("/apps/x", &types.MCPConfig{Path: "/mcp"}))
	testutil.AssertEqualsString(t, "region root", "/apps/x", appMCPRegion("/apps/x", &types.MCPConfig{Path: "/"}))

	newReq := func(body string, headers map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	r := newReq(`{"method":"tools/call","params":{"name":"t1"}}`, nil)
	ops, status, _ := mcpReadOperations(r)
	if status != 0 || len(ops) != 1 || ops[0].Method != "tools/call" || ops[0].Name != "t1" {
		t.Fatalf("body op: %v %d", ops, status)
	}
	body, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(body), "t1") {
		t.Fatal("body must be restored after reading")
	}
	// Headers are checked against the body, never trusted on their own
	encoded := "=?base64?" + base64.StdEncoding.EncodeToString([]byte("file:///a b")) + "?="
	ops, status, _ = mcpReadOperations(newReq(`{"method":"resources/read","params":{"uri":"file:///a b"}}`,
		map[string]string{"Mcp-Method": "resources/read", "Mcp-Name": encoded}))
	if status != 0 || ops[0].Name != "file:///a b" {
		t.Fatalf("matching encoded header must pass: %v %d", ops, status)
	}
	_, status, _ = mcpReadOperations(newReq(`{"method":"tools/call","params":{"name":"drop"}}`,
		map[string]string{"Mcp-Method": "tools/list"}))
	testutil.AssertEqualsInt(t, "method header mismatch", http.StatusBadRequest, status)
	_, status, _ = mcpReadOperations(newReq(`{"method":"tools/call","params":{"name":"drop"}}`,
		map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "list"}))
	testutil.AssertEqualsInt(t, "name header mismatch", http.StatusBadRequest, status)
	// Legacy batches: every operation is returned
	ops, status, _ = mcpReadOperations(newReq(`[{"method":"tools/list"},{"method":"tools/call","params":{"name":"drop"}}]`, nil))
	if status != 0 || len(ops) != 2 || ops[1].Name != "drop" {
		t.Fatalf("batch ops: %v %d", ops, status)
	}
	// Oversized, non-JSON and malformed bodies are refused, not forwarded
	_, status, _ = mcpReadOperations(newReq(strings.Repeat("x", mcpBodySniffLimit+1), nil))
	testutil.AssertEqualsInt(t, "oversized", http.StatusRequestEntityTooLarge, status)
	r = newReq(`{}`, map[string]string{"Content-Type": "text/plain"})
	_, status, _ = mcpReadOperations(r)
	testutil.AssertEqualsInt(t, "non-json", http.StatusUnsupportedMediaType, status)
	_, status, _ = mcpReadOperations(newReq(`not json`, nil))
	testutil.AssertEqualsInt(t, "malformed", http.StatusBadRequest, status)
	// Legacy GET streams carry no operation
	get := httptest.NewRequest(http.MethodGet, "/x", nil)
	ops, status, _ = mcpReadOperations(get)
	if status != 0 || len(ops) != 0 {
		t.Fatalf("GET: %v %d", ops, status)
	}

	unscopedKey := &types.Credential{Type: types.CredentialTypePAT}
	emptyToken := &types.Credential{Type: types.CredentialTypeOAuthAccess}
	testutil.AssertEqualsBool(t, "unscoped pat", false, credentialScoped(unscopedKey))
	testutil.AssertEqualsBool(t, "empty oauth token is scoped", true, credentialScoped(emptyToken))
}

// Apply files declare mcp as True, a path string or a dict; exports render
// the shortest form that round-trips; stage apps accept MCP POSTs without
// stage write access
func TestMCPAppApplyExportAndStage(t *testing.T) {
	server, ts, _ := newMCPAppTestServer(t)
	upstream := newUpstreamRecorder(t)
	dir := t.TempDir()
	appStar := fmt.Sprintf(`
load("proxy.in", "proxy")
app = ace.app("applied", routes=[ace.proxy("/", proxy.config(%q))], permissions=[ace.permission("proxy.in", "config")])`, upstream.server.URL)
	if err := os.WriteFile(filepath.Join(dir, "app.star"), []byte(appStar), 0600); err != nil {
		t.Fatalf("write app.star: %v", err)
	}
	applyPath := filepath.Join(t.TempDir(), "apps.ace")
	applyData := fmt.Sprintf(`
app("/apps/bare", %q, auth="builtin", mcp=True)
app("/apps/rewritten", %q, auth="builtin", mcp="/mcp")
app("/apps/region", %q, auth="builtin", mcp={"path": "/mcp", "scopes": ["r", "w"], "default_scope": "r", "tools": {"drop": "w"}})
`, dir, dir, dir)
	if err := os.WriteFile(applyPath, []byte(applyData), 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}
	ctx := system.WithTrustedOperation(t.Context())
	if _, _, err := server.Apply(ctx, types.Transaction{}, applyPath, "all",
		true, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	server.apps.ResetAllAppCache()

	for path, want := range map[string]types.MCPConfig{
		"/apps/bare":      {Path: "/"},
		"/apps/rewritten": {Path: "/", ContainerPath: "/mcp"},
		"/apps/region":    {Path: "/mcp", Scopes: []string{"r", "w"}, DefaultScope: "r", Tools: map[string]string{"drop": "w"}},
	} {
		info, _, err := server.resolveAppReference("app:" + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		testutil.AssertEqualsString(t, path+" config", want.Canonical(), info.MCP.Canonical())
	}

	// Export renders each in its shortest form
	for path, want := range map[string]string{
		"/apps/bare":      `mcp=True`,
		"/apps/rewritten": `mcp="/mcp"`,
		"/apps/region":    `mcp="{\"path\":\"/mcp\",\"scopes\":[\"r\",\"w\"],\"default_scope\":\"r\",\"tools\":{\"drop\":\"w\"}}"`,
	} {
		out, err := server.ExportAppVersion(ctx, path, "", "")
		if err != nil {
			t.Fatalf("export %s: %v", path, err)
		}
		if !strings.Contains(out, want) {
			t.Fatalf("export of %s must contain %s:\n%s", path, want, out)
		}
	}

	// Re-applying the same file is a no-op for mcp (change detection)
	if _, _, err := server.Apply(ctx, types.Transaction{}, applyPath, "all",
		true, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("re-apply: %v", err)
	}

	// Stage app: its own domain, its own resource; a POST goes through even
	// though stage write access is off (MCP is POST-only)
	apps, err := server.apps.GetAllAppsInfo()
	if err != nil {
		t.Fatalf("apps: %v", err)
	}
	var stage types.AppInfo
	for _, info := range apps {
		if info.Path == "/apps/bare" && info.MainApp != "" {
			stage = info
		}
	}
	if stage.Domain == "" || stage.MCP == nil {
		t.Fatalf("stage app not found or not mcp: %+v", stage)
	}
	stageKey, err := server.CreateApiKey(ctx, &types.ApiKeyCreateRequest{User: "builtin:alice",
		Resources: []string{"app:" + stage.Domain + ":/apps/bare"}})
	if err != nil {
		t.Fatalf("stage key: %v", err)
	}
	tsURL, _ := url.Parse(ts.URL)
	testutil.AssertEqualsString(t, "stage resource", "https://"+stage.Domain+":"+tsURL.Port()+"/apps/bare", stageKey.Resources[0])
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/apps/bare", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Host = stage.Domain
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+stageKey.Key)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("stage call: %v", err)
	}
	body := readBody(t, resp)
	testutil.AssertEqualsInt(t, "stage mcp post", http.StatusOK, resp.StatusCode)
	if !strings.Contains(body, `"tools"`) {
		t.Fatalf("stage response: %s", body)
	}
	// The prod key does not work at stage (distinct resources)
	prodKey, err := server.CreateApiKey(ctx, &types.ApiKeyCreateRequest{User: "builtin:alice", Resources: []string{"app:/apps/bare"}})
	if err != nil {
		t.Fatalf("prod key: %v", err)
	}
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/apps/bare", strings.NewReader(`{}`))
	req.Host = stage.Domain
	req.Header.Set("Authorization", "Bearer "+prodKey.Key)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("stage call with prod key: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "prod key at stage", http.StatusUnauthorized, resp.StatusCode)
}

// An MCP app at /mcp owns the flat well-known path on its host; the
// management surface documents live only at the /_openrun-prefixed paths
// the challenges point to
func TestMCPAppPRMShadowing(t *testing.T) {
	server, ts, client := newMCPAppTestServer(t)
	upstream := newUpstreamRecorder(t)
	createMCPTestApp(t, server, "/mcp", upstream.server.URL, "builtin", "true")
	tsURL, _ := url.Parse(ts.URL)

	resp, err := client.Get(ts.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatalf("app prm: %v", err)
	}
	var prm map[string]any
	decodeJSONBody(t, resp, &prm)
	testutil.AssertEqualsString(t, "app owns /mcp document", "https://localhost:"+tsURL.Port()+"/mcp", prm["resource"].(string))

	resp, err = client.Get(ts.URL + "/.well-known/oauth-protected-resource/_openrun/mcp")
	if err != nil {
		t.Fatalf("surface prm: %v", err)
	}
	decodeJSONBody(t, resp, &prm)
	testutil.AssertEqualsString(t, "surface document at alias", ts.URL+"/_openrun/mcp", prm["resource"].(string))
	// The flat /rest path is not a management document (no app there: 404)
	resp, err = client.Get(ts.URL + "/.well-known/oauth-protected-resource/rest")
	if err != nil {
		t.Fatalf("rest prm: %v", err)
	}
	resp.Body.Close() //nolint:errcheck
	testutil.AssertEqualsInt(t, "no flat rest document", http.StatusNotFound, resp.StatusCode)
	resp, err = client.Get(ts.URL + "/.well-known/oauth-protected-resource/_openrun/rest")
	if err != nil {
		t.Fatalf("rest prm: %v", err)
	}
	decodeJSONBody(t, resp, &prm)
	testutil.AssertEqualsString(t, "rest document", ts.URL+"/_openrun/rest", prm["resource"].(string))
	// The management challenge points at the alias
	resp, err = client.Get(ts.URL + "/_openrun/apps")
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	resp.Body.Close() //nolint:errcheck
	if ch := resp.Header.Get("WWW-Authenticate"); !strings.Contains(ch, "/.well-known/oauth-protected-resource/_openrun/rest") {
		t.Fatalf("management challenge must use the alias path, got %q", ch)
	}
}
