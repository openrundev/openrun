// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"testing"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestApiExternalUrlDefault(t *testing.T) {
	config := &types.ServerConfig{}
	config.System.DefaultDomain = "Example.com"
	config.Https.Port = 25223
	testutil.AssertEqualsString(t, "default with port", "https://example.com:25223", apiExternalUrlFor(config))
	if !apiExternalUrlIsDefault(config) {
		t.Fatal("origin must be reported as defaulted")
	}
	config.Https.Port = 443
	testutil.AssertEqualsString(t, "default port omitted", "https://example.com", apiExternalUrlFor(config))
	for _, port := range []int{-1, 0} {
		config.Https.Port = port
		testutil.AssertEqualsString(t, "no https listener", "", apiExternalUrlFor(config))
	}
	config.Https.Port = 25223
	config.System.DefaultDomain = ""
	testutil.AssertEqualsString(t, "no default domain", "", apiExternalUrlFor(config))

	// Configured values win, callback_url before the default, external_url
	// before callback_url; trailing slashes are dropped
	config.System.DefaultDomain = "example.com"
	config.Security.CallbackUrl = "https://cb.example.com/"
	testutil.AssertEqualsString(t, "callback_url", "https://cb.example.com", apiExternalUrlFor(config))
	config.Api.ExternalUrl = "https://api.example.com/"
	testutil.AssertEqualsString(t, "external_url", "https://api.example.com", apiExternalUrlFor(config))
	if apiExternalUrlIsDefault(config) {
		t.Fatal("a configured origin is not a default")
	}
}

func TestValidateApiExternalUrl(t *testing.T) {
	for _, external := range []string{"https://example.com", "https://example.com:25223", "https://localhost:25223"} {
		for _, loopback := range []bool{false, true} {
			if err := validateApiExternalUrl(external, loopback); err != nil {
				t.Fatalf("%s (loopback %v) must validate: %v", external, loopback, err)
			}
		}
	}
	for _, external := range []string{"http://localhost:25222", "http://127.0.0.1:25222", "http://[::1]:25222", "http://LOCALHOST"} {
		if err := validateApiExternalUrl(external, true); err != nil {
			t.Fatalf("%s must validate for MCP apps: %v", external, err)
		}
		if err := validateApiExternalUrl(external, false); err == nil || !strings.Contains(err.Error(), "plain https origin") {
			t.Fatalf("%s must be refused for the management surfaces, got %v", external, err)
		}
	}
	if err := validateApiExternalUrl("http://example.com", true); err == nil || !strings.Contains(err.Error(), "loopback host") {
		t.Fatalf("an http origin off loopback must be refused with the loopback hint, got %v", err)
	}
	for _, external := range []string{"https://example.com/path", "https://user@example.com", "https://example.com?x=1",
		"https://example.com#f", "ftp://example.com", "example.com", ""} {
		if err := validateApiExternalUrl(external, true); err == nil {
			t.Fatalf("%q must be refused", external)
		}
	}

	// An enabled management surface keeps the strict rule even when the
	// issuer is a loopback http origin
	config := &types.ServerConfig{}
	config.Api.Rest = types.ApiSurfaceConfig{Enable: true, Auth: []string{"admin"}}
	config.Api.MCP.Auth = []string{"admin"}
	config.Api.ExternalUrl = "http://localhost:25222"
	config.Https.Port = 25223
	if err := validateApiSurfaceConfig(config); err == nil || !strings.Contains(err.Error(), "plain https origin") {
		t.Fatalf("an enabled surface with an http issuer must be rejected, got %v", err)
	}
	// With no configured origin the listener default satisfies the surface
	// prerequisite
	config.Api.ExternalUrl = ""
	config.System.DefaultDomain = "example.com"
	if err := validateApiSurfaceConfig(config); err != nil {
		t.Fatalf("the default origin must satisfy an enabled surface: %v", err)
	}
	config.Https.Port = -1
	config.Security.TrustedProxies = []string{"10.0.0.0/8"}
	if err := validateApiSurfaceConfig(config); err == nil || !strings.Contains(err.Error(), "requires api.external_url") {
		t.Fatalf("no listener and no origin must still be rejected, got %v", err)
	}
}

// TestMCPAppIssuerDefaultAndDynamicUpdate: with nothing configured the
// HTTPS listener default lets an MCP app be created; without a listener
// the error names both the fields and the listener; while MCP apps are
// deployed a dynamic update cannot break the origin
func TestMCPAppIssuerDefaultAndDynamicUpdate(t *testing.T) {
	server, _, _ := newMCPAppTestServer(t)
	upstream := newUpstreamRecorder(t)
	ctx := system.WithTrustedOperation(t.Context())
	external := server.staticConfig.Api.ExternalUrl
	server.staticConfig.Api.ExternalUrl = ""
	server.staticConfig.Security.CallbackUrl = ""
	server.staticConfig.Api.Rest.Enable = false
	server.staticConfig.Api.MCP.Enable = false

	server.staticConfig.Https.Port = -1
	_, err := server.CreateApp(ctx, "/apps/noissuer", true, false, &types.CreateAppRequest{SourceUrl: proxyAppDir(t, upstream.server.URL), MCP: "true"})
	if err == nil || !strings.Contains(err.Error(), "external_url") || !strings.Contains(err.Error(), "https.port") {
		t.Fatalf("mcp app without issuer or listener must fail with the config hints, got %v", err)
	}

	server.staticConfig.Https.Port = 25223
	createMCPTestApp(t, server, "/apps/defaulted", upstream.server.URL, "builtin", "true")
	created, _, err := server.resolveAppReference("app:/apps/defaulted")
	if err != nil {
		t.Fatalf("app: %v", err)
	}
	testutil.AssertEqualsString(t, "resource from the listener default", "https://localhost:25223/apps/defaulted",
		server.appMCPResource(created.Path, created.Domain, created.MCP))

	// Dynamic updates: a broken or non-loopback http origin is refused
	// while the app exists; a loopback http origin and an https origin are
	// accepted
	dynamic := func(externalUrl string) error {
		_, err := server.prepareDynamicConfig(ctx, &types.DynamicConfig{RBAC: *rbac.DefaultConfig(),
			Settings: map[string]map[string]any{"api": {"external_url": externalUrl}}}, true)
		return err
	}
	for _, bad := range []string{"http://mcp.example.com", "https://example.com/api", "not a url"} {
		if err := dynamic(bad); err == nil || !strings.Contains(err.Error(), "mcp apps are deployed") {
			t.Fatalf("config update to %q must be refused while MCP apps exist, got %v", bad, err)
		}
	}
	for _, ok := range []string{"http://localhost:25222", "https://mcp.example.com"} {
		if err := dynamic(ok); err != nil {
			t.Fatalf("config update to %q must be accepted: %v", ok, err)
		}
	}
	server.staticConfig.Api.ExternalUrl = external
}

// proxyAppDir writes a minimal proxy app forwarding to the upstream
func proxyAppDir(t *testing.T, upstreamUrl string) string {
	t.Helper()
	dir := t.TempDir()
	appStar := `
load("proxy.in", "proxy")
app = ace.app("loop app", routes=[ace.proxy("/", proxy.config("` + upstreamUrl + `"))],
    permissions=[ace.permission("proxy.in", "config")])`
	if err := os.WriteFile(filepath.Join(dir, "app.star"), []byte(appStar), 0600); err != nil {
		t.Fatalf("write app.star: %v", err)
	}
	return dir
}

// TestMCPAppLoopbackPlaintextFlow: with a loopback http issuer the whole
// client walk works over plaintext on loopback (challenge, protected
// resource document, AS metadata, login, token, call), the management
// surfaces stay https-only, and nothing is served on a non-loopback
// plaintext host
func TestMCPAppLoopbackPlaintextFlow(t *testing.T) {
	server, _, _ := newMCPAppTestServer(t)
	upstream := newUpstreamRecorder(t)
	handler := NewTCPHandler(server.Logger, server.staticConfig, server)
	plain := httptest.NewServer(handler.router)
	t.Cleanup(plain.Close)
	client := plain.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	// The issuer is the plaintext listener on the default domain
	// (localhost; requests to 127.0.0.1 match the same apps)
	plainUrl, _ := url.Parse(plain.URL)
	issuer := "http://localhost:" + plainUrl.Port()
	server.staticConfig.Api.ExternalUrl = issuer
	createMCPTestApp(t, server, "/apps/loop", upstream.server.URL, "builtin",
		`{"path":"/","scopes":["loop:read"],"default_scope":"loop:read"}`)
	resource := issuer + "/apps/loop"

	resp := mcpCall(t, plain, "/apps/loop", "", nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if body := readBody(t, resp); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("challenge over loopback plaintext: want 401 got %d %s", resp.StatusCode, body)
	}

	prmUrl := issuer + "/.well-known/oauth-protected-resource/apps/loop"
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `resource_metadata="`+prmUrl+`"`) {
		t.Fatalf("challenge must point at the plaintext document, got %q", got)
	}

	var prm struct {
		Resource string   `json:"resource"`
		Servers  []string `json:"authorization_servers"`
	}
	resp, err := client.Get(prmUrl)
	if err != nil {
		t.Fatalf("prm: %v", err)
	}
	testutil.AssertEqualsInt(t, "prm over loopback plaintext", http.StatusOK, resp.StatusCode)
	decodeJSONBody(t, resp, &prm)
	testutil.AssertEqualsString(t, "resource", resource, prm.Resource)
	testutil.AssertEqualsString(t, "issuer", issuer, strings.Join(prm.Servers, ","))

	var as struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}

	resp, err = client.Get(plain.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("as metadata: %v", err)
	}
	testutil.AssertEqualsInt(t, "as metadata over loopback plaintext", http.StatusOK, resp.StatusCode)
	decodeJSONBody(t, resp, &as)
	testutil.AssertEqualsString(t, "authorize endpoint", issuer+"/_openrun/oauth/authorize", as.AuthorizationEndpoint)

	// Login, code, token, call: all over plaintext loopback
	verifier := "loopback-verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	code := runAuthorize(t, plain, client, "openrun-cli", "http://127.0.0.1:39999/callback",
		challenge, resource, "loop:read", "alice", "alicepw")
	resp, err = client.PostForm(as.TokenEndpoint, url.Values{
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
	resp = mcpCall(t, plain, "/apps/loop", tokenResp.AccessToken, nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "token at app over loopback plaintext", http.StatusOK, resp.StatusCode)
	_, gotHeaders, _ := upstream.last()
	testutil.AssertEqualsString(t, "user header", "builtin:alice", gotHeaders.Get(types.OPENRUN_HEADER_USER))

	// An app-bound API key accepts the plaintext resource url as the reference
	key, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()), &types.ApiKeyCreateRequest{Resources: []string{resource}})
	if err != nil {
		t.Fatalf("app key by url: %v", err)
	}
	testutil.AssertEqualsString(t, "key resource", resource, strings.Join(key.Resources, ","))

	// The management surfaces and their documents are still https-only
	for _, path := range []string{"/_openrun/apps", "/_openrun/mcp", "/.well-known/oauth-protected-resource/_openrun/rest"} {
		req, _ := http.NewRequest(http.MethodGet, plain.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		readBody(t, resp)
		testutil.AssertEqualsInt(t, path+" over plaintext", http.StatusNotFound, resp.StatusCode)
	}

	// Plaintext off loopback: nothing, not even the documents. Both the
	// Host header and the peer address must be loopback: a remote caller
	// sending Host: localhost (httptest.NewRequest's peer is 192.0.2.1)
	// gets the same plain 404 as a loopback peer asking for another host
	paths := []string{"/apps/loop", "/.well-known/oauth-protected-resource/apps/loop",
		"/.well-known/oauth-authorization-server", "/_openrun/oauth/authorize?resource=" + url.QueryEscape(resource)}
	for _, tc := range []struct{ name, host, remote string }{
		{"remote peer, remote host", "mcp.example.com", "192.0.2.1:1234"},
		{"remote peer, loopback host", "localhost:" + plainUrl.Port(), "192.0.2.1:1234"},
		{"loopback peer, remote host", "mcp.example.com", "127.0.0.1:1234"},
	} {
		for _, path := range paths {
			req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+path, nil)
			req.RemoteAddr = tc.remote
			rec := httptest.NewRecorder()
			handler.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound || rec.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("%s (%s): want a plain 404, got %d %q", path, tc.name, rec.Code, rec.Header().Get("WWW-Authenticate"))
			}
		}
	}
	// Loopback peer and loopback host over plaintext: the region answers
	req := httptest.NewRequest(http.MethodPost, "http://localhost:"+plainUrl.Port()+"/apps/loop", strings.NewReader(`{}`))
	req.RemoteAddr = "[::1]:1234"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.router.ServeHTTP(rec, req)
	testutil.AssertEqualsInt(t, "loopback peer and host", http.StatusUnauthorized, rec.Code)

}
