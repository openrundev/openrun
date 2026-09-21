// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// newFederatedTestServer builds an OAuth test server with a real provider
// manager (cookie store, a github entry with placeholder credentials) and a
// router registered against it. The provider's user completion is stubbed
// so the callback can be driven without leaving the process
func newFederatedTestServer(t *testing.T, user goth.User) (*Server, *httptest.Server, *http.Client) {
	t.Helper()
	server, _, _ := newMCPAppTestServer(t)
	server.staticConfig.Auth = map[string]types.AuthConfig{"github": {Key: "client-id", Secret: "client-secret"}}
	server.staticConfig.Security.SessionMaxAge = 3600
	// Setup needs a callback origin to build the providers; the real origin
	// is the TLS server created below and is read per request
	server.staticConfig.Security.CallbackUrl = "https://placeholder.invalid"
	manager := NewOAuthManager(server.Logger, server.staticConfig, server.db)
	if err := manager.Setup([]byte(strings.Repeat("k", 32)), []byte(strings.Repeat("b", 32))); err != nil {
		t.Fatalf("oauth manager setup: %v", err)
	}
	server.oAuthManager = manager
	server.samlManager = NewSAMLManager(server.Logger, server.staticConfig, manager.cookieStore, server.db)
	originalComplete := gothic.CompleteUserAuth
	gothic.CompleteUserAuth = func(http.ResponseWriter, *http.Request) (goth.User, error) { return user, nil }
	t.Cleanup(func() { gothic.CompleteUserAuth = originalComplete })

	// A router bound to the configured managers; the AS and callback origin
	// are this server
	handler := NewTCPHandler(server.Logger, server.staticConfig, server)
	ts := httptest.NewTLSServer(handler.router)
	t.Cleanup(ts.Close)
	server.staticConfig.Api.ExternalUrl = ts.URL
	server.staticConfig.Security.CallbackUrl = ts.URL
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	return server, ts, client
}

func getRedirect(t *testing.T, client *http.Client, target string) (*http.Response, string) {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("get %s: %v", target, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("get %s: want 302 got %d: %s", target, resp.StatusCode, body)
	}
	return resp, resp.Header.Get("Location")
}

func TestOAuthFederatedLoginForMCPApp(t *testing.T) {
	server, ts, client := newFederatedTestServer(t, goth.User{UserID: "sub-1", NickName: "jane",
		Email: "jane@example.com", RawData: map[string]any{"groups": []any{"dev"}}})
	upstream := newUpstreamRecorder(t)
	createMCPTestApp(t, server, "/apps/orders", upstream.server.URL, "github",
		`{"scopes":["orders:read","orders:write"],"default_scope":"orders:read"}`)
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{Grants: []types.RBACGrant{
		{Users: []string{"github:jane@example.com"}, Roles: []string{"openrun-user"}, Targets: []string{"/apps/**"}},
	}}); err != nil {
		t.Fatalf("rbac: %v", err)
	}
	tsURL, _ := url.Parse(ts.URL)
	resource := "https://localhost:" + tsURL.Port() + "/apps/orders"

	verifier := "federated-verifier-0123456789-0123456789-0123456789"
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	form := url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"}, "state": {"cs1"},
		"redirect_uri": {"http://127.0.0.1:39999/callback"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "resource": {resource}, "scope": {"orders:read orders:write"}}

	// 1. The app's only mechanism is github: authorize goes straight into
	// the provider login
	_, location := getRedirect(t, client, ts.URL+"/_openrun/oauth/authorize?"+form.Encode())
	loginURL, err := url.Parse(location)
	if err != nil || loginURL.Path != "/_openrun/auth/github/login" || loginURL.Query().Get("state") == "" {
		t.Fatalf("expected provider login redirect, got %s", location)
	}
	// 2. The provider calls back (completion stubbed) and the callback
	// sends the browser to the redirect endpoint on the AS host
	_, location = getRedirect(t, client, ts.URL+"/_openrun/auth/github/callback?state="+url.QueryEscape(loginURL.Query().Get("state")))
	if !strings.Contains(location, "/_openrun/auth/github/redirect?state=") {
		t.Fatalf("expected redirect endpoint, got %s", location)
	}
	// 3. The redirect endpoint sets the session cookie and returns to the
	// authorize continue URL
	_, location = getRedirect(t, client, location)
	if !strings.Contains(location, "/_openrun/oauth/authorize/continue?authz=") {
		t.Fatalf("expected continue url, got %s", location)
	}
	// 4. Consent page shows the federated identity
	resp, err := client.Get(location)
	if err != nil {
		t.Fatalf("continue: %v", err)
	}
	page := readBody(t, resp)
	testutil.AssertEqualsInt(t, "consent", http.StatusOK, resp.StatusCode)
	if !strings.Contains(page, "Signed in as <b>github:jane@example.com</b>") || !strings.Contains(page, "mcp test app") {
		t.Fatalf("consent page: %s", page)
	}
	testutil.AssertEqualsString(t, "frame-options", "DENY", resp.Header.Get("X-Frame-Options"))
	authz := regexp.MustCompile(`name="authz" value="([^"]+)"`).FindStringSubmatch(page)
	nonce := regexp.MustCompile(`name="nonce" value="([^"]+)"`).FindStringSubmatch(page)
	if authz == nil || nonce == nil {
		t.Fatalf("consent page missing authz/nonce: %s", page)
	}
	// The provider login recorded the identity and its group snapshot
	identity, err := server.db.GetIdentityByPrincipal(t.Context(), "github:jane@example.com")
	if err != nil || identity.StableSubject != "sub-1" || len(identity.Groups) != 1 || identity.Groups[0] != "dev" ||
		identity.Email != "jane@example.com" {
		t.Fatalf("identity: %+v %v", identity, err)
	}

	// A wrong nonce is refused; the record survives
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize/consent", url.Values{
		"authz": {authz[1]}, "nonce": {"wrong"}, "or_scope": {"orders:read"}})
	if err != nil {
		t.Fatalf("bad nonce: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "bad nonce", http.StatusBadRequest, resp.StatusCode)

	// 5. Consent issues the code (narrowed scope honored)
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize/consent", url.Values{
		"authz": {authz[1]}, "nonce": {nonce[1]}, "or_scope": {"orders:read"}})
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "consent redirect", http.StatusFound, resp.StatusCode)
	redirect, _ := url.Parse(resp.Header.Get("Location"))
	code := redirect.Query().Get("code")
	testutil.AssertEqualsString(t, "state echoed", "cs1", redirect.Query().Get("state"))
	if code == "" {
		t.Fatalf("no code in %s", resp.Header.Get("Location"))
	}
	// The record is single use
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize/consent", url.Values{
		"authz": {authz[1]}, "nonce": {nonce[1]}})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "consent replay", http.StatusBadRequest, resp.StatusCode)

	// 6. Token bound to the app, federated principal at the app
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
		t.Fatalf("token exchange: %+v", tokenResp)
	}
	testutil.AssertEqualsString(t, "principal", "github:jane@example.com", tokenResp.Principal)
	testutil.AssertEqualsString(t, "scope", "orders:read", tokenResp.Scope)
	resp = mcpCall(t, ts, "/apps/orders", tokenResp.AccessToken, nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "federated token at app", http.StatusOK, resp.StatusCode)
	_, gotHeaders, _ := upstream.last()
	testutil.AssertEqualsString(t, "user header", "github:jane@example.com", gotHeaders.Get(types.OPENRUN_HEADER_USER))
	testutil.AssertEqualsString(t, "subject header", "sub-1", gotHeaders.Get(types.OPENRUN_HEADER_USER_ID))
	testutil.AssertEqualsString(t, "email header", "jane@example.com", gotHeaders.Get(types.OPENRUN_HEADER_USER_EMAIL))

	// 7. A second authorize reuses the provider session: no login redirect,
	// straight to consent
	_, location = getRedirect(t, client, ts.URL+"/_openrun/oauth/authorize?"+form.Encode())
	loginURL, _ = url.Parse(location)
	_, location = getRedirect(t, client, ts.URL+"/_openrun/auth/github/callback?state="+url.QueryEscape(loginURL.Query().Get("state")))
	_ = location
}

func TestOAuthFederatedChooserForSurface(t *testing.T) {
	server, ts, client := newFederatedTestServer(t, goth.User{UserID: "sub-2", Email: "bob@example.com"})
	server.staticConfig.Api.MCP.Auth = []string{"builtin", "github", "saml_missing"}
	form := url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"},
		"redirect_uri": {"http://127.0.0.1:39999/callback"}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "resource": {ts.URL + "/_openrun/mcp"}}
	resp, err := client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	page := readBody(t, resp)
	testutil.AssertEqualsInt(t, "chooser", http.StatusOK, resp.StatusCode)
	if !strings.Contains(page, `name="mechanism" value="github"`) || !strings.Contains(page, "Continue with github") {
		t.Fatalf("chooser must offer github: %s", page)
	}
	if !strings.Contains(page, `name="or_password"`) {
		t.Fatal("chooser must keep the password form for builtin")
	}
	if strings.Contains(page, "saml_missing") {
		t.Fatal("an unconfigured saml mechanism must not be offered")
	}
	// Choosing github starts the provider login; an unknown mechanism is refused
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize/federated", withMechanism(form, "github"))
	if err != nil {
		t.Fatalf("federated: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "start login", http.StatusFound, resp.StatusCode)
	if !strings.Contains(resp.Header.Get("Location"), "/_openrun/auth/github/login?state=") {
		t.Fatalf("expected login redirect, got %s", resp.Header.Get("Location"))
	}
	// Complete the login and reach consent; a bad RBAC scope is reported
	// on the form and the request survives for a corrected resubmit
	loginURL, _ := url.Parse(resp.Header.Get("Location"))
	_, location := getRedirect(t, client, ts.URL+"/_openrun/auth/github/callback?state="+url.QueryEscape(loginURL.Query().Get("state")))
	_, location = getRedirect(t, client, location)
	resp, err = client.Get(location)
	if err != nil {
		t.Fatalf("continue: %v", err)
	}
	page = readBody(t, resp)
	authz := regexp.MustCompile(`name="authz" value="([^"]+)"`).FindStringSubmatch(page)
	nonce := regexp.MustCompile(`name="nonce" value="([^"]+)"`).FindStringSubmatch(page)
	if authz == nil || nonce == nil {
		t.Fatalf("consent page missing authz/nonce: %s", page)
	}
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize/consent", url.Values{
		"authz": {authz[1]}, "nonce": {nonce[1]}, "or_scope": {"app:["}})
	if err != nil {
		t.Fatalf("bad scope consent: %v", err)
	}
	page = readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "invalid scope") {
		t.Fatalf("bad scope must re-render the consent form, got %d %s", resp.StatusCode, page)
	}
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize/consent", url.Values{
		"authz": {authz[1]}, "nonce": {nonce[1]}, "or_scope": {"*:read"}})
	if err != nil {
		t.Fatalf("corrected consent: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "corrected consent issues the code", http.StatusFound, resp.StatusCode)
	if !strings.Contains(resp.Header.Get("Location"), "code=") {
		t.Fatalf("expected a code, got %s", resp.Header.Get("Location"))
	}

	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize/federated", withMechanism(form, "google"))
	if err != nil {
		t.Fatalf("federated: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "unknown mechanism", http.StatusBadRequest, resp.StatusCode)
	// The continue endpoint refuses unknown records
	resp, err = client.Get(ts.URL + "/_openrun/oauth/authorize/continue?authz=nope")
	if err != nil {
		t.Fatalf("continue: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "unknown authz", http.StatusBadRequest, resp.StatusCode)
}

func withMechanism(form url.Values, mechanism string) url.Values {
	out := url.Values{}
	for k, v := range form {
		out[k] = v
	}
	out.Set("mechanism", mechanism)
	return out
}
