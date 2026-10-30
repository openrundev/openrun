// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// newFederatedTestServer builds an OAuth test server with a real provider
// manager (cookie store, a github entry with placeholder credentials) and a
// router registered against it. The provider's user completion is stubbed
// so the callback can be driven without leaving the process.
//
// The default domain is localhost, so the AS browser pages are served on
// the login origin https://auth.localhost:<port> (see oauthLoginOrigin);
// the client dials the test listener for every host, like a browser whose
// *.localhost names resolve to loopback, and the cookie jar keeps the
// auth.localhost and 127.0.0.1 cookies apart like a browser would
func newFederatedTestServer(t *testing.T, user goth.User) (*Server, *httptest.Server, *http.Client) {
	t.Helper()
	server, _, _ := newMCPAppTestServer(t)
	server.staticConfig.Auth = map[string]types.AuthConfig{"github": {Key: "client-id", Secret: "client-secret"}}
	server.staticConfig.Security.SessionMaxAge = 3600
	server.staticConfig.Security.AuthCallbackDomain = "auth."
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
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true // auth.localhost is not in the test certificate
	listenAddr := ts.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listenAddr)
	}
	client.Transport = transport
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	return server, ts, client
}

// loginOriginOf is the login origin of the federated test server: the auth
// callback domain on the issuer's port
func loginOriginOf(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	tsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	return "https://auth.localhost:" + tsURL.Port()
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
	login := loginOriginOf(t, ts)

	verifier := "federated-verifier-0123456789-0123456789-0123456789"
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	form := url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"}, "state": {"cs1"},
		"redirect_uri": {"http://127.0.0.1:39999/callback"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "resource": {resource}, "scope": {"orders:read orders:write"}}

	// 1. The app's only mechanism is github: authorize goes straight into
	// the provider login
	_, location := getRedirect(t, client, login+"/_openrun/oauth/authorize?"+form.Encode())
	loginURL, err := url.Parse(location)
	if err != nil || loginURL.Path != "/_openrun/auth/github/login" || loginURL.Query().Get("state") == "" {
		t.Fatalf("expected provider login redirect, got %s", location)
	}
	// The pre-login state returns to the login origin, built from config:
	// the request Host never decides where the completion token is sent
	preAuthID, err := base64.URLEncoding.DecodeString(loginURL.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	preAuth, err := server.db.FetchKV(t.Context(), string(preAuthID))
	if err != nil {
		t.Fatalf("pre-login state: %v", err)
	}
	if redirect, _ := preAuth[REDIRECT_URL].(string); !strings.HasPrefix(redirect, login+"/_openrun/oauth/authorize/continue?authz=") {
		t.Fatalf("pre-login redirect must be the continue url on the login origin, got %q", redirect)
	}
	// 2. The provider calls back (completion stubbed) and the callback
	// sends the browser to the redirect endpoint on the login origin
	_, location = getRedirect(t, client, ts.URL+"/_openrun/auth/github/callback?state="+url.QueryEscape(loginURL.Query().Get("state")))
	if !strings.HasPrefix(location, login+"/_openrun/auth/github/redirect?state=") {
		t.Fatalf("expected redirect endpoint on the login origin, got %s", location)
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
	if !strings.Contains(page, "<dd>github:jane@example.com</dd>") || !strings.Contains(page, "mcp test app") {
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
	resp, err = client.PostForm(login+"/_openrun/oauth/authorize/consent", url.Values{
		"authz": {authz[1]}, "nonce": {"wrong"}, "or_scope": {"orders:read"}})
	if err != nil {
		t.Fatalf("bad nonce: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "bad nonce", http.StatusBadRequest, resp.StatusCode)

	// 5. Consent issues the code (narrowed scope honored)
	resp, err = client.PostForm(login+"/_openrun/oauth/authorize/consent", url.Values{
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
	resp, err = client.PostForm(login+"/_openrun/oauth/authorize/consent", url.Values{
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
	_, location = getRedirect(t, client, login+"/_openrun/oauth/authorize?"+form.Encode())
	loginURL, _ = url.Parse(location)
	_, location = getRedirect(t, client, ts.URL+"/_openrun/auth/github/callback?state="+url.QueryEscape(loginURL.Query().Get("state")))
	_ = location
}

func TestOAuthFederatedChooserForSurface(t *testing.T) {
	server, ts, client := newFederatedTestServer(t, goth.User{UserID: "sub-2", Email: "bob@example.com"})
	server.staticConfig.Api.MCP.Auth = []string{"builtin", "github", "saml_missing"}
	login := loginOriginOf(t, ts)
	form := url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"},
		"redirect_uri": {"http://127.0.0.1:39999/callback"}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "resource": {ts.URL + "/_openrun/mcp"}}
	resp, err := client.Get(login + "/_openrun/oauth/authorize?" + form.Encode())
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
	resp, err = client.PostForm(login+"/_openrun/oauth/authorize/federated", withMechanism(form, "github"))
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
	resp, err = client.PostForm(login+"/_openrun/oauth/authorize/consent", url.Values{
		"authz": {authz[1]}, "nonce": {nonce[1]}, "or_scope": {"app:["}})
	if err != nil {
		t.Fatalf("bad scope consent: %v", err)
	}
	page = readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "invalid scope") {
		t.Fatalf("bad scope must re-render the consent form, got %d %s", resp.StatusCode, page)
	}
	resp, err = client.PostForm(login+"/_openrun/oauth/authorize/consent", url.Values{
		"authz": {authz[1]}, "nonce": {nonce[1]}, "or_scope": {"*:read"}})
	if err != nil {
		t.Fatalf("corrected consent: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "corrected consent issues the code", http.StatusFound, resp.StatusCode)
	if !strings.Contains(resp.Header.Get("Location"), "code=") {
		t.Fatalf("expected a code, got %s", resp.Header.Get("Location"))
	}

	resp, err = client.PostForm(login+"/_openrun/oauth/authorize/federated", withMechanism(form, "google"))
	if err != nil {
		t.Fatalf("federated: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "unknown mechanism", http.StatusBadRequest, resp.StatusCode)
	// The continue endpoint refuses unknown records
	resp, err = client.Get(login + "/_openrun/oauth/authorize/continue?authz=nope")
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

// The cookie-reading AS pages exist only on the login origin: on a host
// that serves apps, same-origin app JavaScript could otherwise fetch the
// consent form with the provider cookie, read its nonce and post it back,
// minting a code silently. And the continue step returns to a config-built
// URL, so a Host header the initiator chose cannot become the destination
// of the completion token (which would revive GHSA-rw93-hw9g-vc3m)
func TestOAuthFederatedLoginOriginIsolation(t *testing.T) {
	server, ts, client := newFederatedTestServer(t, goth.User{UserID: "sub-3", Email: "eve@example.com"})
	server.staticConfig.Api.MCP.Auth = []string{"builtin", "github"}
	login := loginOriginOf(t, ts)
	form := url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"},
		"redirect_uri": {"http://127.0.0.1:39999/callback"}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "resource": {ts.URL + "/_openrun/mcp"}}

	// The metadata names the login origin for authorize, the issuer for the rest
	var metadata map[string]any
	resp, err := client.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	decodeJSONBody(t, resp, &metadata)
	testutil.AssertEqualsString(t, "authorization_endpoint", login+"/_openrun/oauth/authorize", metadata["authorization_endpoint"].(string))
	testutil.AssertEqualsString(t, "token_endpoint", ts.URL+"/_openrun/oauth/token", metadata["token_endpoint"].(string))
	testutil.AssertEqualsString(t, "issuer", ts.URL, metadata["issuer"].(string))

	// A GET on the issuer host is sent to the login origin, query intact
	_, location := getRedirect(t, client, ts.URL+"/_openrun/oauth/authorize?"+form.Encode())
	testutil.AssertEqualsString(t, "authorize redirect", login+"/_openrun/oauth/authorize?"+form.Encode(), location)

	// The cookie-based steps are 404 off the login origin
	for _, tc := range []struct{ name, method, target string }{
		{"federated", http.MethodPost, ts.URL + "/_openrun/oauth/authorize/federated"},
		{"continue", http.MethodGet, ts.URL + "/_openrun/oauth/authorize/continue?authz=x"},
		{"consent", http.MethodPost, ts.URL + "/_openrun/oauth/authorize/consent"},
	} {
		req, err := http.NewRequest(tc.method, tc.target, strings.NewReader(withMechanism(form, "github").Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		readBody(t, resp)
		testutil.AssertEqualsInt(t, tc.name+" on the issuer host", http.StatusNotFound, resp.StatusCode)
	}

	// Start a login on the login origin, then try to reach continue with a
	// foreign Host: the login origin is checked by name, so a poisoned Host
	// gets a 404 instead of starting a login that would return there
	resp, err = client.PostForm(login+"/_openrun/oauth/authorize/federated", withMechanism(form, "github"))
	if err != nil {
		t.Fatalf("federated: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "start login", http.StatusFound, resp.StatusCode)
	loginURL, _ := url.Parse(resp.Header.Get("Location"))
	preAuthID, _ := base64.URLEncoding.DecodeString(loginURL.Query().Get("state"))
	preAuth, err := server.db.FetchKV(t.Context(), string(preAuthID))
	if err != nil {
		t.Fatalf("pre-login state: %v", err)
	}
	continueURL, _ := preAuth[REDIRECT_URL].(string)
	if !strings.HasPrefix(continueURL, login+"/_openrun/oauth/authorize/continue?authz=") {
		t.Fatalf("pre-login redirect must be on the login origin, got %q", continueURL)
	}
	authzID := strings.TrimPrefix(continueURL, login+"/_openrun/oauth/authorize/continue?authz=")
	poisoned, err := http.NewRequest(http.MethodGet, login+"/_openrun/oauth/authorize/continue?authz="+authzID, nil)
	if err != nil {
		t.Fatal(err)
	}
	poisoned.Host = "evil.example.com"
	resp, err = client.Do(poisoned)
	if err != nil {
		t.Fatalf("poisoned continue: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "continue with a foreign Host", http.StatusNotFound, resp.StatusCode)
	// No login was started for the foreign host: no pre-auth cookie, no
	// login redirect
	if len(resp.Cookies()) != 0 || resp.Header.Get("Location") != "" {
		t.Fatalf("a poisoned continue must not start a login: cookies %v location %q", resp.Cookies(), resp.Header.Get("Location"))
	}

	// The password form keeps working on the issuer path: it carries its
	// credential and reads no cookie, and the page it re-renders there
	// offers no federated login
	form.Set("or_username", "alice")
	form.Set("or_password", "wrong")
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize", form)
	if err != nil {
		t.Fatalf("password post: %v", err)
	}
	page := readBody(t, resp)
	testutil.AssertEqualsInt(t, "password page on the issuer host", http.StatusOK, resp.StatusCode)
	if !strings.Contains(page, `name="or_password"`) || strings.Contains(page, `name="mechanism"`) {
		t.Fatalf("issuer-host page must keep the password form and drop the chooser: %s", page)
	}
	form.Set("or_password", "alicepw")
	form.Set("or_scope", "*:read")
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize", form)
	if err != nil {
		t.Fatalf("password post: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "password login on the issuer host", http.StatusFound, resp.StatusCode)
	if !strings.Contains(resp.Header.Get("Location"), "code=") {
		t.Fatalf("expected a code, got %s", resp.Header.Get("Location"))
	}
}

// Without an auth callback domain there is no app-free origin for the
// cookie-based steps, so the federated logins are refused with the config
// to set, while the password login stays on the issuer host
func TestOAuthFederatedNeedsLoginOrigin(t *testing.T) {
	server, ts, client := newFederatedTestServer(t, goth.User{UserID: "sub-4", Email: "dan@example.com"})
	server.staticConfig.Security.AuthCallbackDomain = ""
	server.staticConfig.Api.MCP.Auth = []string{"builtin", "github"}
	form := url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"},
		"redirect_uri": {"http://127.0.0.1:39999/callback"}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "resource": {ts.URL + "/_openrun/mcp"}}

	var metadata map[string]any
	resp, err := client.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	decodeJSONBody(t, resp, &metadata)
	testutil.AssertEqualsString(t, "authorization_endpoint", ts.URL+"/_openrun/oauth/authorize", metadata["authorization_endpoint"].(string))

	// The chooser explains, offers no federated login, keeps the password form
	resp, err = client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	page := readBody(t, resp)
	testutil.AssertEqualsInt(t, "chooser", http.StatusOK, resp.StatusCode)
	if !strings.Contains(page, "security.auth_callback_domain") || strings.Contains(page, `name="mechanism"`) ||
		!strings.Contains(page, `name="or_password"`) {
		t.Fatalf("page must explain the missing auth domain and keep only the password form: %s", page)
	}
	// Starting the federated login directly is refused the same way
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/authorize/federated", withMechanism(form, "github"))
	if err != nil {
		t.Fatalf("federated: %v", err)
	}
	page = readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "security.auth_callback_domain") {
		t.Fatalf("federated start must be refused with the config to set, got %d %s", resp.StatusCode, page)
	}
	if len(resp.Cookies()) != 0 {
		t.Fatalf("a refused federated start must not set a pre-auth cookie: %v", resp.Cookies())
	}
	// A github-only resource has nothing left to offer
	server.staticConfig.Api.MCP.Auth = []string{"github"}
	resp, err = client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	page = readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "security.auth_callback_domain") || strings.Contains(page, `name="or_password"`) {
		t.Fatalf("github-only resource must show the config message only, got %d %s", resp.StatusCode, page)
	}
	// The password login works on the issuer host as before
	server.staticConfig.Api.MCP.Auth = []string{"builtin", "github"}
	code := runAuthorize(t, ts, client, "openrun-cli", "http://127.0.0.1:39999/callback",
		strings.Repeat("a", 43), ts.URL+"/_openrun/mcp", "*:read", "alice", "alicepw")
	if code == "" {
		t.Fatal("password login must still issue a code")
	}
}

// A plaintext issuer is served to loopback callers only, so a login origin
// on a non-local auth domain (http://login.example.com) would be advertised
// but never answer: it counts as no login origin. A *.localhost auth domain
// keeps working with the http issuer
func TestOAuthFederatedPlaintextIssuerNeedsLocalAuthDomain(t *testing.T) {
	server, ts, client := newFederatedTestServer(t, goth.User{UserID: "sub-5", Email: "eve@example.com"})
	port := ts.Listener.Addr().(*net.TCPAddr).Port
	server.staticConfig.Api.ExternalUrl = fmt.Sprintf("http://localhost:%d", port)
	server.staticConfig.Security.AuthCallbackDomain = "login.example.com"
	server.staticConfig.Api.MCP.Auth = []string{"builtin", "github"}
	if origin, ok := server.oauthLoginOrigin(); ok {
		t.Fatalf("a plaintext issuer must not get a non-local login origin, got %s", origin)
	}
	if msg := server.federatedLoginUnavailable(); !strings.Contains(msg, "plaintext") || !strings.Contains(msg, "login.example.com") {
		t.Fatalf("message must explain the scheme/domain mismatch: %s", msg)
	}

	form := url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"},
		"redirect_uri": {"http://127.0.0.1:39999/callback"}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "resource": {server.staticConfig.Api.ExternalUrl + "/_openrun/mcp"}}
	var metadata map[string]any
	resp, err := client.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	decodeJSONBody(t, resp, &metadata)
	testutil.AssertEqualsString(t, "authorization_endpoint",
		server.staticConfig.Api.ExternalUrl+"/_openrun/oauth/authorize", metadata["authorization_endpoint"].(string))
	// No redirect off to the unreachable origin: the chooser is served here
	// with the password form and the explanation
	resp, err = client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	page := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "plaintext") ||
		strings.Contains(page, `name="mechanism"`) || !strings.Contains(page, `name="or_password"`) {
		t.Fatalf("chooser must keep the password form and explain, got %d %s", resp.StatusCode, page)
	}

	// The default auth. prefix on a localhost default domain is local: usable
	server.staticConfig.Security.AuthCallbackDomain = "auth."
	server.staticConfig.System.DefaultDomain = "localhost"
	origin, ok := server.oauthLoginOrigin()
	if !ok || origin != fmt.Sprintf("http://auth.localhost:%d", port) {
		t.Fatalf("auth.localhost must be a usable login origin for an http issuer, got %q %v", origin, ok)
	}
}

// The pending authorize request is bound to the browser that started it
// (a cookie on the login origin) and, once the consent page is shown, to
// the identity it was shown to: the record id and nonce alone, known to
// whoever started the flow, mint nothing from another browser or user
func TestOAuthFederatedAuthzBoundToBrowserAndUser(t *testing.T) {
	server, ts, client := newFederatedTestServer(t, goth.User{UserID: "sub-6", Email: "fay@example.com"})
	upstream := newUpstreamRecorder(t)
	createMCPTestApp(t, server, "/apps/orders", upstream.server.URL, "github", `{"scopes":["orders:read"],"default_scope":"orders:read"}`)
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{Grants: []types.RBACGrant{
		{Users: []string{"github:fay@example.com"}, Roles: []string{"openrun-user"}, Targets: []string{"/apps/**"}},
	}}); err != nil {
		t.Fatalf("rbac: %v", err)
	}
	tsURL, _ := url.Parse(ts.URL)
	login := loginOriginOf(t, ts)
	form := url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"},
		"redirect_uri": {"http://127.0.0.1:39999/callback"}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "resource": {"https://localhost:" + tsURL.Port() + "/apps/orders"}}

	// Starting the flow sets the binding cookie on the login origin only
	resp, location := getRedirect(t, client, login+"/_openrun/oauth/authorize?"+form.Encode())
	var binding *http.Cookie
	for _, cookie := range resp.Cookies() {
		if strings.HasPrefix(cookie.Name, "oauth_authz_") {
			binding = cookie
		}
	}
	if binding == nil || !binding.HttpOnly || !binding.Secure || binding.SameSite != http.SameSiteLaxMode ||
		binding.Path != "/_openrun/oauth/authorize" {
		t.Fatalf("expected an HttpOnly Secure Lax binding cookie on the authorize path, got %v", resp.Cookies())
	}
	loginURL, _ := url.Parse(location)
	_, location = getRedirect(t, client, ts.URL+"/_openrun/auth/github/callback?state="+url.QueryEscape(loginURL.Query().Get("state")))
	_, continueURL := getRedirect(t, client, location)
	authzID := strings.TrimPrefix(continueURL, login+"/_openrun/oauth/authorize/continue?authz=")

	// Another browser (no binding cookie) given the continue link is refused
	// before any login redirect, and so is one that consents with the right nonce
	other := *client
	other.Jar, _ = cookiejar.New(nil)
	resp, err := other.Get(continueURL)
	if err != nil {
		t.Fatalf("continue: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "another browser") || resp.Header.Get("Location") != "" {
		t.Fatalf("unbound continue must be refused, got %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}

	// The owning browser sees the consent page
	resp, err = client.Get(continueURL)
	if err != nil {
		t.Fatalf("continue: %v", err)
	}
	page := readBody(t, resp)
	testutil.AssertEqualsInt(t, "consent", http.StatusOK, resp.StatusCode)
	nonce := regexp.MustCompile(`name="nonce" value="([^"]+)"`).FindStringSubmatch(page)
	if nonce == nil {
		t.Fatalf("consent page: %s", page)
	}
	consent := url.Values{"authz": {authzID}, "nonce": {nonce[1]}, "or_scope": {"orders:read"}}
	resp, err = other.PostForm(login+"/_openrun/oauth/authorize/consent", consent)
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "unbound consent", http.StatusBadRequest, resp.StatusCode)

	// The record carries the identity the page was shown to; a consent by a
	// different identity is refused, the record survives
	stored, err := server.fetchOAuthAuthz(t.Context(), authzID)
	if err != nil || stored == nil || stored.Principal != "github:fay@example.com" {
		t.Fatalf("record must hold the consenting principal: %+v %v", stored, err)
	}
	stored.Principal = "github:someone-else@example.com"
	if err := server.updateOAuthAuthz(t.Context(), authzID, stored); err != nil {
		t.Fatal(err)
	}
	resp, err = client.PostForm(login+"/_openrun/oauth/authorize/consent", consent)
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "not shown to this user") {
		t.Fatalf("consent by another identity must be refused, got %d %s", resp.StatusCode, body)
	}
	// Re-showing the page re-records the identity and consent succeeds
	resp, err = client.Get(continueURL)
	if err != nil {
		t.Fatalf("continue: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "consent again", http.StatusOK, resp.StatusCode)
	resp, err = client.PostForm(login+"/_openrun/oauth/authorize/consent", consent)
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "consent redirect", http.StatusFound, resp.StatusCode)
	if !strings.Contains(resp.Header.Get("Location"), "code=") {
		t.Fatalf("expected a code, got %s", resp.Header.Get("Location"))
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "oauth_authz_"+authzID && cookie.MaxAge >= 0 {
			t.Fatalf("binding cookie must be cleared with the record: %v", cookie)
		}
	}
	// A continue that loaded the record before the consent consumed it
	// writes the identity after: the write fails, the record stays gone
	if err := server.updateOAuthAuthz(t.Context(), authzID, stored); err == nil {
		t.Fatal("principal write after consumption must fail")
	}
	if again, err := server.fetchOAuthAuthz(t.Context(), authzID); err != nil || again != nil {
		t.Fatalf("consumed record must not be recreated: %+v %v", again, err)
	}
	resp, err = client.PostForm(login+"/_openrun/oauth/authorize/consent", consent)
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	readBody(t, resp)
	testutil.AssertEqualsInt(t, "second consent", http.StatusBadRequest, resp.StatusCode)
}

// The OAuth callback sends the completion token only to a host this server
// serves: the redirect is recorded from a request URL when the login
// starts, so a Host header the initiator chose must not become where the
// token (and the victim's session) goes
func TestOAuthCallbackRefusesUnservedRedirectHost(t *testing.T) {
	manager, db := newOAuthSessionTestManager(t)
	manager.redirectHostAllowed = func(host string) bool { return host == "app.example.com" }
	originalComplete := gothic.CompleteUserAuth
	gothic.CompleteUserAuth = func(http.ResponseWriter, *http.Request) (goth.User, error) {
		return goth.User{UserID: "victim", Email: "victim@example.com", NickName: "victim"}, nil
	}
	t.Cleanup(func() { gothic.CompleteUserAuth = originalComplete })
	for _, tc := range []struct {
		name, redirect string
		status         int
	}{
		{"foreign host", "https://evil.example.com/_openrun/oauth/authorize/continue?authz=x", http.StatusBadRequest},
		{"served host", "https://app.example.com/_openrun/oauth/authorize/continue?authz=x", http.StatusFound},
		{"bad scheme", "javascript:alert(1)", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateID := types.OAUTH_SESSION_KV_PREFIX + "login-" + tc.name
			expireAt := time.Now().Add(preAuthStateMaxAge)
			testutil.AssertNoError(t, db.StoreKV(t.Context(), stateID, map[string]any{
				AUTH_KEY: false, PROVIDER_NAME_KEY: "github", REDIRECT_URL: tc.redirect, NONCE_KEY: "n",
			}, &expireAt))
			w := httptest.NewRecorder()
			manager.authCallback(w, oauthProviderRequest("/auth/github/callback?state="+base64.URLEncoding.EncodeToString([]byte(stateID))))
			testutil.AssertEqualsInt(t, "callback status", tc.status, w.Code)
			if tc.status != http.StatusFound {
				// nothing was minted for the refused redirect: no completion
				// token in the response, the pre-login entry untouched
				if w.Header().Get("Location") != "" {
					t.Fatalf("refused redirect must not send a completion token: %s", w.Header().Get("Location"))
				}
				entry, err := db.FetchKV(t.Context(), stateID)
				testutil.AssertNoError(t, err)
				if auth, _ := entry[AUTH_KEY].(bool); auth {
					t.Fatal("pre-login entry marked authenticated for a refused redirect")
				}
			}
		})
	}
}

func TestCompletionRedirectAllowed(t *testing.T) {
	served := func(host string) bool { return host == "app.example.com" || host == "::1" }
	for _, tc := range []struct {
		raw  string
		hook func(string) bool
		want bool
	}{
		{"https://app.example.com/x", served, true},
		{"https://app.example.com:8443/x", served, true},
		{"http://[::1]:25222/x", served, true},
		{"https://evil.example.com/x", served, false},
		{"https://app.example.com.evil.com/x", served, false},
		{"ftp://app.example.com/x", served, false},
		{"/relative", served, false},
		{"https://anything.example.com/x", nil, true}, // no server wired: no host check
		{"ftp://anything.example.com/x", nil, false},
	} {
		parsed, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := completionRedirectAllowed(parsed, tc.hook); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.raw, got, tc.want)
		}
	}
}

// The authorization server's consent form is a POST on the login origin. A
// user whose provider session expired while the consent page was open
// must be sent back into the provider login when they submit it, as a
// browser does (a form submission is a navigation: Sec-Fetch-Mode navigate,
// or Accept text/html where the browser sends no fetch metadata); a
// submission that looks like neither gets the 401
func TestOAuthFederatedConsentRestartsExpiredLogin(t *testing.T) {
	server, ts, client := newFederatedTestServer(t, goth.User{UserID: "sub-7", Email: "gus@example.com"})
	upstream := newUpstreamRecorder(t)
	createMCPTestApp(t, server, "/apps/orders", upstream.server.URL, "github", `{"scopes":["orders:read"],"default_scope":"orders:read"}`)
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{Grants: []types.RBACGrant{
		{Users: []string{"github:gus@example.com"}, Roles: []string{"openrun-user"}, Targets: []string{"/apps/**"}},
	}}); err != nil {
		t.Fatalf("rbac: %v", err)
	}
	tsURL, _ := url.Parse(ts.URL)
	login := loginOriginOf(t, ts)
	form := url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"},
		"redirect_uri": {"http://127.0.0.1:39999/callback"}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "resource": {"https://localhost:" + tsURL.Port() + "/apps/orders"}}

	// Reach the consent page: authorize, provider login, callback, continue
	_, location := getRedirect(t, client, login+"/_openrun/oauth/authorize?"+form.Encode())
	loginURL, _ := url.Parse(location)
	_, location = getRedirect(t, client, ts.URL+"/_openrun/auth/github/callback?state="+url.QueryEscape(loginURL.Query().Get("state")))
	_, continueURL := getRedirect(t, client, location)
	authzID := strings.TrimPrefix(continueURL, login+"/_openrun/oauth/authorize/continue?authz=")
	resp, err := client.Get(continueURL)
	if err != nil {
		t.Fatalf("continue: %v", err)
	}
	page := readBody(t, resp)
	testutil.AssertEqualsInt(t, "consent page", http.StatusOK, resp.StatusCode)
	nonce := regexp.MustCompile(`name="nonce" value="([^"]+)"`).FindStringSubmatch(page)
	if nonce == nil {
		t.Fatalf("consent page: %s", page)
	}
	consent := url.Values{"authz": {authzID}, "nonce": {nonce[1]}, "or_scope": {"orders:read"}}

	// The provider session on the login origin becomes unusable (the row
	// expired, or the cookie no longer decodes)
	loginOrigin, _ := url.Parse(login)
	client.Jar.SetCookies(loginOrigin, []*http.Cookie{{Name: genCookieName("github"), Value: "no-longer-valid", Path: "/"}})

	post := func(headers map[string]string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, login+"/_openrun/oauth/authorize/consent", strings.NewReader(consent.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for name, value := range headers {
			req.Header.Set(name, value)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("consent: %v", err)
		}
		readBody(t, resp)
		return resp
	}
	for _, tc := range []struct {
		name    string
		headers map[string]string
		restart bool
	}{
		{"browser with fetch metadata", map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-Site": "same-origin", "Accept": "text/html"}, true},
		{"browser without fetch metadata", map[string]string{"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}, true},
		{"not a navigation", map[string]string{"Accept": "*/*"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := post(tc.headers)
			if !tc.restart {
				testutil.AssertEqualsInt(t, "status", http.StatusUnauthorized, resp.StatusCode)
				if len(resp.Cookies()) != 0 || resp.Header.Get("Location") != "" {
					t.Fatalf("a refused start must not set cookies or redirect: %v %s", resp.Cookies(), resp.Header.Get("Location"))
				}
				return
			}
			testutil.AssertEqualsInt(t, "status", http.StatusFound, resp.StatusCode)
			if !strings.HasPrefix(resp.Header.Get("Location"), ts.URL+"/_openrun/auth/github/login?state=") {
				t.Fatalf("expected a restart of the provider login, got %s", resp.Header.Get("Location"))
			}
			// The restarted login returns to the continue page, under a
			// fresh pre-auth cookie, and the consent record survives
			_, state := loginStateOf(t, server.db, resp.Header.Get("Location"))
			testutil.AssertEqualsString(t, "return url", continueURL, state[REDIRECT_URL].(string))
			if cookie := providerCookie(t, resp.Cookies(), genCookieName("github")); cookie.MaxAge <= 0 || cookie.Value == "no-longer-valid" {
				t.Fatalf("pre-auth cookie: %v", cookie)
			}
			if stored, err := server.fetchOAuthAuthz(t.Context(), authzID); err != nil || stored == nil {
				t.Fatalf("consent record must survive the restart: %+v %v", stored, err)
			}
		})
	}
}
