// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/crypto/bcrypt"
)

func TestIsBrowserNavigation(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		headers map[string]string
		want    bool
	}{
		{"browser GET", "GET", map[string]string{"Accept": "text/html,application/xhtml+xml"}, true},
		{"browser HEAD", "HEAD", map[string]string{"Accept": "text/html"}, true},
		{"curl default", "GET", map[string]string{"Accept": "*/*"}, false},
		{"no accept header", "GET", nil, false},
		{"api json client", "GET", map[string]string{"Accept": "application/json"}, false},
		{"POST with html accept", "POST", map[string]string{"Accept": "text/html"}, false},
		{"htmx GET", "GET", map[string]string{"HX-Request": "true"}, true},
		{"htmx POST", "POST", map[string]string{"HX-Request": "true"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/testapp", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := isBrowserNavigation(r); got != tc.want {
				t.Errorf("isBrowserNavigation() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUsesFormLogin(t *testing.T) {
	for authType, want := range map[string]bool{
		"system":       true,
		"builtin":      true,
		"none":         false,
		"":             false,
		"cert":         false,
		"github_local": false,
		"saml_okta":    false,
	} {
		if got := usesFormLogin(authType); got != want {
			t.Errorf("usesFormLogin(%q) = %v, want %v", authType, got, want)
		}
	}
}

func newTestFormLoginManager(t *testing.T, cfg *types.ServerConfig) *FormLoginManager {
	t.Helper()
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	manager, err := NewFormLoginManager(logger, func() *types.ServerConfig { return cfg }, nil, nil, nil, nil, cfg.Security.SessionHttpsOnly)
	if err != nil {
		t.Fatalf("NewFormLoginManager failed: %v", err)
	}
	return manager
}

func TestAuthLoginDomain(t *testing.T) {
	tests := []struct {
		name          string
		disable       bool
		callbackDom   string
		defaultDomain string
		wantDomain    string
		wantOk        bool
	}{
		{"prefix + default domain", false, "auth.", "example.com", "auth.example.com", true},
		{"full domain", false, "login.example.com", "example.com", "login.example.com", true},
		{"prefix but no default domain", false, "auth.", "", "", false},
		{"disabled", true, "auth.", "example.com", "", false},
		{"empty callback domain", false, "", "example.com", "", false},
		{"localhost default", false, "auth.", "localhost", "auth.localhost", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &types.ServerConfig{}
			cfg.Security.DisableLoginForm = tc.disable
			cfg.Security.AuthCallbackDomain = tc.callbackDom
			cfg.System.DefaultDomain = tc.defaultDomain
			manager := newTestFormLoginManager(t, cfg)
			gotDomain, gotOk := manager.authLoginDomain()
			if gotDomain != tc.wantDomain || gotOk != tc.wantOk {
				t.Errorf("authLoginDomain() = (%q, %v), want (%q, %v)", gotDomain, gotOk, tc.wantDomain, tc.wantOk)
			}
			if manager.enabled() != tc.wantOk {
				t.Errorf("enabled() = %v, want %v", manager.enabled(), tc.wantOk)
			}
		})
	}
}

func TestCanStartFlow(t *testing.T) {
	tests := []struct {
		name       string
		httpsOnly  bool
		reqScheme  string // "http" or "https"
		host       string
		authDomain string // full auth callback domain (default auth.localhost)
		want       bool
	}{
		{"https-only over https", true, "https", "app.example.com", "", true},
		{"https-only over http non-localhost", true, "http", "app.example.com", "", false},
		{"https-only over http localhost", true, "http", "localhost", "", true},
		{"https-only over http 127.0.0.1", true, "http", "127.0.0.1:8080", "", true},
		{"not https-only over http", false, "http", "app.example.com", "", true},
		// the localhost exception must not send credentials to a remote
		// callback host over cleartext http
		{"https-only over http localhost, remote auth domain", true, "http", "localhost", "login.example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &types.ServerConfig{}
			cfg.Security.SessionHttpsOnly = tc.httpsOnly
			cfg.Security.AuthCallbackDomain = cmp.Or(tc.authDomain, "auth.localhost")
			manager := newTestFormLoginManager(t, cfg)
			r := httptest.NewRequest("GET", "/app", nil)
			r.Host = tc.host
			if tc.reqScheme == "https" {
				r.TLS = &tls.ConnectionState{}
			}
			if got := manager.canStartFlow(r); got != tc.want {
				t.Errorf("canStartFlow() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReservedAuthDomain(t *testing.T) {
	// reserved regardless of disable_login_form, unlike authLoginDomain
	cfg := &types.ServerConfig{}
	cfg.Security.DisableLoginForm = true
	cfg.Security.AuthCallbackDomain = "auth."
	cfg.System.DefaultDomain = "example.com"
	manager := newTestFormLoginManager(t, cfg)

	if _, ok := manager.authLoginDomain(); ok {
		t.Error("authLoginDomain should be false when the form is disabled")
	}
	domain, ok := manager.reservedAuthDomain()
	if !ok || domain != "auth.example.com" {
		t.Errorf("reservedAuthDomain() = (%q, %v), want (auth.example.com, true)", domain, ok)
	}
	if !manager.isReservedAuthHost("auth.example.com") || manager.isReservedAuthHost("app.example.com") {
		t.Error("isReservedAuthHost did not match the auth domain exactly")
	}
}

func TestLoginRedirectTarget(t *testing.T) {
	cfg := &types.ServerConfig{}
	manager := newTestFormLoginManager(t, cfg)

	// safe method: request URL is used
	get := httptest.NewRequest("GET", "https://app.example.com/page?x=1", nil)
	if target, ok := manager.loginRedirectTarget(get); !ok || !strings.Contains(target, "/page?x=1") {
		t.Errorf("GET target = (%q, %v), want the request URL", target, ok)
	}

	// unsafe method with valid same-host HX-Current-URL: use it
	post := httptest.NewRequest("POST", "https://app.example.com/action", nil)
	post.Header.Set("HX-Current-URL", "https://app.example.com/dashboard")
	if target, ok := manager.loginRedirectTarget(post); !ok || target != "https://app.example.com/dashboard" {
		t.Errorf("POST target = (%q, %v), want the HX-Current-URL", target, ok)
	}

	// unsafe method, no HX-Current-URL: cannot start (never replay the POST)
	post2 := httptest.NewRequest("POST", "https://app.example.com/action", nil)
	if _, ok := manager.loginRedirectTarget(post2); ok {
		t.Error("POST without HX-Current-URL should not yield a target")
	}

	// unsafe method, cross-host HX-Current-URL: rejected
	post3 := httptest.NewRequest("POST", "https://app.example.com/action", nil)
	post3.Header.Set("HX-Current-URL", "https://evil.com/x")
	if _, ok := manager.loginRedirectTarget(post3); ok {
		t.Error("cross-host HX-Current-URL must be rejected")
	}
}

func TestFormLoginStateRotation(t *testing.T) {
	// The completion state must differ from the pre-login state. The pre-login
	// token is visible in the login page URL, so the flow initiator knows it:
	// if it stayed valid at complete, an attacker could start a flow (keeping
	// the app-domain nonce cookie), hand the login URL to a victim, and after
	// the victim authenticates poll complete with the known state to mint a
	// session under the victim's identity
	db := NewInmemoryKVStore()
	store := NewKVSessionStore(db,
		[]byte("test-session-key-32bytes-long!!!"),
		[]byte("test-session-block-32bytes-key!!"),
	)
	store.Options.Secure = false

	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &types.ServerConfig{}
	cfg.AdminUser = "admin"
	cfg.Security.AdminPasswordBcrypt = string(hash)
	cfg.Security.AuthCallbackDomain = "auth."
	cfg.System.DefaultDomain = "localhost"

	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	adminAuth := NewAdminBasicAuth(logger, cfg)
	manager, err := NewFormLoginManager(logger, func() *types.ServerConfig { return cfg },
		store, db, adminAuth, nil, false)
	if err != nil {
		t.Fatalf("NewFormLoginManager failed: %v", err)
	}

	// begin the flow on the app domain
	beginRec := httptest.NewRecorder()
	begin := httptest.NewRequest("GET", "http://localhost:25222/app1", nil)
	if !manager.beginLogin(beginRec, begin, "system") {
		t.Fatal("beginLogin did not start the flow")
	}
	loginURL, err := url.Parse(beginRec.Result().Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	loginState := loginURL.Query().Get("state")
	if loginState == "" {
		t.Fatal("login redirect carries no state")
	}
	nonceCookies := beginRec.Result().Cookies() // pre-auth nonce cookie (app domain)

	// submit valid credentials on the auth domain
	form := url.Values{}
	form.Set("state", loginState)
	form.Set("system-username", "admin")
	form.Set("system-password", "secret")
	submit := httptest.NewRequest("POST", "http://auth.localhost:25222"+formLoginPath+"/system",
		strings.NewReader(form.Encode()))
	submit.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("authtype", "system")
	submit = submit.WithContext(context.WithValue(submit.Context(), chi.RouteCtxKey, rctx))
	submitRec := httptest.NewRecorder()
	manager.loginSubmit(submitRec, submit)
	if submitRec.Code != http.StatusFound {
		t.Fatalf("loginSubmit status = %d, body: %s", submitRec.Code, submitRec.Body.String())
	}
	completeLoc := submitRec.Result().Header.Get("Location")
	completeURL, err := url.Parse(completeLoc)
	if err != nil {
		t.Fatal(err)
	}
	if completeURL.Query().Get("state") == loginState {
		t.Fatal("completion redirect reuses the pre-login state, it must be rotated")
	}

	// an attacker holding the nonce cookie replays complete with the
	// pre-login state: no session may be minted
	attack := httptest.NewRequest("GET", "http://localhost:25222"+formCompletePath+"?state="+loginState, nil)
	for _, c := range nonceCookies {
		attack.AddCookie(c)
	}
	attackRec := httptest.NewRecorder()
	manager.complete(attackRec, attack)
	if attackRec.Code != http.StatusOK || !strings.Contains(attackRec.Body.String(), "expired") {
		t.Errorf("complete with the pre-login state must render the expired page, got status %d", attackRec.Code)
	}

	// the browser that ran the whole flow (nonce cookie + rotated state)
	// completes normally
	good := httptest.NewRequest("GET", completeLoc, nil)
	for _, c := range nonceCookies {
		good.AddCookie(c)
	}
	goodRec := httptest.NewRecorder()
	manager.complete(goodRec, good)
	if goodRec.Code != http.StatusFound {
		t.Fatalf("legitimate complete status = %d, body: %s", goodRec.Code, goodRec.Body.String())
	}
	if loc := goodRec.Result().Header.Get("Location"); !strings.HasSuffix(loc, "/app1") {
		t.Errorf("complete redirect = %q, want the original app URL", loc)
	}
	sessionSet := false
	for _, c := range goodRec.Result().Cookies() {
		if c.Name == "system_openrun_session" && c.Value != "" {
			sessionSet = true
		}
	}
	if !sessionSet {
		t.Error("legitimate complete did not set the session cookie")
	}
}

func TestSessionAuthPasswordChangeRevokes(t *testing.T) {
	// A password change must invalidate existing form-login sessions on the
	// next request: the session stores a fingerprint of the bcrypt hash it was
	// authenticated against, checked against the live config
	db := NewInmemoryKVStore()
	store := NewKVSessionStore(db,
		[]byte("test-session-key-32bytes-long!!!"),
		[]byte("test-session-block-32bytes-key!!"),
	)
	store.Options.Secure = false

	cfg := &types.ServerConfig{}
	cfg.AdminUser = "admin"
	cfg.Security.AdminPasswordBcrypt = "$2a$10$adminhash1"
	cfg.Security.AuthCallbackDomain = "auth."
	cfg.System.DefaultDomain = "localhost"
	cfg.BuiltinAuth = map[string]types.BuiltinAuthEntry{
		"alice": {Password: "$2a$10$alicehash1", Groups: []string{"dev"}},
		"bob":   {Password: "$2a$10$bobhash1"},
	}

	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	manager, err := NewFormLoginManager(logger, func() *types.ServerConfig { return cfg },
		store, db, nil, nil, false)
	if err != nil {
		t.Fatalf("NewFormLoginManager failed: %v", err)
	}

	makeSession := func(authType, user string, withFp bool) *http.Request {
		t.Helper()
		setupRec := httptest.NewRecorder()
		session, err := store.Get(httptest.NewRequest("GET", "/app", nil), genCookieName(authType))
		if err != nil {
			t.Fatal(err)
		}
		session.Values[AUTH_KEY] = true
		session.Values[PROVIDER_NAME_KEY] = authType
		session.Values[USER_KEY] = user
		if withFp {
			fp, ok := credentialFingerprint(cfg, authType, user)
			if !ok {
				t.Fatalf("no credential fingerprint for %s/%s", authType, user)
			}
			session.Values[CRED_FP_KEY] = fp
		}
		if err := session.Save(httptest.NewRequest("GET", "/app", nil), setupRec); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/app", nil)
		for _, c := range setupRec.Result().Cookies() {
			r.AddCookie(c)
		}
		return r
	}

	// valid sessions authenticate
	sysReq := makeSession("system", "admin", true)
	if userId, _, ok := manager.sessionAuth(sysReq, "system"); !ok || userId != types.ADMIN_USER {
		t.Fatalf("system sessionAuth = (%q, %v), want admin", userId, ok)
	}
	aliceReq := makeSession("builtin", "alice", true)
	if userId, groups, ok := manager.sessionAuth(aliceReq, "builtin"); !ok ||
		userId != "builtin:alice" || len(groups) != 1 || groups[0] != "dev" {
		t.Fatalf("builtin sessionAuth = (%q, %v, %v)", userId, groups, ok)
	}

	// a session without a fingerprint never authenticates
	if _, _, ok := manager.sessionAuth(makeSession("builtin", "alice", false), "builtin"); ok {
		t.Error("session without a credential fingerprint must not authenticate")
	}

	// password changes revoke the existing sessions immediately
	cfg.Security.AdminPasswordBcrypt = "$2a$10$adminhash2"
	if _, _, ok := manager.sessionAuth(sysReq, "system"); ok {
		t.Error("system session must be revoked after an admin password change")
	}
	cfg.BuiltinAuth["alice"] = types.BuiltinAuthEntry{Password: "$2a$10$alicehash2", Groups: []string{"dev"}}
	if _, _, ok := manager.sessionAuth(aliceReq, "builtin"); ok {
		t.Error("builtin session must be revoked after a password change")
	}

	// user delete revokes as well
	bobReq := makeSession("builtin", "bob", true)
	if _, _, ok := manager.sessionAuth(bobReq, "builtin"); !ok {
		t.Fatal("bob's session should authenticate before the delete")
	}
	delete(cfg.BuiltinAuth, "bob")
	if _, _, ok := manager.sessionAuth(bobReq, "builtin"); ok {
		t.Error("session for a deleted user must not authenticate")
	}
}

func TestValidLogoutRedirect(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{"", "/"},
		{"/dashboard", "/dashboard"},
		{"/dashboard?x=1", "/dashboard?x=1"},
		{"https://app.example.com/x", "/"}, // absolute rejected (no scheme downgrade / off-host)
		{"https://evil.com/x", "/"},        // different host
		{"//evil.com", "/"},                // scheme-relative
		{`/\evil.example/path`, "/"},       // backslash trick (net/http decodes %5C to '\') -> WHATWG //host
		{"javascript:alert(1)", "/"},       // bad scheme
		{"http://app.example.com/y", "/"},  // absolute rejected
	} {
		if got := validLogoutRedirect(tc.raw); got != tc.want {
			t.Errorf("validLogoutRedirect(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestLogoutClearsAllAuthTypes(t *testing.T) {
	// A single logout must clear the session regardless of how login happened.
	// Set up authenticated sessions under cookie names for each auth type
	// (form-login, OAuth and SAML) and verify one logout clears them all
	db := NewInmemoryKVStore()
	store := NewKVSessionStore(db,
		[]byte("test-session-key-32bytes-long!!!"),
		[]byte("test-session-block-32bytes-key!!"),
	)
	store.Options.Secure = false

	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	manager, err := NewFormLoginManager(logger, func() *types.ServerConfig { return &types.ServerConfig{} },
		store, db, nil, nil, false)
	if err != nil {
		t.Fatalf("NewFormLoginManager failed: %v", err)
	}

	// cookie names spanning form-login, OAuth and SAML
	sessions := map[string]string{
		"system_openrun_session":      "system",
		"builtin_openrun_session":     "builtin",
		"github_prod_openrun_session": "github_prod", // OAuth
		"okta_openrun_saml_session":   "okta",        // SAML
	}
	setupReq := httptest.NewRequest("GET", "/app", nil)
	setupRec := httptest.NewRecorder()
	for name, provider := range sessions {
		session, err := store.Get(setupReq, name)
		if err != nil {
			t.Fatalf("store.Get(%s): %v", name, err)
		}
		session.Values[AUTH_KEY] = true
		session.Values[PROVIDER_NAME_KEY] = provider
		session.Values[USER_KEY] = "user@example.com"
		if err := session.Save(setupReq, setupRec); err != nil {
			t.Fatalf("save %s: %v", name, err)
		}
	}
	cookies := setupRec.Result().Cookies()
	if len(cookies) != len(sessions) {
		t.Fatalf("expected %d session cookies, got %d", len(sessions), len(cookies))
	}

	// a request carrying all four session cookies plus an unrelated one
	req := httptest.NewRequest("POST", "/_openrun/logout", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req.AddCookie(&http.Cookie{Name: "unrelated_app_cookie", Value: "keep-me"})

	// the confirmation page sees all four identities
	if got := len(manager.signedInIdentities(req)); got != len(sessions) {
		t.Errorf("signedInIdentities count = %d, want %d", got, len(sessions))
	}

	// A live session must not see a false "signed out" page: ?done=1 with an
	// authenticated cookie renders the confirm page instead (checked while the
	// sessions are still valid, before the logout below)
	doneReq := httptest.NewRequest("GET", "/_openrun/logout?done=1", nil)
	for _, c := range cookies {
		doneReq.AddCookie(c)
	}
	doneRec := httptest.NewRecorder()
	manager.logoutPage(doneRec, doneReq)
	if body := doneRec.Body.String(); strings.Contains(body, "You have been signed out") ||
		!strings.Contains(body, `action="`+formLogoutPath+`"`) {
		t.Error("?done=1 with a live session must render the confirm form, not the signed-out page")
	}

	// logout clears every OpenRun session cookie, not the unrelated one
	rec := httptest.NewRecorder()
	if err := manager.clearSessionCookies(rec, req); err != nil {
		t.Fatalf("clearSessionCookies: %v", err)
	}
	clearedNames := map[string]bool{}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			clearedNames[c.Name] = true
		}
	}
	for name := range sessions {
		if !clearedNames[name] {
			t.Errorf("session cookie %s was not cleared", name)
		}
	}
	if clearedNames["unrelated_app_cookie"] {
		t.Error("unrelated app cookie must not be cleared")
	}
	// server-side KV rows are gone: a fresh Get yields an unauthenticated session
	for name := range sessions {
		reGet := httptest.NewRequest("GET", "/app", nil)
		for _, c := range cookies {
			reGet.AddCookie(c)
		}
		session, _ := store.Get(reGet, name)
		if session != nil {
			if auth, _ := session.Values[AUTH_KEY].(bool); auth {
				t.Errorf("session %s still authenticated after logout", name)
			}
		}
	}
}

// failDeleteKVStore makes DeleteKV fail, to exercise the logout failure path
type failDeleteKVStore struct {
	*InmemoryKVStore
}

func (f *failDeleteKVStore) DeleteKV(ctx context.Context, key string) error {
	return fmt.Errorf("simulated delete failure")
}

func TestLogoutReportsDeletionFailure(t *testing.T) {
	// When the server-side session row cannot be deleted, the store leaves the
	// browser cookie valid, so logout must NOT report success
	db := &failDeleteKVStore{NewInmemoryKVStore()}
	store := NewKVSessionStore(db,
		[]byte("test-session-key-32bytes-long!!!"),
		[]byte("test-session-block-32bytes-key!!"),
	)
	store.Options.Secure = false

	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	manager, err := NewFormLoginManager(logger, func() *types.ServerConfig { return &types.ServerConfig{} },
		store, db, nil, nil, false)
	if err != nil {
		t.Fatalf("NewFormLoginManager failed: %v", err)
	}

	// create an authenticated session (uses UpsertKVBlob, not DeleteKV)
	setupReq := httptest.NewRequest("GET", "/app", nil)
	setupRec := httptest.NewRecorder()
	session, err := store.Get(setupReq, "builtin_openrun_session")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	session.Values[AUTH_KEY] = true
	session.Values[PROVIDER_NAME_KEY] = "builtin"
	session.Values[USER_KEY] = "u"
	if err := session.Save(setupReq, setupRec); err != nil {
		t.Fatalf("save: %v", err)
	}

	req := httptest.NewRequest("POST", "/_openrun/logout", nil)
	for _, c := range setupRec.Result().Cookies() {
		req.AddCookie(c)
	}
	if err := manager.clearSessionCookies(httptest.NewRecorder(), req); err == nil {
		t.Fatal("clearSessionCookies must return an error when the KV delete fails")
	}

	// the full handler must surface that as a 500, not a success redirect
	rec := httptest.NewRecorder()
	manager.logoutSubmit(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("logoutSubmit status = %d, want 500 on deletion failure", rec.Code)
	}
}

func TestLogoutTemplateRenders(t *testing.T) {
	cfg := &types.ServerConfig{}
	manager := newTestFormLoginManager(t, cfg)

	// confirm: signed in, offers the POST sign-out and carries the redirect
	confirm := logoutBody(manager, "confirm", "builtin:testuser", "/myapp")
	if !strings.Contains(confirm, "Signed in as builtin:testuser") {
		t.Error("confirm page does not show the user")
	}
	if !strings.Contains(confirm, `action="`+formLogoutPath+`"`) ||
		!strings.Contains(confirm, `name="redirect" value="/myapp"`) {
		t.Error("confirm page does not post to the logout path with the redirect")
	}
	// done: signed out, links to the redirect, no form
	done := logoutBody(manager, "done", "", "/myapp")
	if !strings.Contains(done, "signed out") || strings.Contains(done, "<form") {
		t.Error("done page should have no form and confirm sign-out")
	}
	if !strings.Contains(done, `href="/myapp"`) {
		t.Error("done page does not link to the redirect target")
	}
	// none: not signed in
	if !strings.Contains(logoutBody(manager, "none", "", "/"), "not signed in") {
		t.Error("none page does not state the user is not signed in")
	}
	// strict headers applied
	w := httptest.NewRecorder()
	manager.renderLogout(w, "confirm", "x", "/")
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") ||
		w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("logout page missing security headers")
	}
}

func logoutBody(manager *FormLoginManager, mode, user, redirect string) string {
	w := httptest.NewRecorder()
	manager.renderLogout(w, mode, user, redirect)
	return w.Body.String()
}

func TestLoginTemplateRenders(t *testing.T) {
	cfg := &types.ServerConfig{}
	cfg.Security.AuthCallbackDomain = "auth.example.com"
	manager := newTestFormLoginManager(t, cfg)

	// form variant, both auth types: per-type submit URL and field names so
	// browser password managers keep the credentials distinct
	for _, authType := range []string{"system", "builtin"} {
		w := httptest.NewRecorder()
		manager.render(w, authType, "state123", "")
		body := w.Body.String()
		if !strings.Contains(body, `name="state" value="state123"`) {
			t.Errorf("%s: rendered page is missing the state field", authType)
		}
		if !strings.Contains(body, manager.styleHref) || !strings.Contains(body, manager.extraHref) {
			t.Errorf("%s: rendered page is missing a stylesheet href", authType)
		}
		if !strings.Contains(body, `action="`+formLoginPath+"/"+authType+`"`) {
			t.Errorf("%s: form does not post to the per-type submit URL", authType)
		}
		if !strings.Contains(body, `name="`+authType+`-username"`) ||
			!strings.Contains(body, `name="`+authType+`-password"`) {
			t.Errorf("%s: form does not use per-type field names", authType)
		}
		// strict CSP: no inline scripts or styles
		if strings.Contains(body, "<script") || strings.Contains(body, "<style") {
			t.Errorf("%s: page must have no inline scripts or styles under the strict CSP", authType)
		}
		// security headers present
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("%s: CSP header missing", authType)
		}
		if w.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: X-Frame-Options header missing", authType)
		}
	}
	if !renderContains(manager, "system", "state123", "", "system auth") {
		t.Error("system page does not mention system auth")
	}
	if !renderContains(manager, "builtin", "state123", "", "builtin auth") {
		t.Error("builtin page does not mention builtin auth")
	}

	// error message is rendered, and html escaped
	if !renderContains(manager, "builtin", "state123", "bad <script>x</script>", "bad &lt;script&gt;") {
		t.Error("error message is not rendered escaped")
	}

	// expired variant: no form
	w := httptest.NewRecorder()
	manager.render(w, "", "", "")
	expiredBody := w.Body.String()
	if strings.Contains(expiredBody, "<form") {
		t.Error("expired page must not render the credentials form")
	}
	if !strings.Contains(expiredBody, "expired") {
		t.Error("expired page does not mention expiry")
	}
}

func renderContains(manager *FormLoginManager, authType, state, errorMsg, want string) bool {
	w := httptest.NewRecorder()
	manager.render(w, authType, state, errorMsg)
	return strings.Contains(w.Body.String(), want)
}
