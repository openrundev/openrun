// Copyright (c) OpenRun Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/go-chi/chi/v5"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	saml2 "github.com/russellhaering/gosaml2"
	saml_types "github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"golang.org/x/crypto/bcrypt"
)

func TestEmailVerifiedClaim(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  map[string]any
		want bool
	}{
		"absent":                  {map[string]any{}, true},
		"oidc true":               {map[string]any{"email_verified": true}, true},
		"oidc false":              {map[string]any{"email_verified": false}, false},
		"oidc string":             {map[string]any{"email_verified": "false"}, false},
		"google verified_email":   {map[string]any{"verified_email": false}, false},
		"google verified true":    {map[string]any{"verified_email": true}, true},
		"oidc wins over google":   {map[string]any{"email_verified": false, "verified_email": true}, false},
		"unexpected type refuses": {map[string]any{"email_verified": 1}, false},
	} {
		if got := emailVerifiedClaim(tc.raw); got != tc.want {
			t.Errorf("%s: got %v want %v", name, got, tc.want)
		}
	}
}

// newOAuthTestManager builds an OAuth manager with one github provider and
// a KV-backed cookie store
func newOAuthTestManager(t *testing.T) (*OAuthManager, *InmemoryKVStore) {
	t.Helper()
	db := NewInmemoryKVStore()
	config := &types.ServerConfig{
		Security: types.SecurityConfig{CallbackUrl: "https://callback.example.com", SessionMaxAge: 3600},
		Auth:     map[string]types.AuthConfig{"github": {Key: "k", Secret: "s"}},
	}
	manager := NewOAuthManager(testutil.TestLogger(), config, db)
	if err := manager.Setup([]byte(strings.Repeat("k", 32)), []byte(strings.Repeat("b", 32))); err != nil {
		t.Fatal(err)
	}
	return manager, db
}

// The redirect endpoint is a GET any site can navigate to: a failed check
// answers an error without touching the session, so a cross-site link
// cannot log the user out
func TestOAuthRedirectFailureKeepsSession(t *testing.T) {
	manager, _ := newOAuthTestManager(t)
	initial := oauthProviderRequest("https://app.example.com/_openrun/auth/github/redirect")
	w := httptest.NewRecorder()
	session, err := manager.cookieStore.Get(initial, genCookieName("github"))
	if err != nil {
		t.Fatal(err)
	}
	session.Values[AUTH_KEY] = true
	session.Values[USER_KEY] = "github:alice"
	if err := session.Save(initial, w); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()

	for _, state := range []string{
		base64.URLEncoding.EncodeToString([]byte("bogus")),                                   // not a login state key
		base64.URLEncoding.EncodeToString([]byte(types.OAUTH_SESSION_KV_PREFIX + "missing")), // unknown entry
		"%%%", // not base64
	} {
		r := oauthProviderRequest("https://app.example.com/_openrun/auth/github/redirect?state=" + state)
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		w = httptest.NewRecorder()
		manager.redirect(w, r)
		if w.Code/100 != 4 {
			t.Fatalf("state %q: expected a client error, got %d", state, w.Code)
		}
		for _, cookie := range w.Result().Cookies() {
			if cookie.MaxAge < 0 {
				t.Fatalf("state %q: failed redirect cleared the session cookie", state)
			}
		}
		check := oauthProviderRequest("https://app.example.com/app")
		for _, cookie := range cookies {
			check.AddCookie(cookie)
		}
		after, err := manager.cookieStore.Get(check, genCookieName("github"))
		if err != nil || after.Values[AUTH_KEY] != true {
			t.Fatalf("state %q: failed redirect destroyed the session: %v %v", state, after.Values, err)
		}
	}
}

// The provider login start needs a pending login state from beginLogin:
// without one no provider session row is allocated
func TestOAuthLoginRequiresPendingState(t *testing.T) {
	manager, db := newOAuthTestManager(t)
	mux := chi.NewRouter()
	manager.RegisterRoutes(http.NewCrossOriginProtection(), mux)
	get := func(state string) *httptest.ResponseRecorder {
		target := "https://callback.example.com/_openrun/auth/github/login"
		if state != "" {
			target += "?state=" + url.QueryEscape(state)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		return w
	}
	pending := types.OAUTH_SESSION_KV_PREFIX + "pending1"
	if err := db.StoreKV(context.Background(), pending, map[string]any{AUTH_KEY: false, PROVIDER_NAME_KEY: "github", NONCE_KEY: "n"}, nil); err != nil {
		t.Fatal(err)
	}
	done := types.OAUTH_SESSION_KV_PREFIX + "done1"
	if err := db.StoreKV(context.Background(), done, map[string]any{AUTH_KEY: true, PROVIDER_NAME_KEY: "github"}, nil); err != nil {
		t.Fatal(err)
	}
	other := types.OAUTH_SESSION_KV_PREFIX + "other1"
	if err := db.StoreKV(context.Background(), other, map[string]any{AUTH_KEY: false, PROVIDER_NAME_KEY: "google"}, nil); err != nil {
		t.Fatal(err)
	}
	rows := len(db.store)
	for _, state := range []string{"", "%%%", base64.URLEncoding.EncodeToString([]byte("bogus")),
		base64.URLEncoding.EncodeToString([]byte(types.OAUTH_SESSION_KV_PREFIX + "missing")),
		base64.URLEncoding.EncodeToString([]byte(done)), base64.URLEncoding.EncodeToString([]byte(other))} {
		if w := get(state); w.Code != http.StatusBadRequest {
			t.Fatalf("state %q: expected 400, got %d %s", state, w.Code, w.Body.String())
		}
	}
	if len(db.store) != rows {
		t.Fatalf("refused login starts allocated %d session rows", len(db.store)-rows)
	}
	w := get(base64.URLEncoding.EncodeToString([]byte(pending)))
	if w.Code != http.StatusTemporaryRedirect || !strings.Contains(w.Header().Get("Location"), "github.com") {
		t.Fatalf("pending state must start the provider login, got %d %s", w.Code, w.Header().Get("Location"))
	}
}

// The gothic handshake session (the provider auth URL with the state,
// kept between the login start and the callback) is created by the
// unauthenticated login endpoint, repeatably for one pending state: its row
// and cookie live for the pre-auth window, not session_max_age
func TestGothicHandshakeSessionLifetime(t *testing.T) {
	db := NewInmemoryKVStore()
	config := &types.ServerConfig{
		Security: types.SecurityConfig{CallbackUrl: "https://callback.example.com", SessionMaxAge: 86400},
		Auth:     map[string]types.AuthConfig{"github": {Key: "k", Secret: "s"}},
	}
	manager := NewOAuthManager(testutil.TestLogger(), config, db)
	if err := manager.Setup([]byte(strings.Repeat("k", 32)), []byte(strings.Repeat("b", 32))); err != nil {
		t.Fatal(err)
	}
	if gothic.Store == manager.cookieStore {
		t.Fatal("gothic must not share the authenticated session store and its lifetime")
	}
	mux := chi.NewRouter()
	manager.RegisterRoutes(http.NewCrossOriginProtection(), mux)
	pending := types.OAUTH_SESSION_KV_PREFIX + "pending1"
	if err := db.StoreKV(context.Background(), pending, map[string]any{AUTH_KEY: false, PROVIDER_NAME_KEY: "github", NONCE_KEY: "n"}, nil); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://callback.example.com/_openrun/auth/github/login?state="+
		url.QueryEscape(base64.URLEncoding.EncodeToString([]byte(pending))), nil))
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("login start: %d %s", w.Code, w.Body.String())
	}
	rows := 0
	for key, deleteAt := range db.deleteAt {
		if !strings.HasPrefix(key, types.HTTP_SESSION_KV_PREFIX+types.GOTHIC_SESSION_COOKIE+":") {
			continue
		}
		rows++
		if deleteAt == nil || deleteAt.After(before.Add(preAuthStateMaxAge+time.Minute)) {
			t.Fatalf("gothic session row %s expires at %v, expected within %v", key, deleteAt, preAuthStateMaxAge)
		}
	}
	if rows != 1 {
		t.Fatalf("expected one gothic session row, found %d", rows)
	}
	var gothicCookie *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == types.GOTHIC_SESSION_COOKIE {
			gothicCookie = cookie
		}
	}
	if gothicCookie == nil || gothicCookie.MaxAge != preAuthSessionMaxAge || !gothicCookie.HttpOnly {
		t.Fatalf("gothic cookie: %+v", gothicCookie)
	}
}

// The callback's state is a keystore key: it must name a pre-login row of
// the OAuth flow, never a row of another namespace with the same shape
func TestAuthCallbackRejectsForeignStateNamespace(t *testing.T) {
	manager, db := newOAuthTestManager(t)
	foreign := types.FORM_LOGIN_KV_PREFIX + "pending1"
	if err := db.StoreKV(context.Background(), foreign, map[string]any{AUTH_KEY: false, PROVIDER_NAME_KEY: "github",
		NONCE_KEY: "n", REDIRECT_URL: "https://app.example.com/"}, nil); err != nil {
		t.Fatal(err)
	}
	originalComplete := gothic.CompleteUserAuth
	completed := false
	gothic.CompleteUserAuth = func(http.ResponseWriter, *http.Request) (goth.User, error) {
		completed = true
		return goth.User{UserID: "u1", Email: "u1@example.com"}, nil
	}
	t.Cleanup(func() { gothic.CompleteUserAuth = originalComplete })
	w := httptest.NewRecorder()
	manager.authCallback(w, oauthProviderRequest("/auth/github/callback?state="+base64.URLEncoding.EncodeToString([]byte(foreign))))
	if w.Code != http.StatusBadRequest || completed {
		t.Fatalf("state naming another namespace: %d %s (provider exchange run: %v)", w.Code, w.Body.String(), completed)
	}
	if _, ok := db.store[foreign]; !ok {
		t.Fatal("state naming another namespace consumed its row")
	}
}

// App-initiated SAML logout is a same-origin action, like the OAuth logout
// behind CrossOriginProtection: a sibling subdomain (another app) is
// another origin and must not be able to start the IdP single logout
func TestIsSameOriginRequest(t *testing.T) {
	for _, tc := range []struct {
		fetchSite, origin string
		want              bool
	}{
		{"same-origin", "", true},
		{"none", "", true},
		{"same-site", "", false},
		{"cross-site", "", false},
		{"cross-site", "https://sp.example", false},
		{"", "", true}, // no browser signal: a non-browser client
		{"", "https://sp.example", true},
		{"", "https://other.example", false},
		{"", "https://evil.sp.example", false},
		{"", "garbage", false},
	} {
		req := httptest.NewRequest(http.MethodPost, "https://sp.example/_openrun/sso/saml_x/slo", nil)
		if tc.fetchSite != "" {
			req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		if got := isSameOriginRequest(req); got != tc.want {
			t.Errorf("Sec-Fetch-Site=%q Origin=%q: got %v, want %v", tc.fetchSite, tc.origin, got, tc.want)
		}
	}
}

// The admin hash is dynamic config: a header accepted against the old hash
// must not keep working from the cache after a change
func TestAdminBasicAuthFollowsDynamicHash(t *testing.T) {
	hash := func(password string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		return string(h)
	}
	config := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}
	config.Security.AdminPasswordBcrypt = hash("first")
	auth := NewAdminBasicAuth(testutil.TestLogger(), config)
	current := config
	auth.getConfig = func() *types.ServerConfig { return current }
	header := func(user, password string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	}
	for range 2 { // the second call is served from the header cache
		if !auth.authenticate(header("admin", "first")) {
			t.Fatal("configured password must authenticate (and from the cache)")
		}
	}
	if auth.authenticate(header("admin", "second")) || auth.authenticate(header("other", "first")) {
		t.Fatal("wrong password or user must not authenticate")
	}

	changed := *config
	changed.Security.AdminPasswordBcrypt = hash("second")
	current = &changed
	if auth.authenticate(header("admin", "first")) {
		t.Fatal("the old password must stop working when the hash changes")
	}
	for range 2 {
		if !auth.authenticate(header("admin", "second")) {
			t.Fatal("the new password must authenticate (and from the cache)")
		}
	}
}

func TestIsPrivateOrLocalIPRanges(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": false, "0.1.2.3": true, "0.0.0.0": true, "100.64.1.1": true, "169.254.169.254": true,
		"64:ff9b::7f00:1": true, "64:ff9b::a00:1": true, "64:ff9b::808:808": false, "2001:db8::1": false, "::1": true,
	} {
		if got := system.IsPrivateOrLocalIP(net.ParseIP(ip)); got != want {
			t.Errorf("%s: got %v want %v", ip, got, want)
		}
	}
}

func TestValidateIdPEndpoint(t *testing.T) {
	for location, ok := range map[string]bool{
		"https://idp.example/sso": true, "http://127.0.0.1:8080/sso": true,
		"javascript:alert(1)": false, "file:///etc/passwd": false, "idp.example/sso": false, "": false,
	} {
		if err := validateIdPEndpoint(location); (err == nil) != ok {
			t.Errorf("%q: ok=%v err=%v", location, ok, err)
		}
	}
}

func TestSAMLGroupsAttr(t *testing.T) {
	values := saml2.Values{
		"memberOf": saml_types.Attribute{Name: "memberOf", Values: []saml_types.AttributeValue{{Value: "ldap-group"}}},
		"teams":    saml_types.Attribute{Name: "teams", Values: []saml_types.AttributeValue{{Value: "t1"}, {Value: "t2"}}},
	}
	if got := samlGroups("teams", values); len(got) != 2 || got[0] != "t1" {
		t.Fatalf("configured attribute: %v", got)
	}
	if got := samlGroups("missing", values); len(got) != 0 {
		t.Fatalf("a configured attribute without values must give no groups, not fall back: %v", got)
	}
	if got := samlGroups("", values); len(got) != 1 || got[0] != "ldap-group" {
		t.Fatalf("default attribute search: %v", got)
	}
}

// An IdP-initiated LogoutRequest clears the local session only when it
// names the session's user and is fresh: a captured request cannot be
// replayed to log another user out, nor replayed later
func TestSAMLIdPLogoutRequestNamesUserAndIsFresh(t *testing.T) {
	const provider = "saml_slo"
	const slo = "https://sp.example/_openrun/sso/saml_slo/slo"
	const issuer = "https://idp.example"
	ks := dsig.RandomKeyStoreForTest()
	_, der, err := ks.GetKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sp := &saml2.SAMLServiceProvider{IdentityProviderIssuer: issuer, ServiceProviderSLOURL: slo,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}},
		MaximumDecompressedBodySize: 10 << 20, MaximumXMLTokens: maxSAMLXMLTokens}
	db := NewInmemoryKVStore()
	store := NewKVSessionStore(db, []byte("test-key-12345678901234567890123456"))
	manager := NewSAMLManager(testutil.TestLogger(), &types.ServerConfig{}, store, db)
	manager.providers = map[string]*saml2.SAMLServiceProvider{provider: sp}
	manager.providerConfigs = map[string]*types.SAMLConfig{provider: {}}
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)
	signing := dsig.NewDefaultSigningContext(ks)
	signing.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	login := func() []*http.Cookie {
		initial := httptest.NewRequest("GET", "https://sp.example/app", nil)
		w := httptest.NewRecorder()
		session, err := store.Get(initial, genSAMLCookieName(provider))
		if err != nil {
			t.Fatal(err)
		}
		session.Values[AUTH_KEY] = true
		session.Values[USER_KEY] = "user@example.com"
		session.Values[SESSION_INDEX_KEY] = "idx1"
		if err := session.Save(initial, w); err != nil {
			t.Fatal(err)
		}
		return w.Result().Cookies()
	}
	authenticated := func(cookies []*http.Cookie) bool {
		check := httptest.NewRequest("GET", "https://sp.example/app", nil)
		for _, cookie := range cookies {
			check.AddCookie(cookie)
		}
		session, err := store.Get(check, genSAMLCookieName(provider))
		return err == nil && session.Values[AUTH_KEY] == true
	}
	logoutRequest := func(nameID string, issued time.Time) string {
		doc := etree.NewDocument()
		err := doc.ReadFromString(fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr" Version="2.0" IssueInstant="%s" Destination="%s"><saml:Issuer>%s</saml:Issuer><saml:NameID>%s</saml:NameID></samlp:LogoutRequest>`,
			issued.UTC().Format(time.RFC3339), slo, issuer, nameID))
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signing.SignEnveloped(doc.Root())
		if err != nil {
			t.Fatal(err)
		}
		doc.SetRoot(signed)
		raw, err := doc.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
	post := func(cookies []*http.Cookie, encoded string) *httptest.ResponseRecorder {
		form := url.Values{"SAMLRequest": {encoded}}
		req := httptest.NewRequest("POST", slo, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "cross-site") // the IdP posts cross-site
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	cookies := login()
	// Another user's request: accepted by the IdP contract, this session kept
	if w := post(cookies, logoutRequest("other@example.com", time.Now())); w.Code != http.StatusFound {
		t.Fatalf("logout request for another user: %d %s", w.Code, w.Body.String())
	}
	if !authenticated(cookies) {
		t.Fatal("a logout request naming another user cleared this session")
	}
	// A stale request is refused
	if w := post(cookies, logoutRequest("user@example.com", time.Now().Add(-time.Hour))); w.Code != http.StatusBadRequest {
		t.Fatalf("stale logout request: %d %s", w.Code, w.Body.String())
	}
	if !authenticated(cookies) {
		t.Fatal("a stale logout request cleared the session")
	}
	// The user's own fresh request logs them out
	if w := post(cookies, logoutRequest("user@example.com", time.Now())); w.Code != http.StatusFound {
		t.Fatalf("own logout request: %d %s", w.Code, w.Body.String())
	}
	if authenticated(cookies) {
		t.Fatal("the user's own logout request must clear the session")
	}
}

// A pre-provisioned identity row (an API key minted before the first login)
// holds a placeholder subject that the first login replaces; a later login
// with a different real subject leaves the recorded subject alone. The
// placeholder is recognised by the missing groups observation, not by its
// value: a verified subject that happens to equal the principal's user part
// is kept too
func TestObserveFederatedIdentityStableSubject(t *testing.T) {
	server, _, _ := newMCPAppTestServer(t)
	ctx := t.Context()
	pre := &types.Identity{Id: "idn_pre", Provider: "github", StableSubject: "alice@example.com",
		PrincipalName: "github:alice@example.com", Groups: []string{}}
	if err := server.db.CreateIdentity(ctx, pre); err != nil {
		t.Fatal(err)
	}
	if err := observeFederatedIdentity(ctx, server.db, "github", "sub-1", "alice@example.com", "alice@example.com", []string{"dev"}); err != nil {
		t.Fatal(err)
	}
	identity, err := server.db.GetIdentityByPrincipal(ctx, "github:alice@example.com")
	if err != nil || identity.Id != "idn_pre" || identity.StableSubject != "sub-1" || len(identity.Groups) != 1 {
		t.Fatalf("first login must fill the placeholder subject on the existing row: %+v %v", identity, err)
	}
	if err := observeFederatedIdentity(ctx, server.db, "github", "sub-2", "alice@example.com", "", []string{"ops"}); err != nil {
		t.Fatal(err)
	}
	identity, err = server.db.GetIdentityByPrincipal(ctx, "github:alice@example.com")
	if err != nil || identity.StableSubject != "sub-1" || identity.Groups[0] != "ops" || identity.Email != "alice@example.com" {
		t.Fatalf("a different real subject must not replace the recorded one (groups still refresh): %+v %v", identity, err)
	}

	// First login with a subject equal to the user part, no pre-provisioned row
	if err := observeFederatedIdentity(ctx, server.db, "oidc", "bob@example.com", "bob@example.com", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := observeFederatedIdentity(ctx, server.db, "oidc", "sub-9", "bob@example.com", "", nil); err != nil {
		t.Fatal(err)
	}
	identity, err = server.db.GetIdentityByPrincipal(ctx, "oidc:bob@example.com")
	if err != nil || identity.StableSubject != "bob@example.com" {
		t.Fatalf("a verified subject equal to the user part is not a placeholder: %+v %v", identity, err)
	}
}
