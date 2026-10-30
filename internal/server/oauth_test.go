// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestGetProviderName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		urlParam  string
		wantName  string
		wantError bool
	}{
		{
			name:      "valid provider",
			urlParam:  "github",
			wantName:  "github",
			wantError: false,
		},
		{
			name:      "provider with delimiter",
			urlParam:  "github_enterprise",
			wantName:  "github_enterprise",
			wantError: false,
		},
		{
			name:      "empty provider",
			urlParam:  "",
			wantName:  "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest("GET", "/auth/"+tt.urlParam+"/login", nil)

			rctx := chi.NewRouteContext()
			if tt.urlParam != "" {
				rctx.URLParams.Add("provider", tt.urlParam)
			}
			r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

			got, err := getProviderName(r)
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				testutil.AssertNoError(t, err)
				testutil.AssertEqualsString(t, "provider name", tt.wantName, got)
			}
		})
	}
}

func TestOAuthManagerSetup(t *testing.T) {
	tests := []struct {
		name      string
		config    *types.ServerConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid github config",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"github": {
						Key:    "test-key",
						Secret: "test-secret",
						Scopes: []string{"user:email"},
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid google config with hosted domain",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"google": {
						Key:          "test-key",
						Secret:       "test-secret",
						HostedDomain: "example.com",
						Scopes:       []string{"openid", "email"},
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid gitlab config",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"gitlab": {
						Key:    "test-key",
						Secret: "test-secret",
						Scopes: []string{"read_user"},
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid digitalocean config",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"digitalocean": {
						Key:    "test-key",
						Secret: "test-secret",
						Scopes: []string{"read"},
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid auth0 config",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"auth0": {
						Key:    "test-key",
						Secret: "test-secret",
						Domain: "example.auth0.com",
						Scopes: []string{"openid", "profile"},
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid okta config",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"okta": {
						Key:    "test-key",
						Secret: "test-secret",
						OrgUrl: "https://example.okta.com",
						Scopes: []string{"openid", "profile"},
					},
				},
			},
			wantError: false,
		},
		{
			name: "missing callback url",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"github": {
						Key:    "test-key",
						Secret: "test-secret",
					},
				},
			},
			wantError: true,
			errorMsg:  "callback_url must be set",
		},
		{
			name: "missing provider key",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"github": {
						Secret: "test-secret",
					},
				},
			},
			wantError: true,
			errorMsg:  "key, and secret must be set",
		},
		{
			name: "missing provider secret",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"github": {
						Key: "test-key",
					},
				},
			},
			wantError: true,
			errorMsg:  "key, and secret must be set",
		},
		{
			name: "unsupported provider",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"unsupported": {
						Key:    "test-key",
						Secret: "test-secret",
					},
				},
			},
			wantError: true,
			errorMsg:  "unsupported auth provider",
		},
		{
			name: "oidc without discovery url",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"oidc": {
						Key:    "test-key",
						Secret: "test-secret",
					},
				},
			},
			wantError: true,
			errorMsg:  "discovery_url is required",
		},
		{
			name: "multiple providers",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"github": {
						Key:    "test-key",
						Secret: "test-secret",
					},
					"google": {
						Key:    "test-key-2",
						Secret: "test-secret-2",
					},
				},
			},
			wantError: false,
		},
		{
			name: "provider with delimiter in name",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{
					"github_enterprise": {
						Key:    "test-key",
						Secret: "test-secret",
					},
				},
			},
			wantError: false,
		},
		{
			name: "empty auth config",
			config: &types.ServerConfig{
				Security: types.SecurityConfig{
					CallbackUrl:   "https://callback.example.com",
					SessionMaxAge: 3600,
				},
				Auth: map[string]types.AuthConfig{},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := testutil.TestLogger()
			db := NewInmemoryKVStore()
			manager := NewOAuthManager(logger, tt.config, db)

			sessionKey := []byte("test-session-key-32byteslong!!")
			sessionBlockKey := []byte("test-session-block-key-32bytes!")

			err := manager.Setup(sessionKey, sessionBlockKey)
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errorMsg)
				} else {
					testutil.AssertStringContains(t, err.Error(), tt.errorMsg)
				}
			} else {
				testutil.AssertNoError(t, err)
				if manager.cookieStore == nil {
					t.Error("expected cookieStore to be set")
				}
			}
		})
	}
}

func TestCheckAuth_ProviderMismatch(t *testing.T) {
	config := &types.ServerConfig{
		Security: types.SecurityConfig{
			CallbackUrl:      "https://callback.example.com",
			SessionMaxAge:    3600,
			SessionHttpsOnly: false,
		},
		Auth: map[string]types.AuthConfig{
			"github": {
				Key:    "test-key",
				Secret: "test-secret",
			},
			"google": {
				Key:    "test-key-2",
				Secret: "test-secret-2",
			},
		},
	}

	logger := testutil.TestLogger()
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	// Create a session with github provider
	cookieName := genCookieName("github")
	r := httptest.NewRequest("GET", "/some-path", nil)
	w := httptest.NewRecorder()

	session, err := manager.cookieStore.Get(r, cookieName)
	testutil.AssertNoError(t, err)
	session.Values[AUTH_KEY] = true
	session.Values[USER_KEY] = "testuser"
	session.Values[PROVIDER_NAME_KEY] = "github"
	err = session.Save(r, w)
	testutil.AssertNoError(t, err)

	// Get the cookie and try to auth with google provider
	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest("GET", "/some-path", nil)
	for _, cookie := range cookies {
		r2.AddCookie(cookie)
	}
	w2 := httptest.NewRecorder()

	userId, groups, err := manager.CheckAuth(w2, r2, "google")

	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "userId", "", userId)
	if len(groups) != 0 {
		t.Errorf("expected no groups, got %d", len(groups))
	}
}

func TestCheckAuth_GroupsAsAnySlice(t *testing.T) {
	manager, _ := newOAuthSessionTestManager(t)

	// Create a session with groups as []any
	cookieName := genCookieName("github")
	r := httptest.NewRequest("GET", "/some-path", nil)
	w := httptest.NewRecorder()

	session, err := manager.cookieStore.Get(r, cookieName)
	testutil.AssertNoError(t, err)
	session.Values[AUTH_KEY] = true
	session.Values[USER_KEY] = "testuser"
	session.Values[PROVIDER_NAME_KEY] = "github"
	session.Values[GROUPS_KEY] = []any{"group1", "group2", 123} // Mix of types
	err = session.Save(r, w)
	testutil.AssertNoError(t, err)

	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest("GET", "/some-path", nil)
	for _, cookie := range cookies {
		r2.AddCookie(cookie)
	}
	w2 := httptest.NewRecorder()

	userId, groups, err := manager.CheckAuth(w2, r2, "github")

	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "userId", "github:testuser", userId)
	testutil.AssertEqualsInt(t, "groups count", 2, len(groups)) // Non-string items filtered out
}

func TestLogin(t *testing.T) {
	manager, _ := newOAuthSessionTestManager(t)

	tests := []struct {
		name         string
		providerName string
		redirectUrl  string
		htmxRequest  bool
	}{
		{
			name:         "normal request",
			providerName: "github",
			redirectUrl:  "https://app.example.com/dashboard",
			htmxRequest:  false,
		},
		{
			name:         "htmx request",
			providerName: "github",
			redirectUrl:  "https://app.example.com/profile",
			htmxRequest:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/some-path", nil)
			if tt.htmxRequest {
				r.Header.Set("HX-Request", "true")
			}

			manager.beginLogin(w, r, tt.providerName, tt.redirectUrl)

			// Check response code
			if tt.htmxRequest {
				testutil.AssertEqualsInt(t, "status code", http.StatusOK, w.Code)
				// Check for HX-Redirect header
				hxRedirect := w.Header().Get("HX-Redirect")
				if hxRedirect == "" {
					t.Error("expected HX-Redirect header")
				}
				testutil.AssertStringContains(t, hxRedirect, "/auth/"+tt.providerName+"/login")
				testutil.AssertStringContains(t, hxRedirect, "state=")
			} else {
				testutil.AssertEqualsInt(t, "status code", http.StatusFound, w.Code)
				location := w.Header().Get("Location")
				testutil.AssertStringContains(t, location, "/auth/"+tt.providerName+"/login")
				testutil.AssertStringContains(t, location, "state=")
			}

			// Verify cookie was set
			cookies := w.Result().Cookies()
			cookieFound := false
			for _, cookie := range cookies {
				if strings.Contains(cookie.Name, tt.providerName) {
					cookieFound = true
					break
				}
			}
			if !cookieFound {
				t.Error("expected cookie to be set")
			}
		})
	}
}

func TestLogout(t *testing.T) {
	manager, _ := newOAuthSessionTestManager(t)

	// Create a session first
	cookieName := genCookieName("github")
	r := httptest.NewRequest("POST", "/auth/github/logout", nil)
	w := httptest.NewRecorder()

	session, err := manager.cookieStore.Get(r, cookieName)
	testutil.AssertNoError(t, err)
	session.Values[AUTH_KEY] = true
	session.Values[USER_KEY] = "testuser"
	err = session.Save(r, w)
	testutil.AssertNoError(t, err)

	// Now test logout
	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest("POST", "/_openrun/logout/github", nil)
	for _, cookie := range cookies {
		r2.AddCookie(cookie)
	}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	r2 = r2.WithContext(context.WithValue(r2.Context(), chi.RouteCtxKey, rctx))

	w2 := httptest.NewRecorder()

	// Register routes and call logout
	mux := chi.NewRouter()
	manager.RegisterRoutes(http.NewCrossOriginProtection(), mux)
	mux.ServeHTTP(w2, r2)

	testutil.AssertEqualsInt(t, "status code", http.StatusTemporaryRedirect, w2.Code)
	location := w2.Header().Get("Location")
	testutil.AssertEqualsString(t, "redirect location", "/", location)

	// Verify the session cookie was invalidated (MaxAge = -1)
	responseCookies := w2.Result().Cookies()
	foundCookie := false
	for _, cookie := range responseCookies {
		if strings.Contains(cookie.Name, "github") {
			foundCookie = true
			if cookie.MaxAge != -1 {
				t.Errorf("expected cookie MaxAge to be -1, got %d", cookie.MaxAge)
			}
		}
	}
	if !foundCookie {
		t.Error("expected logout cookie to be set")
	}
}

func TestLogin_StoreKVError(t *testing.T) {
	// Create a custom DB that returns an error on StoreKV
	errorDB := &errorKVStore{
		storeError: true,
	}

	config := &types.ServerConfig{
		Security: types.SecurityConfig{
			CallbackUrl:      "https://callback.example.com",
			SessionMaxAge:    3600,
			SessionHttpsOnly: false,
		},
		Auth: map[string]types.AuthConfig{
			"github": {
				Key:    "test-key",
				Secret: "test-secret",
			},
		},
	}

	logger := testutil.TestLogger()
	manager := NewOAuthManager(logger, config, errorDB)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/some-path", nil)

	manager.beginLogin(w, r, "github", "https://app.example.com/")

	testutil.AssertEqualsInt(t, "status code", http.StatusInternalServerError, w.Code)
	testutil.AssertStringContains(t, w.Body.String(), "error storing state")
}

// errorKVStore is a mock KVStore that returns errors on demand
type errorKVStore struct {
	InmemoryKVStore
	storeError  bool
	fetchError  bool
	updateError bool
	deleteError bool
}

func (e *errorKVStore) StoreKV(ctx context.Context, key string, value map[string]any, expireAt *time.Time) error {
	if e.storeError {
		return &url.Error{Op: "store", URL: "test", Err: context.DeadlineExceeded}
	}
	return e.InmemoryKVStore.StoreKV(ctx, key, value, expireAt)
}

func (e *errorKVStore) FetchKV(ctx context.Context, key string) (map[string]any, error) {
	if e.fetchError {
		return nil, &url.Error{Op: "fetch", URL: "test", Err: context.DeadlineExceeded}
	}
	return e.InmemoryKVStore.FetchKV(ctx, key)
}

func (e *errorKVStore) FetchKVBlob(ctx context.Context, key string) ([]byte, error) {
	if e.fetchError {
		return nil, &url.Error{Op: "fetch", URL: "test", Err: context.DeadlineExceeded}
	}
	return e.InmemoryKVStore.FetchKVBlob(ctx, key)
}

func (e *errorKVStore) UpsertKVBlob(ctx context.Context, key string, value []byte, expireAt *time.Time) error {
	if e.storeError || e.updateError {
		return &url.Error{Op: "upsert", URL: "test", Err: context.DeadlineExceeded}
	}
	return e.InmemoryKVStore.UpsertKVBlob(ctx, key, value, expireAt)
}

func (e *errorKVStore) UpdateKV(ctx context.Context, key string, value map[string]any) error {
	if e.updateError {
		return &url.Error{Op: "update", URL: "test", Err: context.DeadlineExceeded}
	}
	return e.InmemoryKVStore.UpdateKV(ctx, key, value)
}

func (e *errorKVStore) DeleteKV(ctx context.Context, key string) error {
	if e.deleteError {
		return &url.Error{Op: "delete", URL: "test", Err: context.DeadlineExceeded}
	}
	return e.InmemoryKVStore.DeleteKV(ctx, key)
}

func newOAuthSessionTestManager(t *testing.T) (*OAuthManager, *InmemoryKVStore) {
	t.Helper()
	config := &types.ServerConfig{
		Security: types.SecurityConfig{CallbackUrl: "https://callback.example.com", SessionMaxAge: 3600},
		Auth:     map[string]types.AuthConfig{"github": {Key: "test-key", Secret: "test-secret"}},
	}
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(testutil.TestLogger(), config, db)
	testutil.AssertNoError(t, manager.Setup([]byte("test-session-key-32bytes-long!!!"), []byte("test-session-block-32bytes-key!!")))
	return manager, db
}

func oauthProviderRequest(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestAuthCallbackState(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		status      int
	}{
		{"missing", "", http.StatusBadRequest},
		{"invalid base64", "invalid!!!", http.StatusBadRequest},
		{"not stored", base64.URLEncoding.EncodeToString([]byte(types.OAUTH_SESSION_KV_PREFIX + "nonexistent")), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, _ := newOAuthSessionTestManager(t)
			w := httptest.NewRecorder()
			manager.authCallback(w, oauthProviderRequest("/auth/github/callback?state="+tc.state))
			testutil.AssertEqualsInt(t, "status code", tc.status, w.Code)
		})
	}
}

func TestOAuthRedirectState(t *testing.T) {
	const nonce, redirectURL = "test-nonce-value", "https://app.example.com/dashboard"
	sessionID := types.OAUTH_SESSION_KV_PREFIX + "test-session-id"
	state := base64.URLEncoding.EncodeToString([]byte(sessionID))
	for _, tc := range []struct {
		name, state           string
		auth                  bool
		provider, cookieNonce any
		status                int
		message               string
	}{
		{"missing state", "", false, nil, nil, http.StatusBadRequest, ""},
		{"invalid base64", "invalid!!!", false, nil, "test-nonce", http.StatusBadRequest, ""},
		{"invalid cookie nonce", state, true, "github", []string{nonce}, http.StatusBadRequest, "nonce not found"},
		{"invalid state provider", state, true, []any{"github"}, nonce, http.StatusBadRequest, "error matching session state"},
		{"success", state, true, "github", nonce, http.StatusFound, ""},
		{"unauthenticated", state, false, "github", nonce, http.StatusInternalServerError, "expected auth to be true"},
		{"nonce mismatch", state, true, "github", "wrong-nonce-value", http.StatusInternalServerError, "nonce mismatch"},
		{"provider mismatch", state, true, "google", nonce, http.StatusInternalServerError, "error matching session state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, db := newOAuthSessionTestManager(t)
			if tc.state == state {
				expireAt := time.Now().Add(5 * time.Minute)
				testutil.AssertNoError(t, db.StoreKV(t.Context(), sessionID, map[string]any{
					AUTH_KEY: tc.auth, PROVIDER_NAME_KEY: tc.provider, REDIRECT_URL: redirectURL, NONCE_KEY: nonce,
					USER_KEY: "testuser", USER_ID_KEY: "subject-123", USER_EMAIL_KEY: "test@example.com",
					GROUPS_KEY: []any{"group1", "group2"},
				}, &expireAt))
			}
			r := oauthProviderRequest("/auth/github/redirect?state=" + tc.state)
			if tc.cookieNonce != nil {
				setupReq := httptest.NewRequest(http.MethodGet, "/auth/github/redirect", nil)
				setupRec := httptest.NewRecorder()
				session, err := manager.cookieStore.Get(setupReq, genCookieName("github"))
				testutil.AssertNoError(t, err)
				session.Values[NONCE_KEY], session.Values[REDIRECT_URL] = tc.cookieNonce, redirectURL
				testutil.AssertNoError(t, session.Save(setupReq, setupRec))
				for _, cookie := range setupRec.Result().Cookies() {
					r.AddCookie(cookie)
				}
			}
			w := httptest.NewRecorder()
			manager.redirect(w, r)
			testutil.AssertEqualsInt(t, "status code", tc.status, w.Code)
			if tc.message != "" {
				testutil.AssertStringContains(t, w.Body.String(), tc.message)
			}
			if tc.status != http.StatusFound {
				return
			}
			testutil.AssertEqualsString(t, "redirect location", redirectURL, w.Header().Get("Location"))
			if _, err := db.FetchKV(t.Context(), sessionID); err == nil {
				t.Error("expected error fetching deleted state")
			}
			authed := httptest.NewRequest(http.MethodGet, "/some-path", nil)
			for _, cookie := range w.Result().Cookies() {
				authed.AddCookie(cookie)
			}
			info, err := manager.CheckAuthInfo(httptest.NewRecorder(), authed, "github")
			testutil.AssertNoError(t, err)
			testutil.AssertEqualsString(t, "user subject", "subject-123", info.UserSubject)
			testutil.AssertEqualsString(t, "user email", "test@example.com", info.UserEmail)
		})
	}
}

// oauthNonceCookies returns the app-domain pre-auth cookies beginLogin would
// have set for the browser that started a login with the given nonce
func oauthNonceCookies(t *testing.T, manager *OAuthManager, nonce, redirectURL string) []*http.Cookie {
	t.Helper()
	setupReq := httptest.NewRequest(http.MethodGet, "/auth/github/redirect", nil)
	setupRec := httptest.NewRecorder()
	session, err := manager.cookieStore.Get(setupReq, genCookieName("github"))
	testutil.AssertNoError(t, err)
	session.Values[NONCE_KEY], session.Values[REDIRECT_URL] = nonce, redirectURL
	testutil.AssertNoError(t, session.Save(setupReq, setupRec))
	return setupRec.Result().Cookies()
}

// TestOAuthCallbackRotatesState covers the session fixation reported in
// GHSA-rw93-hw9g-vc3m. The pre-login state token is visible to whoever
// started the flow, so an attacker could start a login (keeping the nonce
// cookie), hand the IdP link to a victim and, once the victim had
// authenticated, finish the login with the known state. The callback must
// consume the pre-login state and hand the browser that completed the IdP
// step a fresh single-use token
func TestOAuthCallbackRotatesState(t *testing.T) {
	const nonce, redirectURL = "attacker-nonce", "https://app.example.com/dashboard"
	preAuthID := types.OAUTH_SESSION_KV_PREFIX + "attacker-started-login"
	preAuthState := base64.URLEncoding.EncodeToString([]byte(preAuthID))
	manager, db := newOAuthSessionTestManager(t)
	originalComplete := gothic.CompleteUserAuth
	gothic.CompleteUserAuth = func(http.ResponseWriter, *http.Request) (goth.User, error) {
		return goth.User{UserID: "victim-subject", Email: "victim@example.com", NickName: "victim",
			RawData: map[string]any{"groups": []any{"admins"}}}, nil
	}
	t.Cleanup(func() { gothic.CompleteUserAuth = originalComplete })

	// The attacker starts a login: pre-auth state in the keystore, nonce cookie
	// in the attacker's jar, state token in the login URL they hand the victim
	expireAt := time.Now().Add(preAuthStateMaxAge)
	testutil.AssertNoError(t, db.StoreKV(t.Context(), preAuthID, map[string]any{
		AUTH_KEY: false, PROVIDER_NAME_KEY: "github", REDIRECT_URL: redirectURL, NONCE_KEY: nonce,
	}, &expireAt))
	attackerCookies := oauthNonceCookies(t, manager, nonce, redirectURL)
	// The browser of the legitimate flow (checked below) holds the same nonce
	// in its own cookie session; a rejected redirect drops the caller's
	// pre-auth session, so the two scenarios must not share a jar
	browserCookies := oauthNonceCookies(t, manager, nonce, redirectURL)

	// 1. The victim completes the IdP step with the attacker's state
	w := httptest.NewRecorder()
	manager.authCallback(w, oauthProviderRequest("/auth/github/callback?state="+preAuthState))
	testutil.AssertEqualsInt(t, "callback status", http.StatusFound, w.Code)
	location, err := url.Parse(w.Header().Get("Location"))
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "redirect host", "app.example.com", location.Host)
	testutil.AssertEqualsString(t, "redirect path", types.INTERNAL_URL_PREFIX+"/auth/github/redirect", location.Path)
	newState := location.Query().Get("state")
	if newState == "" || newState == preAuthState {
		t.Fatalf("state not rotated by the callback: %s", location)
	}
	newIDBytes, err := base64.URLEncoding.DecodeString(newState)
	testutil.AssertNoError(t, err)
	newID := string(newIDBytes)
	if !strings.HasPrefix(newID, types.OAUTH_SESSION_KV_PREFIX) {
		t.Fatalf("unexpected completion key %q", newID)
	}
	if _, err := db.FetchKV(t.Context(), preAuthID); err == nil {
		t.Fatal("pre-login state survived the callback")
	}
	completeState, err := db.FetchKV(t.Context(), newID)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "authenticated", true, completeState[AUTH_KEY] == true)
	testutil.AssertEqualsString(t, "user", "victim@example.com", completeState[USER_KEY].(string))
	testutil.AssertEqualsString(t, "nonce carried over", nonce, completeState[NONCE_KEY].(string))
	if deleteAt := db.deleteAt[newID]; deleteAt == nil || deleteAt.After(time.Now().Add(completeTokenMaxAge+time.Second)) {
		t.Fatalf("completion token expiry %v not bounded by %v", deleteAt, completeTokenMaxAge)
	}

	// 2. The attacker, holding the nonce cookie and the leaked pre-login state,
	// must not be able to finish the victim's login
	r := oauthProviderRequest("/auth/github/redirect?state=" + preAuthState)
	for _, cookie := range attackerCookies {
		r.AddCookie(cookie)
	}
	w = httptest.NewRecorder()
	manager.redirect(w, r)
	if w.Code == http.StatusFound {
		t.Fatal("leaked pre-login state minted a session for the victim")
	}
	if len(w.Result().Cookies()) > 0 && w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("rejected redirect issued a session cookie")
	}

	// 3. Replaying the callback with the consumed state fails and does not
	// mint a second completion token
	w = httptest.NewRecorder()
	manager.authCallback(w, oauthProviderRequest("/auth/github/callback?state="+preAuthState))
	if w.Code == http.StatusFound {
		t.Fatal("replayed callback accepted")
	}
	keys := 0
	for key := range db.store {
		if strings.HasPrefix(key, types.OAUTH_SESSION_KV_PREFIX) {
			keys++
		}
	}
	testutil.AssertEqualsInt(t, "login state entries", 1, keys)

	// 4. In the legitimate flow the same browser holds the nonce cookie and
	// receives the rotated state, and completes the login
	r = oauthProviderRequest("/auth/github/redirect?state=" + newState)
	for _, cookie := range browserCookies {
		r.AddCookie(cookie)
	}
	w = httptest.NewRecorder()
	manager.redirect(w, r)
	testutil.AssertEqualsInt(t, "redirect status", http.StatusFound, w.Code)
	testutil.AssertEqualsString(t, "redirect location", redirectURL, w.Header().Get("Location"))
	authed := httptest.NewRequest(http.MethodGet, "/some-path", nil)
	for _, cookie := range w.Result().Cookies() {
		authed.AddCookie(cookie)
	}
	info, err := manager.CheckAuthInfo(httptest.NewRecorder(), authed, "github")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "user", "github:victim@example.com", info.UserId)
	testutil.AssertEqualsString(t, "user subject", "victim-subject", info.UserSubject)

	// 5. The rotated state is single use
	r = oauthProviderRequest("/auth/github/redirect?state=" + newState)
	for _, cookie := range browserCookies {
		r.AddCookie(cookie)
	}
	w = httptest.NewRecorder()
	manager.redirect(w, r)
	if w.Code == http.StatusFound {
		t.Fatal("completion token reused")
	}
}

// navigationRequest is an app request as a browser sends it for a top level
// navigation to a potentially trustworthy origin (fetch metadata present)
func navigationRequest(target string, cookies []*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("Sec-Fetch-Site", "none")
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	return r
}

// backgroundRequest is an app request a browser sends on its own or from
// page script: a service worker script update by default, or with the
// given fetch mode and destination
func backgroundRequest(target string, cookies []*http.Cookie, metadata ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Sec-Fetch-Mode", "same-origin")
	r.Header.Set("Sec-Fetch-Dest", "serviceworker")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if len(metadata) == 2 {
		r.Header.Set("Sec-Fetch-Mode", metadata[0])
		r.Header.Set("Sec-Fetch-Dest", metadata[1])
	}
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	return r
}

// assertDeniedLoginStart checks the response of a request that may not
// start a login: a 401 which changes nothing in the browser or the store
func assertDeniedLoginStart(t *testing.T, w *httptest.ResponseRecorder, db *InmemoryKVStore, rows int) {
	t.Helper()
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q, want no-store", w.Header().Get("Cache-Control"))
	}
	for _, name := range []string{"Set-Cookie", "Location", "HX-Redirect"} {
		if w.Header().Get(name) != "" {
			t.Fatalf("denied request must not send %s, got %q", name, w.Header().Get(name))
		}
	}
	if len(db.store) != rows {
		t.Fatalf("denied request changed the keystore: %d rows, was %d", len(db.store), rows)
	}
}

// loginStateOf returns the pre-login state row the login redirect names
func loginStateOf(t *testing.T, db KVStore, location string) (string, map[string]any) {
	t.Helper()
	loginURL, err := url.Parse(location)
	testutil.AssertNoError(t, err)
	sessionId, err := base64.URLEncoding.DecodeString(loginURL.Query().Get("state"))
	testutil.AssertNoError(t, err)
	state, err := db.FetchKV(t.Context(), string(sessionId))
	testutil.AssertNoError(t, err)
	return string(sessionId), state
}

// sessionIDOf decodes the session id the cookie carries
func sessionIDOf(t *testing.T, manager *OAuthManager, cookie *http.Cookie) string {
	t.Helper()
	var id string
	store, ok := manager.cookieStore.(*KVSessionStore)
	if !ok {
		t.Fatalf("cookie store is %T, want the KV session store", manager.cookieStore)
	}
	testutil.AssertNoError(t, securecookie.DecodeMulti(cookie.Name, cookie.Value, &id, store.Codecs...))
	return id
}

func providerCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("no %s cookie in %v", name, cookies)
	return nil
}

// TestOAuthBackgroundRequestKeepsPendingLogin is the sequence of
// openrundev/openrun#116: while the user is at the IdP, the browser's
// service worker update fetch (or a poller of a tab whose session expired)
// reaches the app without a session. It must not start another login,
// which would overwrite the pre-auth cookie of the login in flight and
// fail its completion with "error matching session state"
func TestOAuthBackgroundRequestKeepsPendingLogin(t *testing.T) {
	manager, db := newOAuthSessionTestManager(t)
	const appURL = "https://app.example.com/chat/production/"

	// A navigation starts the login
	w := httptest.NewRecorder()
	info, err := manager.CheckAuthInfo(w, navigationRequest(appURL, nil), "github")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "user", "", info.UserId)
	testutil.AssertEqualsInt(t, "login redirect", http.StatusFound, w.Code)
	testutil.AssertStringContains(t, w.Header().Get("Location"), "/auth/github/login?state=")
	preAuthCookies := w.Result().Cookies()
	providerCookie(t, preAuthCookies, genCookieName("github"))
	stateId, state := loginStateOf(t, db, w.Header().Get("Location"))
	nonce, _ := state[NONCE_KEY].(string)
	redirectURL, _ := state[REDIRECT_URL].(string)
	if nonce == "" || redirectURL != appURL {
		t.Fatalf("login state %v", state)
	}
	rows := len(db.store)

	// Background requests arriving with the pre-auth cookie are refused
	// without touching it or the login state
	for _, tc := range []struct {
		name string
		r    *http.Request
	}{
		{"service worker update", backgroundRequest(appURL+"notify-sw.js", preAuthCookies)},
		{"fetch poller", backgroundRequest(appURL+"api/status", preAuthCookies, "cors", "empty")},
		{"event source", backgroundRequest(appURL+"events", preAuthCookies, "cors", "empty")},
		{"prefetch", func() *http.Request {
			r := navigationRequest(appURL+"other", preAuthCookies)
			r.Header.Set("Sec-Purpose", "prefetch;prerender")
			return r
		}()},
		{"non-html client", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, appURL+"api/status", nil)
			r.Header.Set("Accept", "application/json")
			return r
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			info, err := manager.CheckAuthInfo(w, tc.r, "github")
			testutil.AssertNoError(t, err)
			testutil.AssertEqualsString(t, "user", "", info.UserId)
			assertDeniedLoginStart(t, w, db, rows)
			kept, err := db.FetchKV(t.Context(), stateId)
			testutil.AssertNoError(t, err)
			if kept[NONCE_KEY] != nonce {
				t.Fatalf("login state changed: %v", kept)
			}
		})
	}

	// The IdP step completes: the callback consumed the pre-login state and
	// minted the completion token (TestOAuthCallbackRotatesState); the
	// redirect with the untouched pre-auth cookie completes the login
	completeId := types.OAUTH_SESSION_KV_PREFIX + "completion-token"
	expireAt := time.Now().Add(time.Minute)
	testutil.AssertNoError(t, db.DeleteKV(t.Context(), stateId))
	testutil.AssertNoError(t, db.StoreKV(t.Context(), completeId, map[string]any{
		AUTH_KEY: true, PROVIDER_NAME_KEY: "github", REDIRECT_URL: redirectURL, NONCE_KEY: nonce,
		USER_KEY: "jane", USER_ID_KEY: "subject-1", GROUPS_KEY: []any{"dev"},
	}, &expireAt))
	redirectReq := oauthProviderRequest("/auth/github/redirect?state=" + base64.URLEncoding.EncodeToString([]byte(completeId)))
	for _, cookie := range preAuthCookies {
		redirectReq.AddCookie(cookie)
	}
	w = httptest.NewRecorder()
	manager.redirect(w, redirectReq)
	if w.Code != http.StatusFound {
		t.Fatalf("redirect: %d %s", w.Code, w.Body.String())
	}
	testutil.AssertEqualsString(t, "app url", appURL, w.Header().Get("Location"))
	authedCookies := w.Result().Cookies()

	// Authenticated background requests are served: the classifier only
	// applies to a request without a usable session
	w = httptest.NewRecorder()
	info, err = manager.CheckAuthInfo(w, backgroundRequest(appURL+"notify-sw.js", authedCookies), "github")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "user", "github:jane", info.UserId)
	if w.Code != http.StatusOK || w.Header().Get("Location") != "" {
		t.Fatalf("authenticated background request: %d %v", w.Code, w.Header())
	}
}

// A session cookie that cannot be used (undecodable, or naming a row that
// expired) is treated as no session: a navigation starts the login at once
// under a new session id, without the cookie-clearing self redirect of
// earlier versions, and a background request gets the 401 without any
// cookie change
func TestOAuthUnusableCookieStartsLoginAfresh(t *testing.T) {
	const appURL = "https://app.example.com/dashboard"
	cookieName := genCookieName("github")
	for _, tc := range []struct {
		name   string
		cookie func(t *testing.T, manager *OAuthManager, db *InmemoryKVStore) *http.Cookie
	}{
		{"undecodable cookie", func(t *testing.T, manager *OAuthManager, db *InmemoryKVStore) *http.Cookie {
			return &http.Cookie{Name: cookieName, Value: "not-a-valid-cookie-value"}
		}},
		{"signed cookie naming a missing row", func(t *testing.T, manager *OAuthManager, db *InmemoryKVStore) *http.Cookie {
			cookies := oauthNonceCookies(t, manager, "old-nonce", appURL)
			cookie := providerCookie(t, cookies, cookieName)
			id := sessionIDOf(t, manager, cookie)
			testutil.AssertNoError(t, db.DeleteKV(t.Context(), types.HTTP_SESSION_KV_PREFIX+cookieName+":"+id))
			return cookie
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, db := newOAuthSessionTestManager(t)
			stale := tc.cookie(t, manager, db)
			rows := len(db.store)

			// Background: 401, the stale cookie is left alone
			w := httptest.NewRecorder()
			info, err := manager.CheckAuthInfo(w, backgroundRequest(appURL, []*http.Cookie{stale}, "cors", "empty"), "github")
			testutil.AssertNoError(t, err)
			testutil.AssertEqualsString(t, "user", "", info.UserId)
			assertDeniedLoginStart(t, w, db, rows)

			// Navigation: straight into the login, with a fresh session
			w = httptest.NewRecorder()
			info, err = manager.CheckAuthInfo(w, navigationRequest(appURL, []*http.Cookie{stale}), "github")
			testutil.AssertNoError(t, err)
			testutil.AssertEqualsString(t, "user", "", info.UserId)
			testutil.AssertEqualsInt(t, "login redirect", http.StatusFound, w.Code)
			testutil.AssertStringContains(t, w.Header().Get("Location"), "/auth/github/login?state=")
			set := w.Result().Cookies()
			if len(set) != 1 {
				t.Fatalf("want one pre-auth cookie, got %v", set)
			}
			fresh := providerCookie(t, set, cookieName)
			if fresh.MaxAge <= 0 {
				t.Fatalf("pre-auth cookie must be set, not cleared: %v", fresh)
			}
			if id := sessionIDOf(t, manager, fresh); id == "" || (stale.Value != "not-a-valid-cookie-value" && id == sessionIDOf(t, manager, stale)) {
				t.Fatalf("the login must start under a new session id, got %q", id)
			}
			_, state := loginStateOf(t, db, w.Header().Get("Location"))
			if state[REDIRECT_URL] != appURL {
				t.Fatalf("login state %v", state)
			}

			// HTMX: the login redirect goes out as HX-Redirect, not the
			// earlier self redirect
			w = httptest.NewRecorder()
			htmx := backgroundRequest(appURL, []*http.Cookie{stale}, "cors", "empty")
			htmx.Header.Set("HX-Request", "true")
			_, err = manager.CheckAuthInfo(w, htmx, "github")
			testutil.AssertNoError(t, err)
			testutil.AssertEqualsInt(t, "htmx status", http.StatusOK, w.Code)
			testutil.AssertStringContains(t, w.Header().Get("HX-Redirect"), "/auth/github/login?state=")
		})
	}
}

// Background requests do not count against the client's login start budget
// and write no login state
func TestOAuthBackgroundRequestsSkipLoginBudget(t *testing.T) {
	manager, db := newOAuthSessionTestManager(t)
	manager.config.Security.LoginStartRateLimit = 2
	manager.loginRate = newIPRateLimiter(time.Minute, rateLimiterMaxIPs)
	const appURL = "https://app.example.com/dashboard"
	rows := len(db.store)
	for range 10 {
		r := backgroundRequest(appURL+"/poll", nil, "cors", "empty")
		r.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		_, err := manager.CheckAuthInfo(w, r, "github")
		testutil.AssertNoError(t, err)
		assertDeniedLoginStart(t, w, db, rows)
	}
	for i := range 2 {
		r := navigationRequest(appURL, nil)
		r.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		_, err := manager.CheckAuthInfo(w, r, "github")
		testutil.AssertNoError(t, err)
		if w.Code != http.StatusFound {
			t.Fatalf("navigation %d after the background requests: %d, want the login redirect", i, w.Code)
		}
	}
	r := navigationRequest(appURL, nil)
	r.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	_, err := manager.CheckAuthInfo(w, r, "github")
	testutil.AssertNoError(t, err)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("third navigation: %d, want 429 (the limit applies to navigations)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "login") {
		t.Fatalf("429 body: %s", w.Body.String())
	}
}
