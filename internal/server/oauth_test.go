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
