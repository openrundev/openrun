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

	"github.com/go-chi/chi"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestGenCookieName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider string
		want     string
	}{
		{
			name:     "simple provider",
			provider: "github",
			want:     "github_openrun_session",
		},
		{
			name:     "provider with delimiter",
			provider: "github_enterprise",
			want:     "github_enterprise_openrun_session",
		},
		{
			name:     "empty provider",
			provider: "",
			want:     "_openrun_session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := genCookieName(tt.provider)
			testutil.AssertEqualsString(t, "cookie name", tt.want, got)
		})
	}
}

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

func TestValidateProviderName(t *testing.T) {
	config := &types.ServerConfig{
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
	}

	logger := testutil.TestLogger()
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	tests := []struct {
		name     string
		provider string
		want     bool
	}{
		{
			name:     "valid github",
			provider: "github",
			want:     true,
		},
		{
			name:     "valid google",
			provider: "google",
			want:     true,
		},
		{
			name:     "invalid provider",
			provider: "gitlab",
			want:     false,
		},
		{
			name:     "empty provider",
			provider: "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := manager.ValidateProviderName(tt.provider)
			testutil.AssertEqualsBool(t, "validate result", tt.want, got)
		})
	}
}

func TestValidateAuthType(t *testing.T) {
	config := &types.ServerConfig{
		Security: types.SecurityConfig{
			CallbackUrl:   "https://callback.example.com",
			SessionMaxAge: 3600,
		},
		Auth: map[string]types.AuthConfig{
			"github": {
				Key:    "test-key",
				Secret: "test-secret",
			},
		},
		ClientAuth: map[string]types.ClientCertConfig{
			"cert":        {},
			"cert_custom": {},
		},
	}

	logger := testutil.TestLogger()
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	tests := []struct {
		name     string
		authType string
		want     bool
	}{
		{
			name:     "default auth",
			authType: "default",
			want:     true,
		},
		{
			name:     "system auth",
			authType: "system",
			want:     true,
		},
		{
			name:     "none auth",
			authType: "none",
			want:     true,
		},
		{
			name:     "valid provider",
			authType: "github",
			want:     true,
		},
		{
			name:     "cert auth",
			authType: "cert",
			want:     true,
		},
		{
			name:     "cert with prefix",
			authType: "cert_custom",
			want:     true,
		},
		{
			name:     "invalid provider",
			authType: "gitlab",
			want:     false,
		},
		{
			name:     "invalid cert",
			authType: "cert_nonexistent",
			want:     false,
		},
		{
			name:     "rbac prefix with default",
			authType: "rbac:default",
			want:     true,
		},
		{
			name:     "rbac prefix with provider",
			authType: "rbac:github",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := manager.ValidateAuthType(tt.authType)
			testutil.AssertEqualsBool(t, "validate result", tt.want, got)
		})
	}
}

func TestCheckAuth_NoSession(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/some-path", nil)

	userId, groups, err := manager.CheckAuth(w, r, "github")

	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "userId", "", userId)
	if len(groups) != 0 {
		t.Errorf("expected no groups, got %d", len(groups))
	}
}

func TestCheckAuth_WithValidSession(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	// Create a session with auth data
	cookieName := genCookieName("github")
	r := httptest.NewRequest("GET", "/some-path", nil)
	w := httptest.NewRecorder()

	session, err := manager.cookieStore.Get(r, cookieName)
	testutil.AssertNoError(t, err)
	session.Values[AUTH_KEY] = true
	session.Values[USER_KEY] = "testuser"
	session.Values[PROVIDER_NAME_KEY] = "github"
	session.Values[GROUPS_KEY] = []string{"group1", "group2"}
	err = session.Save(r, w)
	testutil.AssertNoError(t, err)

	// Get the cookie from the response and add it to a new request
	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest("GET", "/some-path", nil)
	for _, cookie := range cookies {
		r2.AddCookie(cookie)
	}
	w2 := httptest.NewRecorder()

	userId, groups, err := manager.CheckAuth(w2, r2, "github")

	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "userId", "github:testuser", userId)
	testutil.AssertEqualsInt(t, "groups count", 2, len(groups))
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

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

func TestAuthCallback_MissingState(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/github/callback", nil)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	manager.authCallback(w, r)

	testutil.AssertEqualsInt(t, "status code", http.StatusInternalServerError, w.Code)
}

func TestAuthCallback_InvalidBase64State(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/github/callback?state=invalid!!!", nil)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	manager.authCallback(w, r)

	testutil.AssertEqualsInt(t, "status code", http.StatusInternalServerError, w.Code)
}

func TestAuthCallback_StateNotInDB(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	// Create a valid base64 state that doesn't exist in DB
	sessionId := types.OAUTH_SESSION_KV_PREFIX + "nonexistent"
	state := base64.URLEncoding.EncodeToString([]byte(sessionId))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/github/callback?state="+state, nil)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	manager.authCallback(w, r)

	testutil.AssertEqualsInt(t, "status code", http.StatusInternalServerError, w.Code)
}

func TestRedirect_MissingState(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/github/redirect", nil)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	manager.redirect(w, r)

	testutil.AssertEqualsInt(t, "status code", http.StatusBadRequest, w.Code)
}

func TestRedirect_InvalidBase64State(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	// Create a session first
	cookieName := genCookieName("github")
	r := httptest.NewRequest("GET", "/auth/github/redirect?state=invalid!!!", nil)
	w := httptest.NewRecorder()

	session, err := manager.cookieStore.Get(r, cookieName)
	testutil.AssertNoError(t, err)
	session.Values[NONCE_KEY] = "test-nonce"
	session.Values[REDIRECT_URL] = "https://app.example.com/"
	err = session.Save(r, w)
	testutil.AssertNoError(t, err)

	// Get cookies and create new request
	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest("GET", "/auth/github/redirect?state=invalid!!!", nil)
	for _, cookie := range cookies {
		r2.AddCookie(cookie)
	}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	r2 = r2.WithContext(context.WithValue(r2.Context(), chi.RouteCtxKey, rctx))

	w2 := httptest.NewRecorder()
	manager.redirect(w2, r2)

	testutil.AssertEqualsInt(t, "status code", http.StatusInternalServerError, w2.Code)
}

func TestRedirect_Success(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	// Prepare state in DB
	sessionId := types.OAUTH_SESSION_KV_PREFIX + "test-session-id"
	nonce := "test-nonce-value"
	redirectUrl := "https://app.example.com/dashboard"

	stateMap := map[string]any{
		AUTH_KEY:          true,
		PROVIDER_NAME_KEY: "github",
		REDIRECT_URL:      redirectUrl,
		NONCE_KEY:         nonce,
		USER_KEY:          "testuser",
		GROUPS_KEY:        []any{"group1", "group2"},
	}

	ctx := context.Background()
	expireAt := time.Now().Add(5 * time.Minute)
	err = db.StoreKV(ctx, sessionId, stateMap, &expireAt)
	testutil.AssertNoError(t, err)

	// Create cookie with nonce
	cookieName := genCookieName("github")
	r := httptest.NewRequest("GET", "/auth/github/redirect", nil)
	w := httptest.NewRecorder()

	session, err := manager.cookieStore.Get(r, cookieName)
	testutil.AssertNoError(t, err)
	session.Values[NONCE_KEY] = nonce
	session.Values[REDIRECT_URL] = redirectUrl
	err = session.Save(r, w)
	testutil.AssertNoError(t, err)

	// Create request with state and cookies
	state := base64.URLEncoding.EncodeToString([]byte(sessionId))
	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest("GET", "/auth/github/redirect?state="+state, nil)
	for _, cookie := range cookies {
		r2.AddCookie(cookie)
	}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	r2 = r2.WithContext(context.WithValue(r2.Context(), chi.RouteCtxKey, rctx))

	w2 := httptest.NewRecorder()
	manager.redirect(w2, r2)

	testutil.AssertEqualsInt(t, "status code", http.StatusFound, w2.Code)
	location := w2.Header().Get("Location")
	testutil.AssertEqualsString(t, "redirect location", redirectUrl, location)

	// Verify state was deleted from DB
	_, err = db.FetchKV(ctx, sessionId)
	if err == nil {
		t.Error("expected error fetching deleted state")
	}
}

func TestRedirect_AuthNotTrue(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	// Prepare state in DB with auth = false
	sessionId := types.OAUTH_SESSION_KV_PREFIX + "test-session-id"
	nonce := "test-nonce-value"
	redirectUrl := "https://app.example.com/dashboard"

	stateMap := map[string]any{
		AUTH_KEY:          false, // Auth is false
		PROVIDER_NAME_KEY: "github",
		REDIRECT_URL:      redirectUrl,
		NONCE_KEY:         nonce,
	}

	ctx := context.Background()
	expireAt := time.Now().Add(5 * time.Minute)
	err = db.StoreKV(ctx, sessionId, stateMap, &expireAt)
	testutil.AssertNoError(t, err)

	// Create cookie with nonce
	cookieName := genCookieName("github")
	r := httptest.NewRequest("GET", "/auth/github/redirect", nil)
	w := httptest.NewRecorder()

	session, err := manager.cookieStore.Get(r, cookieName)
	testutil.AssertNoError(t, err)
	session.Values[NONCE_KEY] = nonce
	session.Values[REDIRECT_URL] = redirectUrl
	err = session.Save(r, w)
	testutil.AssertNoError(t, err)

	// Create request with state and cookies
	state := base64.URLEncoding.EncodeToString([]byte(sessionId))
	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest("GET", "/auth/github/redirect?state="+state, nil)
	for _, cookie := range cookies {
		r2.AddCookie(cookie)
	}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	r2 = r2.WithContext(context.WithValue(r2.Context(), chi.RouteCtxKey, rctx))

	w2 := httptest.NewRecorder()
	manager.redirect(w2, r2)

	testutil.AssertEqualsInt(t, "status code", http.StatusInternalServerError, w2.Code)
	testutil.AssertStringContains(t, w2.Body.String(), "expected auth to be true")
}

func TestRedirect_NonceMismatch(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	// Prepare state in DB
	sessionId := types.OAUTH_SESSION_KV_PREFIX + "test-session-id"
	nonce := "test-nonce-value"
	wrongNonce := "wrong-nonce-value"
	redirectUrl := "https://app.example.com/dashboard"

	stateMap := map[string]any{
		AUTH_KEY:          true,
		PROVIDER_NAME_KEY: "github",
		REDIRECT_URL:      redirectUrl,
		NONCE_KEY:         nonce,
		USER_KEY:          "testuser",
		GROUPS_KEY:        []any{"group1"},
	}

	ctx := context.Background()
	expireAt := time.Now().Add(5 * time.Minute)
	err = db.StoreKV(ctx, sessionId, stateMap, &expireAt)
	testutil.AssertNoError(t, err)

	// Create cookie with wrong nonce
	cookieName := genCookieName("github")
	r := httptest.NewRequest("GET", "/auth/github/redirect", nil)
	w := httptest.NewRecorder()

	session, err := manager.cookieStore.Get(r, cookieName)
	testutil.AssertNoError(t, err)
	session.Values[NONCE_KEY] = wrongNonce // Wrong nonce
	session.Values[REDIRECT_URL] = redirectUrl
	err = session.Save(r, w)
	testutil.AssertNoError(t, err)

	// Create request with state and cookies
	state := base64.URLEncoding.EncodeToString([]byte(sessionId))
	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest("GET", "/auth/github/redirect?state="+state, nil)
	for _, cookie := range cookies {
		r2.AddCookie(cookie)
	}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	r2 = r2.WithContext(context.WithValue(r2.Context(), chi.RouteCtxKey, rctx))

	w2 := httptest.NewRecorder()
	manager.redirect(w2, r2)

	testutil.AssertEqualsInt(t, "status code", http.StatusInternalServerError, w2.Code)
	testutil.AssertStringContains(t, w2.Body.String(), "nonce mismatch")
}

func TestRedirect_ProviderMismatch(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

	// Prepare state in DB with different provider
	sessionId := types.OAUTH_SESSION_KV_PREFIX + "test-session-id"
	nonce := "test-nonce-value"
	redirectUrl := "https://app.example.com/dashboard"

	stateMap := map[string]any{
		AUTH_KEY:          true,
		PROVIDER_NAME_KEY: "google", // Different provider
		REDIRECT_URL:      redirectUrl,
		NONCE_KEY:         nonce,
		USER_KEY:          "testuser",
		GROUPS_KEY:        []any{},
	}

	ctx := context.Background()
	expireAt := time.Now().Add(5 * time.Minute)
	err = db.StoreKV(ctx, sessionId, stateMap, &expireAt)
	testutil.AssertNoError(t, err)

	// Create cookie with nonce
	cookieName := genCookieName("github")
	r := httptest.NewRequest("GET", "/auth/github/redirect", nil)
	w := httptest.NewRecorder()

	session, err := manager.cookieStore.Get(r, cookieName)
	testutil.AssertNoError(t, err)
	session.Values[NONCE_KEY] = nonce
	session.Values[REDIRECT_URL] = redirectUrl
	err = session.Save(r, w)
	testutil.AssertNoError(t, err)

	// Create request with state and cookies
	state := base64.URLEncoding.EncodeToString([]byte(sessionId))
	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest("GET", "/auth/github/redirect?state="+state, nil)
	for _, cookie := range cookies {
		r2.AddCookie(cookie)
	}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	r2 = r2.WithContext(context.WithValue(r2.Context(), chi.RouteCtxKey, rctx))

	w2 := httptest.NewRecorder()
	manager.redirect(w2, r2)

	testutil.AssertEqualsInt(t, "status code", http.StatusInternalServerError, w2.Code)
	testutil.AssertStringContains(t, w2.Body.String(), "error matching session state")
}

func TestLogout(t *testing.T) {
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
	db := NewInmemoryKVStore()
	manager := NewOAuthManager(logger, config, db)

	sessionKey := []byte("test-session-key-32bytes-long!!!")
	sessionBlockKey := []byte("test-session-block-32bytes-key!!")
	err := manager.Setup(sessionKey, sessionBlockKey)
	testutil.AssertNoError(t, err)

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
	manager.RegisterRoutes(mux)
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
