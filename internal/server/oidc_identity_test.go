// Copyright (c) OpenRun Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
)

// trust_unverified_email is meaningless for the goth providers, which
// already trust an address without a claim: it is refused, not ignored
func TestTrustUnverifiedEmailOIDCOnly(t *testing.T) {
	manager := &OAuthManager{Logger: testutil.TestLogger(), config: ssoPrivateHostsConfig()}
	_, err := manager.buildProvider("google_corp", types.AuthConfig{Key: "k", Secret: "s", TrustUnverifiedEmail: true}, "https://app.example")
	if err == nil || !strings.Contains(err.Error(), "trust_unverified_email") || !strings.Contains(err.Error(), "google_corp") {
		t.Fatalf("option accepted on a goth provider: %v", err)
	}
}

// The login callback takes the OIDC adapter's email decision as final and
// logs the adapter's reason for a dropped address. The merged raw claims
// cannot be re-evaluated there: an ID token false overwritten by a userinfo
// true reads as verified in them
func TestAuthCallbackOIDCEmailPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		user     goth.User
		wantUser string
		wantLog  string // a fragment of the expected Warn line, "" for no warning
	}{
		{name: "xms_edov accepted", user: goth.User{UserID: "subject", Email: "alice@example.com",
			RawData: map[string]any{"email": "alice@example.com", "xms_edov": true}}, wantUser: "alice@example.com"},
		{name: "overwritten false", user: goth.User{UserID: "subject",
			RawData: map[string]any{"email": "alice@example.com", "email_verified": true, oidcEmailDroppedKey: oidcEmailDroppedFalse}},
			wantUser: "subject", wantLog: "marks the email as unverified"},
		{name: "absent", user: goth.User{UserID: "subject",
			RawData: map[string]any{"email": "alice@example.com", oidcEmailDroppedKey: oidcEmailDroppedAbsent}},
			wantUser: "subject", wantLog: "sent no email verification claim"},
		{name: "malformed", user: goth.User{UserID: "subject",
			RawData: map[string]any{"email": "alice@example.com", "email_verified": "yes", oidcEmailDroppedKey: oidcEmailDroppedMalformed}},
			wantUser: "subject", wantLog: "neither true nor false"},
		{name: "mismatch", user: goth.User{UserID: "subject",
			RawData: map[string]any{"email": "victim@example.com", oidcEmailDroppedKey: oidcEmailDroppedMismatch}},
			wantUser: "subject", wantLog: "userinfo email differs from the ID token email"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			zl := zerolog.New(&logs)
			config := &types.ServerConfig{
				Security: types.SecurityConfig{CallbackUrl: "https://callback.example.com", SessionMaxAge: 3600},
				Auth:     map[string]types.AuthConfig{"github": {Key: "test-key", Secret: "test-secret"}},
			}
			db := NewInmemoryKVStore()
			manager := NewOAuthManager(&types.Logger{Logger: &zl}, config, db)
			testutil.AssertNoError(t, manager.Setup([]byte("test-session-key-32bytes-long!!!"), []byte("test-session-block-32bytes-key!!")))
			// The entry exists without a provider build: the adapter is stubbed
			manager.providerMu.Lock()
			manager.providerConfigs["oidc_company"] = &types.AuthConfig{Key: "k", Secret: "s", DiscoveryUrl: "https://idp.example/.well-known/openid-configuration"}
			manager.providerMu.Unlock()

			user := tc.user
			user.Provider = "oidc_company"
			originalComplete := gothic.CompleteUserAuth
			gothic.CompleteUserAuth = func(http.ResponseWriter, *http.Request) (goth.User, error) { return user, nil }
			t.Cleanup(func() { gothic.CompleteUserAuth = originalComplete })

			preAuthID := types.OAUTH_SESSION_KV_PREFIX + "login"
			expireAt := time.Now().Add(preAuthStateMaxAge)
			testutil.AssertNoError(t, db.StoreKV(t.Context(), preAuthID, map[string]any{
				AUTH_KEY: false, PROVIDER_NAME_KEY: "oidc_company", REDIRECT_URL: "https://app.example.com/", NONCE_KEY: "nonce",
			}, &expireAt))
			r := httptest.NewRequest(http.MethodGet, "/auth/oidc_company/callback?state="+base64.URLEncoding.EncodeToString([]byte(preAuthID)), nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("provider", "oidc_company")
			w := httptest.NewRecorder()
			manager.authCallback(w, r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx)))
			testutil.AssertEqualsInt(t, "callback status", http.StatusFound, w.Code)
			location, err := url.Parse(w.Header().Get("Location"))
			testutil.AssertNoError(t, err)
			newID, err := base64.URLEncoding.DecodeString(location.Query().Get("state"))
			testutil.AssertNoError(t, err)
			completeState, err := db.FetchKV(t.Context(), string(newID))
			testutil.AssertNoError(t, err)
			testutil.AssertEqualsString(t, "user", tc.wantUser, completeState[USER_KEY].(string))

			if tc.wantLog == "" {
				if strings.Contains(logs.String(), "identified by subject") {
					t.Fatalf("unexpected warning: %s", logs.String())
				}
			} else if !strings.Contains(logs.String(), tc.wantLog) || !strings.Contains(logs.String(), `"subject":"subject"`) {
				t.Fatalf("warning %q not logged: %s", tc.wantLog, logs.String())
			}
			if _, present := user.RawData[oidcEmailDroppedKey]; present {
				t.Fatal("the drop marker survived the callback")
			}
		})
	}
}
