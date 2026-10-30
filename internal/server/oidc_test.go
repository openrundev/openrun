// Copyright (c) OpenRun Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/oauth2"
)

func TestOIDCLoginValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer, idToken string
	var profile map[string]any
	var exchanged url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case oidcDiscoveryPath:
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "userinfo_endpoint": issuer + "/userinfo", "id_token_signing_alg_values_supported": []string{"RS256", "HS256", "none"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: &key.PublicKey, KeyID: "test", Use: "sig", Algorithm: "RS256"},
				{Key: []byte("publicly-visible-secret"), KeyID: "hmac", Use: "sig", Algorithm: "HS256"},
			}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			exchanged = r.PostForm
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 120, "id_token": idToken})
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(profile)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	issuer = ts.URL
	adapter, err := (&OAuthManager{config: ssoPrivateHostsConfig()}).buildProvider("oidc_company", types.AuthConfig{
		Key: "client", Secret: "secret", DiscoveryUrl: ts.URL + oidcDiscoveryPath, Scopes: []string{"email"},
	}, "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	p := adapter.(*oidcProvider)

	for _, tc := range []struct {
		name             string
		mutate           func(jwt.MapClaims)
		profile          map[string]any
		foreignSignature bool
		algorithm        string
		wantError        bool
		wantVerified     bool
	}{
		{name: "valid verified email", wantVerified: true},
		{name: "missing email verification", mutate: func(c jwt.MapClaims) { delete(c, "email_verified") }},
		{name: "false email verification", mutate: func(c jwt.MapClaims) { c["email_verified"] = false }},
		{name: "string email verification", mutate: func(c jwt.MapClaims) { c["email_verified"] = "true" }, wantVerified: true},
		{name: "string email verification false", mutate: func(c jwt.MapClaims) { c["email_verified"] = "false" }},
		{name: "malformed email verification", mutate: func(c jwt.MapClaims) { c["email_verified"] = "yes" }},
		{name: "different unverified userinfo email", profile: map[string]any{"sub": "subject", "email": "victim@example.com"}},
		{name: "userinfo explicitly unverified", profile: map[string]any{"sub": "subject", "email_verified": false}},
		{name: "userinfo verified email", profile: map[string]any{"sub": "subject", "email": "new@example.com", "email_verified": true}, wantVerified: true},
		{name: "wrong signature", foreignSignature: true, wantError: true},
		{name: "unsigned token", algorithm: "none", wantError: true},
		{name: "HMAC key from public JWKS", algorithm: "HS256", wantError: true},
		{name: "wrong issuer", mutate: func(c jwt.MapClaims) { c["iss"] = "https://attacker.example" }, wantError: true},
		{name: "wrong audience", mutate: func(c jwt.MapClaims) { c["aud"] = "other-client" }, wantError: true},
		{name: "expired", mutate: func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, wantError: true},
		{name: "missing expiry", mutate: func(c jwt.MapClaims) { delete(c, "exp") }, wantError: true},
		{name: "malformed expiry", mutate: func(c jwt.MapClaims) { c["exp"] = map[string]any{"bad": true} }, wantError: true},
		{name: "missing subject", mutate: func(c jwt.MapClaims) { delete(c, "sub") }, wantError: true},
		{name: "missing nonce", mutate: func(c jwt.MapClaims) { delete(c, "nonce") }, wantError: true},
		{name: "injected authorization code", mutate: func(c jwt.MapClaims) { c["nonce"] = "another-login" }, wantError: true},
		{name: "wrong authorized party", mutate: func(c jwt.MapClaims) { c["azp"] = "other-client" }, wantError: true},
		{name: "multiple audiences without authorized party", mutate: func(c jwt.MapClaims) { c["aud"] = []string{"client", "other"} }, wantError: true},
		{name: "multiple audiences with authorized party", mutate: func(c jwt.MapClaims) { c["aud"] = []string{"client", "other"}; c["azp"] = "client" }, wantVerified: true},
		{name: "wrong access token hash", mutate: func(c jwt.MapClaims) { c["at_hash"] = "wrong" }, wantError: true},
		{name: "userinfo subject substitution", profile: map[string]any{"sub": "other-subject"}, wantError: true},
		{name: "userinfo missing subject", profile: map[string]any{}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initial, err := p.BeginAuth("state")
			if err != nil {
				t.Fatal(err)
			}
			// The values must survive Goth's server-side session serialization.
			restored, err := p.UnmarshalSession(initial.Marshal())
			if err != nil {
				t.Fatal(err)
			}
			session := restored.(*oidcSession)
			authURL, err := url.Parse(session.AuthURL)
			if err != nil {
				t.Fatal(err)
			}
			query := authURL.Query()
			if query.Get("nonce") != session.Nonce || query.Get("nonce") == "" || query.Get("state") != "state" || query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(session.Verifier) {
				t.Fatalf("login not bound to nonce and PKCE: %s", session.AuthURL)
			}
			claims := jwt.MapClaims{"iss": issuer, "aud": "client", "sub": "subject", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": session.Nonce, "email": "user@example.com", "email_verified": true}
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			var signingKey any = key
			if tc.foreignSignature {
				signingKey = foreignKey
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "test"
			switch tc.algorithm {
			case "none":
				token = jwt.NewWithClaims(jwt.SigningMethodNone, claims)
				signingKey = jwt.UnsafeAllowNoneSignatureType
			case "HS256":
				token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				token.Header["kid"] = "hmac"
				signingKey = []byte("publicly-visible-secret")
			}
			idToken, err = token.SignedString(signingKey)
			if err != nil {
				t.Fatal(err)
			}
			profile = tc.profile
			if profile == nil {
				profile = map[string]any{"sub": "subject"}
			}
			_, err = session.Authorize(p, url.Values{"code": {"code"}, "redirect_uri": {"https://attacker.example/callback"}, "code_verifier": {"attacker-verifier"}})
			if err != nil {
				t.Fatal(err)
			}
			if exchanged.Get("redirect_uri") != p.config.RedirectURL || exchanged.Get("code_verifier") != session.Verifier {
				t.Fatalf("callback overrode exchange parameters: %v", exchanged)
			}
			user, err := p.FetchUser(session)
			if (err != nil) != tc.wantError {
				t.Fatalf("FetchUser error = %v, want error %v", err, tc.wantError)
			}
			if err == nil {
				if user.UserID != "subject" || user.Provider != "oidc_company" {
					t.Fatalf("wrong identity: %+v", user)
				}
				// The adapter decides on the email itself: it is set only when
				// verified, and the raw claims are passed through as sent
				if got := user.Email != ""; got != tc.wantVerified {
					t.Fatalf("email %q verified = %v, want %v", user.Email, got, tc.wantVerified)
				}
				if tc.wantVerified && user.Email != "user@example.com" && user.Email != "new@example.com" {
					t.Fatalf("unexpected email %q", user.Email)
				}
				if _, present := user.RawData["email_verified"]; present && tc.name == "missing email verification" {
					t.Fatal("adapter forged an email_verified claim")
				}
				// The access token's expiry (120s from the token endpoint), not
				// the ID token's (1h)
				if remaining := time.Until(user.ExpiresAt); remaining <= 0 || remaining > 10*time.Minute {
					t.Fatalf("ExpiresAt %v is not the access token expiry", user.ExpiresAt)
				}
			}
		})
	}
}

// The discovery document must be the issuer's own: a document at another
// path, or one declaring another issuer, could name a foreign jwks_uri
func TestOIDCDiscoveryIssuerMustMatchURL(t *testing.T) {
	var issuer string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys"})
	}))
	defer ts.Close()
	build := func(discoveryURL string) error {
		_, err := newOIDCProvider("client", "secret", "https://app.example/cb", discoveryURL, nil, true)
		return err
	}
	issuer = ts.URL
	if err := build(ts.URL + oidcDiscoveryPath); err != nil {
		t.Fatalf("issuer document: %v", err)
	}
	if err := build(ts.URL + "/discovery"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("document at another path accepted: %v", err)
	}
	issuer = "https://other.example"
	if err := build(ts.URL + oidcDiscoveryPath); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("document declaring another issuer accepted: %v", err)
	}
}

func TestOIDCLoginSecretsArePerSession(t *testing.T) {
	p := &oidcProvider{config: oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/auth"}}}
	first, err := p.BeginAuth("same-state")
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.BeginAuth("same-state")
	if err != nil {
		t.Fatal(err)
	}
	a, b := first.(*oidcSession), second.(*oidcSession)
	if a.Nonce == b.Nonce || a.Verifier == b.Verifier {
		t.Fatal("login secrets reused")
	}
	if _, err := (&oidcSession{}).Authorize(p, url.Values{"code": {"code"}}); err == nil {
		t.Fatal("legacy login without secrets accepted")
	}
}
