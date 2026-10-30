// Copyright (c) OpenRun Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// oidcProvider implements Goth's adapter using a verifier that checks the ID
// token signature as well as its issuer, audience and expiry. Login-specific
// nonce and PKCE secrets live in the server-side Goth session, never on the
// shared provider or in caller-controlled callback parameters.
type oidcProvider struct {
	name     string
	config   oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	ctx      context.Context // carries the http client for go-oidc and oauth2 calls
}

// oidcDiscoveryPath is where OIDC Discovery 4.1 places the provider
// configuration document, relative to the issuer
const oidcDiscoveryPath = "/.well-known/openid-configuration"

type oidcSession struct {
	AuthURL  string
	Nonce    string
	Verifier string
	Token    *oauth2.Token
	IDToken  string
}

var _ goth.Provider = (*oidcProvider)(nil)
var _ goth.Session = (*oidcSession)(nil)

// oidcFetchTimeout bounds each request to the provider: discovery, JWKS,
// token exchange and userinfo
const oidcFetchTimeout = 30 * time.Second

// newOIDCProvider builds the provider from its discovery document. The
// client used for the discovery fetch is kept for every later call to the
// provider (JWKS, token, userinfo): with allowPrivate false it refuses
// private or local targets, since discovery_url is config:update settable
// and the document names the other endpoints
func newOIDCProvider(key, secret, callbackURL, discoveryURL string, scopes []string, allowPrivate bool) (*oidcProvider, error) {
	client := ssoHTTPClient("OIDC provider", allowPrivate, oidcFetchTimeout)
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned HTTP %d", resp.StatusCode)
	}
	const maxDiscovery = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscovery+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDiscovery {
		return nil, fmt.Errorf("OIDC discovery document too large")
	}
	var metadata oidc.ProviderConfig
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return nil, err
	}
	for _, endpoint := range []string{metadata.IssuerURL, metadata.AuthURL, metadata.TokenURL, metadata.JWKSURL} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, fmt.Errorf("invalid or missing OIDC metadata endpoint")
		}
	}
	// OIDC Discovery 4.3: the document lives at <issuer>/.well-known/
	// openid-configuration and its issuer must be the one the url names
	// (the check oidc.NewProvider makes for a bare issuer). Otherwise a
	// proxied, mirrored or stale document could declare another issuer and
	// jwks_uri, and tokens of that issuer would pass as the configured
	// provider
	if expected := strings.TrimSuffix(metadata.IssuerURL, "/") + oidcDiscoveryPath; strings.TrimSuffix(discoveryURL, "/") != expected {
		return nil, fmt.Errorf("OIDC discovery document issuer %q does not match discovery_url %s (expected %s)",
			metadata.IssuerURL, discoveryURL, expected)
	}
	// Match go-oidc's discovery policy: a public JWKS must only supply
	// asymmetric verification keys, never a shared HMAC secret or "none".
	metadata.Algorithms = slices.DeleteFunc(metadata.Algorithms, func(algorithm string) bool {
		switch algorithm {
		case oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512,
			oidc.PS256, oidc.PS384, oidc.PS512, oidc.EdDSA:
			return false
		default:
			return true
		}
	})
	ctx := oidc.ClientContext(context.Background(), client)
	provider := metadata.NewProvider(ctx)
	scopes = slices.Clone(scopes)
	if !slices.Contains(scopes, oidc.ScopeOpenID) {
		scopes = append(scopes, oidc.ScopeOpenID)
	}
	return &oidcProvider{
		name: "oidc", ctx: ctx, provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: key}),
		config:   oauth2.Config{ClientID: key, ClientSecret: secret, RedirectURL: callbackURL, Endpoint: provider.Endpoint(), Scopes: scopes},
	}, nil
}

func (p *oidcProvider) Name() string                { return p.name }
func (p *oidcProvider) SetName(name string)         { p.name = name }
func (p *oidcProvider) Debug(bool)                  {}
func (p *oidcProvider) RefreshTokenAvailable() bool { return true }
func (p *oidcProvider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return p.config.TokenSource(p.ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
}

func (p *oidcProvider) BeginAuth(state string) (goth.Session, error) {
	nonce, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()
	return &oidcSession{
		AuthURL: p.config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)),
		Nonce:   nonce, Verifier: verifier,
	}, nil
}

func (p *oidcProvider) UnmarshalSession(data string) (goth.Session, error) {
	var session oidcSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (s *oidcSession) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", fmt.Errorf("missing OIDC authorization URL")
	}
	return s.AuthURL, nil
}
func (s *oidcSession) Marshal() string {
	data, _ := json.Marshal(s)
	return string(data)
}
func (s *oidcSession) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p, ok := provider.(*oidcProvider)
	if !ok || s.Nonce == "" || s.Verifier == "" || params.Get("code") == "" {
		return "", fmt.Errorf("invalid OIDC login session")
	}
	// Only the code comes from the callback. In particular, redirect_uri and
	// code_verifier must never override the values bound to this login.
	token, err := p.config.Exchange(p.ctx, params.Get("code"), oauth2.VerifierOption(s.Verifier))
	if err != nil {
		return "", err
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" || !token.Valid() {
		return "", fmt.Errorf("invalid OIDC token response")
	}
	s.Token, s.IDToken = token, idToken
	return token.AccessToken, nil
}

func (p *oidcProvider) FetchUser(session goth.Session) (goth.User, error) {
	s, ok := session.(*oidcSession)
	if !ok || s.Token == nil || s.IDToken == "" || s.Nonce == "" {
		return goth.User{}, fmt.Errorf("missing OIDC token or login nonce")
	}
	token, err := p.verifier.Verify(p.ctx, s.IDToken)
	if err != nil {
		return goth.User{}, err
	}
	if token.Subject == "" || subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(s.Nonce)) != 1 {
		return goth.User{}, fmt.Errorf("OIDC subject missing or nonce mismatch")
	}
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return goth.User{}, err
	}
	// The authorized party, when supplied, must name this client. Multiple
	// audiences require it so another client's ID token cannot be substituted.
	azp, present := claims["azp"]
	if (present && azp != p.config.ClientID) || (len(token.Audience) > 1 && !present) {
		return goth.User{}, fmt.Errorf("OIDC authorized party mismatch")
	}
	if token.AccessTokenHash != "" {
		if err := token.VerifyAccessToken(s.Token.AccessToken); err != nil {
			return goth.User{}, err
		}
	}
	if p.provider.UserInfoEndpoint() != "" {
		info, err := p.provider.UserInfo(p.ctx, oauth2.StaticTokenSource(s.Token))
		if err != nil {
			return goth.User{}, err
		}
		if info.Subject != token.Subject {
			return goth.User{}, fmt.Errorf("OIDC userinfo subject mismatch")
		}
		var profile map[string]any
		if err := info.Claims(&profile); err != nil {
			return goth.User{}, err
		}
		// Verification applies to the email from the same response. Do not carry
		// a true ID-token flag onto a different, unverified UserInfo email.
		if email, present := profile["email"]; present {
			profileEmail, valid := email.(string)
			tokenEmail, _ := claims["email"].(string)
			if !valid || profileEmail != tokenEmail {
				delete(claims, "email_verified")
			}
		}
		for key, value := range profile {
			claims[key] = value
		}
	}
	stringClaim := func(keys ...string) string {
		for _, key := range keys {
			if value, ok := claims[key].(string); ok && value != "" {
				return value
			}
		}
		return ""
	}
	// The email identifies the user only when the IdP vouches for it
	// (oidcEmailVerified): a missing claim is not evidence that the address
	// belongs to the subject, so the user then carries no email and the
	// login falls back to the subject. The raw claims pass through as the
	// IdP sent them; the decision is made here, not by rewriting them
	email := stringClaim("email")
	if !oidcEmailVerified(claims) {
		email = ""
	}
	return goth.User{
		Provider: p.Name(), UserID: token.Subject, Email: email,
		Name: stringClaim("name"), NickName: stringClaim("nickname", "preferred_username"),
		FirstName: stringClaim("given_name"), LastName: stringClaim("family_name"), AvatarURL: stringClaim("picture"),
		RawData: claims, IDToken: s.IDToken, AccessToken: s.Token.AccessToken, RefreshToken: s.Token.RefreshToken,
		// The access token's expiry, like the other goth providers; the ID
		// token has its own, often shorter, lifetime
		ExpiresAt: s.Token.Expiry,
	}, nil
}

// oidcEmailVerified reports whether the claims mark the email as verified:
// email_verified true, as a boolean or as the string "true" that some
// providers send (go-oidc's UserInfo parsing accepts the same). An absent
// or malformed claim is unverified
func oidcEmailVerified(claims map[string]any) bool {
	switch v := claims["email_verified"].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}
