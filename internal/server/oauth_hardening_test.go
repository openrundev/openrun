// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// mintOAuthGrant runs the authorize + code exchange flow for alice via the
// pre-registered CLI client and returns the token response
func mintOAuthGrant(t *testing.T, ts *httptest.Server, client *http.Client, scope string) system.OAuthTokenResponse {
	t.Helper()
	verifier := "hardening-verifier-0123456789-0123456789"
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	redirectUri := "http://127.0.0.1:39999/callback"
	code := runAuthorize(t, ts, client, "openrun-cli", redirectUri, challenge, ts.URL+"/rest", scope, "alice", "alicepw")
	resp, err := client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectUri},
		"client_id": {"openrun-cli"}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var tokenResp system.OAuthTokenResponse
	decodeJSONBody(t, resp, &tokenResp)
	return tokenResp
}

func TestOAuthGrantMaxLifetime(t *testing.T) {
	server, ts, client := newOAuthTestServer(t)

	// Minted token lifetimes are clamped to the grant deadline: with a 30m
	// grant bound, the 1h access token default cannot exceed it
	server.staticConfig.Api.GrantMaxTTL = "30m"
	tokenResp := mintOAuthGrant(t, ts, client, "*")
	if tokenResp.ExpiresIn > 1800 || tokenResp.ExpiresIn <= 0 {
		t.Fatalf("access expiry must be clamped to the 30m grant bound, got %d", tokenResp.ExpiresIn)
	}

	// Past the grant deadline, refresh is closed out: the grant is revoked
	// and the user has to log in again (deadline is re-derived from the
	// grant start, so lowering the bound applies to outstanding grants)
	server.staticConfig.Api.GrantMaxTTL = "1ms"
	time.Sleep(5 * time.Millisecond)
	resp, err := client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokenResp.RefreshToken}, "client_id": {"openrun-cli"}})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var refreshErr struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	decodeJSONBody(t, resp, &refreshErr)
	testutil.AssertEqualsString(t, "refresh error", "invalid_grant", refreshErr.Error)
	if !strings.Contains(refreshErr.Description, "maximum lifetime") {
		t.Fatalf("expected grant lifetime error, got %q", refreshErr.Description)
	}

	// The whole grant was revoked, the access token is dead too
	var listResponse types.AppListResponse
	err = remoteClient(ts, tokenResp.AccessToken).Get("/_openrun/apps", nil, &listResponse)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("access token must be revoked with the expired grant, got %v", err)
	}
}

func TestApiKeyMCPScopeDefault(t *testing.T) {
	server, _, _ := newRemoteApiTestServer(t)
	trustedCtx := system.WithTrustedOperation(context.Background())

	// An mcp-only key with no explicit scopes defaults to the read-only
	// ceiling, matching the OAuth consent default for the MCP surface
	mcpKey, err := server.CreateApiKey(trustedCtx, &types.ApiKeyCreateRequest{
		User: "builtin:alice", Resources: []string{"mcp"}})
	if err != nil {
		t.Fatalf("mcp key: %v", err)
	}
	testutil.AssertEqualsInt(t, "mcp default scopes", 1, len(mcpKey.Scopes))
	testutil.AssertEqualsString(t, "mcp default scope", "*:read", mcpKey.Scopes[0])

	// Explicit scopes are applied unchanged, and rest keys stay unscoped
	writeKey, err := server.CreateApiKey(trustedCtx, &types.ApiKeyCreateRequest{
		User: "builtin:alice", Resources: []string{"mcp"}, Scopes: []string{"*"}})
	if err != nil {
		t.Fatalf("write mcp key: %v", err)
	}
	testutil.AssertEqualsString(t, "explicit scope", "*", writeKey.Scopes[0])
	restKey, err := server.CreateApiKey(trustedCtx, &types.ApiKeyCreateRequest{
		User: "builtin:alice"})
	if err != nil {
		t.Fatalf("rest key: %v", err)
	}
	testutil.AssertEqualsInt(t, "rest key unscoped", 0, len(restKey.Scopes))
}

func TestPruneCredentials(t *testing.T) {
	server, _, _ := newRemoteApiTestServer(t)
	trustedCtx := system.WithTrustedOperation(context.Background())

	longDead := time.Now().Add(-40 * 24 * time.Hour).UTC()
	recentlyExpired := time.Now().Add(-time.Hour).UTC()
	identity, err := server.resolveApiIdentity(trustedCtx, "builtin:alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	makeCred := func(id string, expiry *time.Time) {
		t.Helper()
		if err := server.db.CreateCredential(trustedCtx, &types.Credential{
			Id: id, SecretHash: "h", Type: types.CredentialTypePAT, IdentityId: identity.Id,
			Resources: []string{"rest"}, ExpiresAt: expiry, CreatedBy: "test"}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	makeCred("prune_old", &longDead)           // past the retention window: pruned
	makeCred("prune_recent", &recentlyExpired) // expired, still in retention: kept
	makeCred("prune_never", nil)               // non-expiring: never pruned

	deleted, err := server.db.PruneCredentials(trustedCtx, time.Now().Add(-30*24*time.Hour).UTC())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	testutil.AssertEqualsInt(t, "pruned rows", 1, int(deleted))
	if _, _, err := server.db.GetCredentialWithIdentity(trustedCtx, "prune_old"); err == nil {
		t.Fatal("long-expired credential must be pruned")
	}
	if _, _, err := server.db.GetCredentialWithIdentity(trustedCtx, "prune_recent"); err != nil {
		t.Fatalf("recently expired credential must survive the retention window: %v", err)
	}
	if _, _, err := server.db.GetCredentialWithIdentity(trustedCtx, "prune_never"); err != nil {
		t.Fatalf("non-expiring credential must never be pruned: %v", err)
	}
}

func TestOAuthConsentPageHardening(t *testing.T) {
	_, ts, client := newOAuthTestServer(t)

	// Register a DCR client to render the unverified-client warning
	resp, err := client.Post(ts.URL+"/_openrun/oauth/register", "application/json",
		strings.NewReader(`{"client_name":"Some Tool","redirect_uris":["https://tool.example.com/cb"]}`))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var registered struct {
		ClientId string `json:"client_id"`
	}
	decodeJSONBody(t, resp, &registered)

	verifier := "consent-verifier-0123456789-0123456789"
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	form := url.Values{
		"response_type": {"code"}, "client_id": {registered.ClientId},
		"redirect_uri": {"https://tool.example.com/cb"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "resource": {ts.URL + "/rest"}}
	resp, err = client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("authorize form: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	page := string(body)

	// The consent page names the redirect target and flags DCR clients
	if !strings.Contains(page, "https://tool.example.com/cb") {
		t.Fatal("consent page must show the redirect target")
	}
	if !strings.Contains(page, "registered itself dynamically") {
		t.Fatal("consent page must flag dynamically registered clients")
	}

	// Credential-collecting page: hardened headers, never cached
	testutil.AssertEqualsString(t, "cache-control", "no-store", resp.Header.Get("Cache-Control"))
	testutil.AssertEqualsString(t, "frame-options", "DENY", resp.Header.Get("X-Frame-Options"))
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("consent page must set a CSP")
	}

	// The pre-registered CLI client gets no unverified warning
	form.Set("client_id", "openrun-cli")
	form.Set("redirect_uri", "http://127.0.0.1:39999/callback")
	resp, err = client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("cli authorize form: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if strings.Contains(string(body), "registered itself dynamically") {
		t.Fatal("the pre-registered CLI client must not be flagged as unverified")
	}
}
