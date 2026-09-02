// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/crypto/bcrypt"
)

// End-to-end OAuth 2.1 flow against the real TLS router: DCR registration,
// authorize (builtin-auth login form), PKCE code exchange, using the access
// token at the REST surface, refresh rotation, reuse detection, revocation.

func newOAuthTestServer(t *testing.T) (*Server, *httptest.Server, *http.Client) {
	t.Helper()
	server, ts, _ := newRemoteApiTestServer(t)
	aliceHash, err := bcrypt.GenerateFromPassword([]byte("alicepw"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	server.staticConfig.BuiltinAuth["alice"] = types.BuiltinAuthEntry{
		Password: string(aliceHash), Groups: []string{"dev"}}
	server.staticConfig.Api.Rest.Auth = []string{"builtin", "admin"}
	server.staticConfig.Api.MCP.Auth = []string{"builtin", "admin"}
	server.staticConfig.Api.ExternalUrl = ts.URL
	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // capture the authorize redirect
	}
	return server, ts, client
}

func decodeJSONBody(t *testing.T, resp *http.Response, out any) {
	t.Helper()
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("parse body %s: %v", string(body), err)
	}
}

// runAuthorize posts the login form and returns the authorization code
func runAuthorize(t *testing.T, ts *httptest.Server, client *http.Client,
	clientId, redirectUri, challenge, resource, scope, username, password string) string {
	t.Helper()
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientId},
		"redirect_uri":          {redirectUri},
		"state":                 {"st123"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {resource},
		"or_username":           {username},
		"or_password":           {password},
		"or_scope":              {scope},
	}
	resp, err := client.PostForm(ts.URL+"/_openrun/oauth/authorize", form)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status %d: %s", resp.StatusCode, string(body))
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("redirect location: %v", err)
	}
	testutil.AssertEqualsString(t, "state", "st123", location.Query().Get("state"))
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("authorize redirect missing code")
	}
	return code
}

func TestOAuthFullFlow(t *testing.T) {
	_, ts, client := newOAuthTestServer(t)

	// Well-known metadata is served
	var metadata struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	resp, err := client.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("as metadata: %v", err)
	}
	decodeJSONBody(t, resp, &metadata)
	testutil.AssertEqualsString(t, "issuer", ts.URL, metadata.Issuer)

	var prm struct {
		Resource string `json:"resource"`
	}
	resp, err = client.Get(ts.URL + "/.well-known/oauth-protected-resource/rest")
	if err != nil {
		t.Fatalf("prm: %v", err)
	}
	decodeJSONBody(t, resp, &prm)
	testutil.AssertEqualsString(t, "resource", ts.URL+"/rest", prm.Resource)

	// PKCE pair
	verifier := "test-verifier-value-0123456789-0123456789"
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])

	// Login as alice via the pre-registered CLI client
	redirectUri := "http://127.0.0.1:39999/callback"
	code := runAuthorize(t, ts, client, "openrun-cli", redirectUri, challenge, prm.Resource, "*", "alice", "alicepw")

	// Wrong PKCE verifier is rejected
	resp, err = client.PostForm(metadata.TokenEndpoint, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectUri},
		"client_id": {"openrun-cli"}, "code_verifier": {"wrong-verifier"}})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	resp.Body.Close() //nolint:errcheck
	testutil.AssertEqualsInt(t, "bad verifier status", http.StatusBadRequest, resp.StatusCode)

	// The code was single-use: even the correct verifier fails now, so log in again
	code = runAuthorize(t, ts, client, "openrun-cli", redirectUri, challenge, prm.Resource, "*", "alice", "alicepw")
	resp, err = client.PostForm(metadata.TokenEndpoint, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectUri},
		"client_id": {"openrun-cli"}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var tokenResp system.OAuthTokenResponse
	decodeJSONBody(t, resp, &tokenResp)
	if !strings.HasPrefix(tokenResp.AccessToken, "orun_at_") || !strings.HasPrefix(tokenResp.RefreshToken, "orun_rt_") {
		t.Fatalf("token prefixes: %q %q", tokenResp.AccessToken, tokenResp.RefreshToken)
	}
	testutil.AssertEqualsString(t, "principal", "builtin:alice", tokenResp.Principal)

	// The access token works at the REST surface as alice
	var listResponse types.AppListResponse
	if err := remoteClient(ts, tokenResp.AccessToken).Get("/_openrun/apps",
		url.Values{"appPathGlob": {"/apps/**"}}, &listResponse); err != nil {
		t.Fatalf("access token list apps: %v", err)
	}
	testutil.AssertEqualsInt(t, "apps via access token", 1, len(listResponse.Apps))

	// The refresh token is NOT valid at the REST surface
	err = remoteClient(ts, tokenResp.RefreshToken).Get("/_openrun/apps", nil, &listResponse)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("refresh token must be rejected at the rest surface, got %v", err)
	}

	// Refresh rotation: new pair, old refresh token consumed
	resp, err = client.PostForm(metadata.TokenEndpoint, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokenResp.RefreshToken}, "client_id": {"openrun-cli"}})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var rotated system.OAuthTokenResponse
	decodeJSONBody(t, resp, &rotated)
	if rotated.RefreshToken == tokenResp.RefreshToken || rotated.AccessToken == tokenResp.AccessToken {
		t.Fatal("rotation must mint new tokens")
	}
	if err := remoteClient(ts, rotated.AccessToken).Get("/_openrun/apps",
		url.Values{"appPathGlob": {"/apps/**"}}, &listResponse); err != nil {
		t.Fatalf("rotated access token: %v", err)
	}

	// Reuse of the consumed refresh token revokes the whole grant
	resp, err = client.PostForm(metadata.TokenEndpoint, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokenResp.RefreshToken}, "client_id": {"openrun-cli"}})
	if err != nil {
		t.Fatalf("reuse: %v", err)
	}
	var reuseErr struct {
		Error string `json:"error"`
	}
	decodeJSONBody(t, resp, &reuseErr)
	testutil.AssertEqualsString(t, "reuse error", "invalid_grant", reuseErr.Error)
	// Every token of the grant is now revoked, including the rotated access token
	err = remoteClient(ts, rotated.AccessToken).Get("/_openrun/apps", nil, &listResponse)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("grant-family tokens must be revoked after reuse detection, got %v", err)
	}
}

func TestOAuthDCRAndScopedGrant(t *testing.T) {
	_, ts, client := newOAuthTestServer(t)

	// Register a client (DCR), then run a read-only scoped grant through it
	body := strings.NewReader(`{"client_name": "Test MCP Client", "redirect_uris": ["https://client.example.com/cb"]}`)
	resp, err := client.Post(ts.URL+"/_openrun/oauth/register", "application/json", body)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var registered struct {
		ClientId string `json:"client_id"`
	}
	decodeJSONBody(t, resp, &registered)
	if registered.ClientId == "" {
		t.Fatal("registration returned no client_id")
	}

	// Invalid redirect uris are rejected
	resp, err = client.Post(ts.URL+"/_openrun/oauth/register", "application/json",
		strings.NewReader(`{"redirect_uris": ["http://evil.example.com/cb"]}`))
	if err != nil {
		t.Fatalf("register bad: %v", err)
	}
	resp.Body.Close() //nolint:errcheck
	testutil.AssertEqualsInt(t, "bad redirect status", http.StatusBadRequest, resp.StatusCode)

	verifier := "another-test-verifier-0123456789-0123456789"
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])

	// MCP resource with a read-only scope
	code := runAuthorize(t, ts, client, registered.ClientId, "https://client.example.com/cb",
		challenge, ts.URL+"/_openrun/mcp", "*:read", "alice", "alicepw")
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://client.example.com/cb"},
		"client_id":    {registered.ClientId}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var tokenResp system.OAuthTokenResponse
	decodeJSONBody(t, resp, &tokenResp)
	testutil.AssertEqualsString(t, "scope", "*:read", tokenResp.Scope)

	// The mcp-bound token is rejected at the REST surface (resource binding)
	var listResponse types.AppListResponse
	err = remoteClient(ts, tokenResp.AccessToken).Get("/_openrun/apps", nil, &listResponse)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("mcp-bound access token must be rejected at rest, got %v", err)
	}

	// Refresh cannot expand the scopes
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokenResp.RefreshToken},
		"client_id": {registered.ClientId}, "scope": {"*"}})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var scopeErr struct {
		Error string `json:"error"`
	}
	decodeJSONBody(t, resp, &scopeErr)
	testutil.AssertEqualsString(t, "expand error", "invalid_scope", scopeErr.Error)
}

func TestOAuthRevoke(t *testing.T) {
	_, ts, client := newOAuthTestServer(t)

	verifier := "revoke-test-verifier-0123456789-0123456789"
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	code := runAuthorize(t, ts, client, "openrun-cli", "http://127.0.0.1:39999/callback",
		challenge, ts.URL+"/rest", "*", "alice", "alicepw")
	resp, err := client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"http://127.0.0.1:39999/callback"},
		"client_id":    {"openrun-cli"}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var tokenResp system.OAuthTokenResponse
	decodeJSONBody(t, resp, &tokenResp)

	// Revoking the refresh token (logout) kills the whole grant
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/revoke", url.Values{"token": {tokenResp.RefreshToken}})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close() //nolint:errcheck
	testutil.AssertEqualsInt(t, "revoke status", http.StatusOK, resp.StatusCode)

	var listResponse types.AppListResponse
	err = remoteClient(ts, tokenResp.AccessToken).Get("/_openrun/apps", nil, &listResponse)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("revoked grant's access token must be rejected, got %v", err)
	}

	// Wrong login on the authorize form re-renders with an error, no redirect
	badResp, err := client.PostForm(ts.URL+"/_openrun/oauth/authorize", url.Values{
		"response_type": {"code"}, "client_id": {"openrun-cli"},
		"redirect_uri":   {"http://127.0.0.1:39999/callback"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"resource": {ts.URL + "/rest"}, "or_username": {"alice"}, "or_password": {"wrongpw"}})
	if err != nil {
		t.Fatalf("bad login: %v", err)
	}
	defer badResp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(badResp.Body)
	if badResp.StatusCode != http.StatusOK || !strings.Contains(string(body), "invalid username or password") {
		t.Fatalf("bad login must re-render the form with an error, status %d body %s", badResp.StatusCode, string(body))
	}
}

func TestOAuthConcurrentRefreshConsumption(t *testing.T) {
	server, ts, client := newOAuthTestServer(t)

	verifier := "concurrent-test-verifier-0123456789-0123456789"
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	code := runAuthorize(t, ts, client, "openrun-cli", "http://127.0.0.1:39999/callback",
		challenge, ts.URL+"/rest", "*", "alice", "alicepw")
	resp, err := client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"http://127.0.0.1:39999/callback"},
		"client_id":    {"openrun-cli"}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var tokenResp system.OAuthTokenResponse
	decodeJSONBody(t, resp, &tokenResp)

	// Simulate the losing side of a concurrent rotation at the store layer:
	// mark the refresh token consumed the way a winning rotation would, then
	// present it - the server must treat it as reuse and revoke the grant
	_, rtId, _, err := parseApiToken(tokenResp.RefreshToken)
	if err != nil {
		t.Fatalf("parse rt: %v", err)
	}
	cred, _, err := server.db.GetCredentialWithIdentity(t.Context(), rtId)
	if err != nil {
		t.Fatalf("get rt: %v", err)
	}
	winner := *cred
	winner.Id = "concurrentwinner1"
	winnerAccess := winner
	winnerAccess.Id = "concurrentwinner2"
	if err := server.db.RotateRefreshToken(t.Context(), rtId, &winner, &winnerAccess); err != nil {
		t.Fatalf("first rotation: %v", err)
	}

	// The direct store call for the loser reports the sentinel
	loser := winner
	loser.Id = "concurrentloser1"
	loserAccess := winner
	loserAccess.Id = "concurrentloser2"
	err = server.db.RotateRefreshToken(t.Context(), rtId, &loser, &loserAccess)
	if !errors.Is(err, metadata.ErrRefreshConsumed) {
		t.Fatalf("second rotation must report ErrRefreshConsumed, got %v", err)
	}

	// And the HTTP path revokes the grant on the consumed token
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokenResp.RefreshToken}, "client_id": {"openrun-cli"}})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var reuseErr struct {
		Error string `json:"error"`
	}
	decodeJSONBody(t, resp, &reuseErr)
	testutil.AssertEqualsString(t, "reuse error", "invalid_grant", reuseErr.Error)
	var listResponse types.AppListResponse
	err = remoteClient(ts, tokenResp.AccessToken).Get("/_openrun/apps", nil, &listResponse)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("grant must be revoked after concurrent consumption reuse, got %v", err)
	}
}

func TestApiKeyDeleteIsTypeAware(t *testing.T) {
	server, ts, client := newOAuthTestServer(t)

	verifier := "delete-type-verifier-0123456789-0123456789"
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	code := runAuthorize(t, ts, client, "openrun-cli", "http://127.0.0.1:39999/callback",
		challenge, ts.URL+"/rest", "*", "alice", "alicepw")
	resp, err := client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"http://127.0.0.1:39999/callback"},
		"client_id":    {"openrun-cli"}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var tokenResp system.OAuthTokenResponse
	decodeJSONBody(t, resp, &tokenResp)

	// Deleting the refresh token via the apikey API revokes the whole
	// grant instead of hard-deleting the row: the access token dies too,
	// and the rows survive as revocation evidence
	_, rtId, _, err := parseApiToken(tokenResp.RefreshToken)
	if err != nil {
		t.Fatalf("parse rt: %v", err)
	}
	trustedCtx := system.WithTrustedOperation(context.Background())
	if _, err := server.DeleteApiKey(trustedCtx, rtId); err != nil {
		t.Fatalf("delete refresh credential: %v", err)
	}
	var listResponse types.AppListResponse
	err = remoteClient(ts, tokenResp.AccessToken).Get("/_openrun/apps", nil, &listResponse)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("access token must be revoked when its refresh token is deleted, got %v", err)
	}
	rtCred, _, err := server.db.GetCredentialWithIdentity(trustedCtx, rtId)
	if err != nil {
		t.Fatalf("refresh row must survive as revocation evidence: %v", err)
	}
	if rtCred.RevokedAt == nil {
		t.Fatal("refresh row must be revoked, not deleted")
	}
}
