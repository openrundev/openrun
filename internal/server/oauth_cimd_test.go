// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
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

// newCIMDDocServer serves a client metadata document at /client.json whose
// client_id is its own URL (unless override rewrites the document). The AS
// under test is pointed at it by trusting its certificate and allowing
// private hosts, since httptest listens on loopback
func newCIMDDocServer(t *testing.T, server *Server, redirects []string, override func(doc map[string]any, self string), headers map[string]string) (*httptest.Server, string) {
	t.Helper()
	var self string
	docServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/client.json" {
			http.NotFound(w, r)
			return
		}
		doc := map[string]any{
			"client_id":     self,
			"client_name":   "Doc Client",
			"redirect_uris": redirects,
		}
		if override != nil {
			override(doc, self)
		}
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"client_id":%q,"client_name":%q,"redirect_uris":[%s]%s}`,
			doc["client_id"], doc["client_name"], quoteList(doc["redirect_uris"].([]string)), extraJSON(doc))
	}))
	t.Cleanup(docServer.Close)
	self = docServer.URL + "/client.json"
	server.cimdTLSConfig = docServer.Client().Transport.(*http.Transport).TLSClientConfig
	server.staticConfig.Api.CIMDAllowPrivateHosts = true
	return docServer, self
}

func quoteList(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = fmt.Sprintf("%q", item)
	}
	return strings.Join(quoted, ",")
}

func extraJSON(doc map[string]any) string {
	var extra strings.Builder
	for k, v := range doc {
		if k == "client_id" || k == "client_name" || k == "redirect_uris" {
			continue
		}
		fmt.Fprintf(&extra, ",%q:%q", k, v)
	}
	return extra.String()
}

func TestOAuthCIMDFullFlow(t *testing.T) {
	server, ts, client := newOAuthTestServer(t)
	_, clientId := newCIMDDocServer(t, server, []string{"https://tool.example.com/cb"}, nil, nil)

	// The AS advertises CIMD alongside the (deprecated) registration endpoint
	resp, err := client.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	var meta map[string]any
	decodeJSONBody(t, resp, &meta)
	if meta["client_id_metadata_document_supported"] != true {
		t.Fatalf("AS metadata must advertise CIMD, got %v", meta)
	}
	if meta["registration_endpoint"] == nil {
		t.Fatal("DCR must remain advertised as the fallback")
	}

	// Consent page: name from the document, CIMD note, no DCR warning
	verifier := "cimd-verifier-0123456789-0123456789-0123456789"
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	form := url.Values{
		"response_type": {"code"}, "client_id": {clientId},
		"redirect_uri": {"https://tool.example.com/cb"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "resource": {ts.URL + "/rest"}}
	resp, err = client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("authorize form: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck
	page := string(body)
	testutil.AssertEqualsInt(t, "consent status", http.StatusOK, resp.StatusCode)
	if !strings.Contains(page, "Doc Client") || !strings.Contains(page, "identifies itself by the document") {
		t.Fatalf("consent page must show the document client name and note, got %s", page)
	}
	if strings.Contains(page, "registered itself dynamically") || strings.Contains(page, "localhost") {
		t.Fatal("consent page must not show the DCR or loopback warnings for an https-redirect CIMD client")
	}

	// Full code exchange with the URL client id, then use and refresh
	code := runAuthorize(t, ts, client, clientId, "https://tool.example.com/cb",
		challenge, ts.URL+"/rest", "app:read", "alice", "alicepw")
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://tool.example.com/cb"},
		"client_id":    {clientId}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var tokenResp system.OAuthTokenResponse
	decodeJSONBody(t, resp, &tokenResp)
	if tokenResp.AccessToken == "" || tokenResp.RefreshToken == "" {
		t.Fatalf("token exchange failed: %+v", tokenResp)
	}
	var listResponse types.AppListResponse
	if err := remoteClient(ts, tokenResp.AccessToken).Get("/_openrun/apps", nil, &listResponse); err != nil {
		t.Fatalf("access token must work at the REST surface: %v", err)
	}
	resp, err = client.PostForm(ts.URL+"/_openrun/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokenResp.RefreshToken}, "client_id": {clientId}})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var refreshed system.OAuthTokenResponse
	decodeJSONBody(t, resp, &refreshed)
	if refreshed.AccessToken == "" {
		t.Fatalf("refresh with the CIMD client id must succeed: %+v", refreshed)
	}

	// The document is cached: the first sight is audited once
	if _, ok := server.cimdCache[clientId]; !ok {
		t.Fatal("document must be cached after a successful fetch")
	}
}

func TestOAuthCIMDLoopbackWarningAndTokenExchangeWithoutRegistration(t *testing.T) {
	server, ts, client := newOAuthTestServer(t)
	_, clientId := newCIMDDocServer(t, server, []string{"http://127.0.0.1:39999/callback", "http://localhost:39999/callback"}, nil, nil)

	form := url.Values{
		"response_type": {"code"}, "client_id": {clientId},
		"redirect_uri": {"http://localhost:39999/callback"}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "resource": {ts.URL + "/rest"}}
	resp, err := client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("authorize form: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck
	if !strings.Contains(string(body), "only redirects to your own computer") {
		t.Fatal("consent page must warn for loopback-only CIMD clients")
	}
	// No row was created for the CIMD client
	count, err := server.db.CountOAuthClients(t.Context())
	if err != nil {
		t.Fatalf("count clients: %v", err)
	}
	testutil.AssertEqualsInt(t, "cimd clients are not stored", 0, count)
}

func TestOAuthCIMDRejections(t *testing.T) {
	authorizeError := func(t *testing.T, ts *httptest.Server, client *http.Client, clientId, redirect string) string {
		t.Helper()
		form := url.Values{
			"response_type": {"code"}, "client_id": {clientId},
			"redirect_uri": {redirect}, "code_challenge": {strings.Repeat("a", 43)},
			"code_challenge_method": {"S256"}, "resource": {ts.URL + "/rest"}}
		resp, err := client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		defer resp.Body.Close() //nolint:errcheck
		body, _ := io.ReadAll(resp.Body)
		testutil.AssertEqualsInt(t, "status", http.StatusBadRequest, resp.StatusCode)
		return string(body)
	}

	t.Run("client_id mismatch in document", func(t *testing.T) {
		server, ts, client := newOAuthTestServer(t)
		_, clientId := newCIMDDocServer(t, server, []string{"https://tool.example.com/cb"},
			func(doc map[string]any, self string) { doc["client_id"] = self + "?other" }, nil)
		body := authorizeError(t, ts, client, clientId, "https://tool.example.com/cb")
		if !strings.Contains(body, "does not match the document url") {
			t.Fatalf("expected client_id mismatch error, got %s", body)
		}
	})

	t.Run("redirect not in document", func(t *testing.T) {
		server, ts, client := newOAuthTestServer(t)
		_, clientId := newCIMDDocServer(t, server, []string{"https://tool.example.com/cb"}, nil, nil)
		body := authorizeError(t, ts, client, clientId, "https://evil.example.com/cb")
		if !strings.Contains(body, "not registered for this client") {
			t.Fatalf("expected redirect rejection, got %s", body)
		}
	})

	t.Run("confidential client auth method unsupported", func(t *testing.T) {
		server, ts, client := newOAuthTestServer(t)
		_, clientId := newCIMDDocServer(t, server, []string{"https://tool.example.com/cb"},
			func(doc map[string]any, _ string) { doc["token_endpoint_auth_method"] = "private_key_jwt" }, nil)
		body := authorizeError(t, ts, client, clientId, "https://tool.example.com/cb")
		if !strings.Contains(body, "public clients only") {
			t.Fatalf("expected auth method rejection, got %s", body)
		}
	})

	t.Run("private host refused without allow flag", func(t *testing.T) {
		server, ts, client := newOAuthTestServer(t)
		_, clientId := newCIMDDocServer(t, server, []string{"https://tool.example.com/cb"}, nil, nil)
		server.staticConfig.Api.CIMDAllowPrivateHosts = false // the SSRF guard applies
		body := authorizeError(t, ts, client, clientId, "https://tool.example.com/cb")
		if !strings.Contains(body, "private or local address") {
			t.Fatalf("expected SSRF rejection, got %s", body)
		}
	})

	t.Run("denied domain", func(t *testing.T) {
		server, ts, client := newOAuthTestServer(t)
		_, clientId := newCIMDDocServer(t, server, []string{"https://tool.example.com/cb"}, nil, nil)
		server.staticConfig.Api.CIMDDeniedDomains = []string{"127.0.0.1"}
		body := authorizeError(t, ts, client, clientId, "https://tool.example.com/cb")
		if !strings.Contains(body, "denied by api.cimd_denied_domains") {
			t.Fatalf("expected deny-list rejection, got %s", body)
		}
	})

	t.Run("allow list excludes domain", func(t *testing.T) {
		server, ts, client := newOAuthTestServer(t)
		_, clientId := newCIMDDocServer(t, server, []string{"https://tool.example.com/cb"}, nil, nil)
		server.staticConfig.Api.CIMDAllowedDomains = []string{"clients.example.com"}
		body := authorizeError(t, ts, client, clientId, "https://tool.example.com/cb")
		if !strings.Contains(body, "not in api.cimd_allowed_domains") {
			t.Fatalf("expected allow-list rejection, got %s", body)
		}
	})

	t.Run("no-store document is not cached", func(t *testing.T) {
		server, ts, client := newOAuthTestServer(t)
		_, clientId := newCIMDDocServer(t, server, []string{"https://tool.example.com/cb"}, nil,
			map[string]string{"Cache-Control": "no-store"})
		form := url.Values{
			"response_type": {"code"}, "client_id": {clientId},
			"redirect_uri": {"https://tool.example.com/cb"}, "code_challenge": {strings.Repeat("a", 43)},
			"code_challenge_method": {"S256"}, "resource": {ts.URL + "/rest"}}
		resp, err := client.Get(ts.URL + "/_openrun/oauth/authorize?" + form.Encode())
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		resp.Body.Close() //nolint:errcheck
		testutil.AssertEqualsInt(t, "status", http.StatusOK, resp.StatusCode)
		if _, cached := server.cimdCache[clientId]; cached {
			t.Fatal("no-store documents must not be cached")
		}
	})
}

func TestCIMDHelpers(t *testing.T) {
	for id, want := range map[string]bool{
		"https://app.example.com/oauth/client.json": true,
		"https://app.example.com/":                  false, // no path component
		"https://app.example.com":                   false,
		"http://app.example.com/client.json":        false, // https only
		"https://user:pw@app.example.com/c.json":    false, // no credentials
		"https://app.example.com/c.json#frag":       false, // no fragment
		"orc_0123456789abcdef":                      false, // DCR id
		"openrun-cli":                               false,
	} {
		testutil.AssertEqualsBool(t, id, want, isCIMDClientId(id))
	}

	for ip, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "172.16.5.5": true, "192.168.1.1": true,
		"169.254.169.254": true, "100.64.0.1": true, "0.0.0.0": true, "::1": true, "fe80::1": true,
		"fd00::1": true, "93.184.216.34": false, "2606:2800:220:1:248:1893:25c8:1946": false,
	} {
		testutil.AssertEqualsBool(t, ip, want, isPrivateOrLocalIP(net.ParseIP(ip)))
	}

	ttl := func(cc string) time.Duration { return cimdCacheTTL(http.Header{"Cache-Control": {cc}}) }
	testutil.AssertEqualsInt(t, "default", int(cimdDefaultCacheTTL), int(ttl("")))
	testutil.AssertEqualsInt(t, "max-age", int(90*time.Second), int(ttl("public, max-age=90")))
	testutil.AssertEqualsInt(t, "capped", int(cimdMaxCacheTTL), int(ttl("max-age=999999999")))
	testutil.AssertEqualsInt(t, "no-store", 0, int(ttl("no-store")))
	testutil.AssertEqualsInt(t, "no-cache", 0, int(ttl("max-age=60, no-cache")))
	multi := http.Header{"Cache-Control": {"max-age=3600", "no-store"}}
	testutil.AssertEqualsInt(t, "no-store in a later field", 0, int(cimdCacheTTL(multi)))

	// Fetches never route through an environment proxy: the dial guard
	// must see the document host itself
	t.Setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
	_, transport := (&Server{staticConfig: &types.ServerConfig{}}).cimdHTTPClient()
	if transport.Proxy != nil {
		t.Fatal("cimd fetch transport must not use a proxy")
	}

	server := &Server{staticConfig: &types.ServerConfig{}}
	server.staticConfig.Api.CIMDAllowedDomains = []string{"example.com"}
	server.staticConfig.Api.CIMDDeniedDomains = []string{"bad.example.com"}
	if err := server.cimdDomainAllowed("app.example.com"); err != nil {
		t.Fatalf("subdomain of an allowed domain must pass: %v", err)
	}
	if err := server.cimdDomainAllowed("example.com"); err != nil {
		t.Fatalf("the allowed domain itself must pass: %v", err)
	}
	if err := server.cimdDomainAllowed("notexample.com"); err == nil {
		t.Fatal("suffix without a dot boundary must not match")
	}
	if err := server.cimdDomainAllowed("x.bad.example.com"); err == nil {
		t.Fatal("deny must win over allow")
	}
}
