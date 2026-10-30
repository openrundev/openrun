// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// ssoPrivateHostsConfig is the config letting the SSO fetches of a test reach
// its loopback httptest servers
func ssoPrivateHostsConfig() *types.ServerConfig {
	return &types.ServerConfig{Security: types.SecurityConfig{SSOAllowPrivateHosts: true}}
}

// The metadata_url is config:update settable: by default the fetch must not
// reach a loopback (or any private) address, and a response body must not
// be echoed into the error, which reaches the config update caller
func TestSAMLMetadataFetchRefusesPrivateHosts(t *testing.T) {
	t.Parallel()
	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("internal-service-secret"))
	}))
	defer ts.Close()

	manager := NewSAMLManager(testutil.TestLogger(), &types.ServerConfig{}, nil, nil)
	_, err := manager.buildSAMLProvider(context.Background(), "saml_x", types.SAMLConfig{MetadataURL: ts.URL}, "https://sp.example")
	if !errors.Is(err, system.ErrPrivateAddress) {
		t.Fatalf("loopback metadata url not refused: %v", err)
	}
	if hits != 0 {
		t.Fatalf("metadata server was contacted %d times", hits)
	}

	// With the static opt-in the fetch is made, and the error names the
	// status only
	manager = NewSAMLManager(testutil.TestLogger(), ssoPrivateHostsConfig(), nil, nil)
	_, err = manager.buildSAMLProvider(context.Background(), "saml_x", types.SAMLConfig{MetadataURL: ts.URL}, "https://sp.example")
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("expected status error, got %v", err)
	}
	if strings.Contains(err.Error(), "internal-service-secret") {
		t.Fatalf("response body echoed in error: %v", err)
	}
	if hits != 1 {
		t.Fatalf("metadata server was contacted %d times", hits)
	}
}

// The discovery_url is config:update settable too, and a nil startup config
// (never the case in the server, only in tests) must refuse as well
func TestOIDCDiscoveryRefusesPrivateHosts(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("discovery server contacted: %s", r.URL)
	}))
	defer ts.Close()
	for _, manager := range []*OAuthManager{{}, {config: &types.ServerConfig{}}} {
		_, err := manager.buildProvider("oidc_x", types.AuthConfig{Key: "k", Secret: "s", DiscoveryUrl: ts.URL + oidcDiscoveryPath}, "https://app.example")
		if !errors.Is(err, system.ErrPrivateAddress) {
			t.Fatalf("loopback discovery url not refused: %v", err)
		}
	}
}

// A redirect of an IdP fetch is dialed through the same guarded transport,
// and an https to http downgrade is refused
func TestSSOClientRedirects(t *testing.T) {
	t.Parallel()
	hops := 0
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, ts.URL+r.URL.Path+"/x", http.StatusFound)
	}))
	defer ts.Close()

	client := ssoHTTPClient("test", true, oidcFetchTimeout)
	resp, err := client.Get(ts.URL + "/a")
	if err == nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "stopped after 3 redirects") {
		t.Fatalf("redirect loop not bounded: %v", err)
	}
	if hops != ssoMaxRedirects+1 {
		t.Fatalf("expected %d requests, got %d", ssoMaxRedirects+1, hops)
	}

	// A guarded client follows a redirect only to a public address: the
	// first hop is refused before any connection since the server is local,
	// so test the hop check with a public-looking redirect target instead
	guarded := ssoHTTPClient("test", false, oidcFetchTimeout)
	if _, err := guarded.Get(ts.URL + "/b"); !errors.Is(err, system.ErrPrivateAddress) {
		t.Fatalf("guarded client reached loopback: %v", err)
	}
	downgrade := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/", http.StatusFound)
	}))
	defer downgrade.Close()
	tlsClient := downgrade.Client()
	tlsClient.CheckRedirect = ssoHTTPClient("test", true, oidcFetchTimeout).CheckRedirect
	if _, err := tlsClient.Get(downgrade.URL); err == nil || !strings.Contains(err.Error(), "redirect from https to http refused") {
		t.Fatalf("https to http redirect not refused: %v", err)
	}
}
