// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	appcore "github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/types"
	saml2 "github.com/russellhaering/gosaml2"
)

func newAuthRedirectTestServer(defaultDomain string, fallbackUnknownDomains bool) *Server {
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{
		System: types.SystemConfig{
			DefaultDomain:          defaultDomain,
			FallbackUnknownDomains: fallbackUnknownDomains,
		},
	}
	return &Server{
		Logger:      logger,
		config:      config,
		authHandler: NewAdminBasicAuth(logger, config),
		oAuthManager: &OAuthManager{
			Logger:          logger,
			config:          config,
			providerConfigs: map[string]*types.AuthConfig{},
		},
		samlManager: &SAMLManager{
			Logger:    logger,
			config:    config,
			providers: map[string]*saml2.SAMLServiceProvider{},
		},
		rbacManager: &rbac.RBACManager{
			Logger:     logger,
			RbacConfig: &types.RBACConfig{},
		},
	}
}

func newAuthRedirectTestApp(authType types.AppAuthnType) *appcore.App {
	return &appcore.App{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		AppEntry: &types.AppEntry{
			Path: "/myapp",
			Metadata: types.AppMetadata{
				AuthnType: authType,
			},
		},
	}
}

func TestAuthenticateAndServeAppRedirectsFallbackOAuthToCanonicalHost(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", true)
	app := newAuthRedirectTestApp("github")

	req := httptest.NewRequest(http.MethodGet, "http://unknown.test:8080/myapp?x=1", nil)
	rec := httptest.NewRecorder()

	server.authenticateAndServeApp(rec, req, app)

	if rec.Code != http.StatusFound {
		t.Fatalf("status: want %d got %d", http.StatusFound, rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "http://example.com:8080/myapp?x=1" {
		t.Fatalf("location: got %q", got)
	}
}

func TestAuthenticateAndServeAppRedirectsFallbackSAMLToCanonicalHostForHTMX(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", true)
	app := newAuthRedirectTestApp("saml_okta")

	req := httptest.NewRequest(http.MethodGet, "https://unknown.test/myapp?x=1", nil)
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()

	server.authenticateAndServeApp(rec, req, app)

	if got := rec.Header().Get("HX-Redirect"); got != "https://example.com/myapp?x=1" {
		t.Fatalf("HX-Redirect: got %q", got)
	}
}

func TestCanonicalAuthRedirectURLTreatsLocalhostAliasesAsEquivalent(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("localhost", true)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:25222/myapp", nil)

	if redirectURL, redirectNeeded := server.canonicalAuthRedirectURL(req, types.AppPathDomain{Path: "/myapp"}); redirectNeeded {
		t.Fatalf("unexpected redirect to %q", redirectURL)
	}
}

func TestMatchAppRejectsUnknownHostWhenFallbackDisabled(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", false)
	server.apps = &AppStore{
		Logger:  server.Logger,
		server:  server,
		allApps: []types.AppInfo{{AppPathDomain: types.AppPathDomain{Path: "/myapp"}}},
		allDomains: map[string]bool{
			"example.com": true,
		},
	}

	if _, err := server.MatchApp("unknown.test", "/myapp"); err == nil {
		t.Fatal("MatchApp should reject unknown hosts when fallback_unknown_domains is disabled")
	}
}

func TestMatchAppFallsBackToDefaultDomainWhenEnabled(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", true)
	server.apps = &AppStore{
		Logger:  server.Logger,
		server:  server,
		allApps: []types.AppInfo{{AppPathDomain: types.AppPathDomain{Path: "/myapp"}}},
		allDomains: map[string]bool{
			"example.com": true,
		},
	}

	appInfo, err := server.MatchApp("unknown.test", "/myapp")
	if err != nil {
		t.Fatalf("MatchApp returned error: %v", err)
	}
	if appInfo.Path != "/myapp" {
		t.Fatalf("matched path: got %q", appInfo.Path)
	}
}
