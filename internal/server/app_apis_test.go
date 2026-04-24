// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestIsOpenRunCookieName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cookie string
		want   bool
	}{
		{name: "oauth session", cookie: "github_openrun_session", want: true},
		{name: "saml session", cookie: "saml_okta_openrun_saml_session", want: true},
		{name: "gothic session", cookie: "_gothic_session", want: true},
		{name: "app cookie", cookie: "sessionid", want: false},
		{name: "contains openrun but different suffix", cookie: "openrun_theme", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isOpenRunCookieName(tt.cookie); got != tt.want {
				t.Fatalf("isOpenRunCookieName(%q): want %v got %v", tt.cookie, tt.want, got)
			}
		})
	}
}

func TestStripOpenRunCookies(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/myapp", nil)
	req.Header.Add("Cookie", strings.Join([]string{
		"app_session=keep1",
		"github_openrun_session=drop1",
		"theme=keep2",
		"_gothic_session=drop2",
		"saml_okta_openrun_saml_session=drop3",
	}, "; "))

	stripOpenRunCookies(req)

	got := req.Header.Values("Cookie")
	if len(got) != 1 {
		t.Fatalf("cookie header count: want 1 got %d", len(got))
	}
	if got[0] != "app_session=keep1; theme=keep2" {
		t.Fatalf("cookie header: got %q", got[0])
	}
}

func TestStripOpenRunCookiesRemovesHeaderWhenOnlyOpenRunCookiesRemain(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/myapp", nil)
	req.Header.Add("Cookie", "github_openrun_session=drop1; _gothic_session=drop2")

	stripOpenRunCookies(req)

	if got := req.Header.Get("Cookie"); got != "" {
		t.Fatalf("cookie header: want empty got %q", got)
	}
}

func TestStripOpenRunCookieHeaderFastPath(t *testing.T) {
	t.Parallel()

	const cookieHeader = "app_session=keep1; theme=keep2"
	got, changed := stripOpenRunCookieHeader(cookieHeader)
	if changed {
		t.Fatal("expected fast path to leave header unchanged")
	}
	if got != cookieHeader {
		t.Fatalf("cookie header: want %q got %q", cookieHeader, got)
	}
}

func TestStripOpenRunCookieHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  string
		want    string
		changed bool
	}{
		{
			name:    "removes oauth and saml cookies",
			header:  "app_session=keep1; github_openrun_session=drop1; theme=keep2; saml_okta_openrun_saml_session=drop2",
			want:    "app_session=keep1; theme=keep2",
			changed: true,
		},
		{
			name:    "removes gothic cookie",
			header:  "app_session=keep1; _gothic_session=drop1; theme=keep2",
			want:    "app_session=keep1; theme=keep2",
			changed: true,
		},
		{
			name:    "handles extra whitespace",
			header:  "  app_session=keep1  ;\tgithub_openrun_session=drop1\t;  theme=keep2 ",
			want:    "app_session=keep1; theme=keep2",
			changed: true,
		},
		{
			name:    "handles duplicate separators",
			header:  "app_session=keep1;; github_openrun_session=drop1; ; theme=keep2;",
			want:    "app_session=keep1; theme=keep2",
			changed: true,
		},
		{
			name:    "handles cookie without equals",
			header:  "app_session=keep1; github_openrun_session; theme=keep2",
			want:    "app_session=keep1; theme=keep2",
			changed: true,
		},
		{
			name:    "keeps non openrun cookie containing openrun substring",
			header:  "app_session=keep1; openrun_theme=keep2",
			want:    "app_session=keep1; openrun_theme=keep2",
			changed: false,
		},
		{
			name:    "removes all cookies when only openrun remain",
			header:  "_gothic_session=drop1; github_openrun_session=drop2",
			want:    "",
			changed: true,
		},
		{
			name:    "empty header",
			header:  "",
			want:    "",
			changed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, changed := stripOpenRunCookieHeader(tt.header)
			if changed != tt.changed {
				t.Fatalf("changed: want %v got %v", tt.changed, changed)
			}
			if got != tt.want {
				t.Fatalf("cookie header: want %q got %q", tt.want, got)
			}
		})
	}
}

func TestStripOpenRunCookiesMultipleHeaders(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/myapp", nil)
	req.Header["Cookie"] = []string{
		"app_session=keep1; github_openrun_session=drop1",
		"theme=keep2",
		"_gothic_session=drop2",
	}

	stripOpenRunCookies(req)

	got := req.Header["Cookie"]
	if len(got) != 2 {
		t.Fatalf("cookie header count: want 2 got %d", len(got))
	}
	if got[0] != "app_session=keep1" {
		t.Fatalf("cookie header 0: got %q", got[0])
	}
	if got[1] != "theme=keep2" {
		t.Fatalf("cookie header 1: got %q", got[1])
	}
}

func TestStripOpenRunCookiesLeavesHeadersUntouchedWhenNoMatch(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/myapp", nil)
	req.Header["Cookie"] = []string{
		"app_session=keep1; theme=keep2",
		"locale=en-US",
	}

	before := append([]string(nil), req.Header["Cookie"]...)
	stripOpenRunCookies(req)
	after := req.Header["Cookie"]

	if len(after) != len(before) {
		t.Fatalf("cookie header count: want %d got %d", len(before), len(after))
	}
	for i := range before {
		if after[i] != before[i] {
			t.Fatalf("cookie header %d: want %q got %q", i, before[i], after[i])
		}
	}
}

func BenchmarkStripOpenRunCookieHeaderNoMatch(b *testing.B) {
	const cookieHeader = "app_session=keep1; theme=keep2; locale=en-US"
	for i := 0; i < b.N; i++ {
		stripOpenRunCookieHeader(cookieHeader)
	}
}

func BenchmarkStripOpenRunCookieHeaderWithOpenRunCookies(b *testing.B) {
	const cookieHeader = "app_session=keep1; github_openrun_session=drop1; theme=keep2; _gothic_session=drop2; saml_okta_openrun_saml_session=drop3"
	for i := 0; i < b.N; i++ {
		stripOpenRunCookieHeader(cookieHeader)
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
