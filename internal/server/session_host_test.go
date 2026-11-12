// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

// A session is bound to the host its login was completed for: a login
// completed for one app domain is not accepted on another app domain
func TestOAuthSessionBoundToHost(t *testing.T) {
	manager, _ := newOAuthSessionTestManager(t)
	manager.redirectHostAllowed = func(host string) bool {
		return host == "tools.customer.com" || host == "tools.stage.customer.com"
	}
	orig := gothic.CompleteUserAuth
	gothic.CompleteUserAuth = func(http.ResponseWriter, *http.Request) (goth.User, error) {
		return goth.User{UserID: "user-subject", Email: "user@example.com", RawData: map[string]any{}}, nil
	}
	t.Cleanup(func() { gothic.CompleteUserAuth = orig })

	// Login started on the stage host
	r := httptest.NewRequest(http.MethodGet, "https://tools.stage.customer.com/", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	info, err := manager.CheckAuthInfo(w, r, "github")
	if err != nil || info.UserId != "" || w.Code != http.StatusFound {
		t.Fatalf("login not started: %v %d", err, w.Code)
	}
	preAuthCookies := w.Result().Cookies()
	loginURL, _ := url.Parse(w.Header().Get("Location"))

	w = httptest.NewRecorder()
	manager.authCallback(w, oauthProviderRequest("/auth/github/callback?state="+loginURL.Query().Get("state")))
	if w.Code != http.StatusFound {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))

	r = oauthProviderRequest("https://tools.stage.customer.com/auth/github/redirect?state=" + loc.Query().Get("state"))
	for _, c := range preAuthCookies {
		r.AddCookie(c)
	}
	w = httptest.NewRecorder()
	manager.redirect(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("redirect: %d %s", w.Code, w.Body.String())
	}
	sessionCookies := w.Result().Cookies()

	check := func(target string) string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Set("Accept", "text/html")
		for _, c := range sessionCookies {
			r.AddCookie(c)
		}
		info, err := manager.CheckAuthInfo(httptest.NewRecorder(), r, "github")
		if err != nil {
			t.Fatal(err)
		}
		return info.UserId
	}

	if got := check("https://tools.stage.customer.com/page"); got != "github:user@example.com" {
		t.Fatalf("session not accepted on the host it was issued for: %q", got)
	}
	if got := check("https://TOOLS.stage.customer.com:8443/page"); got != "github:user@example.com" {
		t.Fatalf("session host match should ignore case and port: %q", got)
	}
	if got := check("https://tools.customer.com/admin"); got != "" {
		t.Fatalf("session issued for the stage host was accepted on another host as %q", got)
	}
}

func TestNormalizeSessionHost(t *testing.T) {
	tests := map[string]string{
		"App.Example.com":      "app.example.com",
		"app.example.com:8443": "app.example.com",
		"app.example.com.":     "app.example.com",
		"127.0.0.1:25222":      "localhost",
		"localhost:25222":      "localhost",
		"[::1]:25222":          "localhost",
	}
	for in, want := range tests {
		if got := normalizeSessionHost(in); got != want {
			t.Errorf("normalizeSessionHost(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sessionHostOfUrl("/relative/path"); got != "" {
		t.Errorf("relative url should have no session host, got %q", got)
	}
}
