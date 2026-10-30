// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

// The HTTP Basic credentials that authenticate a request to a system or
// builtin auth app are OpenRun's own (the admin password or a builtin user's
// password). They are consumed by OpenRun and must never be forwarded to the
// app: a proxied upstream, a container or a forward auth service could
// otherwise recover and replay the password. Credentials that belong to the
// app (any other Authorization scheme, authenticated by the form login
// session cookie) keep passing through.
func TestBasicLoginCredentialsAreNotForwarded(t *testing.T) {
	s, ts, _ := newMCPAppTestServer(t)
	s.staticConfig.AdminUser = "admin"
	s.staticConfig.Security.AdminPasswordBcrypt = hashPassword(t, "adminpw")
	upstream := newUpstreamRecorder(t)
	createMCPTestApp(t, s, "/apps/builtin", upstream.server.URL, "builtin", "")
	createMCPTestApp(t, s, "/apps/system", upstream.server.URL, "system", "")

	for _, tc := range []struct {
		name, path, user, password string
	}{
		{"builtin", "/apps/builtin/", "alice", "alicepw"},
		{"system", "/apps/system/", "admin", "adminpw"},
	} {
		t.Run(tc.name+" basic", func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, ts.URL+tc.path, nil)
			req.SetBasicAuth(tc.user, tc.password)
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close() //nolint:errcheck
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d, want 200", resp.StatusCode)
			}
			_, headers, _ := upstream.last()
			if got := headers.Values("Authorization"); len(got) != 0 {
				t.Fatalf("OpenRun Basic credentials reached the app: %q", got)
			}
		})
	}

	// A wrong password never reaches the app at all
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/apps/builtin/", nil)
	req.SetBasicAuth("alice", "wrong")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad password: status %d, want 401", resp.StatusCode)
	}

	// An app-owned Bearer token on a request authenticated by the form login
	// session cookie is passed through to the app (documented behavior)
	t.Run("bearer with form session passes through", func(t *testing.T) {
		kv := NewInmemoryKVStore()
		store := NewKVSessionStore(kv,
			[]byte("test-session-key-32bytes-long!!!"),
			[]byte("test-session-block-32bytes-key!!"))
		s.formLogin.cookieStore = store
		s.formLogin.db = kv
		s.staticConfig.Security.AuthCallbackDomain = "auth." // enables the form login
		if !s.formLogin.enabled() {
			t.Fatal("form login should be enabled")
		}

		setupRec := httptest.NewRecorder()
		session, err := store.Get(httptest.NewRequest(http.MethodGet, "/apps/builtin/", nil), genCookieName("builtin"))
		if err != nil {
			t.Fatal(err)
		}
		fp, ok := credentialFingerprint(s.Config(), s.formLogin.adminPasswordHash(), s.users, "builtin", "alice")
		if !ok {
			t.Fatal("no credential fingerprint for alice")
		}
		session.Values[AUTH_KEY] = true
		session.Values[PROVIDER_NAME_KEY] = "builtin"
		session.Values[USER_KEY] = "alice"
		session.Values[CRED_FP_KEY] = fp
		markSessionLogin(session, s.formLogin.sessionAbsoluteMaxAge)
		if err := session.Save(httptest.NewRequest(http.MethodGet, "/apps/builtin/", nil), setupRec); err != nil {
			t.Fatal(err)
		}

		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/apps/builtin/", nil)
		for _, c := range setupRec.Result().Cookies() {
			req.AddCookie(c)
		}
		req.Header.Set("Authorization", "Bearer app-owned-token")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		_, headers, _ := upstream.last()
		if got := headers.Get("Authorization"); got != "Bearer app-owned-token" {
			t.Fatalf("app-owned Authorization = %q, want passthrough", got)
		}
		if headers.Get("Cookie") != "" {
			t.Fatalf("OpenRun session cookie reached the app: %q", headers.Get("Cookie"))
		}
		if got := headers.Get(types.OPENRUN_HEADER_PREFIX + "User"); got != "builtin:alice" {
			t.Fatalf("session user = %q, want builtin:alice", got)
		}
	})
}
