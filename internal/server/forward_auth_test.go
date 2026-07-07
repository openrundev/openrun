// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

func newForwardAuthTestServer(config *types.ServerConfig) *Server {
	if config == nil {
		config = &types.ServerConfig{}
	}
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	return &Server{
		Logger:                logger,
		staticConfig:          config,
		forwardAuthHTTPClient: newForwardAuthHTTPClient(config),
	}
}

func TestForwardAuthMiddlewareAllowsAndCopiesHeaders(t *testing.T) {
	var authMethod string
	var authBody string
	var authHeaders http.Header
	var upstreamHeaders http.Header
	nextCalled := false

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read auth body: %v", err)
		}

		authMethod = r.Method
		authBody = string(body)
		authHeaders = r.Header.Clone()
		w.Header().Set("Remote-User", "auth-user")
		w.Header().Set("Remote-Email", "auth@example.com")
		w.Header().Set("X-Skip", "do-not-copy")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer authServer.Close()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		upstreamHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("app ok"))
	})

	req := httptest.NewRequest(http.MethodPost, "http://app.example.com:8080/app/api?x=1", strings.NewReader("request body"))
	req.RemoteAddr = "198.51.100.40:4242"
	req.Header.Set("Authorization", "Bearer original")
	req.Header.Set("Cookie", "app=1")
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Real-IP", "203.0.113.100")
	req.Header.Set(types.OPENRUN_HEADER_USER, "spoofed-user")

	ctx := context.WithValue(req.Context(), types.USER_ID, "real-user")
	ctx = context.WithValue(ctx, types.USER_SUBJECT, "subject-123")
	ctx = context.WithValue(ctx, types.USER_EMAIL, "real@example.com")
	ctx = context.WithValue(ctx, types.CUSTOM_PERMS, []string{"read:data", "write:data"})
	ctx = context.WithValue(ctx, types.RBAC_ENABLED, true)
	req = req.WithContext(ctx)

	s := newForwardAuthTestServer(nil)
	handler := s.forwardAuthMiddleware(next, &types.ForwardConfig{
		AuthUrl:             authServer.URL,
		ForwardHeaders:      []string{"Authorization"},
		CopyResponseHeaders: []string{"Remote-User", "Remote-Email>X-Auth-Email"},
	})

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body %q", resp.Code, http.StatusCreated, resp.Body.String())
	}
	if resp.Body.String() != "app ok" {
		t.Fatalf("body = %q, want %q", resp.Body.String(), "app ok")
	}
	if !nextCalled {
		t.Fatal("next handler was not called")
	}

	assertHeader(t, authHeaders, "Authorization", "Bearer original")
	assertHeader(t, authHeaders, "Cookie", "")
	assertHeader(t, authHeaders, "X-Forwarded-Method", http.MethodPost)
	assertHeader(t, authHeaders, "X-Forwarded-Proto", "http")
	assertHeader(t, authHeaders, "X-Forwarded-Host", "app.example.com:8080")
	assertHeader(t, authHeaders, "X-Forwarded-Uri", "/app/api?x=1")
	assertHeader(t, authHeaders, "X-Forwarded-For", "198.51.100.40")
	assertHeader(t, authHeaders, "X-Real-IP", "198.51.100.40")
	assertHeader(t, authHeaders, types.OPENRUN_HEADER_USER, "real-user")
	assertHeader(t, authHeaders, types.OPENRUN_HEADER_USER_ID, "subject-123")
	assertHeader(t, authHeaders, types.OPENRUN_HEADER_USER_EMAIL, "real@example.com")
	assertHeader(t, authHeaders, types.OPENRUN_HEADER_PERMS, "read:data,write:data")
	assertHeader(t, authHeaders, types.OPENRUN_HEADER_APP_RBAC_ENABLED, "true")

	if authMethod != http.MethodGet {
		t.Fatalf("auth method = %q, want %q", authMethod, http.MethodGet)
	}
	if authBody != "" {
		t.Fatalf("auth body = %q, want empty", authBody)
	}

	assertHeader(t, upstreamHeaders, "Remote-User", "auth-user")
	assertHeader(t, upstreamHeaders, "X-Auth-Email", "auth@example.com")
	assertHeader(t, upstreamHeaders, "Remote-Email", "")
	assertHeader(t, upstreamHeaders, "X-Skip", "")
}

func TestForwardAuthMiddlewareDeniesWithAuthResponse(t *testing.T) {
	tests := map[string]struct {
		status      int
		headerName  string
		headerValue string
	}{
		"unauthorized": {status: http.StatusUnauthorized, headerName: "WWW-Authenticate", headerValue: `Basic realm="auth"`},
		"forbidden":    {status: http.StatusForbidden, headerName: "X-Deny-Reason", headerValue: "blocked"},
		"redirect":     {status: http.StatusFound, headerName: "Location", headerValue: "/login"},
		"server error": {status: http.StatusInternalServerError, headerName: "X-Auth-Error", headerValue: "down"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			nextCalled := false
			authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(tc.headerName, tc.headerValue)
				w.Header().Add("Set-Cookie", "auth_session=abc; Path=/")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("auth response"))
			}))
			defer authServer.Close()

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			s := newForwardAuthTestServer(nil)
			handler := s.forwardAuthMiddleware(next, &types.ForwardConfig{AuthUrl: authServer.URL})
			req := httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil)
			req.RemoteAddr = "198.51.100.40:4242"
			resp := httptest.NewRecorder()

			handler.ServeHTTP(resp, req)

			if nextCalled {
				t.Fatal("next handler was called")
			}
			if resp.Code != tc.status {
				t.Fatalf("status = %d, want %d", resp.Code, tc.status)
			}
			if resp.Body.String() != "auth response" {
				t.Fatalf("body = %q, want %q", resp.Body.String(), "auth response")
			}
			if got := resp.Header().Get(tc.headerName); got != tc.headerValue {
				t.Fatalf("%s = %q, want %q", tc.headerName, got, tc.headerValue)
			}
			if got := resp.Header().Values("Set-Cookie"); len(got) != 1 || got[0] != "auth_session=abc; Path=/" {
				t.Fatalf("Set-Cookie = %#v, want auth_session cookie", got)
			}
		})
	}
}

func TestForwardAuthMiddlewareErrorScenarios(t *testing.T) {
	t.Run("nil config passes through", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusAccepted)
		})
		s := newForwardAuthTestServer(nil)
		handler := s.forwardAuthMiddleware(next, nil)

		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil))

		if !nextCalled {
			t.Fatal("next handler was not called")
		}
		if resp.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusAccepted)
		}
	})

	t.Run("empty auth url fails closed", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})
		s := newForwardAuthTestServer(nil)
		handler := s.forwardAuthMiddleware(next, &types.ForwardConfig{})

		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil))

		if nextCalled {
			t.Fatal("next handler was called")
		}
		if resp.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusInternalServerError)
		}
	})

	t.Run("invalid auth url fails closed", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("next handler was called")
		})
		s := newForwardAuthTestServer(nil)
		handler := s.forwardAuthMiddleware(next, &types.ForwardConfig{AuthUrl: "://bad"})

		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil))

		if resp.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusInternalServerError)
		}
	})

	t.Run("auth request failure returns bad gateway", func(t *testing.T) {
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		authURL := authServer.URL
		authServer.Close()

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("next handler was called")
		})
		s := newForwardAuthTestServer(nil)
		handler := s.forwardAuthMiddleware(next, &types.ForwardConfig{AuthUrl: authURL})

		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil))

		if resp.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusBadGateway)
		}
	})

	t.Run("auth request timeout returns bad gateway", func(t *testing.T) {
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer authServer.Close()

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("next handler was called")
		})
		s := newForwardAuthTestServer(&types.ServerConfig{
			System: types.SystemConfig{ForwardAuthTimeoutSecs: 1},
		})
		handler := s.forwardAuthMiddleware(next, &types.ForwardConfig{
			AuthUrl: authServer.URL,
		})

		resp := httptest.NewRecorder()
		start := time.Now()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil))
		elapsed := time.Since(start)

		if resp.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusBadGateway)
		}
		if elapsed >= 1500*time.Millisecond {
			t.Fatalf("elapsed = %s, want timeout near 1s", elapsed)
		}
	})
}

func TestSetForwardAuthHeadersHonorsTrustedProxy(t *testing.T) {
	s := newForwardAuthTestServer(&types.ServerConfig{
		Security: types.SecurityConfig{TrustedProxies: []string{"10.0.0.1"}},
	})

	req := httptest.NewRequest(http.MethodPatch, "http://service.local/resource?q=1", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
	req.Header.Set("X-Forwarded-Proto", "https")

	header := http.Header{}
	header.Set("Forwarded", "for=spoof")
	header.Set("X-Forwarded-For", "198.51.100.10")
	header.Set("X-Forwarded-Proto", "http")
	header.Set("X-Real-IP", "198.51.100.11")

	setForwardAuthHeaders(header, req, s.staticConfig)

	assertHeader(t, header, "Forwarded", "")
	assertHeader(t, header, "X-Forwarded-For", "203.0.113.5")
	assertHeader(t, header, "X-Real-IP", "203.0.113.5")
	assertHeader(t, header, "X-Forwarded-Proto", "https")
	assertHeader(t, header, "X-Forwarded-Method", http.MethodPatch)
	assertHeader(t, header, "X-Forwarded-Host", "service.local")
	assertHeader(t, header, "X-Forwarded-Uri", "/resource?q=1")
}

func TestForwardAuthHeaderCopyHelpers(t *testing.T) {
	t.Run("request headers support host allowlist and skip hop by hop", func(t *testing.T) {
		authReq := httptest.NewRequest(http.MethodGet, "http://auth.example.com/check", nil)
		originalReq := httptest.NewRequest(http.MethodGet, "http://app.example.com/path", nil)
		originalReq.Host = "app.example.com"
		originalReq.Header.Set("X-Test", "copy-me")
		originalReq.Header.Set("Connection", "keep-alive")

		copyForwardAuthRequestHeaders(authReq, originalReq, []string{"Host", "X-Test", "Connection"})

		if authReq.Host != "app.example.com" {
			t.Fatalf("auth host = %q, want %q", authReq.Host, "app.example.com")
		}
		assertHeader(t, authReq.Header, "X-Test", "copy-me")
		assertHeader(t, authReq.Header, "Connection", "")
	})

	t.Run("response headers support no default copy and renamed allowlist", func(t *testing.T) {
		sourceHeader, targetHeader := parseForwardAuthHeaderCopy("Remote-Email>X-Webauth-Email")
		if sourceHeader != "Remote-Email" || targetHeader != "X-Webauth-Email" {
			t.Fatalf("parse copy = %q, %q; want Remote-Email, X-Webauth-Email", sourceHeader, targetHeader)
		}

		src := http.Header{}
		src.Set("Remote-User", "auth-user")
		src.Set("Remote-Email", "auth@example.com")
		src.Set("Connection", "close")

		defaultDst := http.Header{}
		copyForwardAuthResponseHeaders(defaultDst, src, nil)
		assertHeader(t, defaultDst, "Remote-User", "")
		assertHeader(t, defaultDst, "Remote-Email", "")
		assertHeader(t, defaultDst, "Connection", "")

		allowDst := http.Header{}
		copyForwardAuthResponseHeaders(allowDst, src, []string{"Remote-Email>X-Webauth-Email"})
		assertHeader(t, allowDst, "X-Webauth-Email", "auth@example.com")
		assertHeader(t, allowDst, "Remote-Email", "")
		assertHeader(t, allowDst, "Remote-User", "")
	})
}

func assertHeader(t *testing.T, header http.Header, name string, want string) {
	t.Helper()
	if got := header.Get(name); got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}
