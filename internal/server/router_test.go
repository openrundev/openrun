// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func newRouterTestServer(adminOverTCP, redirectToHTTPS bool) (*types.ServerConfig, *Server, *types.Logger) {
	config := &types.ServerConfig{
		Http: types.HttpConfig{
			RedirectToHttps: redirectToHTTPS,
		},
		Https: types.HttpsConfig{
			Port: 7443,
		},
		Security: types.SecurityConfig{
			AdminOverTCP: adminOverTCP,
		},
	}
	logger := types.NewLogger(&types.LogConfig{
		Level: "WARN",
	})
	server := &Server{
		Logger:         logger,
		config:         config,
		authHandler:    NewAdminBasicAuth(logger, config),
		oAuthManager:   &OAuthManager{Logger: logger, config: config},
		samlManager:    &SAMLManager{Logger: logger, config: config},
		csrfMiddleware: http.NewCrossOriginProtection(),
	}
	return config, server, logger
}

func TestRouterNewTCPHandler_SystemRoutes(t *testing.T) {
	config, server, logger := newRouterTestServer(false, false)
	handler := NewTCPHandler(logger, config, server)

	healthReq := httptest.NewRequest(http.MethodGet, "http://example.com/_openrun/health", nil)
	healthRec := httptest.NewRecorder()
	handler.router.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("health status: want %d got %d", http.StatusOK, healthRec.Code)
	}
	if strings.TrimSpace(healthRec.Body.String()) != "OK" {
		t.Fatalf("health body: want OK got %q", healthRec.Body.String())
	}

	perfReq := httptest.NewRequest(http.MethodGet, "http://example.com/testperf", nil)
	perfRec := httptest.NewRecorder()
	handler.router.ServeHTTP(perfRec, perfReq)
	if perfRec.Code != http.StatusOK {
		t.Fatalf("testperf status: want %d got %d", http.StatusOK, perfRec.Code)
	}
	if !strings.Contains(perfRec.Body.String(), `"status":"ok"`) {
		t.Fatalf("testperf body: unexpected %q", perfRec.Body.String())
	}

	internalReq := httptest.NewRequest(http.MethodGet, "http://example.com/_openrun/apps", nil)
	internalRec := httptest.NewRecorder()
	handler.router.ServeHTTP(internalRec, internalReq)
	if internalRec.Code != http.StatusNotFound {
		t.Fatalf("internal status when admin over tcp disabled: want %d got %d", http.StatusNotFound, internalRec.Code)
	}
}

func TestRouterNewTCPHandler_AdminOverTCPRequiresAuth(t *testing.T) {
	config, server, logger := newRouterTestServer(true, false)
	handler := NewTCPHandler(logger, config, server)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/_openrun/apps", nil)
	rec := httptest.NewRecorder()
	handler.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: want %d got %d", http.StatusUnauthorized, rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="openrun"` {
		t.Fatalf("WWW-Authenticate header: got %q", got)
	}
}

func TestRouterNewTCPHandler_RedirectToHTTPS(t *testing.T) {
	config, server, logger := newRouterTestServer(false, true)
	handler := NewTCPHandler(logger, config, server)

	req := httptest.NewRequest(http.MethodGet, "http://example.com:8080/testperf?x=1", nil)
	rec := httptest.NewRecorder()
	handler.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status: want %d got %d", http.StatusPermanentRedirect, rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://example.com:7443/testperf?x=1" {
		t.Fatalf("location: got %q", got)
	}
}

func TestRouterNewUDSHandler_NoAppRoutes(t *testing.T) {
	config, server, logger := newRouterTestServer(false, false)
	handler := NewUDSHandler(logger, config, server)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/testperf", nil)
	rec := httptest.NewRecorder()
	handler.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: want %d got %d", http.StatusNotFound, rec.Code)
	}
}

func TestRouterHTTPSRedirectMiddleware(t *testing.T) {
	_, server, logger := newRouterTestServer(false, false)
	handler := &Handler{
		Logger: logger,
		server: server,
	}

	redirectReq := httptest.NewRequest(http.MethodGet, "http://example.com/any", nil)
	redirectRec := httptest.NewRecorder()
	handler.httpsRedirectMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called for plain http request")
	})).ServeHTTP(redirectRec, redirectReq)
	if redirectRec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status: want %d got %d", http.StatusPermanentRedirect, redirectRec.Code)
	}
	if got := redirectRec.Header().Get("Location"); got != "https://example.com/any" {
		t.Fatalf("location: got %q", got)
	}

	tlsReq := httptest.NewRequest(http.MethodGet, "https://example.com/any", nil)
	tlsReq.TLS = &tls.ConnectionState{}
	tlsRec := httptest.NewRecorder()
	called := false
	handler.httpsRedirectMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(tlsRec, tlsReq)
	if !called {
		t.Fatalf("expected next handler to be called for https request")
	}
	if tlsRec.Code != http.StatusNoContent {
		t.Fatalf("status: want %d got %d", http.StatusNoContent, tlsRec.Code)
	}
}

func TestRouterPanicRecovery(t *testing.T) {
	mw := panicRecovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/panic", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: want %d got %d", http.StatusInternalServerError, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "boom") {
		t.Fatalf("body: expected panic message, got %q", rec.Body.String())
	}
}

func TestRouterPathAndOperationHelpers(t *testing.T) {
	pathTests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{name: "valid", path: "/app/ok"},
		{name: "contains /..", path: "/app/../bad", wantErr: "path cannot contain '/..'"},
		{name: "contains ../", path: "../bad", wantErr: "path cannot contain '../'"},
		{name: "contains /./", path: "/app/./bad", wantErr: "path cannot contain '/./'"},
		{name: "suffix /.", path: "/app/.", wantErr: "path cannot end with '/.'"},
		{name: "reserved _cl_", path: "/app/name_cl_reserved", wantErr: "last section of path cannot contain _cl_"},
	}

	for _, tc := range pathTests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePathForCreate(tc.path)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error: want containing %q got %q", tc.wantErr, err.Error())
			}
		})
	}

	if got := genOperationName("op", true, true); got != "op_promote_approve" {
		t.Fatalf("operation name: got %q", got)
	}
	if got := genOperationName("op", true, false); got != "op_promote" {
		t.Fatalf("operation name: got %q", got)
	}
	if got := genOperationName("op", false, true); got != "op_approve" {
		t.Fatalf("operation name: got %q", got)
	}
	if got := genOperationName("op", false, false); got != "op" {
		t.Fatalf("operation name: got %q", got)
	}
}

func TestRouterBoolAndSignatureHelpers(t *testing.T) {
	if got, err := parseBoolArg("", true); err != nil || !got {
		t.Fatalf("empty arg: want true,nil got %t,%v", got, err)
	}
	if got, err := parseBoolArg("false", true); err != nil || got {
		t.Fatalf("false arg: want false,nil got %t,%v", got, err)
	}
	if got, err := parseBoolArg("not-bool", false); err == nil || got {
		t.Fatalf("invalid arg: want false,error got %t,%v", got, err)
	} else {
		reqErr, ok := err.(types.RequestError)
		if !ok {
			t.Fatalf("invalid arg error type: got %T", err)
		}
		if reqErr.Code != http.StatusBadRequest {
			t.Fatalf("invalid arg status code: want %d got %d", http.StatusBadRequest, reqErr.Code)
		}
	}

	secret := "secret-token"
	body := []byte(`{"ref":"refs/heads/main"}`)
	valid := "sha256=" + hashPayload(secret, body)
	if err := validateSignature(secret, valid, body); err != nil {
		t.Fatalf("validateSignature valid: unexpected error %v", err)
	}
	if !validatePayload(secret, hashPayload(secret, body), body) {
		t.Fatalf("validatePayload: expected true")
	}
	if validatePayload(secret, "badhash", body) {
		t.Fatalf("validatePayload: expected false")
	}

	signatureTests := []struct {
		name      string
		signature string
		wantErr   string
	}{
		{name: "missing separator", signature: "abc", wantErr: "does not contain ="},
		{name: "wrong algorithm", signature: "sha1=abc", wantErr: "signature should be a 'sha256' hash"},
		{name: "wrong hash", signature: "sha256=abc", wantErr: "invalid payload"},
	}
	for _, tc := range signatureTests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSignature(secret, tc.signature, body)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error: want containing %q got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestRouterServeInternalAndWebhooksRegistration(t *testing.T) {
	handler := &Handler{}
	internal := handler.serveInternal(false)
	if internal == nil {
		t.Fatalf("internal router should not be nil")
	}

	internalReq := httptest.NewRequest(http.MethodGet, "http://example.com/does-not-exist", nil)
	internalRec := httptest.NewRecorder()
	internal.ServeHTTP(internalRec, internalReq)
	if internalRec.Code != http.StatusNotFound {
		t.Fatalf("internal unknown route status: want %d got %d", http.StatusNotFound, internalRec.Code)
	}

	webhooks := handler.serveWebhooks()
	if webhooks == nil {
		t.Fatalf("webhook router should not be nil")
	}

	for _, endpoint := range []string{"/reload", "/reload_promote", "/promote"} {
		req := httptest.NewRequest(http.MethodPost, "http://example.com"+endpoint, nil)
		rec := httptest.NewRecorder()
		webhooks.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status: want %d got %d", endpoint, http.StatusBadRequest, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "appPath is required") {
			t.Fatalf("%s body: unexpected %q", endpoint, rec.Body.String())
		}
	}
}
