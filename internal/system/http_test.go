// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestGetClientIPIgnoresUntrustedHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "198.51.100.10:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.Header.Set("X-Real-IP", "203.0.113.2")

	clientIP := GetClientIP(req, nil)
	testutil.AssertEqualsString(t, "client ip", "198.51.100.10", clientIP)
}

func TestGetClientIPUsesTrustedProxyHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	req.Header.Set("X-Forwarded-For", "198.51.100.20, 127.0.0.2")

	clientIP := GetClientIP(req, []string{"127.0.0.0/8"})
	testutil.AssertEqualsString(t, "client ip", "198.51.100.20", clientIP)
}

func TestGetClientIPFallsBackToXRealIPForTrustedProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	req.Header.Set("X-Real-IP", "198.51.100.30")

	clientIP := GetClientIP(req, []string{"127.0.0.1"})
	testutil.AssertEqualsString(t, "client ip", "198.51.100.30", clientIP)
}

func TestGetRequestSchemeIgnoresHeaderFromUntrustedPeer(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "198.51.100.10:4321"
	req.Header.Set("X-Forwarded-Proto", "https")

	testutil.AssertEqualsString(t, "scheme", "http", GetRequestScheme(req, []string{"127.0.0.0/8"}))
}

func TestGetRequestSchemeUsesFirstHeaderValue(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	req.Header.Set("X-Forwarded-Proto", "https, http")

	testutil.AssertEqualsString(t, "scheme", "https", GetRequestScheme(req, []string{"127.0.0.1"}))
}

func TestGetRequestSchemeRejectsBogusHeaderValue(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	req.Header.Set("X-Forwarded-Proto", "ftp")

	testutil.AssertEqualsString(t, "scheme", "http", GetRequestScheme(req, []string{"127.0.0.1"}))
}

func TestValidHostHeader(t *testing.T) {
	testCases := []struct {
		host string
		want bool
	}{
		{host: "example.com", want: true},
		{host: "example.com:8443", want: true},
		{host: "[2001:db8::1]:8443", want: true},
		{host: "example.com/health?x=", want: false},
		{host: "exa mple.com", want: false},
		{host: "", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.host, func(t *testing.T) {
			testutil.AssertEqualsBool(t, "valid host", tc.want, ValidHostHeader(tc.host))
		})
	}
}

func TestGetHostname(t *testing.T) {
	testCases := []struct {
		name string
		host string
		want string
	}{
		{name: "hostname", host: "example.com:8443", want: "example.com"},
		{name: "ipv4", host: "198.51.100.10:8443", want: "198.51.100.10"},
		{name: "ipv6 with port", host: "[2001:db8::1]:8443", want: "2001:db8::1"},
		{name: "ipv6 bracketed", host: "[2001:db8::1]", want: "2001:db8::1"},
		{name: "ipv6 bare", host: "2001:db8::1", want: "2001:db8::1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testutil.AssertEqualsString(t, "hostname", tc.want, GetHostname(tc.host))
		})
	}
}

func TestResponseErrorUnauthorizedExplainsCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	client := NewHttpClient(server.URL, "", false)
	err := client.Get("/_openrun/apps", nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	var reqErr types.RequestError
	if !errors.As(err, &reqErr) || reqErr.Code != http.StatusUnauthorized {
		t.Fatalf("expected a 401 RequestError, got %T %v", err, err)
	}
	for _, want := range []string{"Unauthorized: no credential for " + server.URL, "openrun login --server " + server.URL, "OPENRUN_API_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}

	client = NewHttpClient(server.URL, "orun_pat_stale", false)
	err = client.Get("/_openrun/apps", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized: "+server.URL+" rejected the credential.") {
		t.Errorf("expected a rejected credential error, got %v", err)
	}
}

func TestResponseErrorShapes(t *testing.T) {
	remote := NewHttpClient("https://example.com", "", false)
	local := NewHttpClient("./run/openrun.sock", "", false)
	for _, tc := range []struct {
		name   string
		client *HttpClient
		status int
		body   string
		want   string
		code   int
	}{
		{"request error json", remote, 403, `{"code": 403, "message": "user builtin:alice does not have permission app:create"}`, "user builtin:alice does not have permission app:create", 403},
		{"request error without code", remote, 400, `{"message": "bad glob"}`, "bad glob", 400},
		{"error document", remote, 500, `{"status": "failed", "error": "handler panicked"}`, "handler panicked", 500},
		{"plain body", remote, 404, "404 page not found\n", "404 page not found", 404},
		{"empty body", remote, 502, "", "Bad Gateway", 502},
		{"unix socket 401 keeps body", local, 401, "Unauthorized\n", "Unauthorized", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.client.ResponseError(tc.status, []byte(tc.body))
			var reqErr types.RequestError
			if !errors.As(err, &reqErr) {
				t.Fatalf("expected a RequestError, got %T %v", err, err)
			}
			testutil.AssertEqualsInt(t, "code", tc.code, reqErr.Code)
			testutil.AssertEqualsString(t, "message", tc.want, err.Error())
		})
	}
}

func TestTransportErrorNamesConfiguredServer(t *testing.T) {
	client := NewHttpClient(t.TempDir()+"/missing.sock", "", false)
	err := client.Get("/_openrun/apps", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot connect to the openrun server at ") || !strings.Contains(err.Error(), "openrun server start") {
		t.Errorf("expected a server-not-running hint, got %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedUrl := "http://" + listener.Addr().String()
	listener.Close() //nolint:errcheck
	err = NewHttpClient(closedUrl, "", false).Get("/_openrun/apps", nil, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "cannot connect to "+closedUrl+": ") || strings.Contains(err.Error(), "server start") {
		t.Errorf("expected a plain connect error for a remote server, got %v", err)
	}

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(tlsServer.Close)
	err = NewHttpClient(tlsServer.URL, "", false).Get("/_openrun/apps", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot verify the certificate of "+tlsServer.URL) || !strings.Contains(err.Error(), "skip_cert_check") {
		t.Errorf("expected a certificate hint, got %v", err)
	}
}
