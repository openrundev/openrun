// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
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

func TestGetRequestSchemeDefaultsToHTTP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "198.51.100.10:4321"
	req.Header.Set("X-Forwarded-Proto", "https")

	testutil.AssertEqualsString(t, "scheme", "http", GetRequestScheme(req, nil))
}

func TestGetRequestSchemeIgnoresHeaderFromUntrustedPeer(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "198.51.100.10:4321"
	req.Header.Set("X-Forwarded-Proto", "https")

	testutil.AssertEqualsString(t, "scheme", "http", GetRequestScheme(req, []string{"127.0.0.0/8"}))
}

func TestGetRequestSchemeHonorsHeaderFromTrustedProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	req.Header.Set("X-Forwarded-Proto", "https")

	testutil.AssertEqualsString(t, "scheme", "https", GetRequestScheme(req, []string{"127.0.0.0/8"}))
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
