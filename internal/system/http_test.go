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
