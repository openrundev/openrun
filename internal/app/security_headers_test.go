// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

func TestApplySecurityHeaders(t *testing.T) {
	tests := []struct {
		name    string
		level   int
		present map[string]string // header -> expected value
		absent  []string
	}{
		{
			name:   "level 0 adds nothing",
			level:  0,
			absent: []string{"X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security", "Content-Security-Policy"},
		},
		{
			name:   "level 1 rounds down to 0",
			level:  1,
			absent: []string{"X-Content-Type-Options", "X-Frame-Options"},
		},
		{
			name:  "level 2 baseline",
			level: 2,
			present: map[string]string{
				"X-Content-Type-Options": "nosniff",
				"X-Frame-Options":        "SAMEORIGIN",
				"Referrer-Policy":        "strict-origin-when-cross-origin",
			},
			absent: []string{"Strict-Transport-Security", "Content-Security-Policy", "Cross-Origin-Opener-Policy"},
		},
		{
			name:  "level 4 rounds down to 2",
			level: 4,
			present: map[string]string{
				"X-Frame-Options": "SAMEORIGIN",
			},
			absent: []string{"Strict-Transport-Security"},
		},
		{
			name:  "level 5 adds HSTS and stricter framing",
			level: 5,
			present: map[string]string{
				"X-Content-Type-Options":            "nosniff",
				"X-Frame-Options":                   "DENY",
				"Strict-Transport-Security":         "max-age=31536000; includeSubDomains",
				"Cross-Origin-Opener-Policy":        "same-origin",
				"X-Permitted-Cross-Domain-Policies": "none",
			},
			absent: []string{"Content-Security-Policy", "Cross-Origin-Embedder-Policy"},
		},
		{
			name:  "level 9 rounds down to 5",
			level: 9,
			present: map[string]string{
				"X-Frame-Options":           "DENY",
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
			},
			absent: []string{"Content-Security-Policy"},
		},
		{
			name:  "level 10 full strict set",
			level: 10,
			present: map[string]string{
				"X-Frame-Options":              "DENY",
				"Strict-Transport-Security":    "max-age=63072000; includeSubDomains; preload",
				"Content-Security-Policy":      "default-src 'self'",
				"Cross-Origin-Embedder-Policy": "require-corp",
				"Cross-Origin-Resource-Policy": "same-origin",
				"Permissions-Policy":           "geolocation=(), microphone=(), camera=()",
			},
		},
		{
			name:  "level above 10 treated as 10",
			level: 25,
			present: map[string]string{
				"Content-Security-Policy": "default-src 'self'",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			applySecurityHeaders(h, tt.level)
			for k, want := range tt.present {
				if got := h.Get(k); got != want {
					t.Errorf("header %q = %q, want %q", k, got, want)
				}
			}
			for _, k := range tt.absent {
				if got := h.Get(k); got != "" {
					t.Errorf("header %q = %q, want absent", k, got)
				}
			}
		})
	}
}

// TestSecurityHeaderWriterWithReverseProxy verifies that headers are applied
// at write time so upstream headers copied by httputil.ReverseProxy (which
// uses Add) override the defaults instead of producing duplicates.
func TestSecurityHeaderWriterWithReverseProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "ALLOWALL")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello")) //nolint:errcheck
	}))
	defer upstream.Close()

	upstreamUrl, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstreamUrl)

	recorder := httptest.NewRecorder()
	writer := &securityHeaderWriter{ResponseWriter: recorder, level: 2}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	proxy.ServeHTTP(writer, request)

	if got := recorder.Header().Values("X-Frame-Options"); len(got) != 1 || got[0] != "ALLOWALL" {
		t.Errorf("X-Frame-Options = %v, want single upstream value ALLOWALL", got)
	}
	if got := recorder.Header().Values("X-Content-Type-Options"); len(got) != 1 || got[0] != "nosniff" {
		t.Errorf("X-Content-Type-Options = %v, want single default nosniff", got)
	}
}

// TestSecurityHeaderWriterImplicitWriteHeader verifies headers are applied on
// the implicit WriteHeader triggered by the first Write
func TestSecurityHeaderWriterImplicitWriteHeader(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &securityHeaderWriter{ResponseWriter: recorder, level: 2}
	if _, err := writer.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestApplySecurityHeadersDoesNotOverrideExisting(t *testing.T) {
	h := http.Header{}
	h.Set("X-Frame-Options", "ALLOW-FROM https://example.com")
	h.Set("Content-Security-Policy", "default-src *")
	applySecurityHeaders(h, 10)

	// App-provided values should be preserved (set-if-absent), except X-Frame-Options
	// which levels 5+ deliberately force to DENY.
	if got := h.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY (forced at level>=5)", got)
	}
	if got := h.Get("Content-Security-Policy"); got != "default-src *" {
		t.Errorf("Content-Security-Policy = %q, want app value preserved", got)
	}
}
