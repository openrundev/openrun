// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"net/url"
	"testing"
)

func TestCanonicalProxyHost(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		canonical string
		want      string
	}{
		{
			name:      "matching hostname is preserved",
			host:      "example.com:8443",
			canonical: "example.com",
			want:      "example.com:8443",
		},
		{
			name:      "mismatched hostname falls back to canonical (preserves client port)",
			host:      "attacker.example:8443",
			canonical: "example.com",
			want:      "example.com:8443",
		},
		{
			name:      "no canonical port and no client port returns bare canonical",
			host:      "attacker.example",
			canonical: "default.example",
			want:      "default.example",
		},
		{
			name:      "localhost alias matches 127.0.0.1",
			host:      "127.0.0.1:25222",
			canonical: "localhost",
			want:      "127.0.0.1:25222",
		},
		{
			name:      "ipv6 loopback aliases localhost",
			host:      "[::1]:25222",
			canonical: "localhost",
			want:      "[::1]:25222",
		},
		{
			name:      "localhost alias compare is case insensitive",
			host:      "Localhost:8080",
			canonical: "127.0.0.1",
			want:      "Localhost:8080",
		},
		{
			name:      "canonical port pins the port (matching host, wrong port)",
			host:      "example.com:443",
			canonical: "example.com:8443",
			want:      "example.com:8443",
		},
		{
			name:      "canonical port pins the port (mismatched host)",
			host:      "attacker.example:443",
			canonical: "example.com:8443",
			want:      "example.com:8443",
		},
		{
			name:      "bare ipv6 canonical is bracketed",
			host:      "attacker.example:443",
			canonical: "2001:db8::1",
			want:      "[2001:db8::1]:443",
		},
		{
			name:      "bracketed ipv6 canonical without port is not double bracketed",
			host:      "attacker.example:443",
			canonical: "[2001:db8::1]",
			want:      "[2001:db8::1]:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canonicalProxyHost(tt.host, tt.canonical); got != tt.want {
				t.Fatalf("canonicalProxyHost(%q, %q) = %q, want %q", tt.host, tt.canonical, got, tt.want)
			}
		})
	}
}

func TestRewriteProxyLocation(t *testing.T) {
	tests := []struct {
		name      string
		loc       string
		upstream  string
		stripPath string
		want      string
		wantOK    bool
	}{
		{
			name:     "absolute URL to upstream is stripped to path",
			loc:      "http://127.0.0.1:32899/app1/",
			upstream: "http://127.0.0.1:32899",
			want:     "/app1/",
			wantOK:   true,
		},
		{
			name:     "absolute URL host match is case insensitive",
			loc:      "http://Example.COM:8080/x",
			upstream: "http://example.com:8080",
			want:     "/x",
			wantOK:   true,
		},
		{
			name:     "absolute URL preserves query and fragment",
			loc:      "http://127.0.0.1:32899/x?a=1&b=2#frag",
			upstream: "http://127.0.0.1:32899",
			want:     "/x?a=1&b=2#frag",
			wantOK:   true,
		},
		{
			name:      "absolute URL re-prefixes stripPath",
			loc:       "http://127.0.0.1:32899/bar",
			upstream:  "http://127.0.0.1:32899",
			stripPath: "/app1",
			want:      "/app1/bar",
			wantOK:    true,
		},
		{
			name:     "absolute URL with empty path becomes root",
			loc:      "http://127.0.0.1:32899",
			upstream: "http://127.0.0.1:32899",
			want:     "/",
			wantOK:   true,
		},
		{
			name:     "absolute URL to a different host is left alone",
			loc:      "https://example.com/x",
			upstream: "http://127.0.0.1:32899",
			wantOK:   false,
		},
		{
			name:     "path-absolute Location without stripPath is left alone",
			loc:      "/foo",
			upstream: "http://127.0.0.1:32899",
			wantOK:   false,
		},
		{
			name:      "path-absolute Location is re-prefixed when stripPath is set",
			loc:       "/foo",
			upstream:  "http://127.0.0.1:32899",
			stripPath: "/app1",
			want:      "/app1/foo",
			wantOK:    true,
		},
		{
			name:      "path-absolute Location preserves query under stripPath",
			loc:       "/foo?x=1",
			upstream:  "http://127.0.0.1:32899",
			stripPath: "/app1",
			want:      "/app1/foo?x=1",
			wantOK:    true,
		},
		{
			name:      "stripPath of \"/\" is treated as no strip",
			loc:       "/foo",
			upstream:  "http://127.0.0.1:32899",
			stripPath: "/",
			wantOK:    false,
		},
		{
			name:     "truly relative Location is left alone",
			loc:      "foo/bar",
			upstream: "http://127.0.0.1:32899",
			wantOK:   false,
		},
		{
			name:     "empty path with query keeps query",
			loc:      "http://127.0.0.1:32899/?q=1",
			upstream: "http://127.0.0.1:32899",
			want:     "/?q=1",
			wantOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, err := url.Parse(tt.upstream)
			if err != nil {
				t.Fatalf("bad upstream %q: %v", tt.upstream, err)
			}
			got, ok := rewriteProxyLocation(tt.loc, upstream, tt.stripPath)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got=%q)", ok, tt.wantOK, got)
			}
			if ok && got != tt.want {
				t.Fatalf("rewriteProxyLocation(%q, %q, %q) = %q, want %q", tt.loc, tt.upstream, tt.stripPath, got, tt.want)
			}
		})
	}
}
