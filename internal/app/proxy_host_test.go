// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import "testing"

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
