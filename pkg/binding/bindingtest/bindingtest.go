// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// Package bindingtest provides test helpers for binding provider tests.
package bindingtest

import (
	"net/url"
	"testing"
)

// AssertURL parses rawURL and asserts each component matches.
func AssertURL(t *testing.T, rawURL, scheme, host, user, password, path string, query map[string]string) {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", rawURL, err)
	}
	if u.Scheme != scheme {
		t.Fatalf("scheme = %q, want %q", u.Scheme, scheme)
	}
	if u.Host != host {
		t.Fatalf("host = %q, want %q", u.Host, host)
	}
	if u.User.Username() != user {
		t.Fatalf("user = %q, want %q", u.User.Username(), user)
	}
	if gotPassword, _ := u.User.Password(); gotPassword != password {
		t.Fatalf("password = %q, want %q", gotPassword, password)
	}
	if u.Path != path {
		t.Fatalf("path = %q, want %q", u.Path, path)
	}

	q := u.Query()
	if len(q) != len(query) {
		t.Fatalf("query length = %d, want %d; query = %v", len(q), len(query), q)
	}
	for key, want := range query {
		if got := q.Get(key); got != want {
			t.Fatalf("query[%s] = %q, want %q", key, got, want)
		}
	}
}
