// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"net/url"
	"testing"
)

func TestBuildPostgresAccountURLWithBindingHostname(t *testing.T) {
	accountURL, err := buildAccountURL("postgres://admin:secret@localhost:5432/appdb?sslmode=disable", "cl_role", "p@ss", "")
	if err != nil {
		t.Fatalf("buildAccountURL() error = %v", err)
	}
	assertURL(t, accountURL, "postgres", "localhost:5432", "cl_role", "p@ss", "/appdb", map[string]string{
		"sslmode": "disable",
	})

	bindingURL, err := buildAccountURL("postgres://admin:secret@localhost:5432/appdb?sslmode=disable", "cl_role", "p@ss", "host.docker.internal")
	if err != nil {
		t.Fatalf("buildAccountURL() with binding hostname error = %v", err)
	}
	assertURL(t, bindingURL, "postgres", "host.docker.internal:5432", "cl_role", "p@ss", "/appdb", map[string]string{
		"sslmode": "disable",
	})
}

func TestBuildMysqlAccountURLWithBindingHostname(t *testing.T) {
	accountURL, err := buildMysqlAccountURL("mysql://root:mysql@localhost:3306/?parseTime=true", "cl_user", "p@ss", "cl_db", "")
	if err != nil {
		t.Fatalf("buildMysqlAccountURL() error = %v", err)
	}
	assertURL(t, accountURL, "mysql", "localhost:3306", "cl_user", "p@ss", "/cl_db", map[string]string{
		"parseTime": "true",
	})

	bindingURL, err := buildMysqlAccountURL("mysql://root:mysql@localhost:3306/?parseTime=true", "cl_user", "p@ss", "cl_db", "host.docker.internal")
	if err != nil {
		t.Fatalf("buildMysqlAccountURL() with binding hostname error = %v", err)
	}
	assertURL(t, bindingURL, "mysql", "host.docker.internal:3306", "cl_user", "p@ss", "/cl_db", map[string]string{
		"parseTime": "true",
	})
}

func assertURL(t *testing.T, rawURL, scheme, host, user, password, path string, query map[string]string) {
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
