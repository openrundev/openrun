// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/markbates/goth"
	"github.com/openrundev/openrun/internal/types"
)

// Failed password checks are counted per client IP: once the limit is
// reached, further checks from the IP are refused for the window, while
// other IPs are unaffected
func TestPasswordCheckRateLimit(t *testing.T) {
	limiter := newIPRateLimiter(time.Minute, rateLimiterMaxIPs)
	config := &types.ServerConfig{}
	config.Security.LoginFailureRateLimit = 3

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	other := httptest.NewRequest("GET", "/", nil)
	other.RemoteAddr = "192.0.2.2:1234"

	for i := range 3 {
		if !passwordCheckAllowed(limiter, config, req) {
			t.Fatalf("check %d refused before the limit", i)
		}
		recordPasswordFailure(limiter, config, req)
	}
	if passwordCheckAllowed(limiter, config, req) {
		t.Fatal("check allowed after the failure limit")
	}
	if !passwordCheckAllowed(limiter, config, other) {
		t.Fatal("another IP refused")
	}

	// A limit of 0 disables the check
	config.Security.LoginFailureRateLimit = 0
	if !passwordCheckAllowed(limiter, config, req) {
		t.Fatal("check refused with the limit disabled")
	}
}

func TestAzureVerifiedEmail(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		user     goth.User
		want     string
		isAzure  bool
	}{
		{"other provider", "github", goth.User{Email: "a@example.com"}, "", false},
		{"azuread mail ignored", "azuread", goth.User{UserID: "alice@corp.com", Email: "victim@corp.com"}, "alice@corp.com", true},
		{"azuread named instance", "azuread_corp", goth.User{UserID: "alice@corp.com", Email: "victim@corp.com"}, "alice@corp.com", true},
		{"microsoftonline named instance", "microsoftonline_work", goth.User{Email: "victim@corp.com",
			RawData: map[string]any{"userPrincipalName": "carol@corp.com"}}, "carol@corp.com", true},
		{"github named instance", "github_corp", goth.User{Email: "a@example.com"}, "", false},
		{"azuread upn", "azuread", goth.User{UserID: "alice@corp.com", Email: "alice@corp.com"}, "alice@corp.com", true},
		{"azuread guest", "azuread", goth.User{UserID: "bob_partner.com#EXT#@corp.onmicrosoft.com", Email: "bob@partner.com"}, "", true},
		{"azuread no upn", "azuread", goth.User{UserID: "", Email: "victim@corp.com"}, "", true},
		{"microsoftonline upn", "microsoftonline", goth.User{Email: "victim@corp.com",
			RawData: map[string]any{"userPrincipalName": "carol@corp.com"}}, "carol@corp.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, isAzure := azureVerifiedEmail(tt.provider, tt.user)
			if got != tt.want || isAzure != tt.isAzure {
				t.Fatalf("azureVerifiedEmail = %q %v, want %q %v", got, isAzure, tt.want, tt.isAzure)
			}
		})
	}
}

func TestRedactServiceConfig(t *testing.T) {
	got := redactServiceConfig(map[string]string{
		"url":          "postgres://admin:hunter2@db:5432/postgres",
		"password":     "hunter2",
		"ref":          `{{secret "pg_admin"}}`,
		"password_ref": `{{secret "pg_admin"}}`,
		"host":         "db",
	})
	if strings.Contains(got["url"], "hunter2") || !strings.Contains(got["url"], "admin") {
		t.Errorf("url password not redacted: %q", got["url"])
	}
	if got["password"] != RedactedValue {
		t.Errorf("password not redacted: %q", got["password"])
	}
	if got["password_ref"] != `{{secret "pg_admin"}}` || got["ref"] != `{{secret "pg_admin"}}` {
		t.Errorf("secret references should be kept: %v", got)
	}
	if got["host"] != "db" {
		t.Errorf("host changed: %q", got["host"])
	}

	if got := redactConnectionPassword("db:5432"); got != "db:5432" {
		t.Errorf("plain host:port changed: %q", got)
	}
	if got := redactConnectionPassword("postgres://admin:hunter2@db:5432/postgres?sslmode=disable"); got !=
		"postgres://admin@db:5432/postgres?"+RedactedValue {
		t.Errorf("url not rebuilt from its safe parts: %q", got)
	}
}

// Every PostgreSQL connection string form which pgx parses to a password
// must come out of the redaction without it. Each input is first checked to
// really carry the password for pgx, so the cases stay realistic (the second
// and third are the shapes a field by field redaction missed)
func TestRedactConnectionPasswordPostgres(t *testing.T) {
	for _, value := range []string{
		"postgres://admin:hunter2@db/postgres",
		"postgres://admin@db/postgres?password=hunter2",
		"postgres:///postgres?host=db&user=admin&%70assword=hunter2",
		"host=db user=admin password=hunter2 dbname=postgres",
		"host=db user=admin password=&hunter2 dbname=postgres",
		"host=db user=admin password='hunter2' dbname=postgres",
		"host=db user=admin password = hunter2",
	} {
		cfg, err := pgconn.ParseConfig(value)
		if err != nil || !strings.Contains(cfg.Password, "hunter2") {
			t.Fatalf("test input %q does not carry the password for pgx: %v", value, err)
		}
		redacted := redactConnectionPassword(value)
		if strings.Contains(redacted, "hunter2") {
			t.Errorf("password visible in %q: %q", value, redacted)
		}
		if cfg, err := pgconn.ParseConfig(redacted); err == nil && strings.Contains(cfg.Password, "hunter2") {
			t.Errorf("redacted %q still parses to the password", redacted)
		}
	}
	// Non postgres forms
	for _, value := range []string{
		"Server=db;User Id=admin;Password=hunter2;",
		"admin:hunter2@tcp(db:3306)/app",
		"redis://:hunter2@cache:6379/0",
	} {
		if redacted := redactConnectionPassword(value); strings.Contains(redacted, "hunter2") {
			t.Errorf("password visible in %q: %q", value, redacted)
		}
	}
}

func TestContainerIdRegex(t *testing.T) {
	for _, id := range []string{"abc123", "openrun-app_1.web", "3f2a9c"} {
		if !containerIdRegex.MatchString(id) {
			t.Errorf("valid id %q rejected", id)
		}
	}
	for _, id := range []string{"", "-f", "--format={{.}}", "a b", "../x", "a\nb"} {
		if containerIdRegex.MatchString(id) {
			t.Errorf("invalid id %q accepted", id)
		}
	}
}
