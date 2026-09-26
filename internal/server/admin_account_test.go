// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/base64"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// A generated admin password must be usable: its hash is computed in the
// background and must be what AdminBasicAuth checks against and what the form
// login session fingerprint reads, both directly and through the dynamic
// config merge (the effective config is a copy of the static one)
func TestSetupAdminAccountGeneratedPasswordUsable(t *testing.T) {
	logger := testutil.TestLogger()
	static := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}

	password, hash, err := setupAdminAccount(logger, static)
	if err != nil {
		t.Fatalf("setupAdminAccount: %v", err)
	}
	if password == "" {
		t.Fatal("expected a generated password")
	}
	if hash == nil {
		t.Fatal("expected a generated password hash")
	}
	if static.Security.AdminPasswordBcrypt != "" {
		t.Fatal("generated hash must not be written to the config")
	}

	// Basic auth handler holds the static config and the generated hash
	auth := NewAdminBasicAuth(logger, static)
	auth.generated = hash
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:"+password))
	if !auth.authenticate(header) {
		t.Fatal("generated password rejected by basic auth")
	}
	wrong := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:not-the-password"))
	if auth.authenticate(wrong) {
		t.Fatal("wrong password accepted")
	}

	// The form login fingerprint resolves through the handler, from the
	// effective config (static + dynamic merge), both with no dynamic entries
	// and after a merge with entries
	for _, dynamic := range []*types.DynamicConfig{
		{},
		{Settings: map[string]map[string]any{"system": {"default_domain": "example.com"}}},
	} {
		effective, err := mergeDynamicConfig(logger, static, dynamic, func(v string) (string, error) { return v, nil })
		if err != nil {
			t.Fatalf("mergeDynamicConfig: %v", err)
		}
		fp, ok := credentialFingerprint(effective, auth.passwordHash, string(types.AppAuthnSystem), "admin")
		if !ok || fp == "" {
			t.Fatal("credential fingerprint not resolvable from the effective config")
		}
		if _, ok := credentialFingerprint(effective, nil, string(types.AppAuthnSystem), "admin"); ok {
			t.Fatal("credential fingerprint must not resolve without the generated hash")
		}
	}

	// A configured hash is left alone, no password is generated and the
	// handler uses the configured hash
	configured := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}
	configured.Security.AdminPasswordBcrypt = "$2a$10$configured"
	password, hash, err = setupAdminAccount(logger, configured)
	if err != nil {
		t.Fatalf("setupAdminAccount: %v", err)
	}
	if password != "" || hash != nil || configured.Security.AdminPasswordBcrypt != "$2a$10$configured" {
		t.Fatal("configured hash must not be replaced")
	}
	if got := NewAdminBasicAuth(logger, configured).passwordHash(); got != "$2a$10$configured" {
		t.Fatalf("passwordHash = %q, want the configured hash", got)
	}

	// No admin user: nothing is generated and no hash is available
	noAdmin := &types.ServerConfig{}
	password, hash, err = setupAdminAccount(logger, noAdmin)
	if err != nil {
		t.Fatalf("setupAdminAccount: %v", err)
	}
	if password != "" || hash != nil {
		t.Fatal("no admin account expected without an admin user")
	}
	if got := NewAdminBasicAuth(logger, noAdmin).passwordHash(); got != "" {
		t.Fatalf("passwordHash = %q, want empty", got)
	}
}
