// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/base64"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// A generated admin password must be usable: the hash has to land in the
// static config (what AdminBasicAuth checks against) and survive the dynamic
// config merge (what the form login session fingerprint reads). Regression
// test for the hash being written to the effective config only, which made
// the printed password fail with "hashedSecret too short"
func TestSetupAdminAccountGeneratedPasswordUsable(t *testing.T) {
	logger := testutil.TestLogger()
	static := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}
	s := &Server{Logger: logger, staticConfig: static}

	password, err := s.setupAdminAccount()
	if err != nil {
		t.Fatalf("setupAdminAccount: %v", err)
	}
	if password == "" {
		t.Fatal("expected a generated password")
	}
	if static.Security.AdminPasswordBcrypt == "" {
		t.Fatal("generated hash not written to the static config")
	}

	// Basic auth handler holds the static config
	auth := NewAdminBasicAuth(logger, static)
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:"+password))
	if !auth.authenticate(header) {
		t.Fatal("generated password rejected by basic auth")
	}
	wrong := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:not-the-password"))
	if auth.authenticate(wrong) {
		t.Fatal("wrong password accepted")
	}

	// The effective config (static + dynamic merge) must carry the hash, both
	// with no dynamic entries and after a merge with entries
	for _, dynamic := range []*types.DynamicConfig{
		{},
		{Settings: map[string]map[string]any{"system": {"default_domain": "example.com"}}},
	} {
		effective, err := mergeDynamicConfig(logger, static, dynamic, func(v string) (string, error) { return v, nil })
		if err != nil {
			t.Fatalf("mergeDynamicConfig: %v", err)
		}
		if effective.Security.AdminPasswordBcrypt != static.Security.AdminPasswordBcrypt {
			t.Fatal("generated hash missing from the effective config")
		}
		if _, ok := credentialFingerprint(effective, string(types.AppAuthnSystem), "admin"); !ok {
			t.Fatal("credential fingerprint not resolvable from the effective config")
		}
	}

	// A configured hash is left alone and no password is generated
	configured := &types.ServerConfig{GlobalConfig: types.GlobalConfig{AdminUser: "admin"}}
	configured.Security.AdminPasswordBcrypt = "$2a$10$configured"
	s = &Server{Logger: logger, staticConfig: configured}
	password, err = s.setupAdminAccount()
	if err != nil {
		t.Fatalf("setupAdminAccount: %v", err)
	}
	if password != "" || configured.Security.AdminPasswordBcrypt != "$2a$10$configured" {
		t.Fatal("configured hash must not be replaced")
	}
}
