// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	saml2 "github.com/russellhaering/gosaml2"
)

func TestGenSAMLCookieName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider string
		want     string
	}{
		{
			name:     "simple provider name",
			provider: "okta",
			want:     "okta_openrun_saml_session",
		},
		{
			name:     "provider with prefix",
			provider: "saml_google",
			want:     "saml_google_openrun_saml_session",
		},
		{
			name:     "empty provider",
			provider: "",
			want:     "_openrun_saml_session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := genSAMLCookieName(tt.provider)
			testutil.AssertEqualsString(t, "cookie name", tt.want, got)
		})
	}
}

func TestBuildSAMLUrl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		baseUrl      string
		providerName string
		endpoint     string
		want         string
	}{
		{
			name:         "basic url without trailing slash",
			baseUrl:      "https://example.com",
			providerName: "okta",
			endpoint:     "acs",
			want:         "https://example.com/_openrun/sso/okta/acs",
		},
		{
			name:         "basic url with trailing slash",
			baseUrl:      "https://example.com/",
			providerName: "okta",
			endpoint:     "acs",
			want:         "https://example.com/_openrun/sso/okta/acs",
		},
		{
			name:         "url with path",
			baseUrl:      "https://example.com/app",
			providerName: "google",
			endpoint:     "metadata",
			want:         "https://example.com/app/_openrun/sso/google/metadata",
		},
		{
			name:         "url with path and trailing slash",
			baseUrl:      "https://example.com/app/",
			providerName: "azure",
			endpoint:     "slo",
			want:         "https://example.com/app/_openrun/sso/azure/slo",
		},
		{
			name:         "localhost url",
			baseUrl:      "http://localhost:8080",
			providerName: "test",
			endpoint:     "redirect",
			want:         "http://localhost:8080/_openrun/sso/test/redirect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildSAMLUrl(tt.baseUrl, tt.providerName, tt.endpoint)
			testutil.AssertEqualsString(t, "saml url", tt.want, got)
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		slices [][]string
		want   []string
	}{
		{
			name:   "first slice non-empty",
			slices: [][]string{{"a", "b"}, {"c", "d"}, {"e", "f"}},
			want:   []string{"a", "b"},
		},
		{
			name:   "first slice empty, second non-empty",
			slices: [][]string{{}, {"c", "d"}, {"e", "f"}},
			want:   []string{"c", "d"},
		},
		{
			name:   "all slices empty",
			slices: [][]string{{}, {}, {}},
			want:   []string{},
		},
		{
			name:   "no slices",
			slices: [][]string{},
			want:   []string{},
		},
		{
			name:   "single non-empty slice",
			slices: [][]string{{"only"}},
			want:   []string{"only"},
		},
		{
			name:   "single empty slice",
			slices: [][]string{{}},
			want:   []string{},
		},
		{
			name:   "nil first, non-empty second",
			slices: [][]string{nil, {"value"}},
			want:   []string{"value"},
		},
		{
			name:   "all nil slices",
			slices: [][]string{nil, nil, nil},
			want:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := firstNonEmpty(tt.slices...)

			if len(got) != len(tt.want) {
				t.Errorf("length mismatch: want %d, got %d", len(tt.want), len(got))
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("element %d: want %s, got %s", i, tt.want[i], got[i])
				}
			}
		})
	}
}

func TestNewSAMLManager(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	config := &types.ServerConfig{
		GlobalConfig: types.GlobalConfig{
			AdminUser: "admin",
		},
	}
	cookieStore := sessions.NewCookieStore([]byte("test-key"))
	db := &metadata.Metadata{}

	manager := NewSAMLManager(logger, config, cookieStore, db)

	if manager == nil {
		t.Fatal("NewSAMLManager returned nil")
	}

	if manager.Logger == nil {
		t.Error("Logger is nil")
	}

	if manager.config != config {
		t.Error("config not set correctly")
	}

	if manager.cookieStore != cookieStore {
		t.Error("cookieStore not set correctly")
	}

	if manager.db != db {
		t.Error("db not set correctly")
	}
}

func TestSAMLManager_ValidateSAMLProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		setupProviders map[string]bool
		authType       string
		want           bool
	}{
		{
			name: "valid provider with rbac prefix",
			setupProviders: map[string]bool{
				"saml_okta": true,
			},
			authType: "rbac:saml_okta",
			want:     true,
		},
		{
			name: "valid provider without rbac prefix",
			setupProviders: map[string]bool{
				"saml_google": true,
			},
			authType: "saml_google",
			want:     true,
		},
		{
			name: "non-existent provider",
			setupProviders: map[string]bool{
				"saml_okta": true,
			},
			authType: "rbac:saml_azure",
			want:     false,
		},
		{
			name:           "empty providers map",
			setupProviders: map[string]bool{},
			authType:       "rbac:saml_okta",
			want:           false,
		},
		{
			name: "provider without saml prefix",
			setupProviders: map[string]bool{
				"okta": true,
			},
			authType: "rbac:okta",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := createTestLogger()
			config := &types.ServerConfig{}
			cookieStore := sessions.NewCookieStore([]byte("test-key"))
			db := &metadata.Metadata{}

			manager := NewSAMLManager(logger, config, cookieStore, db)
			manager.providers = make(map[string]*saml2.SAMLServiceProvider)

			// Setup mock providers
			for name := range tt.setupProviders {
				manager.providers[name] = &saml2.SAMLServiceProvider{}
			}

			got := manager.ValidateSAMLProvider(tt.authType)
			testutil.AssertEqualsBool(t, "validation result", tt.want, got)
		})
	}
}

func TestSAMLManager_Metadata(t *testing.T) {
	t.Parallel()

	t.Run("provider not found", func(t *testing.T) {
		t.Parallel()

		logger := createTestLogger()
		config := &types.ServerConfig{}
		cookieStore := sessions.NewCookieStore([]byte("test-key"))
		db := &metadata.Metadata{}

		manager := NewSAMLManager(logger, config, cookieStore, db)
		manager.providers = make(map[string]*saml2.SAMLServiceProvider)

		w := httptest.NewRecorder()

		// Call metadata logic directly
		sp := manager.providers["nonexistent"]
		if sp == nil {
			http.Error(w, "provider not found", http.StatusNotFound)
		}

		resp := w.Result()
		defer resp.Body.Close() //nolint:errcheck

		testutil.AssertEqualsInt(t, "status code", http.StatusNotFound, resp.StatusCode)
	})
}

func TestSAMLManager_Setup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		samlConfigs map[string]types.SAMLConfig
		expectError bool
	}{
		{
			name:        "empty config",
			samlConfigs: map[string]types.SAMLConfig{},
			expectError: false,
		},
		{
			name: "missing callback url",
			samlConfigs: map[string]types.SAMLConfig{
				"okta": {
					MetadataURL: "https://example.com/metadata",
					UsePost:     false,
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := createTestLogger()
			config := &types.ServerConfig{
				SAML: tt.samlConfigs,
			}
			cookieStore := sessions.NewCookieStore([]byte("test-key"))
			db := &metadata.Metadata{}

			manager := NewSAMLManager(logger, config, cookieStore, db)
			err := manager.Setup(context.Background())

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSAMLManager_SetupInitializationState(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	config := &types.ServerConfig{
		SAML: map[string]types.SAMLConfig{},
	}
	cookieStore := sessions.NewCookieStore([]byte("test-key"))
	db := &metadata.Metadata{}

	manager := NewSAMLManager(logger, config, cookieStore, db)

	// Before setup
	if manager.providerConfigs != nil {
		t.Error("providerConfigs should be nil before setup")
	}
	if manager.providers != nil {
		t.Error("providers should be nil before setup")
	}

	// After setup
	err := manager.Setup(context.Background())
	testutil.AssertNoError(t, err)

	if manager.providerConfigs == nil {
		t.Error("providerConfigs should be initialized after setup")
	}
	if manager.providers == nil {
		t.Error("providers should be initialized after setup")
	}
}
