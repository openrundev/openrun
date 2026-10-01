// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	saml2 "github.com/russellhaering/gosaml2"
)

const TestMetadataXML = `
<?xml
version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor entityID="http://www.okta.com/exkvzxe13p1NAy06x697" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>MIIDtDCCApygAwIBAgIGAZmhUie/MA0GCSqGSIb3DQEBCwUAMIGaMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxGzAZBgNVBAMMEmludGVncmF0b3ItMzM2Njk5MzEcMBoGCSqG
SIb3DQEJARYNaW5mb0Bva3RhLmNvbTAeFw0yNTEwMDExOTQ3NTlaFw0zNTEwMDExOTQ4NTlaMIGa
MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNj
bzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxGzAZBgNVBAMMEmludGVncmF0
b3ItMzM2Njk5MzEcMBoGCSqGSIb3DQEJARYNaW5mb0Bva3RhLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAKIe8sJMm9je/bnxS5VU+L2G+NzxNvuvDV9nUL694IfRc+I7HF50SzRO
LHnvTwnbr3Qn+SGr8ALsmBRp18M2Hl2Z/A013GXvzVVm/kd5/tEpUFC72igplooe33d2Lb73E1L7
5W17OMm4lVfr+qjRy1rziWQBflBpGcSXvmtDPHzw8+nSbF9sE8joRxUeaORShTbWDd5gE+Kxyn5o
SaTdUea68shn1rVTspygHGp/cuWE1sjdv4ucLL15dEexfxPfICTvweU7wculH+G5DDBNkwn/9ZXb
MovxCa7/plL1f+g5F7RwU8NAAvri8cAFg0HpsTbmZ1pHpKh6wk9p+BPdGHMCAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEAF8c/bwmMpvm56L2/dc6ibj5Bcbo3iV2Y7pVxHO4s5sE8KDfC/EtjmztN7mY4
fDk5bdLbqs+KE4gzRAYDbQh6E7SCGXq58uFQtxV5SZcVUgarN/kdw19vdSmQeJ6jSY1Cw1ZgUZ7G
+xCw3RWjcnag6N6+AcXJSvLjyflyAzlaM40WwlfPuU881xEI2rUGJt9/A5alyqfCRbirgNn9gp5L
WpMAX/ybz9KfNwBcc9vXyqsEDU2eq63v1tepFx+nNbYMLgwjX4IPqbvsvYrch7UR4AuCl3A6O2Dg
jIB7CjthniGJgrOycH3szloBKE/g9XlyCvtcML2fiwGep4WPlY0V/g==</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://integrator-3366993.okta.com/app/integrator-3366993_samlopen_1/exkvzxe13p1NAy06x697/sso/saml"/>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://integrator-3366993.okta.com/app/integrator-3366993_samlopen_1/exkvzxe13p1NAy06x697/sso/saml"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>
`

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

			logger := testutil.TestLogger()
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

			logger := testutil.TestLogger()
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

	logger := testutil.TestLogger()
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

func TestSAMLManager_Login_ProviderNotFound(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)
	manager.providers = make(map[string]*saml2.SAMLServiceProvider)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Test login with non-existent provider
	manager.login(w, req, "nonexistent", "http://example.com/redirect")

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	testutil.AssertEqualsInt(t, "status code", http.StatusNotFound, resp.StatusCode)
}

func TestSAMLManager_Login_Success(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)
	manager.providers = map[string]*saml2.SAMLServiceProvider{
		"saml_okta": {
			IdentityProviderSSOURL:      "https://idp.example.com/sso",
			IdentityProviderSSOBinding:  saml2.BindingHttpRedirect,
			AssertionConsumerServiceURL: "http://example.com/_openrun/sso/saml_okta/acs",
			ServiceProviderIssuer:       "http://example.com/_openrun/sso/saml_okta/metadata",
			AudienceURI:                 "http://example.com/_openrun/sso/saml_okta/metadata",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Test successful login initiation
	manager.login(w, req, "saml_okta", "http://example.com/redirect")

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	// Should redirect to IdP
	testutil.AssertEqualsInt(t, "status code", http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "https://idp.example.com/sso") {
		t.Errorf("expected redirect to IdP SSO URL, got: %s", location)
	}
}

func TestSAMLManager_Routes_Metadata(t *testing.T) {
	t.Parallel()

	// Start test HTTP server serving IDP metadata
	idpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(TestMetadataXML)) //nolint:errcheck
	}))
	defer idpServer.Close()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{
		Security: types.SecurityConfig{
			CallbackUrl: "http://example.com",
		},
		SAML: map[string]types.SAMLConfig{
			"okta": {
				MetadataURL: idpServer.URL,
				UsePost:     false,
				SPKeyFile:   "random", // Use random key for testing
			},
		},
	}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)

	// Setup the SAML provider using the test IDP metadata
	err := manager.Setup(context.Background())
	testutil.AssertNoError(t, err)

	// Create chi router and register routes
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	// Test SP metadata endpoint (generates our SP metadata based on IDP config)
	req := httptest.NewRequest(http.MethodGet, "/_openrun/sso/saml_okta/metadata", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	// Debug: print the response body if there's an error
	body := w.Body.String()
	if resp.StatusCode != http.StatusOK {
		t.Logf("Response body: %s", body)
	}

	testutil.AssertEqualsInt(t, "status code", http.StatusOK, resp.StatusCode)

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/samlmetadata+xml") {
		t.Errorf("expected Content-Type to contain 'application/samlmetadata+xml', got: %s", contentType)
	}

	// Verify the response body contains valid XML with expected elements
	if !strings.Contains(body, "EntityDescriptor") {
		t.Error("expected response to contain EntityDescriptor element")
	}
	if !strings.Contains(body, "SPSSODescriptor") {
		t.Error("expected response to contain SPSSODescriptor element")
	}
	if !strings.Contains(body, "AssertionConsumerService") {
		t.Error("expected response to contain AssertionConsumerService element")
	}
}

func TestSAMLManager_Routes_MetadataProviderNotFound(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)
	manager.providers = make(map[string]*saml2.SAMLServiceProvider)

	// Create chi router and register routes
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	// Test metadata endpoint with non-existent provider
	req := httptest.NewRequest(http.MethodGet, "/_openrun/sso/nonexistent/metadata", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	testutil.AssertEqualsInt(t, "status code", http.StatusNotFound, resp.StatusCode)
}

func TestSAMLManager_Routes_ACSMissingSAMLResponse(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)
	manager.providers = map[string]*saml2.SAMLServiceProvider{
		"saml_okta": {},
	}
	manager.providerConfigs = map[string]*types.SAMLConfig{
		"saml_okta": {},
	}

	// Create chi router and register routes
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	// Test ACS endpoint without SAMLResponse
	req := httptest.NewRequest(http.MethodPost, "/_openrun/sso/saml_okta/acs", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	testutil.AssertEqualsInt(t, "status code", http.StatusBadRequest, resp.StatusCode)
}

func TestSAMLManager_Routes_RedirectMissingRelay(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)

	// Create chi router and register routes
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	// Test redirect endpoint without relay parameter
	req := httptest.NewRequest(http.MethodGet, "/_openrun/sso/saml_okta/redirect", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	testutil.AssertEqualsInt(t, "status code", http.StatusBadRequest, resp.StatusCode)
}

func TestSAMLManager_Routes_RedirectSuccess(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)

	// Create chi router and register routes
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	// Store state in database
	sessionId := "saml_session_test123"
	stateMap := map[string]any{
		AUTH_KEY:          true,
		PROVIDER_NAME_KEY: "saml_okta",
		USER_KEY:          "user@example.com",
		GROUPS_KEY:        []any{"group1", "group2"},
		SESSION_INDEX_KEY: "session123",
		REDIRECT_URL:      "http://example.com/app",
		NONCE_KEY:         "nonce123",
	}
	err := db.StoreKV(context.Background(), sessionId, stateMap, nil)
	testutil.AssertNoError(t, err)

	// Create request with session cookie
	relayEncoded := "c2FtbF9zZXNzaW9uX3Rlc3QxMjM=" // base64 of "saml_session_test123"
	req := httptest.NewRequest(http.MethodGet, "/_openrun/sso/saml_okta/redirect?relay="+relayEncoded, nil)
	w := httptest.NewRecorder()

	// Set up session cookie with nonce
	session, err := cookieStore.Get(req, "saml_okta_openrun_saml_session")
	testutil.AssertNoError(t, err)
	session.Values[NONCE_KEY] = "nonce123"
	session.Values[REDIRECT_URL] = "http://example.com/app"
	err = session.Save(req, w)
	testutil.AssertNoError(t, err)

	// Copy cookies from response to request
	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}

	// Reset response writer
	w = httptest.NewRecorder()

	// Test successful redirect through router
	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	testutil.AssertEqualsInt(t, "status code", http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	testutil.AssertEqualsString(t, "redirect location", "http://example.com/app", location)

	// Verify session was deleted from database
	_, err = db.FetchKV(context.Background(), sessionId)
	if err == nil {
		t.Error("expected session to be deleted from database")
	}
}

func TestSAMLManager_Routes_RedirectNonceMismatch(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)

	// Create chi router and register routes
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	// Store state in database with one nonce
	sessionId := "saml_session_test456"
	stateMap := map[string]any{
		AUTH_KEY:          true,
		PROVIDER_NAME_KEY: "saml_okta",
		USER_KEY:          "user@example.com",
		GROUPS_KEY:        []any{"group1"},
		SESSION_INDEX_KEY: "session123",
		REDIRECT_URL:      "http://example.com/app",
		NONCE_KEY:         "nonce123",
	}
	err := db.StoreKV(context.Background(), sessionId, stateMap, nil)
	testutil.AssertNoError(t, err)

	// Create request with session cookie with different nonce
	relayEncoded := "c2FtbF9zZXNzaW9uX3Rlc3Q0NTY=" // base64 of "saml_session_test456"
	req := httptest.NewRequest(http.MethodGet, "/_openrun/sso/saml_okta/redirect?relay="+relayEncoded, nil)
	w := httptest.NewRecorder()

	// Set up session cookie with wrong nonce
	session, err := cookieStore.Get(req, "saml_okta_openrun_saml_session")
	testutil.AssertNoError(t, err)
	session.Values[NONCE_KEY] = "wrong_nonce"
	session.Values[REDIRECT_URL] = "http://example.com/app"
	err = session.Save(req, w)
	testutil.AssertNoError(t, err)

	// Copy cookies from response to request
	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}

	// Reset response writer
	w = httptest.NewRecorder()

	// Test redirect with nonce mismatch
	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	testutil.AssertEqualsInt(t, "status code", http.StatusInternalServerError, resp.StatusCode)
}

func TestSAMLManager_Routes_RedirectInvalidRelayBase64(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/_openrun/sso/saml_okta/redirect?relay=invalid!!!", nil)
	w := httptest.NewRecorder()

	session, err := cookieStore.Get(req, "saml_okta_openrun_saml_session")
	testutil.AssertNoError(t, err)
	session.Values[NONCE_KEY] = "nonce123"
	session.Values[REDIRECT_URL] = "http://example.com/app"
	err = session.Save(req, w)
	testutil.AssertNoError(t, err)

	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	testutil.AssertEqualsInt(t, "status code", http.StatusBadRequest, resp.StatusCode)
}

func TestSAMLManager_Routes_RedirectInvalidNonceType(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	sessionId := "saml_session_invalid_nonce"
	stateMap := map[string]any{
		AUTH_KEY:          true,
		PROVIDER_NAME_KEY: "saml_okta",
		USER_KEY:          "user@example.com",
		GROUPS_KEY:        []any{"group1"},
		SESSION_INDEX_KEY: "session123",
		REDIRECT_URL:      "http://example.com/app",
		NONCE_KEY:         "nonce123",
	}
	err := db.StoreKV(context.Background(), sessionId, stateMap, nil)
	testutil.AssertNoError(t, err)

	relayEncoded := "c2FtbF9zZXNzaW9uX2ludmFsaWRfbm9uY2U="
	req := httptest.NewRequest(http.MethodGet, "/_openrun/sso/saml_okta/redirect?relay="+relayEncoded, nil)
	w := httptest.NewRecorder()

	session, err := cookieStore.Get(req, "saml_okta_openrun_saml_session")
	testutil.AssertNoError(t, err)
	session.Values[NONCE_KEY] = []string{"nonce123"}
	session.Values[REDIRECT_URL] = "http://example.com/app"
	err = session.Save(req, w)
	testutil.AssertNoError(t, err)

	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	testutil.AssertEqualsInt(t, "status code", http.StatusBadRequest, resp.StatusCode)
}

func TestSAMLManager_Routes_RedirectInvalidStateProviderType(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	sessionId := "saml_session_invalid_provider"
	stateMap := map[string]any{
		AUTH_KEY:          true,
		PROVIDER_NAME_KEY: []any{"saml_okta"},
		USER_KEY:          "user@example.com",
		GROUPS_KEY:        []any{"group1"},
		SESSION_INDEX_KEY: "session123",
		REDIRECT_URL:      "http://example.com/app",
		NONCE_KEY:         "nonce123",
	}
	err := db.StoreKV(context.Background(), sessionId, stateMap, nil)
	testutil.AssertNoError(t, err)

	relayEncoded := "c2FtbF9zZXNzaW9uX2ludmFsaWRfcHJvdmlkZXI="
	req := httptest.NewRequest(http.MethodGet, "/_openrun/sso/saml_okta/redirect?relay="+relayEncoded, nil)
	w := httptest.NewRecorder()

	session, err := cookieStore.Get(req, "saml_okta_openrun_saml_session")
	testutil.AssertNoError(t, err)
	session.Values[NONCE_KEY] = "nonce123"
	session.Values[REDIRECT_URL] = "http://example.com/app"
	err = session.Save(req, w)
	testutil.AssertNoError(t, err)

	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	testutil.AssertEqualsInt(t, "status code", http.StatusBadRequest, resp.StatusCode)
}

func TestSAMLManager_Routes_LogoutProviderNotFound(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)
	manager.providers = make(map[string]*saml2.SAMLServiceProvider)

	// Create chi router and register routes
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	// Test logout endpoint with non-existent provider
	req := httptest.NewRequest(http.MethodPost, "/_openrun/sso/nonexistent/slo", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	testutil.AssertEqualsInt(t, "status code", http.StatusNotFound, resp.StatusCode)
}

func TestSAMLManager_Routes_LogoutNotAuthenticated(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)
	manager.providers = map[string]*saml2.SAMLServiceProvider{
		"saml_okta": {},
	}

	// Create chi router and register routes
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	// Create a session but not authenticated
	req := httptest.NewRequest(http.MethodPost, "/_openrun/sso/saml_okta/slo", nil)
	w := httptest.NewRecorder()

	session, err := cookieStore.Get(req, "saml_okta_openrun_saml_session")
	testutil.AssertNoError(t, err)
	session.Values[AUTH_KEY] = false
	err = session.Save(req, w)
	testutil.AssertNoError(t, err)

	// Copy cookies from response to request
	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}

	// Reset response writer
	w = httptest.NewRecorder()

	// Test logout when not authenticated (should return without error)
	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	// Should not error, just return (no redirect)
	testutil.AssertEqualsInt(t, "status code", http.StatusOK, resp.StatusCode)
}

func TestSAMLManager_Routes_LogoutSuccess(t *testing.T) {
	t.Parallel()

	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	db := NewInmemoryKVStore()

	manager := NewSAMLManager(logger, config, cookieStore, db)
	manager.providers = map[string]*saml2.SAMLServiceProvider{
		"saml_okta": {
			IdentityProviderSLOURL:     "", // No SLO URL
			IdentityProviderSLOBinding: saml2.BindingHttpRedirect,
		},
	}

	// Create chi router and register routes
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)

	// Create authenticated session
	req := httptest.NewRequest(http.MethodPost, "/_openrun/sso/saml_okta/slo", nil)
	w := httptest.NewRecorder()

	session, err := cookieStore.Get(req, "saml_okta_openrun_saml_session")
	testutil.AssertNoError(t, err)
	session.Values[AUTH_KEY] = true
	session.Values[USER_KEY] = "user@example.com"
	session.Values[SESSION_INDEX_KEY] = "session123"
	err = session.Save(req, w)
	testutil.AssertNoError(t, err)

	// Copy cookies from response to request
	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}

	// Reset response writer
	w = httptest.NewRecorder()

	// Test logout
	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close() //nolint:errcheck

	// Should redirect to root when no SLO URL
	testutil.AssertEqualsInt(t, "status code", http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	testutil.AssertEqualsString(t, "redirect location", "/", location)
}

func TestSAMLSessionAuth(t *testing.T) {
	t.Parallel()
	const user = "saml_okta:user@example.com"
	for _, tc := range []struct {
		name          string
		values        map[any]any
		user          string
		groups        []string
		err           string
		corrupt, htmx bool
	}{
		{name: "authenticated", values: map[any]any{GROUPS_KEY: []string{"developers", "admins"}}, user: user, groups: []string{"developers", "admins"}},
		{name: "string groups", values: map[any]any{GROUPS_KEY: []string{"group1", "group2"}}, user: user, groups: []string{"group1", "group2"}},
		{name: "any groups", values: map[any]any{GROUPS_KEY: []any{"group1", "group2"}}, user: user, groups: []string{"group1", "group2"}},
		{name: "mixed groups", values: map[any]any{GROUPS_KEY: []any{"group1", 123, "group2"}}, user: user, groups: []string{"group1", "group2"}},
		{name: "no groups", user: user, groups: []string{}},
		{name: "empty user", values: map[any]any{USER_KEY: ""}, err: "no user key in session"},
		{name: "missing user", values: map[any]any{USER_KEY: nil}, err: "no user key in session"},
		{name: "invalid cookie", corrupt: true},
		{name: "invalid HTMX cookie", corrupt: true, htmx: true},
		{name: "provider mismatch", values: map[any]any{PROVIDER_NAME_KEY: "saml_azure"}},
		{name: "missing authentication", values: map[any]any{AUTH_KEY: nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := "test-key-12345678901234567890123456"
			if tc.corrupt {
				key = "short"
			}
			store := sessions.NewCookieStore([]byte(key))
			manager := NewSAMLManager(testutil.TestLogger(), &types.ServerConfig{}, store, NewInmemoryKVStore())
			req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
			if tc.htmx {
				req.Header.Set("HX-Request", "true")
			}
			if tc.corrupt {
				req.AddCookie(&http.Cookie{Name: genSAMLCookieName("saml_okta"), Value: "invalid-cookie-value"})
			} else {
				manager.providers = map[string]*saml2.SAMLServiceProvider{"saml_okta": {}, "saml_azure": {}}
				session, err := store.Get(req, genSAMLCookieName("saml_okta"))
				testutil.AssertNoError(t, err)
				session.Values[AUTH_KEY], session.Values[PROVIDER_NAME_KEY], session.Values[USER_KEY] = true, "saml_okta", "user@example.com"
				for key, value := range tc.values {
					if value == nil {
						delete(session.Values, key)
					} else {
						session.Values[key] = value
					}
				}
				setup := httptest.NewRecorder()
				testutil.AssertNoError(t, session.Save(req, setup))
				for _, cookie := range setup.Result().Cookies() {
					req.AddCookie(cookie)
				}
			}
			w := httptest.NewRecorder()
			userID, groups, err := manager.CheckSAMLAuth(w, req, "saml_okta")
			if tc.err == "" {
				testutil.AssertNoError(t, err)
			} else {
				testutil.AssertErrorContains(t, err, tc.err)
			}
			testutil.AssertEqualsString(t, "user id", tc.user, userID)
			if !reflect.DeepEqual(groups, tc.groups) {
				t.Errorf("groups = %v, want %v", groups, tc.groups)
			}
			if tc.htmx && w.Header().Get("HX-Redirect") == "" {
				t.Error("expected HX-Redirect header")
			}
		})
	}
}
