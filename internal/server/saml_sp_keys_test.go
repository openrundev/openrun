// Copyright (c) OpenRun Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

// newSAMLTestManager builds a manager from the test IdP metadata with the
// given SP key settings and returns its router and provider
func newSAMLTestManager(t *testing.T, usePost bool, keyFile, certFile string) (*SAMLManager, *chi.Mux, *saml2.SAMLServiceProvider) {
	t.Helper()
	idpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(TestMetadataXML)) //nolint:errcheck
	}))
	t.Cleanup(idpServer.Close)
	config := &types.ServerConfig{
		Security: types.SecurityConfig{CallbackUrl: "https://sp.example", SSOAllowPrivateHosts: true},
		SAML: map[string]types.SAMLConfig{"okta": {
			MetadataURL: idpServer.URL, UsePost: usePost, SPKeyFile: keyFile, SPCertFile: certFile}},
	}
	cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
	manager := NewSAMLManager(testutil.TestLogger(), config, cookieStore, NewInmemoryKVStore())
	if err := manager.Setup(context.Background()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)
	return manager, mux, manager.getProvider("saml_okta")
}

// writeTestKeyPair writes a self-signed RSA certificate and key as PEM files
func writeTestKeyPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "sp.crt"), filepath.Join(dir, "sp.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func getSPMetadata(t *testing.T, mux *chi.Mux) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://sp.example/_openrun/sso/saml_okta/metadata", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("metadata: %d %s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// The SP metadata is served without an SP keypair (no key descriptors, the
// SLO endpoint listed) and with one (keys listed, validity in days)
func TestSAMLManager_MetadataWithAndWithoutSPKeys(t *testing.T) {
	t.Parallel()
	_, mux, sp := newSAMLTestManager(t, false, "", "")
	if sp.SPKeyStore != nil || sp.SignAuthnRequests {
		t.Fatal("no SP keypair expected")
	}
	body := getSPMetadata(t, mux)
	if strings.Contains(body, "KeyDescriptor") || !strings.Contains(body, `SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example/_openrun/sso/saml_okta/slo"`) {
		t.Fatalf("metadata without keys must list the SLO endpoint and no keys: %s", body)
	}

	certFile, keyFile := writeTestKeyPair(t)
	_, mux, sp = newSAMLTestManager(t, false, keyFile, certFile)
	if _, ok := sp.SPKeyStore.(dsig.TLSCertKeyStore); !ok || !sp.SignAuthnRequests {
		t.Fatalf("configured key files must install the decryption key store, got %T", sp.SPKeyStore)
	}
	body = getSPMetadata(t, mux)
	if !strings.Contains(body, `use="signing"`) || !strings.Contains(body, `use="encryption"`) ||
		!strings.Contains(body, "SingleLogoutService") || !strings.Contains(body, `AuthnRequestsSigned="true"`) {
		t.Fatalf("metadata with keys must list both key uses and the SLO endpoint: %s", body)
	}
	validUntil := strings.SplitN(strings.SplitN(body, `validUntil="`, 2)[1], `"`, 2)[0]
	until, err := time.Parse(time.RFC3339, validUntil)
	if err != nil || until.Before(time.Now().Add(24*time.Hour)) {
		t.Fatalf("validUntil must be days away, got %s (%v)", validUntil, err)
	}
}

func inflateSAMLRequest(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return string(inflated)
}

// A signed AuthnRequest over the Redirect binding signs the query string
// and carries no XML signature; over the POST binding it is enveloped
func TestSAMLManager_SignedAuthnRequestPerBinding(t *testing.T) {
	t.Parallel()
	_, _, sp := newSAMLTestManager(t, false, "random", "")
	manager := NewSAMLManager(testutil.TestLogger(), &types.ServerConfig{},
		sessions.NewCookieStore([]byte("test-key-12345678901234567890123456")), NewInmemoryKVStore())
	manager.providers = map[string]*saml2.SAMLServiceProvider{"saml_okta": sp}

	w := httptest.NewRecorder()
	manager.login(w, httptest.NewRequest(http.MethodGet, "https://sp.example/app", nil), "saml_okta", "https://sp.example/app")
	testutil.AssertEqualsInt(t, "redirect", http.StatusFound, w.Code)
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	if query.Get("SigAlg") == "" || query.Get("Signature") == "" {
		t.Fatalf("redirect binding must sign the query string: %s", location)
	}
	if request := inflateSAMLRequest(t, query.Get("SAMLRequest")); strings.Contains(request, "Signature") {
		t.Fatalf("redirect binding must not embed an XML signature: %s", request)
	}

	_, _, sp = newSAMLTestManager(t, true, "random", "")
	manager.providers = map[string]*saml2.SAMLServiceProvider{"saml_okta": sp}
	w = httptest.NewRecorder()
	manager.login(w, httptest.NewRequest(http.MethodGet, "https://sp.example/app", nil), "saml_okta", "https://sp.example/app")
	testutil.AssertEqualsInt(t, "post form", http.StatusOK, w.Code)
	encoded := html.UnescapeString(strings.SplitN(strings.SplitN(w.Body.String(), `name="SAMLRequest" value="`, 2)[1], `"`, 2)[0])
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !strings.Contains(string(raw), "SignatureValue") {
		t.Fatalf("post binding must embed the XML signature (%v): %s", err, raw)
	}
}

// Logout to an IdP SLO endpoint over the Redirect binding sends an unsigned
// LogoutRequest document; with an SP keypair the query string is signed,
// without one it is not (signing would dereference the missing key store)
func TestSAMLManager_LogoutRequestSigningFollowsSPKeys(t *testing.T) {
	t.Parallel()
	for _, keyFile := range []string{"", "random"} {
		_, _, sp := newSAMLTestManager(t, false, keyFile, "")
		sp.IdentityProviderSLOURL = "https://idp.example/slo"
		sp.IdentityProviderSLOBinding = saml2.BindingHttpRedirect
		cookieStore := sessions.NewCookieStore([]byte("test-key-12345678901234567890123456"))
		manager := NewSAMLManager(testutil.TestLogger(), &types.ServerConfig{}, cookieStore, NewInmemoryKVStore())
		manager.providers = map[string]*saml2.SAMLServiceProvider{"saml_okta": sp}
		mux := chi.NewRouter()
		manager.RegisterRoutes(mux)

		req := httptest.NewRequest(http.MethodPost, "https://sp.example/_openrun/sso/saml_okta/slo", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		w := httptest.NewRecorder()
		session, err := cookieStore.Get(req, "saml_okta_openrun_saml_session")
		if err != nil {
			t.Fatal(err)
		}
		session.Values[AUTH_KEY] = true
		session.Values[USER_KEY] = "user@example.com"
		session.Values[SESSION_INDEX_KEY] = "session123"
		if err := session.Save(req, w); err != nil {
			t.Fatal(err)
		}
		for _, cookie := range w.Result().Cookies() {
			req.AddCookie(cookie)
		}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusFound {
			t.Fatalf("key %q: logout %d %s", keyFile, w.Code, w.Body.String())
		}
		location, err := url.Parse(w.Header().Get("Location"))
		if err != nil || location.Host != "idp.example" || location.Query().Get("SAMLRequest") == "" {
			t.Fatalf("key %q: expected IdP logout redirect, got %s", keyFile, w.Header().Get("Location"))
		}
		// The Redirect binding signs the query string, never the XML
		request := inflateSAMLRequest(t, location.Query().Get("SAMLRequest"))
		if strings.Contains(request, "SignatureValue") {
			t.Fatalf("key %q: redirect binding must not embed an XML signature: %s", keyFile, request)
		}
		if querySigned := location.Query().Get("Signature") != ""; querySigned != (keyFile != "") {
			t.Fatalf("key %q: query signed=%v: %s", keyFile, querySigned, location)
		}
	}
}
