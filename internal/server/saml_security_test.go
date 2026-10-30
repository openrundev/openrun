// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/go-chi/chi/v5"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestSAMLManager_SignedAssertionReplayAndLogoutValidation(t *testing.T) {
	const provider = "saml_audit"
	const acs = "https://sp.example/_openrun/sso/saml_audit/acs"
	const slo = "https://sp.example/_openrun/sso/saml_audit/slo"
	const issuer = "https://idp.example"
	const audience = "https://sp.example/metadata"
	ks := dsig.RandomKeyStoreForTest()
	_, der, err := ks.GetKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sp := &saml2.SAMLServiceProvider{IdentityProviderIssuer: issuer, AssertionConsumerServiceURL: acs, ServiceProviderSLOURL: slo, AudienceURI: audience, IDPCertificateStore: &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}, AllowMissingAttributes: true, MaximumDecompressedBodySize: 10 << 20, MaximumXMLTokens: maxSAMLXMLTokens}
	db := NewInmemoryKVStore()
	store := NewKVSessionStore(db, []byte("test-key-12345678901234567890123456"))
	manager := NewSAMLManager(testutil.TestLogger(), &types.ServerConfig{}, store, db)
	manager.providers = map[string]*saml2.SAMLServiceProvider{provider: sp}
	manager.providerConfigs = map[string]*types.SAMLConfig{provider: {}}
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)
	now := time.Now().UTC()
	assertion := etree.NewDocument()
	err = assertion.ReadFromString(fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion" Version="2.0" IssueInstant="%s"><saml:Issuer>%s</saml:Issuer><saml:Subject><saml:NameID>victim@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="%s" InResponseTo="_original_request" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>`, now.Format(time.RFC3339), issuer, acs, now.Add(time.Minute).Format(time.RFC3339), now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339), audience))
	if err != nil {
		t.Fatal(err)
	}
	signing := dsig.NewDefaultSigningContext(ks)
	signing.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := signing.SignEnveloped(assertion.Root())
	if err != nil {
		t.Fatal(err)
	}
	wrap := func(requestID string) string {
		doc := etree.NewDocument()
		err := doc.ReadFromString(fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>`, now.Format(time.RFC3339), acs, requestID, issuer))
		if err != nil {
			t.Fatal(err)
		}
		doc.Root().AddChild(signed.Copy())
		raw, err := doc.WriteToString()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// The relay state is a keystore key: a row of another namespace with the
	// same shape must not be read or consumed through the ACS, even with a
	// valid assertion
	foreign := types.FORM_LOGIN_KV_PREFIX + "_original_request"
	if err := db.StoreKV(context.Background(), foreign, map[string]any{AUTH_KEY: false, PROVIDER_NAME_KEY: provider,
		REQUEST_ID_KEY: "_original_request", REDIRECT_URL: "https://sp.example/app", NONCE_KEY: "n"}, nil); err != nil {
		t.Fatal(err)
	}
	foreignForm := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(wrap("_original_request")))},
		"RelayState": {base64.URLEncoding.EncodeToString([]byte(foreign))}}
	foreignReq := httptest.NewRequest("POST", acs, strings.NewReader(foreignForm.Encode()))
	foreignReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	foreignW := httptest.NewRecorder()
	mux.ServeHTTP(foreignW, foreignReq)
	if foreignW.Code != http.StatusBadRequest || !strings.Contains(foreignW.Body.String(), "error matching session state") {
		t.Fatalf("relay naming another namespace accepted: %d %s", foreignW.Code, foreignW.Body.String())
	}
	if _, ok := db.store[foreign]; !ok {
		t.Fatal("relay naming another namespace consumed its row")
	}

	var authenticatedCookies []*http.Cookie
	for _, requestID := range []string{"_original_request", "_different_request"} {
		stateID := types.SAML_SESSION_KV_PREFIX + requestID
		state := map[string]any{AUTH_KEY: false, PROVIDER_NAME_KEY: provider, REQUEST_ID_KEY: requestID, REDIRECT_URL: "https://sp.example/app", NONCE_KEY: "browser-owned-nonce"}
		if err := db.StoreKV(context.Background(), stateID, state, nil); err != nil {
			t.Fatal(err)
		}
		// nonceCookies mints the app-domain pre-login cookie session login
		// would have set for a browser starting this flow
		nonceCookies := func() []*http.Cookie {
			initial := httptest.NewRequest("GET", "https://sp.example/app", nil)
			cookieWriter := httptest.NewRecorder()
			session, err := store.Get(initial, genSAMLCookieName(provider))
			if err != nil {
				t.Fatal(err)
			}
			session.Values[NONCE_KEY] = "browser-owned-nonce"
			session.Values[REDIRECT_URL] = "https://sp.example/app"
			session.Values[PROVIDER_NAME_KEY] = provider
			if err := session.Save(initial, cookieWriter); err != nil {
				t.Fatal(err)
			}
			return cookieWriter.Result().Cookies()
		}
		browserCookies := nonceCookies()
		raw := wrap(requestID)
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))
		validated, err := sp.ValidateEncodedResponse(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if validated.SignatureValidated || !validated.Assertions[0].SignatureValidated {
			t.Fatal("fixture must have an unsigned envelope and a signed assertion")
		}
		form := url.Values{"SAMLResponse": {encoded}, "RelayState": {base64.URLEncoding.EncodeToString([]byte(stateID))}}
		req := httptest.NewRequest("POST", acs, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if requestID != "_original_request" {
			if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "assertion InResponseTo mismatch") {
				t.Fatalf("replayed assertion accepted: %d %s", w.Code, w.Body.String())
			}
			state, err := db.FetchKV(context.Background(), stateID)
			if err != nil {
				t.Fatal(err)
			}
			if state[AUTH_KEY] != false {
				t.Fatal("replay authenticated the new login state")
			}
			continue
		}
		if w.Code != http.StatusFound {
			t.Fatalf("ACS rejected: %d %s", w.Code, w.Body.String())
		}
		// The pre-login relay is known to whoever started the flow, so the ACS
		// must consume it and hand the browser a fresh completion token; the
		// leaked relay plus the initiator's nonce cookie must not mint a
		// session for the user the IdP vouched for (GHSA-rw93-hw9g-vc3m)
		location, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		originalRelay := base64.URLEncoding.EncodeToString([]byte(stateID))
		if relay := location.Query().Get("relay"); relay == "" || relay == originalRelay {
			t.Fatalf("relay not rotated by the ACS: %s", location)
		}
		if _, err := db.FetchKV(context.Background(), stateID); err == nil {
			t.Fatal("pre-login state survived the ACS")
		}
		// the attacker holds a nonce cookie of their own (they started the
		// flow); a rejected redirect drops that pre-login session, so it must
		// not be the one the legitimate completion below relies on
		attacker := httptest.NewRequest("GET", "https://sp.example/_openrun/sso/"+provider+"/redirect?relay="+originalRelay, nil)
		for _, cookie := range nonceCookies() {
			attacker.AddCookie(cookie)
		}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, attacker)
		if w.Code == http.StatusFound {
			t.Fatal("leaked pre-login relay minted a session")
		}
		replay := httptest.NewRequest("POST", acs, strings.NewReader(form.Encode()))
		replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, replay)
		if w.Code == http.StatusFound {
			t.Fatal("replayed ACS post with the consumed relay accepted")
		}
		redirect := httptest.NewRequest("GET", location.String(), nil)
		for _, cookie := range browserCookies {
			redirect.AddCookie(cookie)
		}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, redirect)
		if w.Code != http.StatusFound {
			t.Fatalf("redirect rejected: %d %s", w.Code, w.Body.String())
		}
		authenticatedCookies = w.Result().Cookies()
		check := httptest.NewRequest("GET", "https://sp.example/app", nil)
		for _, cookie := range authenticatedCookies {
			check.AddCookie(cookie)
		}
		user, _, err := manager.CheckSAMLAuth(httptest.NewRecorder(), check, provider)
		if err != nil || user != provider+":victim@example.com" {
			t.Fatalf("login failed: %s %v", user, err)
		}
	}
	tampered := strings.Replace(wrap("_different_request"), "victim@example.com", "admin@example.com", 1)
	if _, err := sp.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString([]byte(tampered))); err == nil {
		t.Fatal("tampered signed identity accepted")
	}
	commented := strings.Replace(wrap("_original_request"), "victim@example.com", "victim<!-- comment -->@example.com", 1)
	ai, err := sp.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString([]byte(commented)))
	if err != nil || ai.NameID != "victim@example.com" {
		t.Fatalf("comment behavior: %+v %v", ai, err)
	}
	unsignedLogout := fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="_never_issued"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>`, now.Format(time.RFC3339), slo, issuer)
	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(unsignedLogout))}}
	req := httptest.NewRequest("POST", slo, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	for _, cookie := range authenticatedCookies {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unsigned logout accepted: %d %s", w.Code, w.Body.String())
	}
	check := httptest.NewRequest("GET", "https://sp.example/app", nil)
	for _, cookie := range authenticatedCookies {
		check.AddCookie(cookie)
	}
	after, err := store.Get(check, genSAMLCookieName(provider))
	if err != nil {
		t.Fatal(err)
	}
	if after.Values[AUTH_KEY] != true {
		t.Fatal("unsigned logout cleared session")
	}

	// A delayed, valid response to an earlier logout must not clear a newer login.
	logoutDoc := etree.NewDocument()
	if err := logoutDoc.ReadFromString(unsignedLogout); err != nil {
		t.Fatal(err)
	}
	signedLogout, err := signing.SignEnveloped(logoutDoc.Root())
	if err != nil {
		t.Fatal(err)
	}
	logoutDoc.SetRoot(signedLogout)
	rawLogout, err := logoutDoc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	form.Set("SAMLResponse", base64.StdEncoding.EncodeToString(rawLogout))
	req = httptest.NewRequest("POST", slo, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range authenticatedCookies {
		req.AddCookie(cookie)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("signed logout response rejected: %d %s", w.Code, w.Body.String())
	}
	check = httptest.NewRequest("GET", "https://sp.example/app", nil)
	for _, cookie := range authenticatedCookies {
		check.AddCookie(cookie)
	}
	after, err = store.Get(check, genSAMLCookieName(provider))
	if err != nil {
		t.Fatal(err)
	}
	if after.Values[AUTH_KEY] != true {
		t.Fatal("delayed logout response cleared a newer session")
	}

	// Exercise application validation with cryptographically valid assertions.
	for _, tc := range []struct {
		name, reason string
		mutate       func(*etree.Element)
		duplicate    bool
		signResponse bool
		responseOnly bool
	}{
		{name: "signed response and assertion", signResponse: true},
		{name: "signed response only", signResponse: true, responseOnly: true},
		{name: "missing signed request", reason: "InResponseTo mismatch", mutate: func(el *etree.Element) {
			el.FindElement("./Subject/SubjectConfirmation/SubjectConfirmationData").RemoveAttr("InResponseTo")
		}},
		{name: "missing audience", reason: "missing audience restriction", mutate: func(el *etree.Element) {
			conditions := el.FindElement("./Conditions")
			conditions.RemoveChild(conditions.FindElement("./AudienceRestriction"))
		}},
		{name: "wrong audience", reason: "invalid audience", mutate: func(el *etree.Element) {
			el.FindElement("./Conditions/AudienceRestriction/Audience").SetText("https://another-sp.example")
		}},
		{name: "multiple signed assertions", reason: "exactly one assertion", duplicate: true},
		{name: "multiple assertions in signed response", reason: "exactly one assertion", duplicate: true, signResponse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateID := types.SAML_SESSION_KV_PREFIX + tc.name
			state := map[string]any{AUTH_KEY: false, PROVIDER_NAME_KEY: provider, REQUEST_ID_KEY: "_original_request", REDIRECT_URL: "https://sp.example/app", NONCE_KEY: "nonce"}
			if err := db.StoreKV(context.Background(), stateID, state, nil); err != nil {
				t.Fatal(err)
			}
			modified := assertion.Root().Copy()
			if tc.mutate != nil {
				tc.mutate(modified)
			}
			signed, err = signing.SignEnveloped(modified)
			if err != nil {
				t.Fatal(err)
			}
			doc := etree.NewDocument()
			if err := doc.ReadFromString(wrap("_original_request")); err != nil {
				t.Fatal(err)
			}
			if tc.duplicate {
				modified.CreateAttr("ID", "_second_assertion")
				second, err := signing.SignEnveloped(modified)
				if err != nil {
					t.Fatal(err)
				}
				doc.Root().AddChild(second)
			}
			if tc.responseOnly {
				assertion := doc.Root().FindElement("./Assertion")
				assertion.RemoveChild(assertion.FindElement("./Signature"))
			}
			if tc.signResponse {
				root, err := signing.SignEnveloped(doc.Root())
				if err != nil {
					t.Fatal(err)
				}
				doc.SetRoot(root)
			}
			raw, err := doc.WriteToBytes()
			if err != nil {
				t.Fatal(err)
			}
			form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(raw)}, "RelayState": {base64.URLEncoding.EncodeToString([]byte(stateID))}}
			req := httptest.NewRequest("POST", acs, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			wantStatus := http.StatusUnauthorized
			if tc.reason == "" {
				wantStatus = http.StatusFound
			}
			if w.Code != wantStatus || (tc.reason != "" && !strings.Contains(w.Body.String(), tc.reason)) {
				t.Fatalf("wanted %s, got %d %s", tc.reason, w.Code, w.Body.String())
			}
			remaining, err := db.FetchKV(context.Background(), stateID)
			if tc.reason == "" {
				// a successful ACS consumes the pre-login state and redirects
				// with a fresh, authenticated completion token
				if err == nil {
					t.Fatal("pre-login state survived a successful ACS")
				}
				location, err := url.Parse(w.Header().Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				completeID, err := base64.URLEncoding.DecodeString(location.Query().Get("relay"))
				if err != nil {
					t.Fatal(err)
				}
				complete, err := db.FetchKV(context.Background(), string(completeID))
				if err != nil || complete[AUTH_KEY] != true || complete[USER_KEY] != "victim@example.com" {
					t.Fatalf("completion state: %+v %v", complete, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if remaining[AUTH_KEY] != false {
				t.Fatal("rejected assertion authenticated the login state")
			}
		})
	}
}

func TestSAMLManager_XMLComplexityLimit(t *testing.T) {
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(TestMetadataXML)) }))
	defer metadata.Close()
	config := &types.ServerConfig{}
	config.Security.CallbackUrl = "https://sp.example"
	config.Security.SSOAllowPrivateHosts = true
	manager := NewSAMLManager(testutil.TestLogger(), config, nil, nil)
	sp, err := manager.buildSAMLProvider(context.Background(), "saml_audit", types.SAMLConfig{MetadataURL: metadata.URL, UsePost: true}, "https://sp.example")
	if err != nil {
		t.Fatal(err)
	}
	// About 14 KB XML, well below byte limits but above the complexity limit.
	raw := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` + strings.Repeat("<a/>", 3400) + `</samlp:Response>`
	var buf bytes.Buffer
	compressor, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = compressor.Write([]byte(raw))
	_ = compressor.Close()
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	_, err = sp.RetrieveAssertionInfo(encoded)
	if err == nil || !strings.Contains(err.Error(), "too many XML tokens") {
		t.Fatalf("expected complexity limit before signature checking, got %v", err)
	}
	for _, validate := range []func(string) error{
		func(s string) error { _, err := sp.ValidateEncodedLogoutResponsePOST(s); return err },
		func(s string) error { _, err := sp.ValidateEncodedLogoutRequestPOST(s); return err },
	} {
		if err := validate(encoded); err == nil || !strings.Contains(err.Error(), "too many XML tokens") {
			t.Fatalf("logout XML not bounded: %v", err)
		}
	}
}

func TestSAMLManager_RejectsEmptyEncryptedAssertion(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	key, _, err := ks.GetKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// Only the public key is needed to construct this unsigned message.
	wrappedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, make([]byte, 16), nil)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewSAMLManager(testutil.TestLogger(), &types.ServerConfig{}, nil, nil)
	manager.providers = map[string]*saml2.SAMLServiceProvider{"saml_audit": {SPKeyStore: ks, IDPCertificateStore: &dsig.MemoryX509CertificateStore{}, MaximumXMLTokens: maxSAMLXMLTokens}}
	mux := chi.NewRouter()
	manager.RegisterRoutes(mux)
	for _, algorithm := range []string{"http://www.w3.org/2009/xmlenc11#aes128-gcm", "http://www.w3.org/2001/04/xmlenc#aes128-cbc"} {
		t.Run(algorithm, func(t *testing.T) {
			raw := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_response"><saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:EncryptionMethod Algorithm="%s"/><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData><xenc:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></xenc:KeyInfo></xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>`, algorithm, base64.StdEncoding.EncodeToString(wrappedKey))
			form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(raw))}}
			req := httptest.NewRequest("POST", "https://sp.example/_openrun/sso/saml_audit/acs", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "encrypted data is smaller") {
				t.Fatalf("malformed ciphertext should return an error without panicking: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestSAMLMetadataRequiresIssuer(t *testing.T) {
	for _, entityID := range []string{"", "   "} {
		t.Run(fmt.Sprintf("entityID=%q", entityID), func(t *testing.T) {
			raw := strings.Replace(TestMetadataXML, `entityID="http://www.okta.com/exkvzxe13p1NAy06x697"`, `entityID="`+entityID+`"`, 1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(raw)) }))
			defer ts.Close()
			manager := NewSAMLManager(testutil.TestLogger(), ssoPrivateHostsConfig(), nil, nil)
			if _, err := manager.buildSAMLProvider(context.Background(), "saml_company", types.SAMLConfig{MetadataURL: ts.URL}, "https://sp.example"); err == nil || !strings.Contains(err.Error(), "entityID") {
				t.Fatalf("metadata disabled issuer validation: %v", err)
			}
		})
	}
	// Padding around the entityID is dropped, so the exact issuer comparison
	// made on every response matches what the IdP sends
	const entityID = "http://www.okta.com/exkvzxe13p1NAy06x697"
	raw := strings.Replace(TestMetadataXML, `entityID="`+entityID+`"`, `entityID="  `+entityID+`  "`, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(raw)) }))
	defer ts.Close()
	manager := NewSAMLManager(testutil.TestLogger(), ssoPrivateHostsConfig(), nil, nil)
	sp, err := manager.buildSAMLProvider(context.Background(), "saml_company", types.SAMLConfig{MetadataURL: ts.URL}, "https://sp.example")
	if err != nil {
		t.Fatal(err)
	}
	if sp.IdentityProviderIssuer != entityID {
		t.Fatalf("issuer %q not normalized", sp.IdentityProviderIssuer)
	}
}
