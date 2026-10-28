// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"github.com/openrundev/openrun/internal/testutil"
)

// fakeACMEServer is a minimal ACME CA for exercising the client's order
// flow. It does not verify JWS signatures or solve challenges: every order
// is created "ready" with no authorizations and finalizes to a self-signed
// certificate. A new order whose "replaces" field is set is rejected with
// the alreadyReplaced problem, the way a CA answers an ARI renewal for a
// certificate that was already replaced once.
type fakeACMEServer struct {
	srv    *httptest.Server
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate

	mu          sync.Mutex
	orders      int      // newOrder requests received
	replaces    []string // the replaces field of each newOrder request
	finalized   int
	certsServed int
}

func newFakeACMEServer(t *testing.T) *fakeACMEServer {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testutil.AssertNoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake acme ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	testutil.AssertNoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	testutil.AssertNoError(t, err)

	f := &fakeACMEServer{caKey: caKey, caCert: caCert}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

// jwsPayload decodes the payload of the JWS envelope in the request body.
func jwsPayload(r *http.Request) ([]byte, error) {
	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(envelope.Payload)
}

func (f *fakeACMEServer) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (f *fakeACMEServer) writeProblem(w http.ResponseWriter, status int, problemType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": problemType, "detail": detail, "status": status})
}

func (f *fakeACMEServer) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
	base := f.srv.URL
	switch r.URL.Path {
	case "/dir":
		f.writeJSON(w, http.StatusOK, map[string]any{
			"newNonce":   base + "/new-nonce",
			"newAccount": base + "/new-account",
			"newOrder":   base + "/new-order",
			"revokeCert": base + "/revoke",
			"keyChange":  base + "/key-change",
		})
	case "/new-nonce":
		w.WriteHeader(http.StatusOK)
	case "/new-account":
		w.Header().Set("Location", base+"/account/1")
		f.writeJSON(w, http.StatusCreated, map[string]any{"status": "valid"})
	case "/new-order":
		payload, err := jwsPayload(r)
		if err != nil {
			f.writeProblem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", err.Error())
			return
		}
		var order struct {
			Identifiers []acme.Identifier `json:"identifiers"`
			Replaces    string            `json:"replaces"`
		}
		if err := json.Unmarshal(payload, &order); err != nil {
			f.writeProblem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", err.Error())
			return
		}
		f.mu.Lock()
		f.orders++
		f.replaces = append(f.replaces, order.Replaces)
		f.mu.Unlock()
		if order.Replaces != "" {
			f.writeProblem(w, http.StatusConflict, acme.ProblemTypeAlreadyReplaced,
				"certificate "+order.Replaces+" has already been replaced")
			return
		}
		w.Header().Set("Location", base+"/order/1")
		f.writeJSON(w, http.StatusCreated, map[string]any{
			"status":         "ready",
			"identifiers":    order.Identifiers,
			"authorizations": []string{},
			"finalize":       base + "/order/1/finalize",
		})
	case "/order/1/finalize":
		payload, err := jwsPayload(r)
		if err != nil {
			f.writeProblem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", err.Error())
			return
		}
		var body struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal(payload, &body); err != nil {
			f.writeProblem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", err.Error())
			return
		}
		if _, err := base64.RawURLEncoding.DecodeString(body.CSR); err != nil {
			f.writeProblem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:badCSR", err.Error())
			return
		}
		f.mu.Lock()
		f.finalized++
		f.mu.Unlock()
		w.Header().Set("Location", base+"/order/1")
		f.writeJSON(w, http.StatusOK, map[string]any{
			"status":      "valid",
			"finalize":    base + "/order/1/finalize",
			"certificate": base + "/cert/1",
		})
	case "/cert/1":
		f.mu.Lock()
		f.certsServed++
		f.mu.Unlock()
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			f.writeProblem(w, http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal", err.Error())
			return
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: "example.com"},
			DNSNames:     []string{"example.com"},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, f.caCert, &leafKey.PublicKey, f.caKey)
		if err != nil {
			f.writeProblem(w, http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw})
	default:
		f.writeProblem(w, http.StatusNotFound, "urn:ietf:params:acme:error:malformed", "unknown path "+r.URL.Path)
	}
}

// A renewal that names the certificate it replaces (ARI) can be rejected by
// the CA with alreadyReplaced when that certificate was already replaced,
// for example by a renewal whose result was lost before being stored. The
// ACME client must retry the order without the replaces field so that the
// renewal completes, instead of failing on every attempt until the
// certificate expires (caddyserver/certmagic#361)
func TestACMEClientRetriesAlreadyReplaced(t *testing.T) {
	ca := newFakeACMEServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := acmez.Client{Client: &acme.Client{
		Directory:  ca.srv.URL + "/dir",
		HTTPClient: ca.srv.Client(),
	}}
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testutil.AssertNoError(t, err)
	account, err := client.NewAccount(ctx, acme.Account{TermsOfServiceAgreed: true, PrivateKey: accountKey})
	testutil.AssertNoError(t, err)

	// The certificate being renewed: ARI identifies it by authority key id
	// and serial number
	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testutil.AssertNoError(t, err)
	oldTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	oldDER, err := x509.CreateCertificate(rand.Reader, oldTemplate, ca.caCert, &oldKey.PublicKey, ca.caKey)
	testutil.AssertNoError(t, err)
	oldCert, err := x509.ParseCertificate(oldDER)
	testutil.AssertNoError(t, err)

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testutil.AssertNoError(t, err)
	csr, err := acmez.NewCSR(certKey, []string{"example.com"})
	testutil.AssertNoError(t, err)
	params, err := acmez.OrderParametersFromCSR(account, csr)
	testutil.AssertNoError(t, err)
	params.Replaces = oldCert

	certs, err := client.ObtainCertificate(ctx, params)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "certificate chains", 1, len(certs))
	block, _ := pem.Decode(certs[0].ChainPEM)
	if block == nil {
		t.Fatal("expected PEM certificate in chain")
	}
	issued, err := x509.ParseCertificate(block.Bytes)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "issued cert name", "example.com", issued.DNSNames[0])

	ca.mu.Lock()
	defer ca.mu.Unlock()
	testutil.AssertEqualsInt(t, "order attempts", 2, ca.orders)
	if ca.replaces[0] == "" {
		t.Fatal("expected first order to carry the replaces field")
	}
	testutil.AssertEqualsString(t, "second order replaces", "", ca.replaces[1])
	testutil.AssertEqualsInt(t, "finalized orders", 1, ca.finalized)
	testutil.AssertEqualsInt(t, "certificates served", 1, ca.certsServed)
}
