// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"path"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestAcmeEnabled(t *testing.T) {
	testutil.AssertEqualsBool(t, "disabled by default", false, acmeEnabled(&types.HttpsConfig{}))
	testutil.AssertEqualsBool(t, "enabled with email", true, acmeEnabled(&types.HttpsConfig{ServiceEmail: "a@example.com"}))
	testutil.AssertEqualsBool(t, "enabled with custom ca", true, acmeEnabled(&types.HttpsConfig{ACMECAUrl: "https://ca.internal/acme/directory"}))
}

func TestConfigureACMEIssuerLetsEncrypt(t *testing.T) {
	issuer := certmagic.ACMEIssuer{}
	cfg := types.HttpsConfig{ServiceEmail: "a@example.com", UseStaging: true}
	testutil.AssertNoError(t, configureACMEIssuer(&cfg, &issuer))
	testutil.AssertEqualsString(t, "staging ca", certmagic.LetsEncryptStagingCA, issuer.CA)
	testutil.AssertEqualsString(t, "staging test ca", certmagic.LetsEncryptStagingCA, issuer.TestCA)
	testutil.AssertEqualsString(t, "email", "a@example.com", issuer.Email)
	testutil.AssertEqualsBool(t, "agreed", true, issuer.Agreed)
	testutil.AssertEqualsBool(t, "http challenge disabled", true, issuer.DisableHTTPChallenge)
	if issuer.TrustedRoots != nil {
		t.Error("expected no trusted roots")
	}
	if issuer.ExternalAccount != nil {
		t.Error("expected no external account")
	}

	issuer = certmagic.ACMEIssuer{}
	cfg.UseStaging = false
	testutil.AssertNoError(t, configureACMEIssuer(&cfg, &issuer))
	testutil.AssertEqualsString(t, "production ca", certmagic.LetsEncryptProductionCA, issuer.CA)
	testutil.AssertEqualsString(t, "production test ca", certmagic.LetsEncryptStagingCA, issuer.TestCA)
}

func TestConfigureACMEIssuerCustomCA(t *testing.T) {
	issuer := certmagic.ACMEIssuer{}
	cfg := types.HttpsConfig{
		ACMECAUrl:  "https://ca.internal/acme/directory",
		UseStaging: true, // ignored when acme_ca_url is set
	}
	testutil.AssertNoError(t, configureACMEIssuer(&cfg, &issuer))
	testutil.AssertEqualsString(t, "custom ca", "https://ca.internal/acme/directory", issuer.CA)
	testutil.AssertEqualsString(t, "no test ca", "", issuer.TestCA)
	testutil.AssertEqualsString(t, "email", "", issuer.Email)
}

func TestConfigureACMEIssuerReapply(t *testing.T) {
	// The same issuer template (certmagic.DefaultACME in the server) can be
	// configured more than once; optional fields from a previous config must
	// not leak into the next one
	certDir := t.TempDir()
	certPath := path.Join(certDir, "root.crt")
	keyPath := path.Join(certDir, "root.key")
	testutil.AssertNoError(t, GenerateSelfSignedCertificate(certPath, keyPath, time.Hour))

	issuer := certmagic.ACMEIssuer{TestCA: certmagic.LetsEncryptStagingCA}
	cfg := types.HttpsConfig{
		ACMECAUrl:     "https://ca.internal/acme/directory",
		ACMECACert:    certPath,
		ACMEEABKeyId:  "key1",
		ACMEEABMacKey: "mac1",
	}
	testutil.AssertNoError(t, configureACMEIssuer(&cfg, &issuer))
	testutil.AssertEqualsString(t, "no test ca", "", issuer.TestCA)

	testutil.AssertNoError(t, configureACMEIssuer(&types.HttpsConfig{ServiceEmail: "a@example.com"}, &issuer))
	testutil.AssertEqualsString(t, "production ca", certmagic.LetsEncryptProductionCA, issuer.CA)
	testutil.AssertEqualsString(t, "test ca restored", certmagic.LetsEncryptStagingCA, issuer.TestCA)
	if issuer.TrustedRoots != nil {
		t.Error("expected trusted roots to be cleared")
	}
	if issuer.ExternalAccount != nil {
		t.Error("expected external account to be cleared")
	}
}

func TestConfigureACMEIssuerCACert(t *testing.T) {
	certDir := t.TempDir()
	certPath := path.Join(certDir, "root.crt")
	keyPath := path.Join(certDir, "root.key")
	testutil.AssertNoError(t, GenerateSelfSignedCertificate(certPath, keyPath, time.Hour))

	issuer := certmagic.ACMEIssuer{}
	cfg := types.HttpsConfig{ACMECAUrl: "https://ca.internal/acme/directory", ACMECACert: certPath}
	testutil.AssertNoError(t, configureACMEIssuer(&cfg, &issuer))
	if issuer.TrustedRoots == nil {
		t.Error("expected trusted roots to be set")
	}

	cfg.ACMECACert = path.Join(certDir, "missing.crt")
	err := configureACMEIssuer(&cfg, &certmagic.ACMEIssuer{})
	testutil.AssertErrorContains(t, err, "error loading acme_ca_cert")

	cfg.ACMECACert = keyPath // valid file, not a certificate
	err = configureACMEIssuer(&cfg, &certmagic.ACMEIssuer{})
	testutil.AssertErrorContains(t, err, "error loading acme_ca_cert")
}

func TestConfigureACMEIssuerEAB(t *testing.T) {
	issuer := certmagic.ACMEIssuer{}
	cfg := types.HttpsConfig{
		ACMECAUrl:     "https://ca.example.com/acme/directory",
		ACMEEABKeyId:  "key1",
		ACMEEABMacKey: "mac1",
	}
	testutil.AssertNoError(t, configureACMEIssuer(&cfg, &issuer))
	if issuer.ExternalAccount == nil {
		t.Fatal("expected external account to be set")
	}
	testutil.AssertEqualsString(t, "eab key id", "key1", issuer.ExternalAccount.KeyID)
	testutil.AssertEqualsString(t, "eab mac key", "mac1", issuer.ExternalAccount.MACKey)

	cfg.ACMEEABMacKey = ""
	err := configureACMEIssuer(&cfg, &certmagic.ACMEIssuer{})
	testutil.AssertErrorContains(t, err, "must be set together")
}

func TestConfigureACMEIssuerHTTPChallenge(t *testing.T) {
	// HTTP challenge works with Let's Encrypt (service_email only)
	issuer := certmagic.ACMEIssuer{}
	cfg := types.HttpsConfig{ServiceEmail: "a@example.com", EnableHTTPChallenge: true}
	testutil.AssertNoError(t, configureACMEIssuer(&cfg, &issuer))
	testutil.AssertEqualsString(t, "production ca", certmagic.LetsEncryptProductionCA, issuer.CA)
	testutil.AssertEqualsBool(t, "http challenge enabled", false, issuer.DisableHTTPChallenge)

	// and with a custom ACME CA
	issuer = certmagic.ACMEIssuer{}
	cfg = types.HttpsConfig{ACMECAUrl: "https://ca.internal/acme/directory", EnableHTTPChallenge: true}
	testutil.AssertNoError(t, configureACMEIssuer(&cfg, &issuer))
	testutil.AssertEqualsBool(t, "http challenge enabled", false, issuer.DisableHTTPChallenge)
}
