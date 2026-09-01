// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"os"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v2/acme"
	"github.com/openrundev/openrun/internal/types"
)

// acmeEnabled reports whether certmagic based automatic certificates are
// enabled. A custom ACME CA can be enabled without a service email since
// private CAs generally do not require one
func acmeEnabled(cfg *types.HttpsConfig) bool {
	return cfg.ServiceEmail != "" || cfg.ACMECAUrl != ""
}

// configureACMEIssuer applies the https config to the certmagic ACME issuer
// template. acme_ca_url takes precedence over the Let's Encrypt
// production/staging selection done through use_staging
func configureACMEIssuer(cfg *types.HttpsConfig, issuer *certmagic.ACMEIssuer) error {
	// The issuer template passed in is the shared certmagic.DefaultACME, so
	// every field derived from the config has to be set on all paths; a field
	// left alone keeps its certmagic default or a previously applied value
	issuer.TrustedRoots = nil
	issuer.ExternalAccount = nil

	switch {
	case cfg.ACMECAUrl != "":
		issuer.CA = cfg.ACMECAUrl
		// Certmagic retries against TestCA, which defaults to Let's Encrypt
		// staging; clear it so retries stay on the configured CA
		issuer.TestCA = ""
	case cfg.UseStaging:
		issuer.CA = certmagic.LetsEncryptStagingCA
		issuer.TestCA = certmagic.LetsEncryptStagingCA
	default:
		issuer.CA = certmagic.LetsEncryptProductionCA
		issuer.TestCA = certmagic.LetsEncryptStagingCA // retries use staging to avoid rate limits
	}

	if cfg.ACMECACert != "" {
		// The custom CA endpoint may be serving a cert the system trust
		// store does not know about
		roots, err := loadRootCAs(os.ExpandEnv(cfg.ACMECACert))
		if err != nil {
			return fmt.Errorf("error loading acme_ca_cert %s: %w", cfg.ACMECACert, err)
		}
		issuer.TrustedRoots = roots
	}

	if (cfg.ACMEEABKeyId == "") != (cfg.ACMEEABMacKey == "") {
		return fmt.Errorf("acme_eab_key_id and acme_eab_mac_key must be set together")
	}
	if cfg.ACMEEABKeyId != "" {
		issuer.ExternalAccount = &acme.EAB{
			KeyID:  cfg.ACMEEABKeyId,
			MACKey: cfg.ACMEEABMacKey,
		}
	}

	issuer.Agreed = true
	issuer.Email = cfg.ServiceEmail
	issuer.DisableHTTPChallenge = !cfg.EnableHTTPChallenge
	return nil
}
