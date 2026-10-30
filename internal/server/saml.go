// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	saml2 "github.com/russellhaering/gosaml2"
	saml_types "github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAML auth using gosaml2 library. Standard SAML flow, using KV-backed gorilla
// sessions so browser cookies only carry opaque session ids.
// Two unusual situations are handled:
// 1. The SAML callback url is on domain a.com while the app is on b.com. The standard flow does not work since the ACS api (on a.com) cannot
//  set cookies on b.com. This is handled by having a redirect api on b.com which sets the cookies
// 2. There could be multiple OpenRun server instances. The metadata database is used to save the session info after the user is authenticated.
//  This db entry is used in the redirect api to create the cookies, and then db entry is deleted.

// The flow is
//  1. At service startup, SAMLServiceProvider is initialized
//  2. For apps using SAML, CheckSAMLAuth is called to check if the user is authenticated
//  3. CheckSAMLAuth verifies the session cookie to see if the user is authenticated. If yes, done
//  4. If the user is not authenticated, login function is called (API is currently on the app domain)
//  5. Login creates a sessionid and nonce. Saves entry in DB with sessionid as key and state map as value
//  6. Login creates a cookie with the nonce and redirect url. Redirects to the SAML provider's login page, with sessionid in RelayState
//  7. SAML provider's login page redirects to the ACS api on the callback domain, with sessionid in RelayState
//  8. ACS api validates the sessionid, deletes that DB entry and stores the state map with the user id and groups
//     info under a new short-lived sessionid (the pre-login sessionid is known to whoever started the flow)
//  9. ACS api redirects to the redirect API on the app domain, passing the new sessionid in the relay parameter
//  10. redirect API validates the passed sessionid, nonce from DB statemap against nonce from cookie,
//  11. redirect stores the authenticated session, with the user id and groups info and deletes the DB entry
//  12. Redirects back to original app url, which will again call CheckSAMLAuth and find the authenticated cookie
const SAML_AUTH_PREFIX = "saml_"

// Bound XML complexity before round-trip validation and signature processing.
// Byte limits alone do not bound the cost of documents with many tiny elements.
const maxSAMLXMLTokens = 10000

// SAMLManager manages the SAML providers and their configurations
type SAMLManager struct {
	*types.Logger
	config      *types.ServerConfig        // startup config: initial providers
	getConfig   func() *types.ServerConfig // current (dynamic) config for per-request settings
	cookieStore sessions.Store
	db          KVStore

	// redirectHostAllowed gates the host of the post-login redirect at the
	// ACS, see completionRedirectAllowed. Wired by NewServer
	redirectHostAllowed func(host string) bool
	// loginRate is the login start limiter shared with the other login
	// types, wired by NewServer
	loginRate *ipRateLimiter

	// providerMu guards the provider maps, which are replaced when dynamic
	// config entries add/change/remove saml providers at runtime
	providerMu      sync.RWMutex
	providerConfigs map[string]*types.SAMLConfig
	providers       map[string]*saml2.SAMLServiceProvider
}

func NewSAMLManager(logger *types.Logger, config *types.ServerConfig, cookieStore sessions.Store, db KVStore) *SAMLManager {
	return &SAMLManager{
		Logger:      logger,
		config:      config,
		getConfig:   func() *types.ServerConfig { return config },
		cookieStore: cookieStore,
		db:          db,
	}
}

func genSAMLCookieName(provider string) string {
	return fmt.Sprintf("%s_%s", provider, types.SAML_SESSION_COOKIE)
}

func (s *SAMLManager) Setup(ctx context.Context) error {
	return s.registerProviders(ctx, s.config.SAML, s.config.Security.CallbackUrl)
}

// registerProviders retains startup tolerance for unavailable IdP metadata.
func (s *SAMLManager) registerProviders(ctx context.Context, configs map[string]types.SAMLConfig, callbackUrl string) error {
	publish, err := s.prepareProviders(ctx, configs, callbackUrl, false)
	if err != nil {
		return err
	}
	publish()
	return nil
}

// prepareProviders builds the provider set without modifying live auth. Dynamic
// updates reject invalid providers; startup can disable unavailable providers.
// callbackUrl is the security.callback_url the SP endpoints live on (passed
// in: on a dynamic config change the new value is not yet the current config)
func (s *SAMLManager) prepareProviders(ctx context.Context, samlConfigs map[string]types.SAMLConfig, callbackUrl string, strict bool) (func(), error) {
	providerConfigs := make(map[string]*types.SAMLConfig)
	providers := make(map[string]*saml2.SAMLServiceProvider)
	if len(samlConfigs) > 0 && callbackUrl == "" {
		return nil, fmt.Errorf("security.callback_url must be set for enabling SAML")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var buildErrors []error
	for name, config := range samlConfigs {
		name = SAML_AUTH_PREFIX + name
		providerConfigs[name] = &config
		wg.Go(func() {
			provider, err := s.buildSAMLProvider(ctx, name, config, callbackUrl)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if strict {
					buildErrors = append(buildErrors, fmt.Errorf("error building SAML provider %s: %w", name, err))
				} else {
					s.Error().Err(err).Msgf("error building SAML provider for %s, provider disabled until reload", name)
				}
				return
			}
			providers[name] = provider
		})
	}
	wg.Wait()
	if err := errors.Join(buildErrors...); err != nil {
		return nil, err
	}
	return func() {
		s.providerMu.Lock()
		defer s.providerMu.Unlock()
		s.providerConfigs = providerConfigs
		s.providers = providers
	}, nil
}

// getProvider returns one registered SAML provider, nil if not configured or
// disabled by a build failure
func (s *SAMLManager) getProvider(providerName string) *saml2.SAMLServiceProvider {
	s.providerMu.RLock()
	defer s.providerMu.RUnlock()
	return s.providers[providerName]
}

// getProviderConfig returns the config for one registered SAML provider
func (s *SAMLManager) getProviderConfig(providerName string) *types.SAMLConfig {
	s.providerMu.RLock()
	defer s.providerMu.RUnlock()
	return s.providerConfigs[providerName]
}

func (s *SAMLManager) ValidateSAMLProvider(authType string) bool {
	providerName := strings.TrimPrefix(authType, rbac.RBAC_AUTH_PREFIX)
	return s.getProvider(providerName) != nil
}

// CheckSAMLAuth checks the SAML session for an app request; without a
// valid session the login flow is started, returning to the request URL
func (s *SAMLManager) CheckSAMLAuth(w http.ResponseWriter, r *http.Request, appProvider string) (string, []string, error) {
	return s.checkSAMLAuth(w, r, appProvider, system.GetRequestUrl(r, s.getConfig().Security.TrustedProxies))
}

// checkSAMLAuth is CheckSAMLAuth with an explicit post-login URL: the OAuth
// AS passes its config-built continue URL (oauth_federated.go), app
// requests pass the request URL (their host is validated by MatchApp)
func (s *SAMLManager) checkSAMLAuth(w http.ResponseWriter, r *http.Request, appProvider, requestUrl string) (string, []string, error) {
	cookieName := genSAMLCookieName(appProvider)

	session, err := s.cookieStore.Get(r, cookieName)
	if err != nil {
		s.Warn().Err(err).Msg("failed to get saml session")
		if session != nil {
			// delete the session
			session.Options.MaxAge = -1
			session.Save(r, w) //nolint:errcheck
		}

		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", requestUrl)
		} else {
			http.Redirect(w, r, requestUrl, http.StatusTemporaryRedirect)
		}
		return "", nil, nil
	}

	redirectCaller := false
	if auth, ok := session.Values[AUTH_KEY].(bool); !ok || !auth {
		// Store the target URL before redirecting to login
		s.Debug().Msg("no saml auth cookie, redirecting to login")
		redirectCaller = true
	}

	// Check if provider name matches the one in the session
	if providerName, ok := session.Values[PROVIDER_NAME_KEY].(string); !ok || providerName != appProvider {
		s.Warn().Msg("provider mismatch, redirecting to login")
		redirectCaller = true
	}

	if !redirectCaller && !sessionWithinAbsoluteLifetime(session, s.getConfig().Security.SessionAbsoluteMaxAge, time.Now()) {
		s.Debug().Msg("saml session past its absolute lifetime, redirecting to login")
		redirectCaller = true
	}

	if redirectCaller {
		// do the SAML login flow
		s.login(w, r, appProvider, requestUrl)
		return "", nil, nil
	}

	userId, ok := session.Values[USER_KEY].(string)
	if !ok || userId == "" {
		s.Warn().Msg("no user key in session")
		return "", nil, fmt.Errorf("no user key in session")
	}

	groups := make([]string, 0)
	if raw, ok := session.Values[GROUPS_KEY]; ok {
		if arr, ok := raw.([]string); ok {
			groups = arr
		} else if arr, ok := raw.([]any); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok {
					groups = append(groups, s)
				}
			}
		}
	}

	renewSession(s.Logger, w, r, session, s.getConfig().Security.SessionAbsoluteMaxAge) // sliding expiry

	return appProvider + ":" + userId, groups, nil
}

func buildSAMLUrl(baseUrl, providerName, endpoint string) string {
	baseUrl = strings.TrimSuffix(baseUrl, "/")
	return baseUrl + path.Join(types.INTERNAL_URL_PREFIX, "sso", providerName, endpoint)
}

func (s *SAMLManager) buildSAMLProvider(ctx context.Context, providerName string, config types.SAMLConfig, baseURL string) (*saml2.SAMLServiceProvider, error) {
	idp, err := s.fetchAndParseIDPMetadata(ctx, config.MetadataURL)
	if err != nil {
		return nil, fmt.Errorf("IdP metadata error: %w", err)
	}

	if baseURL == "" {
		return nil, fmt.Errorf("callback url is not set, required for SAML")
	}

	// Choose SSO URL and binding
	idpSSOURL := idp.SSO_Redirect
	idpSSOBinding := saml2.BindingHttpRedirect
	if config.UsePost {
		idpSSOURL = idp.SSO_POST
		idpSSOBinding = saml2.BindingHttpPost
	}
	if idpSSOURL == "" {
		// The IdP metadata does not advertise an SSO endpoint for the selected
		// binding. Failing here avoids emitting an AuthnRequest with an empty
		// destination (which loops the login back to the app) at request time.
		binding := "HTTP-Redirect"
		if config.UsePost {
			binding = "HTTP-POST"
		}
		return nil, fmt.Errorf("IdP metadata has no SSO endpoint for %s binding (set use_post appropriately)", binding)
	}

	// Choose SLO URL (optional)
	idpSLOURL := ""
	idpSLOBinding := ""
	if config.UsePost {
		if idp.SLO_POST != "" {
			idpSLOURL, idpSLOBinding = idp.SLO_POST, saml2.BindingHttpPost
		}
	}
	if idpSLOURL == "" && idp.SLO_Redirect != "" {
		idpSLOURL, idpSLOBinding = idp.SLO_Redirect, saml2.BindingHttpRedirect
	}

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:     idpSSOURL,
		IdentityProviderSSOBinding: idpSSOBinding,
		IdentityProviderSLOURL:     idpSLOURL,
		IdentityProviderSLOBinding: idpSLOBinding,
		IdentityProviderIssuer:     idp.Issuer,

		AssertionConsumerServiceURL: buildSAMLUrl(baseURL, providerName, "acs"),
		ServiceProviderSLOURL:       buildSAMLUrl(baseURL, providerName, "slo"),
		ServiceProviderIssuer:       buildSAMLUrl(baseURL, providerName, "metadata"),
		AudienceURI:                 buildSAMLUrl(baseURL, providerName, "metadata"),

		IDPCertificateStore:         idp.CertStore,
		AllowMissingAttributes:      true,
		MaximumDecompressedBodySize: 10 << 20,
		MaximumXMLTokens:            maxSAMLXMLTokens,
		ForceAuthn:                  config.ForceAuthn,
	}

	// Optional SP signing/encryption. The keypair is installed twice:
	// SetSPKeyStore feeds the signing context (any crypto.Signer), while the
	// SPKeyStore field is what gosaml2 reads to decrypt an EncryptedAssertion
	// and what the logout paths here check to decide whether to sign. With
	// only the setter, encrypted assertions fail with "no decryption certs
	// available" although the metadata advertises the encryption key
	if config.SPKeyFile == "random" {
		sp.SPKeyStore = dsig.RandomKeyStoreForTest()
		sp.SignAuthnRequests = true
	} else if config.SPKeyFile != "" && config.SPCertFile != "" {
		ks, kp, err := s.loadSPKeyStore(config.SPCertFile, config.SPKeyFile)
		if err != nil {
			return nil, fmt.Errorf("SP keypair error: %w", err)
		}
		if err := sp.SetSPKeyStore(ks); err != nil {
			return nil, fmt.Errorf("error setting SP key store: %w", err)
		}
		sp.SPKeyStore = dsig.TLSCertKeyStore(kp)
		sp.SignAuthnRequests = true
	}

	return sp, nil
}

func (s *SAMLManager) loadSPKeyStore(certPath, keyPath string) (*saml2.KeyStore, tls.Certificate, error) {
	kp, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("load sp keypair: %w", err)
	}
	signer, ok := kp.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, tls.Certificate{}, fmt.Errorf("SP private key does not implement crypto.Signer")
	}
	var leafDER []byte
	if len(kp.Certificate) > 0 {
		leafDER = kp.Certificate[0]
	}
	ks := &saml2.KeyStore{
		Signer: signer,
		Cert:   leafDER,
	}
	return ks, kp, nil
}

type idpConfig struct {
	Issuer       string
	SSO_Redirect string
	SSO_POST     string
	SLO_Redirect string
	SLO_POST     string
	CertStore    *dsig.MemoryX509CertificateStore
}

// maxIdPMetadataBytes bounds an IdP metadata document (a few certificates
// and endpoints; real documents are tens of kilobytes)
const maxIdPMetadataBytes = 4 << 20

// validateIdPEndpoint accepts an http(s) location for an IdP endpoint the
// browser is sent to
func validateIdPEndpoint(location string) error {
	parsed, err := url.Parse(location)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return fmt.Errorf("endpoint %q is not an http(s) url", location)
	}
	return nil
}

// samlMetadataTimeout bounds the IdP metadata fetch
const samlMetadataTimeout = 60 * time.Second

// fetchAndParseIDPMetadata fetches the IdP metadata document. The url is
// config:update settable, so the fetch refuses private or local targets
// unless security.sso_allow_private_hosts is set, and a non-200 response's
// body is not echoed into the error (which reaches the config update
// response), so the fetch cannot read an internal service for the caller
func (s *SAMLManager) fetchAndParseIDPMetadata(ctx context.Context, url string) (*idpConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, samlMetadataTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := ssoHTTPClient("SAML metadata", ssoAllowPrivateHosts(s.config), samlMetadataTimeout)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET metadata: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET metadata: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxIdPMetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read metadata: %w", err)
	}
	if len(raw) > maxIdPMetadataBytes {
		return nil, fmt.Errorf("metadata document larger than %d bytes", maxIdPMetadataBytes)
	}

	var ed saml_types.EntityDescriptor
	if err := xml.Unmarshal(raw, &ed); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	if ed.IDPSSODescriptor == nil {
		return nil, errors.New("metadata has no IDPSSODescriptor")
	}
	// gosaml2 treats an empty IdentityProviderIssuer as opting out of issuer
	// validation. Never let malformed metadata silently disable that check.
	ed.EntityID = strings.TrimSpace(ed.EntityID) // gosaml2 compares the issuer exactly
	if ed.EntityID == "" {
		return nil, errors.New("metadata has no entityID")
	}

	// Collect IdP certs
	cstore := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{}}
	for _, kd := range ed.IDPSSODescriptor.KeyDescriptors {
		// If Use is "signing" or empty (some IdPs omit), trust it for signature validation
		if kd.Use != "" && !strings.EqualFold(kd.Use, "signing") {
			continue
		}
		// Navigate KeyInfo -> X509Data -> X509Certificate(s)
		for _, xc := range kd.KeyInfo.X509Data.X509Certificates {
			if strings.TrimSpace(xc.Data) == "" {
				continue
			}
			der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(xc.Data))
			if err != nil {
				return nil, fmt.Errorf("decode X509Certificate: %w", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("parse X509Certificate: %w", err)
			}
			cstore.Roots = append(cstore.Roots, cert)
		}
	}

	if len(cstore.Roots) == 0 {
		return nil, errors.New("no IdP certificates found in metadata")
	}

	// Find SSO/SLO endpoints by binding. The browser is redirected or
	// posted to these locations, so only web urls are accepted
	var ssoRedirect, ssoPOST, sloRedirect, sloPOST string
	for _, s := range ed.IDPSSODescriptor.SingleSignOnServices {
		if err := validateIdPEndpoint(s.Location); err != nil {
			return nil, fmt.Errorf("SingleSignOnService: %w", err)
		}
		switch s.Binding {
		case saml2.BindingHttpRedirect:
			if ssoRedirect == "" {
				ssoRedirect = s.Location
			}
		case saml2.BindingHttpPost:
			if ssoPOST == "" {
				ssoPOST = s.Location
			}
		}
	}
	for _, s := range ed.IDPSSODescriptor.SingleLogoutServices {
		if err := validateIdPEndpoint(s.Location); err != nil {
			return nil, fmt.Errorf("SingleLogoutService: %w", err)
		}
		switch s.Binding {
		case saml2.BindingHttpRedirect:
			if sloRedirect == "" {
				sloRedirect = s.Location
			}
		case saml2.BindingHttpPost:
			if sloPOST == "" {
				sloPOST = s.Location
			}
		}
	}

	return &idpConfig{
		Issuer:       ed.EntityID,
		SSO_Redirect: ssoRedirect,
		SSO_POST:     ssoPOST,
		SLO_Redirect: sloRedirect,
		SLO_POST:     sloPOST,
		CertStore:    cstore,
	}, nil
}

func (s *SAMLManager) RegisterRoutes(mux *chi.Mux) {
	mux.Get(types.INTERNAL_URL_PREFIX+"/sso/{provider}/metadata", func(w http.ResponseWriter, r *http.Request) {
		s.metadata(w, r)
	})
	mux.Post(types.INTERNAL_URL_PREFIX+"/sso/{provider}/acs", func(w http.ResponseWriter, r *http.Request) {
		s.acs(w, r)
	})
	mux.Post(types.INTERNAL_URL_PREFIX+"/sso/{provider}/slo", func(w http.ResponseWriter, r *http.Request) {
		s.logout(w, r)
	})
	mux.Get(types.INTERNAL_URL_PREFIX+"/sso/{provider}/redirect", func(w http.ResponseWriter, r *http.Request) {
		s.redirect(w, r)
	})
}

// spMetadata builds the SP entity descriptor. gosaml2's builders both
// require an SP keypair (Metadata fails on the missing encryption
// certificate, MetadataWithSLO on the signing one, and the latter takes
// its validity in nanoseconds), so without keys the descriptor is built
// here. The SLO endpoint is listed either way: the slo handler reads the
// POST binding (SAMLRequest/SAMLResponse form fields)
func spMetadata(sp *saml2.SAMLServiceProvider) (*saml_types.EntityDescriptor, error) {
	var ed *saml_types.EntityDescriptor
	if sp.SPKeyStore != nil {
		var err error
		if ed, err = sp.Metadata(); err != nil {
			return nil, err
		}
	} else {
		ed = &saml_types.EntityDescriptor{
			ValidUntil: time.Now().UTC().Add(7 * 24 * time.Hour),
			EntityID:   sp.ServiceProviderIssuer,
			SPSSODescriptor: &saml_types.SPSSODescriptor{
				AuthnRequestsSigned:        sp.SignAuthnRequests,
				WantAssertionsSigned:       !sp.SkipSignatureValidation,
				ProtocolSupportEnumeration: saml2.SAMLProtocolNamespace,
				AssertionConsumerServices: []saml_types.IndexedEndpoint{{
					Binding:  saml2.BindingHttpPost,
					Location: sp.AssertionConsumerServiceURL,
					Index:    1,
				}},
			},
		}
	}
	if sp.ServiceProviderSLOURL != "" {
		ed.SPSSODescriptor.SingleLogoutServices = []saml_types.Endpoint{{
			Binding:  saml2.BindingHttpPost,
			Location: sp.ServiceProviderSLOURL,
		}}
	}
	return ed, nil
}

func (s *SAMLManager) metadata(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	sp := s.getProvider(providerName)
	if sp == nil {
		http.Error(w, fmt.Sprintf("provider %s not found", providerName), http.StatusNotFound)
		return
	}
	ed, err := spMetadata(sp)
	if err != nil {
		http.Error(w, "metadata error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(ed); err != nil {
		http.Error(w, "error encoding metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *SAMLManager) login(w http.ResponseWriter, r *http.Request, providerName, redirectUrl string) {
	sp := s.getProvider(providerName)
	if sp == nil {
		http.Error(w, fmt.Sprintf("provider %s not found", providerName), http.StatusNotFound)
		return
	}
	if !loginStartAllowed(s.loginRate, s.getConfig(), r) {
		tooManyLoginStarts(w)
		return
	}

	sessionId, nonce, err := passwd.GenerateSessionNonce()
	if err != nil {
		http.Error(w, "error generating session nonce: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sessionId = types.SAML_SESSION_KV_PREFIX + sessionId

	// Build the AuthnRequest up front so its ID can be persisted in the state
	// map and later enforced against the assertion's InResponseTo (anti-replay,
	// rejects unsolicited/IdP-injected assertions).
	// A signed request carries an enveloped XML signature only with the
	// POST binding; the Redirect binding signs the query string instead
	// (SAML bindings 3.4.4.1), done by BuildAuthURLRedirect below
	usePost := sp.IdentityProviderSSOBinding == saml2.BindingHttpPost
	var authDoc *etree.Document
	if sp.SignAuthnRequests && usePost {
		authDoc, err = sp.BuildAuthRequestDocument()
	} else {
		authDoc, err = sp.BuildAuthRequestDocumentNoSig()
	}
	if err != nil {
		http.Error(w, "auth request err: "+err.Error(), http.StatusInternalServerError)
		return
	}
	requestID := authDoc.Root().SelectAttrValue("ID", "")
	if requestID == "" {
		http.Error(w, "auth request missing ID", http.StatusInternalServerError)
		return
	}

	stateMap := make(map[string]any)
	stateMap[AUTH_KEY] = false
	stateMap[PROVIDER_NAME_KEY] = providerName
	stateMap[REDIRECT_URL] = redirectUrl
	stateMap[NONCE_KEY] = nonce
	stateMap[REQUEST_ID_KEY] = requestID

	// Store the state map in the database with the session id as the key
	expireAt := time.Now().Add(preAuthStateMaxAge)
	err = s.db.StoreKV(r.Context(), sessionId, stateMap, &expireAt)
	if err != nil {
		http.Error(w, "error storing state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cookieName := genSAMLCookieName(providerName)
	session, err := s.cookieStore.Get(r, cookieName)
	if err != nil {
		http.Error(w, "error getting session: "+err.Error(), http.StatusInternalServerError)
		if session != nil {
			session.Options.MaxAge = -1
			_ = session.Save(r, w)
		}
		return
	}

	// Save a cookie with the nonce (this is on the app domain, not the callback domain)
	session.Values[AUTH_KEY] = false
	session.Values[PROVIDER_NAME_KEY] = providerName
	session.Values[NONCE_KEY] = nonce
	session.Values[REDIRECT_URL] = redirectUrl
	session.Options.MaxAge = preAuthSessionMaxAge // short-lived until login completes
	if err := session.Save(r, w); err != nil {
		http.Error(w, "error saving session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// The relay state is the session id, encoded in base64
	relayState := base64.URLEncoding.EncodeToString([]byte(sessionId))
	if usePost {
		body, err := sp.BuildAuthBodyPostFromDocument(relayState, authDoc)
		if err != nil {
			http.Error(w, "auth body err: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err = w.Write(body)
		if err != nil {
			http.Error(w, "error writing auth body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}
	url, err := sp.BuildAuthURLRedirect(relayState, authDoc)
	if err != nil {
		http.Error(w, "auth url err: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", url)
	} else {
		http.Redirect(w, r, url, http.StatusFound)
	}
}

// samlGroups selects the group values of an assertion. A configured
// groups_attr is authoritative: a user without values in it has no groups,
// rather than whatever another attribute happens to hold. Without one the
// common attribute names are tried in order
func samlGroups(groupsAttr string, values saml2.Values) []string {
	if groupsAttr != "" {
		return values.GetAll(groupsAttr)
	}
	return firstNonEmpty(values.GetAll("groups"),
		values.GetAll("memberOf"),
		values.GetAll("roles"),
		values.GetAll("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"),
	)
}

func (s *SAMLManager) acs(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	sp := s.getProvider(providerName)
	if sp == nil {
		http.Error(w, fmt.Sprintf("provider %s not found", providerName), http.StatusNotFound)
		return
	}

	const maxACSBody = 10 << 20 // 10 MiB
	r.Body = http.MaxBytesReader(w, r.Body, maxACSBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	b64Response := r.PostFormValue("SAMLResponse")
	if b64Response == "" {
		http.Error(w, "missing SAMLResponse", http.StatusBadRequest)
		return
	}
	ai, err := sp.RetrieveAssertionInfo(b64Response)
	if err != nil {
		http.Error(w, "assertion invalid: "+err.Error(), http.StatusUnauthorized)
		return
	}

	if ai.WarningInfo.InvalidTime {
		http.Error(w, "assertion invalid time", http.StatusUnauthorized)
		return
	}

	if ai.WarningInfo.NotInAudience {
		http.Error(w, "assertion invalid audience", http.StatusUnauthorized)
		return
	}

	if ai.WarningInfo.OneTimeUse {
		// IdP explicitly marked the assertion for one-time use; we do not keep a
		// consumed-assertion cache, so reject rather than risk a replay.
		http.Error(w, "assertion marked one-time-use", http.StatusUnauthorized)
		return
	}

	// We consume one identity per login. Reject ambiguous assertion sets and
	// require an explicit audience (the library permits absent restrictions).
	if len(ai.Assertions) != 1 {
		http.Error(w, "expected exactly one assertion", http.StatusUnauthorized)
		return
	}
	assertion := &ai.Assertions[0]
	if assertion.Conditions == nil || len(assertion.Conditions.AudienceRestrictions) == 0 {
		http.Error(w, "assertion missing audience restriction", http.StatusUnauthorized)
		return
	}

	if ai.NameID == "" {
		// An empty NameID would produce an authenticated-but-unusable session
		// that returns an error on every subsequent request.
		http.Error(w, "assertion has empty NameID", http.StatusUnauthorized)
		return
	}

	config := s.getProviderConfig(providerName)
	if config == nil {
		http.Error(w, fmt.Sprintf("provider config %s not found", providerName), http.StatusNotFound)
		return
	}

	groups := samlGroups(config.GroupsAttr, ai.Values)

	if r.PostFormValue("RelayState") == "" {
		http.Error(w, "relay is required", http.StatusBadRequest)
		return
	}
	sessionIdBytes, err := base64.URLEncoding.DecodeString(r.PostFormValue("RelayState"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sessionId := string(sessionIdBytes)
	// The relay state is a keystore key: only a pre-login row of this flow
	// may be read and consumed through it, never a row of another namespace
	if !strings.HasPrefix(sessionId, types.SAML_SESSION_KV_PREFIX) {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}
	stateMap, err := s.db.FetchKV(r.Context(), sessionId)
	if err != nil {
		http.Error(w, "error fetching KV state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	stateProviderName, ok := stateValueString(stateMap, PROVIDER_NAME_KEY)
	if !ok || stateProviderName != providerName {
		http.Error(w, "error matching session state", http.StatusInternalServerError)
		return
	}
	auth, ok := stateValueBool(stateMap, AUTH_KEY)
	if !ok || auth {
		http.Error(w, "error matching session state, expected auth to be false", http.StatusInternalServerError)
		return
	}

	// Bind the signed assertion to this login. The library accepts unsigned
	// Response envelopes containing signed assertions, so the outer InResponseTo
	// alone is attacker-controlled and cannot prevent assertion replay.
	expectedRequestID, ok := stateValueString(stateMap, REQUEST_ID_KEY)
	if !ok || expectedRequestID == "" {
		http.Error(w, "error matching session state", http.StatusInternalServerError)
		return
	}
	if assertion.Subject == nil || assertion.Subject.SubjectConfirmation == nil ||
		assertion.Subject.SubjectConfirmation.SubjectConfirmationData == nil ||
		assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo != expectedRequestID {
		http.Error(w, "assertion InResponseTo mismatch", http.StatusUnauthorized)
		return
	}
	response, err := sp.ValidateEncodedResponse(b64Response)
	if err != nil {
		http.Error(w, "response invalid: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if response.InResponseTo != expectedRequestID {
		http.Error(w, "assertion InResponseTo mismatch", http.StatusUnauthorized)
		return
	}
	s.Trace().Str("user_id", ai.NameID).Str("provider_name", providerName).Msgf("authenticated saml user with groups %+v", groups)

	redirectUrl, ok := stateValueString(stateMap, REDIRECT_URL)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}

	if err := observeFederatedIdentity(r.Context(), s.db, providerName, ai.NameID, ai.NameID, "", groups); err != nil {
		s.Error().Err(err).Msg("error recording authenticated identity")
		http.Error(w, "error recording authenticated identity", http.StatusInternalServerError)
		return
	}

	redirectParsed, err := url.Parse(redirectUrl)
	if err != nil {
		http.Error(w, "error parsing relay: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !completionRedirectAllowed(redirectParsed, s.redirectHostAllowed) {
		s.Warn().Str("redirect", redirectUrl).Msg("login redirect names a host this server does not serve")
		http.Error(w, "error matching session state, redirect host not served", http.StatusBadRequest)
		return
	}

	// Mark the state authenticated under a NEW key. The pre-login relay state
	// is visible to whoever initiated the flow (it is in the AuthnRequest URL
	// or form that login sends the browser to), so it must not stay valid once
	// the IdP has vouched for a user: an attacker could start a login (keeping
	// the app-domain nonce cookie), hand the IdP link to a victim and, after
	// the victim authenticates, call redirect with the known relay to mint a
	// session under the victim's identity. The fresh completion token is only
	// ever sent to the browser that posted the assertion, and redirect
	// additionally requires the nonce cookie of the browser that initiated the
	// flow - in the legitimate flow the same browser holds both. Consuming the
	// old key first is the atomic gate: a replayed or concurrent ACS post for
	// the same relay cannot mint a second completion token
	consumed, err := s.db.DeleteKVIfPresent(r.Context(), sessionId)
	if err != nil {
		http.Error(w, "error updating state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !consumed {
		http.Error(w, "error matching session state, login already completed", http.StatusBadRequest)
		return
	}
	completeKey, err := passwd.GenerateRandomKey(24)
	if err != nil {
		http.Error(w, "error generating state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	completeId := types.SAML_SESSION_KV_PREFIX + base64.URLEncoding.EncodeToString(completeKey)
	stateMap[AUTH_KEY] = true
	stateMap[USER_KEY] = ai.NameID
	stateMap[GROUPS_KEY] = groups
	stateMap[SESSION_INDEX_KEY] = ai.SessionIndex
	expireAt := time.Now().Add(completeTokenMaxAge)
	if err := s.db.StoreKV(r.Context(), completeId, stateMap, &expireAt); err != nil {
		http.Error(w, "error storing state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	relayState := base64.URLEncoding.EncodeToString([]byte(completeId))

	// Redirect to the sso/redirect url on the original app domain, so that the required cookie can be set on the app domain
	redirectAppDomain := redirectParsed.Scheme + "://" + redirectParsed.Host + types.INTERNAL_URL_PREFIX + "/sso/" + providerName + "/redirect?relay=" + relayState
	http.Redirect(w, r, redirectAppDomain, http.StatusFound)
}

func (s *SAMLManager) redirect(w http.ResponseWriter, r *http.Request) {
	relayStr := r.URL.Query().Get("relay")
	if relayStr == "" {
		http.Error(w, "relay is required", http.StatusBadRequest)
		return
	}
	providerName := chi.URLParam(r, "provider")
	cookieName := genSAMLCookieName(providerName)
	session, err := s.cookieStore.Get(r, cookieName)
	if err != nil {
		http.Error(w, "error getting session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// A failed check leaves the session alone: this is a GET any site can
	// navigate to (the Lax cookie comes along), so deleting the session on
	// error would let a cross-site link log the user out; a stale pre-auth
	// cookie expires on its own
	nonceFromCookie, ok := sessionValueString(session, NONCE_KEY)
	if !ok {
		http.Error(w, "error matching session, nonce not found", http.StatusBadRequest)
		return
	}
	sessionIdBytes, err := base64.URLEncoding.DecodeString(relayStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sessionId := string(sessionIdBytes)
	if !strings.HasPrefix(sessionId, types.SAML_SESSION_KV_PREFIX) {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}

	// Get the state map, delete the entry from database, validate state, set the session values
	// in the cookie and then redirect to original url
	stateMap, err := s.db.FetchKV(r.Context(), sessionId)
	if err != nil {
		http.Error(w, "error fetching state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	auth, ok := stateMap[AUTH_KEY].(bool)
	if !ok {
		http.Error(w, "error matching session, auth not found", http.StatusInternalServerError)
		return
	}
	if !auth {
		http.Error(w, "error matching session, expected auth to be true", http.StatusInternalServerError)
		return
	}

	redirectUrl, ok := session.Values[REDIRECT_URL].(string)
	if !ok {
		http.Error(w, "error matching session, redirect url not found", http.StatusInternalServerError)
		return
	}

	stateProviderName, ok := stateValueString(stateMap, PROVIDER_NAME_KEY)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}
	stateRedirectURL, ok := stateValueString(stateMap, REDIRECT_URL)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}
	if stateProviderName != providerName || stateRedirectURL != redirectUrl {
		http.Error(w, "error matching session state", http.StatusInternalServerError)
		return
	}

	stateNonce, ok := stateValueString(stateMap, NONCE_KEY)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(stateNonce), []byte(nonceFromCookie)) != 1 {
		http.Error(w, "error matching session state, nonce mismatch", http.StatusInternalServerError)
		return
	}

	// Consume the single-use state entry only after the caller has proven (via the
	// nonce cookie) that it owns this login, so a leaked relay token alone cannot
	// delete another user's in-flight login state.
	consumed, err := s.db.DeleteKVIfPresent(r.Context(), sessionId)
	if err != nil {
		http.Error(w, "error deleting state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !consumed {
		http.Error(w, "error matching session state, login already completed", http.StatusBadRequest)
		return
	}

	// Update the session cookie to authenticated, with the new values
	userID, ok := stateValueString(stateMap, USER_KEY)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}
	groups, ok := stateValueStringSlice(stateMap, GROUPS_KEY)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}
	sessionIndex, ok := stateValueString(stateMap, SESSION_INDEX_KEY)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}
	// Rotate the session id on the unauthenticated->authenticated transition to
	// prevent session fixation (a fixated pre-auth cookie must not remain valid).
	session.ID = ""
	session.Values[AUTH_KEY] = true
	session.Values[USER_KEY] = userID
	session.Values[GROUPS_KEY] = groups
	session.Values[SESSION_INDEX_KEY] = sessionIndex
	delete(session.Values, REDIRECT_URL)
	delete(session.Values, NONCE_KEY)
	markSessionLogin(session, s.getConfig().Security.SessionAbsoluteMaxAge)
	if err = session.Save(r, w); err != nil {
		http.Error(w, "error saving session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectUrl, http.StatusFound)
}

// logout serves the SP SLO endpoint. It handles three cases: an IdP-initiated
// LogoutRequest (validated by signature, answered with a LogoutResponse), the
// IdP's LogoutResponse to an SP-initiated logout, and an app-initiated logout
// (same-origin only) that clears the session and optionally notifies the IdP.
func (s *SAMLManager) logout(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	sp := s.getProvider(providerName)
	if sp == nil {
		http.Error(w, fmt.Sprintf("provider %s not found", providerName), http.StatusNotFound)
		return
	}

	const maxSLOBody = 10 << 20 // 10 MiB
	r.Body = http.MaxBytesReader(w, r.Body, maxSLOBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// IdP-initiated Single Logout: validate the signed LogoutRequest before
	// acting, then reply with a LogoutResponse (not a fresh LogoutRequest).
	if samlRequest := r.PostFormValue("SAMLRequest"); samlRequest != "" {
		s.handleIdpLogoutRequest(w, r, sp, providerName, samlRequest)
		return
	}

	// IdP's response to an SP-initiated LogoutRequest: validate and finish.
	if samlResponse := r.PostFormValue("SAMLResponse"); samlResponse != "" {
		if _, err := sp.ValidateEncodedLogoutResponsePOST(samlResponse); err != nil {
			http.Error(w, "logout response invalid: "+err.Error(), http.StatusBadRequest)
			return
		}
		// App-initiated logout already cleared the local session before sending
		// the LogoutRequest. A response must not clear a newer login session.
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// App-initiated logout. This is a state-changing same-origin action, so
	// reject cross-site requests (logout CSRF defense); the IdP-driven cases
	// above authenticate via a signed message instead.
	if !isSameOriginRequest(r) {
		http.Error(w, "cross origin logout rejected", http.StatusForbidden)
		return
	}

	cookieName := genSAMLCookieName(providerName)
	session, err := s.cookieStore.Get(r, cookieName)
	if err != nil {
		http.Error(w, "error getting session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if auth, ok := session.Values[AUTH_KEY].(bool); !ok || !auth {
		return // no need to logout if not authenticated
	}

	nameID, _ := session.Values[USER_KEY].(string)
	sessionIndex, _ := session.Values[SESSION_INDEX_KEY].(string)

	// clear local session
	for k := range session.Values {
		delete(session.Values, k)
	}
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		http.Error(w, "error clearing session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// optional IdP SLO (front-channel)
	if sp.IdentityProviderSLOURL != "" && nameID != "" && sessionIndex != "" {
		// Sign only with an SP keypair: the signing path dereferences the
		// key store and panics without one
		// Like the AuthnRequest (login): an enveloped XML signature only
		// over the POST binding, the Redirect binding signs the query string
		var doc *etree.Document
		var err error
		signed := sp.SPKeyStore != nil
		redirectBinding := sp.IdentityProviderSLOBinding == saml2.BindingHttpRedirect
		if signed && !redirectBinding {
			doc, err = sp.BuildLogoutRequestDocument(nameID, sessionIndex)
		} else {
			doc, err = sp.BuildLogoutRequestDocumentNoSig(nameID, sessionIndex)
		}
		if err == nil {
			if redirectBinding {
				var url string
				if signed {
					// Signs the query string, which needs the SP keypair
					url, err = sp.BuildLogoutURLRedirect("", doc)
				} else {
					url, err = samlRedirectURL(sp.IdentityProviderSLOURL, doc)
				}
				if err == nil && url != "" {
					http.Redirect(w, r, url, http.StatusFound)
					return
				}
			}
			if body, err := sp.BuildLogoutBodyPostFromDocument("", doc); err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(body) //nolint:errcheck
				return
			}
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// samlRedirectURL encodes a SAML message for the unsigned HTTP-Redirect
// binding (deflate, base64, SAMLRequest query parameter) on the given
// endpoint. gosaml2's redirect builders always sign the query, which
// needs an SP keypair
func samlRedirectURL(endpoint string, doc *etree.Document) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	message, err := doc.WriteToString()
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write([]byte(message)); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// handleIdpLogoutRequest validates an IdP-initiated LogoutRequest and answers
// with a LogoutResponse addressed to the IdP's SLO endpoint.
func (s *SAMLManager) handleIdpLogoutRequest(w http.ResponseWriter, r *http.Request, sp *saml2.SAMLServiceProvider, providerName, encodedRequest string) {
	req, err := sp.ValidateEncodedLogoutRequestPOST(encodedRequest)
	if err != nil {
		http.Error(w, "logout request invalid: "+err.Error(), http.StatusBadRequest)
		return
	}
	// The library checks the signature, issuer and destination, not the
	// age: a captured request stays valid forever otherwise
	if skew := time.Since(req.IssueInstant); req.IssueInstant.IsZero() || skew > idpLogoutRequestMaxAge || skew < -idpLogoutRequestMaxAge {
		http.Error(w, "logout request invalid: IssueInstant outside the accepted window", http.StatusBadRequest)
		return
	}

	// Clear the local session (best effort; requires the browser cookie),
	// only when it belongs to the user the request names: a signed request
	// captured once could otherwise be replayed cross-site to log out
	// another user of the provider
	nameID := ""
	if req.NameID != nil {
		nameID = req.NameID.Value
	}
	s.clearSAMLSessionFor(w, r, providerName, nameID)

	var doc *etree.Document
	if sp.SPKeyStore != nil {
		doc, err = sp.BuildLogoutResponseDocument(saml2.StatusCodeSuccess, req.ID)
	} else {
		doc, err = sp.BuildLogoutResponseDocumentNoSig(saml2.StatusCodeSuccess, req.ID)
	}
	if err != nil {
		http.Error(w, "error building logout response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if sp.IdentityProviderSLOURL != "" {
		if body, err := sp.BuildLogoutResponseBodyPostFromDocument("", doc); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(body) //nolint:errcheck
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// idpLogoutRequestMaxAge bounds the age (and future skew) of an
// IdP-initiated LogoutRequest's IssueInstant
const idpLogoutRequestMaxAge = 10 * time.Minute

// clearSAMLSessionFor clears the local session when it is the one an IdP
// LogoutRequest names (same NameID); any other session is left alone
func (s *SAMLManager) clearSAMLSessionFor(w http.ResponseWriter, r *http.Request, providerName, nameID string) {
	session, err := s.cookieStore.Get(r, genSAMLCookieName(providerName))
	if err != nil || session.IsNew {
		return
	}
	user, _ := session.Values[USER_KEY].(string)
	if nameID == "" || user != nameID {
		s.Warn().Str("provider", providerName).Msg("IdP logout request names another user, local session kept")
		return
	}
	s.clearSAMLSession(w, r, providerName)
}

// clearSAMLSession removes the local SAML session cookie and its server-side row.
func (s *SAMLManager) clearSAMLSession(w http.ResponseWriter, r *http.Request, providerName string) {
	session, err := s.cookieStore.Get(r, genSAMLCookieName(providerName))
	if err != nil {
		return
	}
	for k := range session.Values {
		delete(session.Values, k)
	}
	session.Options.MaxAge = -1
	_ = session.Save(r, w)
}

// isSameOriginRequest reports whether a state-changing request originated from
// the same origin, using Sec-Fetch-Site when present and falling back to an
// Origin/Host comparison. Requests with no cross-origin signal are allowed,
// matching net/http's CrossOriginProtection default for non-browser clients.
// Like CrossOriginProtection, "same-site" counts as cross-origin: apps on
// sibling subdomains are separate origins (and separate trust domains), and
// a page on one must not be able to log the user out of another, which for
// SAML also starts the IdP single logout
func isSameOriginRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "cross-site", "same-site":
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func firstNonEmpty(slices ...[]string) []string {
	for _, s := range slices {
		if len(s) > 0 {
			return s
		}
	}
	return []string{}
}
