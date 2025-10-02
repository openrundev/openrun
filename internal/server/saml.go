// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto"
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
	"time"

	"github.com/go-chi/chi"
	"github.com/gorilla/sessions"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	saml2 "github.com/russellhaering/gosaml2"
	saml_types "github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

const SAML_AUTH_PREFIX = "saml_"

// SAMLManager manages the SAML providers and their configurations
type SAMLManager struct {
	*types.Logger
	config          *types.ServerConfig
	providerConfigs map[string]*types.SAMLConfig
	providers       map[string]*saml2.SAMLServiceProvider
	cookieStore     *sessions.CookieStore
}

func NewSAMLManager(logger *types.Logger, config *types.ServerConfig, cookieStore *sessions.CookieStore) *SAMLManager {
	return &SAMLManager{
		Logger:      logger,
		config:      config,
		cookieStore: cookieStore,
	}
}

func genSAMLCookieName(provider string) string {
	return fmt.Sprintf("%s_openrun_saml_session", provider)
}

func (s *SAMLManager) Setup(ctx context.Context) error {
	s.providerConfigs = make(map[string]*types.SAMLConfig)
	s.providers = make(map[string]*saml2.SAMLServiceProvider)
	for name, config := range s.config.SAML {
		name = SAML_AUTH_PREFIX + name
		s.providerConfigs[name] = &config
		provider, err := s.buildSAMLProvider(ctx, name, config)
		if err != nil {
			return fmt.Errorf("error building SAML provider for %s: %w", name, err)
		}
		s.providers[name] = provider
	}

	return nil
}

func (s *SAMLManager) ValidateSAMLProvider(authType string) bool {
	providerName := strings.TrimPrefix(authType, RBAC_AUTH_PREFIX)
	return s.providers[providerName] != nil
}

func (s *SAMLManager) CheckSAMLAuth(w http.ResponseWriter, r *http.Request, appProvider string) (string, []string, error) {
	cookieName := genSAMLCookieName(appProvider)
	session, err := s.cookieStore.Get(r, cookieName)
	requestUrl := url.QueryEscape(system.GetRequestUrl(r))
	redirectUrl := s.config.Security.CallbackUrl + types.INTERNAL_URL_PREFIX + "/sso/" + appProvider + "/login?relay=" + requestUrl
	if err != nil {
		s.Warn().Err(err).Msg("failed to get saml session")
		if session != nil {
			// delete the session
			session.Options.MaxAge = -1
			s.cookieStore.Save(r, w, session) //nolint:errcheck
		}
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", redirectUrl)
		} else {
			http.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
		}
		return "", nil, err
	}
	if auth, ok := session.Values[AUTH_KEY].(bool); !ok || !auth {
		// Store the target URL before redirecting to login
		s.Warn().Err(err).Msg("no auth, redirecting to login")
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", redirectUrl)
		} else {
			http.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
		}
		return "", nil, nil
	}

	// Check if provider name matches the one in the session
	if providerName, ok := session.Values[PROVIDER_NAME_KEY].(string); !ok || providerName != appProvider {
		s.Warn().Err(err).Msg("provider mismatch, redirecting to login")
		http.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
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
		}
	}

	// Clear the redirect target after successful authentication
	delete(session.Values, REDIRECT_URL)
	err = session.Save(r, w)
	if err != nil {
		s.Warn().Err(err).Msg("failed to save session")
		return "", nil, err
	}

	return appProvider + ":" + userId, groups, nil
}

func buildSAMLUrl(baseUrl, providerName, endpoint string) string {
	baseUrl = strings.TrimSuffix(baseUrl, "/")
	return baseUrl + path.Join(types.INTERNAL_URL_PREFIX, "sso", providerName, endpoint)
}

func (s *SAMLManager) buildSAMLProvider(ctx context.Context, providerName string, config types.SAMLConfig) (*saml2.SAMLServiceProvider, error) {
	idp, err := s.fetchAndParseIDPMetadata(ctx, config.MetadataURL)
	if err != nil {
		return nil, fmt.Errorf("IdP metadata error: %w", err)
	}

	baseURL := s.config.Security.CallbackUrl
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
		ForceAuthn:                  config.ForceAuthn,
	}

	// Optional SP signing/encryption
	if config.SPKeyFile == "random" {
		sp.SPKeyStore = dsig.RandomKeyStoreForTest()
		sp.SignAuthnRequests = true
	} else if config.SPKeyFile != "" && config.SPCertFile != "" {
		var err error
		ks, err := s.loadSPKeyStore(config.SPKeyFile, config.SPCertFile)
		if err != nil {
			return nil, fmt.Errorf("SP keypair error: %w", err)
		}
		if err := sp.SetSPKeyStore(ks); err != nil {
			return nil, fmt.Errorf("error setting SP key store: %w", err)
		}
		sp.SignAuthnRequests = true
	}

	return sp, nil
}

func (s *SAMLManager) loadSPKeyStore(certPath, keyPath string) (*saml2.KeyStore, error) {
	kp, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load sp keypair: %w", err)
	}
	signer, ok := kp.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("SP private key does not implement crypto.Signer")
	}
	var leafDER []byte
	if len(kp.Certificate) > 0 {
		leafDER = kp.Certificate[0]
	}
	ks := &saml2.KeyStore{
		Signer: signer,
		Cert:   leafDER,
	}
	return ks, nil
}

type idpConfig struct {
	Issuer       string
	SSO_Redirect string
	SSO_POST     string
	SLO_Redirect string
	SLO_POST     string
	CertStore    *dsig.MemoryX509CertificateStore
}

func (s *SAMLManager) fetchAndParseIDPMetadata(ctx context.Context, url string) (*idpConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET metadata: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("GET metadata: status %d: %s", resp.StatusCode, string(b))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read metadata: %w", err)
	}

	var ed saml_types.EntityDescriptor
	if err := xml.Unmarshal(raw, &ed); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	if ed.IDPSSODescriptor == nil {
		return nil, errors.New("metadata has no IDPSSODescriptor")
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

	// Find SSO/SLO endpoints by binding
	var ssoRedirect, ssoPOST, sloRedirect, sloPOST string
	for _, s := range ed.IDPSSODescriptor.SingleSignOnServices {
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
	mux.Get(types.INTERNAL_URL_PREFIX+"/sso/{provider}/login", func(w http.ResponseWriter, r *http.Request) {
		s.login(w, r)
	})
	mux.Post(types.INTERNAL_URL_PREFIX+"/sso/{provider}/acs", func(w http.ResponseWriter, r *http.Request) {
		s.acs(w, r)
	})
	mux.Post(types.INTERNAL_URL_PREFIX+"/sso/{provider}/slo", func(w http.ResponseWriter, r *http.Request) {
		s.logout(w, r)
	})
}

func (s *SAMLManager) metadata(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	sp := s.providers[providerName]
	if sp == nil {
		http.Error(w, fmt.Sprintf("provider %s not found", providerName), http.StatusNotFound)
		return
	}
	var ed *saml_types.EntityDescriptor
	var err error

	if sp.ServiceProviderSLOURL != "" {
		ed, err = sp.MetadataWithSLO(24)
	} else {
		ed, err = sp.Metadata()
	}
	if err != nil {
		http.Error(w, "metadata error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(ed); err != nil {
		http.Error(w, "error encoding metadata: "+err.Error(), 500)
		return
	}
}

func (s *SAMLManager) login(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	sp := s.providers[providerName]
	if sp == nil {
		http.Error(w, fmt.Sprintf("provider %s not found", providerName), http.StatusNotFound)
		return
	}

	relay := r.URL.Query().Get("relay")
	if relay == "" {
		relay = "/"
	}

	if sp.IdentityProviderSSOBinding == saml2.BindingHttpPost {
		body, err := sp.BuildAuthBodyPost(relay)
		if err != nil {
			http.Error(w, "auth body err: "+err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(body)
		return
	}
	url, err := sp.BuildAuthURL(relay)
	if err != nil {
		http.Error(w, "auth url err: "+err.Error(), 500)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *SAMLManager) acs(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	sp := s.providers[providerName]
	if sp == nil {
		http.Error(w, fmt.Sprintf("provider %s not found", providerName), http.StatusNotFound)
		return
	}

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

	config := s.providerConfigs[providerName]
	if config == nil {
		http.Error(w, fmt.Sprintf("provider config %s not found", providerName), http.StatusNotFound)
		return
	}

	groups := firstNonEmpty(ai.Values.GetAll(config.GroupsAttr),
		ai.Values.GetAll("groups"),
		ai.Values.GetAll("memberOf"),
		ai.Values.GetAll("roles"),
		ai.Values.GetAll("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"),
	)

	cookieName := genSAMLCookieName(providerName)
	session, err := s.cookieStore.Get(r, cookieName)
	if err != nil {
		http.Error(w, "error getting session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values[AUTH_KEY] = true
	session.Values[USER_KEY] = ai.NameID
	session.Values[PROVIDER_NAME_KEY] = providerName
	session.Values[GROUPS_KEY] = groups
	session.Values["sessionIndex"] = ai.SessionIndex

	if err := session.Save(r, w); err != nil {
		http.Error(w, "save session: "+err.Error(), 500)
		return
	}

	relay := r.PostFormValue("RelayState")
	if relay == "" {
		relay = "/"
	}
	http.Redirect(w, r, relay, http.StatusFound)
}

func (s *SAMLManager) logout(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	sp := s.providers[providerName]
	if sp == nil {
		http.Error(w, fmt.Sprintf("provider %s not found", providerName), http.StatusNotFound)
		return
	}

	cookieName := genSAMLCookieName(providerName)
	session, err := s.cookieStore.Get(r, cookieName)
	if err != nil {
		http.Error(w, "error getting session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nameID, _ := session.Values["nameID"].(string)
	sessionIndex, _ := session.Values["sessionIndex"].(string)

	// clear local session
	for k := range session.Values {
		delete(session.Values, k)
	}
	_ = session.Save(r, w)

	// optional IdP SLO (front-channel)
	if sp.IdentityProviderSLOURL != "" && nameID != "" && sessionIndex != "" {
		doc, err := sp.BuildLogoutRequestDocument(nameID, sessionIndex)
		if err == nil {
			if sp.IdentityProviderSLOBinding == saml2.BindingHttpRedirect {
				if url, err := sp.BuildLogoutURLRedirect("", doc); err == nil && url != "" {
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

func firstNonEmpty(slices ...[]string) []string {
	for _, s := range slices {
		if len(s) > 0 {
			return s
		}
	}
	return []string{}
}
