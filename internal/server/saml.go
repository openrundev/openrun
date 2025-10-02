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
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	saml2 "github.com/russellhaering/gosaml2"
	saml_types "github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAML auth using gosaml2 library. Standard SAML flow, using cookies for saving session state.
// Two unusual situations are handled:
// 1. The SAML callback url is on domain a.com while the app is on b.com. The standard flow does not work since the ACS api (on a.com) cannot
//  set cookies on b.com. This is handled by having a redirect api on b.com which sets the cookies
// 2. There could be multiple OpenRun server instances. The metadata database is used to save the session info after the user is authenticated.
//  This db entry is used in the redirect api to create the cookies, and then db entry is deleted.

const SAML_AUTH_PREFIX = "saml_"

// SAMLManager manages the SAML providers and their configurations
type SAMLManager struct {
	*types.Logger
	config          *types.ServerConfig
	providerConfigs map[string]*types.SAMLConfig
	providers       map[string]*saml2.SAMLServiceProvider
	cookieStore     *sessions.CookieStore
	db              *metadata.Metadata
}

func NewSAMLManager(logger *types.Logger, config *types.ServerConfig, cookieStore *sessions.CookieStore, db *metadata.Metadata) *SAMLManager {
	return &SAMLManager{
		Logger:      logger,
		config:      config,
		cookieStore: cookieStore,
		db:          db,
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
	requestUrl := system.GetRequestUrl(r)

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
		http.Error(w, "error encoding metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *SAMLManager) login(w http.ResponseWriter, r *http.Request, providerName, redirectUrl string) {
	sp := s.providers[providerName]
	if sp == nil {
		http.Error(w, fmt.Sprintf("provider %s not found", providerName), http.StatusNotFound)
		return
	}

	sessionId, nonce, err := passwd.GenerateSessionNonce()
	if err != nil {
		http.Error(w, "error generating session nonce: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sessionId = "saml_session_" + sessionId
	stateMap := make(map[string]any)
	stateMap[AUTH_KEY] = false
	stateMap[PROVIDER_NAME_KEY] = providerName
	stateMap[REDIRECT_URL] = redirectUrl
	stateMap[NONCE_KEY] = nonce

	// Store the state map in the database with the session id as the key
	expireAt := time.Now().Add(5 * time.Minute)
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
	if err := session.Save(r, w); err != nil {
		http.Error(w, "error saving session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// The relay state is the session id and the redirect url, encoded in base64
	relayState := base64.URLEncoding.EncodeToString([]byte(sessionId))
	if sp.IdentityProviderSSOBinding == saml2.BindingHttpPost {
		body, err := sp.BuildAuthBodyPost(relayState)
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
	url, err := sp.BuildAuthURL(relayState)
	if err != nil {
		http.Error(w, "auth url err: "+err.Error(), http.StatusInternalServerError)
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
	s.Trace().Str("user_id", ai.NameID).Str("provider_name", providerName).Msgf("authenticated saml user with groups %+v", groups)

	sessionIdBytes, err := base64.URLEncoding.DecodeString(r.PostFormValue("RelayState"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sessionId := string(sessionIdBytes)
	stateMap, err := s.db.FetchKV(r.Context(), sessionId)
	if err != nil {
		http.Error(w, "error fetching KV state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if stateMap[PROVIDER_NAME_KEY] != providerName {
		http.Error(w, "error matching session state", http.StatusInternalServerError)
		return
	}
	if stateMap[AUTH_KEY] != false {
		http.Error(w, "error matching session state, expected auth to be false", http.StatusInternalServerError)
		return
	}
	redirectUrl := stateMap[REDIRECT_URL].(string)

	// Update the state map, set to authenticated and add the user id and groups
	stateMap[AUTH_KEY] = true
	stateMap[USER_KEY] = ai.NameID
	stateMap[GROUPS_KEY] = groups
	stateMap[SESSION_INDEX_KEY] = ai.SessionIndex
	err = s.db.UpdateKV(r.Context(), sessionId, stateMap)
	if err != nil {
		http.Error(w, "error updating KV state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	redirectParsed, err := url.Parse(redirectUrl)
	if err != nil {
		http.Error(w, "error parsing relay: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to the sso/redirect url on the original app domain, so that the required cookie can be set on the app domain
	redirectAppDomain := redirectParsed.Scheme + "://" + redirectParsed.Host + types.INTERNAL_URL_PREFIX + "/sso/" + providerName + "/redirect?relay=" + r.PostFormValue("RelayState")
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
	}

	sessionNonce := session.Values[NONCE_KEY].(string)
	sessionIdBytes, err := base64.URLEncoding.DecodeString(relayStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sessionId := string(sessionIdBytes)
	success := false

	defer func() {
		if !success {
			session.Options.MaxAge = -1 // delete the session if there is an error
			_ = session.Save(r, w)
		}
	}()

	// Get the state map, delete the entry from database, validate state, set the session values
	// in the cookie and then redirect to original url
	stateMap, err := s.db.FetchKV(r.Context(), sessionId)
	if err != nil {
		http.Error(w, "error fetching state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = s.db.DeleteKV(r.Context(), sessionId)
	if err != nil {
		http.Error(w, "error deleting state: "+err.Error(), http.StatusInternalServerError)
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

	if stateMap[PROVIDER_NAME_KEY] != providerName || stateMap[REDIRECT_URL] != redirectUrl {
		http.Error(w, "error matching session state", http.StatusInternalServerError)
		return
	}

	if stateMap[NONCE_KEY] != sessionNonce {
		http.Error(w, "error matching session state, nonce mismatch", http.StatusInternalServerError)
		return
	}

	// Update the session cookie with the new values
	success = true
	session.Values[AUTH_KEY] = true
	session.Values[USER_KEY] = stateMap[USER_KEY].(string)
	session.Values[GROUPS_KEY] = stateMap[GROUPS_KEY].([]any)
	session.Values[SESSION_INDEX_KEY] = stateMap[SESSION_INDEX_KEY].(string)
	delete(session.Values, REDIRECT_URL)
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "error saving session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectUrl, http.StatusFound)
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
