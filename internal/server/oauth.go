// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"

	"github.com/markbates/goth/providers/amazon"
	"github.com/markbates/goth/providers/auth0"
	"github.com/markbates/goth/providers/azuread"
	"github.com/markbates/goth/providers/bitbucket"
	"github.com/markbates/goth/providers/digitalocean"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/gitlab"
	"github.com/markbates/goth/providers/google"
	"github.com/markbates/goth/providers/microsoftonline"
	"github.com/markbates/goth/providers/okta"
)

// OAuth and OIDC support using goth library. Standard OAuth flow, using
// KV-backed gorilla sessions so browser cookies only carry opaque session ids.
// Two unusual situations are handled:
// 1. The OAuth callback url is on domain a.com while the app is on b.com. The standard flow does not work since the callback api (on a.com) cannot
//  set cookies on b.com. This is handled by having a redirect api on b.com which sets the cookies
// 2. There could be multiple OpenRun server instances. The metadata database is used to save the session info after the user is authenticated.
//  This db entry is used in the redirect api to create the cookies, and then db entry is deleted.

// The flow is
// 1. At service startup, OAuthManager and all the providers are initialized
// 2. For apps using OAuth/OIDC, CheckAuth is called to check if the user is authenticated
// 3. CheckAuth verifies the session cookie to see if the user is authenticated. If yes, done
// 4. If the user is not authenticated, beginLogin function is called (API is currently on the app domain)
// 5. beginLogin creates a sessionid and nonce. Saves entry in DB with sessionid as key and state map as value
// 6. beginLogin creates a cookie with the nonce and redirect url. Calls the login API on the callback domain
// 7. Redirects to the OAuth provider's login page, with sessionid in state
// 8. Login API calls gothic.BeginAuthHandler to redirect to the OAuth provider's login page
// 9. OAuth provider's login page redirects to the callback api on the callback domain, with sessionid in state
// 10. Callback api validates the sessionid, deletes that DB entry and stores the state map with the user id and groups
//     info under a new short-lived sessionid (the pre-login sessionid is known to whoever started the flow)
// 11. Callback api redirects to the redirect API on the app domain, passing the new sessionid in the state parameter
// 12. redirect API validates the passed sessionid, nonce from DB statemap against nonce from cookie,
// 13. redirect stores the authenticated session, with the user id and groups info and deletes the DB entry
// 14. Redirects back to original app url, which will again call CheckAuth and find the authenticated cookie

const (
	PROVIDER_NAME_DELIMITER = "_"
	AUTH_KEY                = "authenticated"
	USER_KEY                = "user" // email/userid/nickname (for git email/nickname/userid)
	USER_ID_KEY             = "user_id"
	USER_EMAIL_KEY          = "email"
	USER_NICKNAME_KEY       = "nickname"
	PROVIDER_NAME_KEY       = "provider_name"
	GROUPS_KEY              = "groups"
	SESSION_INDEX_KEY       = "session_index"
	NONCE_KEY               = "nonce"
	REDIRECT_URL            = "redirect"
	REQUEST_ID_KEY          = "request_id" // SAML AuthnRequest ID, used to enforce InResponseTo
)

// preAuthSessionMaxAge (seconds) is the window a login handshake stays valid:
// the pre-auth nonce cookie and the keystore state row (the login page's state
// token, the OAuth/SAML relay state) both expire after it. It bounds how long a
// login page or IdP page can sit open before the submit is rejected as
// expired. One hour keeps that from being a nuisance while still keeping
// abandoned handshakes short-lived relative to the session lifetime: the state
// token is a random single-use key bound to the browser's nonce cookie, so a
// longer window does not widen the CSRF/fixation surface
const preAuthSessionMaxAge = 3600

// preAuthStateMaxAge is preAuthSessionMaxAge as a duration, for the keystore
// state row expiry
const preAuthStateMaxAge = preAuthSessionMaxAge * time.Second

// OAuthManager manages the OAuth providers and their configurations (also OIDC)
type OAuthManager struct {
	*types.Logger
	config      *types.ServerConfig        // startup config: cookie store settings, initial providers
	getConfig   func() *types.ServerConfig // current (dynamic) config for per-request settings
	cookieStore sessions.Store
	db          KVStore

	// redirectHostAllowed gates the host of the post-login redirect at the
	// callback, see completionRedirectAllowed. Wired by NewServer
	redirectHostAllowed func(host string) bool
	// loginRate is the login start limiter shared with the other login
	// types, wired by NewServer
	loginRate *ipRateLimiter

	// providerMu guards providerConfigs, which is replaced when dynamic
	// config entries add/change/remove auth providers at runtime
	providerMu      sync.RWMutex
	providerConfigs map[string]*types.AuthConfig
}

type OAuthAuthInfo struct {
	UserId      string
	Groups      []string
	UserSubject string
	UserEmail   string
}

func NewOAuthManager(logger *types.Logger, config *types.ServerConfig, db KVStore) *OAuthManager {
	return &OAuthManager{
		Logger:    logger,
		config:    config,
		getConfig: func() *types.ServerConfig { return config },
		db:        db,
	}
}

func getProviderName(r *http.Request) (string, error) {
	provider := chi.URLParam(r, "provider")
	if provider == "" {
		return "", fmt.Errorf("provider not specified in url")
	}
	return provider, nil
}

func genCookieName(provider string) string {
	return fmt.Sprintf("%s_%s", provider, types.OAUTH_SESSION_COOKIE)
}

func (s *OAuthManager) Setup(sessionKey []byte, sessionBlockKey []byte) error {
	cookieStore := NewKVSessionStore(s.db, sessionKey, sessionBlockKey)
	cookieStore.MaxAge(s.config.Security.SessionMaxAge)
	cookieStore.Options.Path = "/"
	cookieStore.Options.HttpOnly = true
	cookieStore.Options.Secure = s.config.Security.SessionHttpsOnly
	cookieStore.Options.SameSite = http.SameSiteLaxMode
	s.cookieStore = cookieStore

	// gothic keeps its own session (the provider auth URL with the state)
	// between the login start and the callback. That handshake row is
	// created by the unauthenticated login endpoint, so it gets the
	// pre-auth lifetime like the other login-state rows, not the
	// session_max_age of an authenticated session: a pending state can be
	// used to start the provider login repeatedly (without the gothic
	// cookie each start is a new row), which must not pile up day-long rows
	gothicStore := NewKVSessionStore(s.db, sessionKey, sessionBlockKey)
	gothicStore.MaxAge(preAuthSessionMaxAge)
	gothicStore.Options.Path = "/"
	gothicStore.Options.HttpOnly = true
	gothicStore.Options.Secure = s.config.Security.SessionHttpsOnly
	gothicStore.Options.SameSite = http.SameSiteLaxMode
	gothic.Store = gothicStore
	gothic.GetProviderName = getProviderName

	// Static config errors fail server startup
	return s.registerProviders(s.config.Auth, s.config.Security.CallbackUrl, true)
}

// buildProvider creates the goth provider for one auth config entry, with
// its callback on the given security.callback_url
func (s *OAuthManager) buildProvider(providerName string, auth types.AuthConfig, callbackBase string) (goth.Provider, error) {
	key := auth.Key
	secret := auth.Secret
	scopes := auth.Scopes

	if providerName == "" || key == "" || secret == "" {
		return nil, fmt.Errorf("provider, key, and secret must be set for each auth provider")
	}

	callbackUrl := callbackBase + types.INTERNAL_URL_PREFIX + "/auth/" + providerName + "/callback"
	providerSplit := strings.SplitN(providerName, PROVIDER_NAME_DELIMITER, 2)
	providerType := providerSplit[0]

	var provider goth.Provider
	switch providerType {
	case "github":
		provider = github.New(key, secret, callbackUrl, scopes...)
	case "google": // google supports hosted domain option
		gp := google.New(key, secret, callbackUrl, scopes...)
		if auth.HostedDomain != "" {
			gp.SetHostedDomain(auth.HostedDomain)
		}
		provider = gp
	case "digitalocean":
		provider = digitalocean.New(key, secret, callbackUrl, scopes...)
	case "bitbucket":
		provider = bitbucket.New(key, secret, callbackUrl, scopes...)
	case "amazon":
		provider = amazon.New(key, secret, callbackUrl, scopes...)
	case "azuread": // azuread requires a resources array, setting nil for now
		provider = azuread.New(key, secret, callbackUrl, nil, scopes...)
	case "microsoftonline":
		provider = microsoftonline.New(key, secret, callbackUrl, scopes...)
	case "gitlab":
		provider = gitlab.New(key, secret, callbackUrl, scopes...)
	case "auth0": // auth0 requires a domain
		provider = auth0.New(key, secret, callbackUrl, auth.Domain, scopes...)
	case "okta": // okta requires an org url
		provider = okta.New(key, secret, auth.OrgUrl, callbackUrl, scopes...)
	case "oidc": // openidConnect requires a discovery url
		if auth.DiscoveryUrl == "" {
			return nil, fmt.Errorf("discovery_url is required for OIDC provider")
		}
		op, err := newOIDCProvider(key, secret, callbackUrl, auth.DiscoveryUrl, scopes, ssoAllowPrivateHosts(s.config))
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
		}
		provider = op
	default:
		return nil, fmt.Errorf("unsupported auth provider: %s", providerName)
	}

	provider.SetName(providerName)
	return provider, nil
}

// registerProviders builds the goth providers for an auth config map and
// swaps them in as the full provider set. With failFast any bad entry is
// an error; otherwise a bad entry is logged and skipped. Persisted dynamic
// config loaded at startup can tolerate an unavailable provider.
func (s *OAuthManager) registerProviders(auth map[string]types.AuthConfig, callbackUrl string, failFast bool) error {
	publish, err := s.prepareProviders(auth, callbackUrl, failFast)
	if err != nil {
		return err
	}
	publish()
	return nil
}

// prepareProviders builds the provider set without changing registered
// auth. callbackUrl is the security.callback_url the providers call back
// to (passed in: on a dynamic config change the new value is not yet the
// current config when the providers are rebuilt)
func (s *OAuthManager) prepareProviders(auth map[string]types.AuthConfig, callbackUrl string, failFast bool) (func(), error) {
	providerConfigs := make(map[string]*types.AuthConfig, len(auth))
	providers := make([]goth.Provider, 0, len(auth))
	for providerName, authConfig := range auth {
		provider, err := s.buildProvider(providerName, authConfig, callbackUrl)
		if err != nil {
			if failFast {
				return nil, err
			}
			s.Error().Err(err).Msgf("error building oauth provider %s, provider disabled", providerName)
			continue
		}
		providers = append(providers, provider)
		providerConfigs[providerName] = &authConfig
	}

	if len(providers) != 0 && callbackUrl == "" {
		return nil, fmt.Errorf("security.callback_url must be set for enabling OAuth")
	}

	return func() {
		s.providerMu.Lock()
		s.providerConfigs = providerConfigs
		s.providerMu.Unlock()

		goth.ClearProviders()
		goth.UseProviders(providers...) // Register the providers with goth
	}, nil
}

// getProviderConfig returns the config for one registered provider, nil if
// the provider is not configured
func (s *OAuthManager) getProviderConfig(provider string) *types.AuthConfig {
	s.providerMu.RLock()
	defer s.providerMu.RUnlock()
	return s.providerConfigs[provider]
}

func (s *OAuthManager) RegisterRoutes(csrfMiddleware *http.CrossOriginProtection, mux *chi.Mux) {
	mux.Get(types.INTERNAL_URL_PREFIX+"/auth/{provider}/login", func(w http.ResponseWriter, r *http.Request) {
		// Start the provider login only for a pending login state created by
		// beginLogin: gothic stores a session row per start, which an
		// unauthenticated caller must not be able to allocate at will
		if !s.pendingLoginState(r) {
			http.Error(w, "error matching session state, start the login again", http.StatusBadRequest)
			return
		}
		gothic.BeginAuthHandler(w, r)
	})

	mux.Get(types.INTERNAL_URL_PREFIX+"/auth/{provider}/callback", s.authCallback)

	mux.Get(types.INTERNAL_URL_PREFIX+"/auth/{provider}/redirect", s.redirect)

	mux.Method("POST", types.INTERNAL_URL_PREFIX+"/logout/{provider}", csrfMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// gothic.Logout(w, r) needs to be called on the callback domain, so not done
		// Set user as not authenticated in session
		providerName := chi.URLParam(r, "provider")
		cookieName := genCookieName(providerName)
		session, err := s.cookieStore.Get(r, cookieName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Set user as unauthenticated in session
		session.Values[AUTH_KEY] = false
		session.Options.MaxAge = -1
		if err := session.Save(r, w); err != nil {
			// Save deletes the server-side row before clearing the cookie; if it
			// fails the session is still valid, so do not report a clean logout.
			http.Error(w, "error clearing session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})))
}

func (s *OAuthManager) ValidateProviderName(provider string) bool {
	return s.getProviderConfig(provider) != nil
}

func (s *OAuthManager) ValidateAuthType(authType string) bool {
	authType = strings.TrimPrefix(authType, rbac.RBAC_AUTH_PREFIX)
	switch authType {
	case string(types.AppAuthnDefault), string(types.AppAuthnSystem), string(types.AppAuthnNone),
		string(types.AppAuthnBuiltin):
		// builtin is always a valid auth type: user entries can be added
		// dynamically after the app is created
		return true
	default:
		if authType == "cert" || strings.HasPrefix(authType, "cert_") {
			_, ok := s.getConfig().ClientAuth[authType]
			return ok
		}
		return s.ValidateProviderName(authType)
	}
}

func (s *OAuthManager) CheckAuth(w http.ResponseWriter, r *http.Request, appProvider string) (string, []string, error) {
	authInfo, err := s.CheckAuthInfo(w, r, appProvider)
	return authInfo.UserId, authInfo.Groups, err
}

// CheckAuthInfo checks the provider session for an app request; without a
// valid session the login flow is started, returning to the request URL
func (s *OAuthManager) CheckAuthInfo(w http.ResponseWriter, r *http.Request, appProvider string) (OAuthAuthInfo, error) {
	return s.checkAuthInfo(w, r, appProvider, system.GetRequestUrl(r, s.getConfig().Security.TrustedProxies))
}

// checkAuthInfo is CheckAuthInfo with an explicit post-login URL: the
// OAuth AS passes its config-built continue URL (oauth_federated.go), app
// requests pass the request URL (their host is validated by MatchApp)
func (s *OAuthManager) checkAuthInfo(w http.ResponseWriter, r *http.Request, appProvider, requestUrl string) (OAuthAuthInfo, error) {
	cookieName := genCookieName(appProvider)

	session, err := s.cookieStore.Get(r, cookieName)
	if err != nil {
		// An undecodable cookie, or one naming an expired or missing row:
		// the request is unauthenticated. The cookie is not cleared here
		// (a request which may not start a login must not change the
		// browser's cookies, and a navigation gets a fresh pre-auth
		// session from beginLogin, which replaces it)
		s.Warn().Err(err).Msg("failed to get session, starting login")
		s.startLogin(w, r, appProvider, requestUrl)
		return OAuthAuthInfo{}, nil
	}

	redirectCaller := false
	if auth, ok := session.Values[AUTH_KEY].(bool); !ok || !auth {
		s.Debug().Msg("no auth cookie, redirecting to login")
		redirectCaller = true
	}

	// Check if provider name matches the one in the session
	if providerName, ok := session.Values[PROVIDER_NAME_KEY].(string); !ok || providerName != appProvider {
		s.Warn().Msg("provider mismatch, redirecting to login")
		redirectCaller = true
	}

	if !redirectCaller && !sessionWithinAbsoluteLifetime(session, s.getConfig().Security.SessionAbsoluteMaxAge, time.Now()) {
		s.Debug().Msg("session past its absolute lifetime, redirecting to login")
		redirectCaller = true
	}

	if redirectCaller {
		// do the OAuth login flow
		s.startLogin(w, r, appProvider, requestUrl)
		return OAuthAuthInfo{}, nil
	}

	userId, ok := session.Values[USER_KEY].(string)
	if !ok || userId == "" {
		s.Warn().Msg("no user key in session")
		return OAuthAuthInfo{}, fmt.Errorf("no user key in session")
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

	userSubject, _ := sessionValueString(session, USER_ID_KEY)
	userEmail, _ := sessionValueString(session, USER_EMAIL_KEY)

	renewSession(s.Logger, w, r, session, s.getConfig().Security.SessionAbsoluteMaxAge) // sliding expiry

	return OAuthAuthInfo{
		UserId:      appProvider + ":" + userId,
		Groups:      groups,
		UserSubject: userSubject,
		UserEmail:   userEmail,
	}, nil
}

// startLogin starts the login flow for an app request without a usable
// session, when the request is one that may start a login (canStartLogin);
// any other request gets a 401 which changes nothing
func (s *OAuthManager) startLogin(w http.ResponseWriter, r *http.Request, providerName, redirectUrl string) {
	if !canStartLogin(r) {
		s.Debug().Msg("background request without a session, not starting login")
		denyLoginStart(w)
		return
	}
	s.beginLogin(w, r, providerName, redirectUrl)
}

func (s *OAuthManager) beginLogin(w http.ResponseWriter, r *http.Request, providerName, redirectUrl string) {
	if !loginStartAllowed(s.loginRate, s.getConfig(), r) {
		tooManyLoginStarts(w)
		return
	}
	sessionId, nonce, err := passwd.GenerateSessionNonce()
	if err != nil {
		http.Error(w, "error generating session nonce: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sessionId = types.OAUTH_SESSION_KV_PREFIX + sessionId
	stateMap := make(map[string]any)
	stateMap[AUTH_KEY] = false
	stateMap[PROVIDER_NAME_KEY] = providerName
	stateMap[REDIRECT_URL] = redirectUrl
	stateMap[NONCE_KEY] = nonce

	// Store the state map in the database with the session id as the key
	expireAt := time.Now().Add(preAuthStateMaxAge)
	err = s.db.StoreKV(r.Context(), sessionId, stateMap, &expireAt)
	if err != nil {
		http.Error(w, "error storing state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session, ok := freshPreAuthSession(w, r, s.cookieStore, genCookieName(providerName))
	if !ok {
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

	// The state is the session id, encoded in base64
	state := base64.URLEncoding.EncodeToString([]byte(sessionId))
	authUrl := fmt.Sprintf("%s%s/auth/%s/login?state=%s", s.getConfig().Security.CallbackUrl, types.INTERNAL_URL_PREFIX, providerName, state)

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", authUrl)
	} else {
		http.Redirect(w, r, authUrl, http.StatusFound)
	}
}

// pendingLoginState reports whether the request's state names a pre-login
// entry of this provider (stored by beginLogin, not yet authenticated)
func (s *OAuthManager) pendingLoginState(r *http.Request) bool {
	sessionId, err := base64.URLEncoding.DecodeString(r.URL.Query().Get("state"))
	if err != nil || !strings.HasPrefix(string(sessionId), types.OAUTH_SESSION_KV_PREFIX) {
		return false
	}
	stateMap, err := s.db.FetchKV(r.Context(), string(sessionId))
	if err != nil {
		return false
	}
	auth, ok := stateValueBool(stateMap, AUTH_KEY)
	provider, _ := stateValueString(stateMap, PROVIDER_NAME_KEY)
	return ok && !auth && provider == chi.URLParam(r, "provider")
}

func (s *OAuthManager) authCallback(w http.ResponseWriter, r *http.Request) {
	state := gothic.GetState(r)
	if state == "" {
		http.Error(w, "state is required", http.StatusBadRequest)
		return
	}
	sessionId, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The state is a keystore key: only a pre-login row of this flow may be
	// read and consumed through it, never a row of another namespace
	if !strings.HasPrefix(string(sessionId), types.OAUTH_SESSION_KV_PREFIX) {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}

	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		s.Warn().Err(err).Msg("failed to complete user auth")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stateMap, err := s.db.FetchKV(r.Context(), string(sessionId))
	if err != nil {
		http.Error(w, "error fetching KV state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	providerName := chi.URLParam(r, "provider")
	stateProviderName, ok := stateValueString(stateMap, PROVIDER_NAME_KEY)
	if !ok || stateProviderName != providerName {
		http.Error(w, "error matching session state", http.StatusInternalServerError)
		return
	}

	providerConfig := s.getProviderConfig(providerName)
	if providerConfig == nil {
		http.Error(w, fmt.Sprintf("provider %s not configured", providerName), http.StatusInternalServerError)
		return
	}

	// Enforce the hosted-domain restriction whenever it is configured, not only
	// for the google provider. Providers that emit the "hd" claim (Google, or
	// OIDC in front of Google Workspace) are checked against it; for any other
	// provider the claim is absent, so a configured hosted_domain fails closed
	// instead of being silently ignored.
	if providerConfig.HostedDomain != "" {
		hostedDomain, _ := user.RawData["hd"].(string)
		if hostedDomain != providerConfig.HostedDomain {
			http.Error(w, fmt.Sprintf("user does not belong to the required hosted domain. Found %q, expected %q",
				hostedDomain, providerConfig.HostedDomain), http.StatusForbidden)
			return
		}
	}

	auth, ok := stateValueBool(stateMap, AUTH_KEY)
	if !ok || auth {
		http.Error(w, "error matching session state, expected auth to be false", http.StatusInternalServerError)
		return
	}

	stateMap[USER_ID_KEY] = user.UserID
	stateMap[USER_NICKNAME_KEY] = user.NickName
	// Only trust the email as an identity when the IdP vouches for it:
	// otherwise a user on a permissive IdP could assert an arbitrary address
	// (e.g. someone else's) and match RBAC grants for it. The OIDC adapter
	// (oidc.go) decides this itself and leaves Email empty for an address
	// that is not marked verified; the goth providers are gated on the
	// claim here. An address that was dropped is logged: the user is then
	// identified by subject, which an operator with email-keyed grants
	// would otherwise only see as access denied
	email := ""
	if emailVerifiedClaim(user.RawData) {
		email = user.Email
	}
	if email != "" {
		stateMap[USER_EMAIL_KEY] = email
	} else if rawEmail, _ := user.RawData["email"].(string); rawEmail != "" {
		s.Warn().Str("provider", providerName).Str("subject", user.UserID).Msg(
			"the identity provider's email claim is not marked verified: the user is identified by subject, grants keyed by the email will not match")
	}

	lookupKeys := []string{USER_EMAIL_KEY, USER_ID_KEY, USER_NICKNAME_KEY}
	if strings.HasPrefix(providerName, "git") {
		// For git providers, prefer nickname over userid as it is more meaningful
		lookupKeys = []string{USER_EMAIL_KEY, USER_NICKNAME_KEY, USER_ID_KEY}
	}
	userId := ""
	for _, key := range lookupKeys {
		userId, ok = stateMap[key].(string)
		if ok && userId != "" {
			break
		}
	}

	if userId == "" {
		s.Warn().Msg("user id could not be found")
		http.Error(w, errors.New("user id could not be found").Error(), http.StatusInternalServerError)
		return
	}

	// Get groups from user.RawData
	groups := make([]string, 0)
	if raw, ok := user.RawData["groups"]; ok {
		if arr, ok := raw.([]any); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok {
					groups = append(groups, s)
				}
			}
		}
	}
	s.Trace().Str("user_id", user.UserID).Str("email", user.Email).Str("nickname", user.NickName).
		Str("provider_name", providerName).Msgf("authenticated user with groups %+v", groups)

	// Only a newly verified IdP login refreshes durable groups; reading an old
	// browser session must not extend the snapshot's freshness.
	verifiedEmail, _ := stateMap[USER_EMAIL_KEY].(string) // set above only when the IdP did not mark it unverified
	if err := observeFederatedIdentity(r.Context(), s.db, providerName, user.UserID, userId, verifiedEmail, groups); err != nil {
		s.Error().Err(err).Msg("error recording authenticated identity")
		http.Error(w, "error recording authenticated identity", http.StatusInternalServerError)
		return
	}

	redirectUrl, ok := stateValueString(stateMap, REDIRECT_URL)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
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

	// Mark the state authenticated under a NEW key. The pre-login state token
	// is visible to whoever initiated the flow (it is in the login URL that
	// beginLogin redirects to), so it must not stay valid once the IdP has
	// vouched for a user: an attacker could start a login (keeping the
	// app-domain nonce cookie), hand the login URL to a victim and, after the
	// victim authenticates, call redirect with the known state to mint a
	// session under the victim's identity. The fresh completion token is only
	// ever sent to the browser that completed the IdP step, and redirect
	// additionally requires the nonce cookie of the browser that initiated the
	// flow - in the legitimate flow the same browser holds both. Consuming the
	// old key first is the atomic gate: a replayed or concurrent callback for
	// the same state cannot mint a second completion token
	completeId, err := s.rotateLoginState(r, string(sessionId), stateMap, userId, groups)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if completeId == "" {
		http.Error(w, "error matching session state, login already completed", http.StatusBadRequest)
		return
	}
	state = base64.URLEncoding.EncodeToString([]byte(completeId))

	// Redirect to the auth/redirect url on the original app domain, so that the required cookie can be set on the app domain
	redirectAppDomain := redirectParsed.Scheme + "://" + redirectParsed.Host + types.INTERNAL_URL_PREFIX + "/auth/" + providerName + "/redirect?state=" + state
	http.Redirect(w, r, redirectAppDomain, http.StatusFound)
}

// completionRedirectAllowed reports whether a stored post-login redirect may
// be the destination of the completion token: an http(s) URL on a host this
// server serves. The redirect is recorded from a request URL when the login
// starts, so a Host header the initiator chose must not become the place
// the token (and with it the victim's session) is sent to. hostAllowed is
// the server's served-host check; nil (a manager built without a server, in
// tests) accepts any host
func completionRedirectAllowed(redirectParsed *url.URL, hostAllowed func(string) bool) bool {
	if (redirectParsed.Scheme != "http" && redirectParsed.Scheme != "https") || redirectParsed.Host == "" {
		return false
	}
	return hostAllowed == nil || hostAllowed(redirectParsed.Hostname())
}

// rotateLoginState atomically consumes the pre-login state entry and stores the
// authenticated state (user id and groups added) under a fresh random key with
// a short expiry, returning the new key. It returns "" with a nil error when
// the pre-login entry was already consumed (replayed or concurrent callback)
func (s *OAuthManager) rotateLoginState(r *http.Request, sessionId string, stateMap map[string]any, userId string, groups []string) (string, error) {
	consumed, err := s.db.DeleteKVIfPresent(r.Context(), sessionId)
	if err != nil {
		return "", fmt.Errorf("error updating state: %w", err)
	}
	if !consumed {
		return "", nil
	}
	completeKey, err := passwd.GenerateRandomKey(24)
	if err != nil {
		return "", fmt.Errorf("error generating state: %w", err)
	}
	completeId := types.OAUTH_SESSION_KV_PREFIX + base64.URLEncoding.EncodeToString(completeKey)
	stateMap[AUTH_KEY] = true
	stateMap[USER_KEY] = userId
	stateMap[GROUPS_KEY] = groups
	expireAt := time.Now().Add(completeTokenMaxAge)
	if err := s.db.StoreKV(r.Context(), completeId, stateMap, &expireAt); err != nil {
		return "", fmt.Errorf("error storing state: %w", err)
	}
	return completeId, nil
}

// emailVerifiedClaim reports whether the IdP's email claim can be trusted as an
// identity. The claim is absent for providers that do not emit it (e.g. GitHub,
// whose API emails are already verified), in which case we keep the prior
// behavior of trusting the email; it is only dropped when explicitly false.
// The OIDC adapter is stricter (oidcEmailVerified: absent is unverified) and
// applies its policy before the user reaches here, by leaving Email empty
func emailVerifiedClaim(raw map[string]any) bool {
	// OIDC userinfo/id_token: email_verified; Google's v2 userinfo
	// endpoint (the goth google provider): verified_email
	v, ok := raw["email_verified"]
	if !ok {
		v, ok = raw["verified_email"]
	}
	if !ok {
		return true
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	default:
		return false
	}
}

func (s *OAuthManager) redirect(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "state is required", http.StatusBadRequest)
		return
	}
	providerName := chi.URLParam(r, "provider")
	cookieName := genCookieName(providerName)
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
	sessionIdBytes, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sessionId := string(sessionIdBytes)
	if !strings.HasPrefix(sessionId, types.OAUTH_SESSION_KV_PREFIX) {
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
	// nonce cookie) that it owns this login, so a leaked state token alone cannot
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
	// Rotate the session id on the unauthenticated->authenticated transition to
	// prevent session fixation (a fixated pre-auth cookie must not remain valid).
	session.ID = ""
	session.Values[AUTH_KEY] = true
	session.Values[USER_KEY] = userID
	session.Values[PROVIDER_NAME_KEY] = providerName
	session.Values[GROUPS_KEY] = groups
	if userSubject, ok := stateValueString(stateMap, USER_ID_KEY); ok {
		session.Values[USER_ID_KEY] = userSubject
	} else {
		delete(session.Values, USER_ID_KEY)
	}
	if userEmail, ok := stateValueString(stateMap, USER_EMAIL_KEY); ok {
		session.Values[USER_EMAIL_KEY] = userEmail
	} else {
		delete(session.Values, USER_EMAIL_KEY)
	}
	delete(session.Values, REDIRECT_URL)
	delete(session.Values, NONCE_KEY)
	markSessionLogin(session, s.getConfig().Security.SessionAbsoluteMaxAge)
	if err = session.Save(r, w); err != nil {
		http.Error(w, "error saving session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectUrl, http.StatusFound)
}
