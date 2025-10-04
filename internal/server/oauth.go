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
	"time"

	"github.com/go-chi/chi"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/openrundev/openrun/internal/passwd"
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
	"github.com/markbates/goth/providers/openidConnect"
)

// OAuth and OIDC support using goth library. Standard OAuth flow, using cookies for saving session state.
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
// 10. Callback api validates the sessionid, and updates the state map in the DB with the user id and groups info
// 11. Callback api redirects to the redirect API on the app domain, again passing the sessionid in the state parameter
// 12. redirect API validates the passed sessionid, nonce from DB statemap against nonce from cookie,
// 13. redirect sets the session cookie in authenticated state, with the user id and groups info and deletes the DB entry
// 14. Redirects back to original app url, which will again call CheckAuth and find the authenticated cookie

const (
	PROVIDER_NAME_DELIMITER = "_"
	SESSION_COOKIE          = "openrun_session"
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
)

// OAuthManager manages the OAuth providers and their configurations (also OIDC)
type OAuthManager struct {
	*types.Logger
	config          *types.ServerConfig
	cookieStore     *sessions.CookieStore
	providerConfigs map[string]*types.AuthConfig
	db              KVStore
}

func NewOAuthManager(logger *types.Logger, config *types.ServerConfig, db KVStore) *OAuthManager {
	return &OAuthManager{
		Logger: logger,
		config: config,
		db:     db,
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
	return fmt.Sprintf("%s_%s", provider, SESSION_COOKIE)
}

func (s *OAuthManager) Setup(sessionKey []byte, sessionBlockKey []byte) error {
	s.cookieStore = sessions.NewCookieStore(sessionKey, sessionBlockKey)
	s.cookieStore.MaxAge(s.config.Security.SessionMaxAge)
	s.cookieStore.Options.Path = "/"
	s.cookieStore.Options.HttpOnly = true
	s.cookieStore.Options.Secure = s.config.Security.SessionHttpsOnly
	s.cookieStore.Options.SameSite = http.SameSiteLaxMode

	gothic.Store = s.cookieStore // Set the store for gothic
	gothic.GetProviderName = getProviderName
	s.providerConfigs = make(map[string]*types.AuthConfig)

	providers := make([]goth.Provider, 0)
	for providerName, auth := range s.config.Auth {
		auth := auth
		key := auth.Key
		secret := auth.Secret
		scopes := auth.Scopes

		if providerName == "" || key == "" || secret == "" {
			return fmt.Errorf("provider, key, and secret must be set for each auth provider")
		}

		callbackUrl := s.config.Security.CallbackUrl + types.INTERNAL_URL_PREFIX + "/auth/" + providerName + "/callback"
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
				return fmt.Errorf("discovery_url is required for OIDC provider")
			}
			op, err := openidConnect.New(key, secret, callbackUrl, auth.DiscoveryUrl, scopes...)
			if err != nil {
				return fmt.Errorf("failed to create OIDC provider: %w", err)
			}
			provider = op
		default:
			return fmt.Errorf("unsupported auth provider: %s", providerName)
		}

		provider.SetName(providerName)
		providers = append(providers, provider)
		s.providerConfigs[providerName] = &auth
	}

	if len(providers) != 0 && s.config.Security.CallbackUrl == "" {
		return fmt.Errorf("security.callback_url must be set for enabling OAuth")
	}

	goth.UseProviders(providers...) // Register the providers with goth
	return nil
}

func (s *OAuthManager) RegisterRoutes(mux *chi.Mux) {
	mux.Get(types.INTERNAL_URL_PREFIX+"/auth/{provider}/login", func(w http.ResponseWriter, r *http.Request) {
		// Start login process
		gothic.BeginAuthHandler(w, r)
	})

	mux.Get(types.INTERNAL_URL_PREFIX+"/auth/{provider}/callback", s.authCallback)

	mux.Get(types.INTERNAL_URL_PREFIX+"/auth/{provider}/redirect", s.redirect)

	mux.Post(types.INTERNAL_URL_PREFIX+"/logout/{provider}", func(w http.ResponseWriter, r *http.Request) {
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
		_ = session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
}

func (s *OAuthManager) ValidateProviderName(provider string) bool {
	return s.providerConfigs[provider] != nil
}

func (s *OAuthManager) ValidateAuthType(authType string) bool {
	authType = strings.TrimPrefix(authType, RBAC_AUTH_PREFIX)
	switch authType {
	case string(types.AppAuthnDefault), string(types.AppAuthnSystem), string(types.AppAuthnNone):
		return true
	default:
		if authType == "cert" || strings.HasPrefix(authType, "cert_") {
			_, ok := s.config.ClientAuth[authType]
			return ok
		}
		return s.ValidateProviderName(authType)
	}
}

func (s *OAuthManager) CheckAuth(w http.ResponseWriter, r *http.Request, appProvider string) (string, []string, error) {
	cookieName := genCookieName(appProvider)
	requestUrl := system.GetRequestUrl(r)

	session, err := s.cookieStore.Get(r, cookieName)
	if err != nil {
		s.Warn().Err(err).Msg("failed to get session")
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
		s.Debug().Msg("no auth cookie, redirecting to login")
		redirectCaller = true
	}

	// Check if provider name matches the one in the session
	if providerName, ok := session.Values[PROVIDER_NAME_KEY].(string); !ok || providerName != appProvider {
		s.Warn().Msg("provider mismatch, redirecting to login")
		redirectCaller = true
	}

	if redirectCaller {
		// do the OAuth login flow
		s.beginLogin(w, r, appProvider, requestUrl)
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

	return appProvider + ":" + userId, groups, nil
}

func (s *OAuthManager) beginLogin(w http.ResponseWriter, r *http.Request, providerName, redirectUrl string) {
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
	expireAt := time.Now().Add(5 * time.Minute)
	err = s.db.StoreKV(r.Context(), sessionId, stateMap, &expireAt)
	if err != nil {
		http.Error(w, "error storing state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cookieName := genCookieName(providerName)
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

	// The state is the session id, encoded in base64
	state := base64.URLEncoding.EncodeToString([]byte(sessionId))
	authUrl := fmt.Sprintf("%s%s/auth/%s/login?state=%s", s.config.Security.CallbackUrl, types.INTERNAL_URL_PREFIX, providerName, state)

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", authUrl)
	} else {
		http.Redirect(w, r, authUrl, http.StatusFound)
	}
}

func (s *OAuthManager) authCallback(w http.ResponseWriter, r *http.Request) {
	state := gothic.GetState(r)
	sessionId, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	if stateMap[PROVIDER_NAME_KEY] != providerName {
		http.Error(w, "error matching session state", http.StatusInternalServerError)
		return
	}

	providerConfig := s.providerConfigs[providerName]
	if providerConfig == nil {
		http.Error(w, fmt.Sprintf("provider %s not configured", providerName), http.StatusInternalServerError)
		return
	}

	providerType := strings.SplitN(providerName, PROVIDER_NAME_DELIMITER, 2)[0]
	switch providerType {
	case "google":
		if providerConfig.HostedDomain != "" && user.RawData["hd"] != providerConfig.HostedDomain {
			http.Error(w, fmt.Sprintf("user does not belong to the required hosted domain. Found %s, expected %s",
				user.RawData["hd"], providerConfig.HostedDomain), http.StatusInternalServerError)
			return
		}
	}

	if stateMap[AUTH_KEY] != false {
		http.Error(w, "error matching session state, expected auth to be false", http.StatusInternalServerError)
		return
	}

	stateMap[USER_ID_KEY] = user.UserID
	stateMap[USER_EMAIL_KEY] = user.Email
	stateMap[USER_NICKNAME_KEY] = user.NickName

	lookupKeys := []string{USER_EMAIL_KEY, USER_ID_KEY, USER_NICKNAME_KEY}
	if strings.HasPrefix(providerName, "git") {
		// For git providers, prefer nickname over userid as it is more meaningful
		lookupKeys = []string{USER_EMAIL_KEY, USER_NICKNAME_KEY, USER_ID_KEY}
	}
	userId := ""
	ok := false
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

	// Update the state map, set to authenticated and add the user id and groups
	stateMap[AUTH_KEY] = true
	stateMap[USER_KEY] = userId
	stateMap[GROUPS_KEY] = groups
	err = s.db.UpdateKV(r.Context(), string(sessionId), stateMap)
	if err != nil {
		http.Error(w, "error updating KV state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	redirectUrl := stateMap[REDIRECT_URL].(string)
	redirectParsed, err := url.Parse(redirectUrl)
	if err != nil {
		http.Error(w, "error parsing relay: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to the auth/redirect url on the original app domain, so that the required cookie can be set on the app domain
	redirectAppDomain := redirectParsed.Scheme + "://" + redirectParsed.Host + types.INTERNAL_URL_PREFIX + "/auth/" + providerName + "/redirect?state=" + state
	http.Redirect(w, r, redirectAppDomain, http.StatusFound)
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
	}

	success := false
	defer func() {
		if !success {
			session.Options.MaxAge = -1 // delete the session if there is an error
			_ = session.Save(r, w)
		}
	}()

	nonceFromCookie := session.Values[NONCE_KEY].(string)
	sessionIdBytes, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sessionId := string(sessionIdBytes)

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

	if subtle.ConstantTimeCompare([]byte(stateMap[NONCE_KEY].(string)), []byte(nonceFromCookie)) != 1 {
		http.Error(w, "error matching session state, nonce mismatch", http.StatusInternalServerError)
		return
	}

	// Update the session cookie to authenticated, with the new values
	success = true
	session.Values[AUTH_KEY] = true
	session.Values[USER_KEY] = stateMap[USER_KEY].(string)
	session.Values[GROUPS_KEY] = stateMap[GROUPS_KEY].([]any)
	delete(session.Values, REDIRECT_URL)
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "error saving session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectUrl, http.StatusFound)
}
