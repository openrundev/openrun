// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// Form-based login for the system and builtin app auth types. Browser
// navigations to a protected app get an HTML login page (styled like the
// console); non-browser/API clients keep the HTTP Basic auth challenge.
// Credentials are verified through the same AdminBasicAuth/BuiltinAuth bcrypt
// paths as basic auth, and the authenticated identity is stored in a KV-backed
// session cookie on the app's own domain (the store the SSO/SAML cookies use,
// cookie names system_openrun_session / builtin_openrun_session).
//
// The login page is served ONLY from a dedicated auth callback domain
// (security.auth_callback_domain, default auth.<default_domain>) on which no
// apps can be created. This keeps app JavaScript from ever being same-origin
// with the credential form, and lets the page ship under a strict CSP. The
// flow is therefore cross-domain, mirroring the OAuth handshake:
//
//  1. app domain: an app request with no valid session calls beginLogin, which
//     stores the login state (auth type, original URL, nonce) in the KV store,
//     sets a short-lived pre-auth cookie carrying the nonce on the app domain,
//     and redirects to the auth domain login page.
//  2. auth domain: the login page renders the form (state in a hidden field);
//     the POST verifies credentials and, on success, marks the KV state
//     authenticated and redirects to the complete endpoint back on the app
//     domain.
//  3. app domain: complete validates the pre-auth nonce cookie against the KV
//     state (CSRF + binds the flow to the browser that started it), rotates the
//     session id to prevent fixation, writes the authenticated session cookie,
//     and redirects to the original app URL.
//
// If security.disable_login_form is set (or no auth domain can be resolved),
// system/builtin fall back to the plain HTTP Basic challenge for browsers too.
//
// The page assets are embedded into the binary. They are maintained as a
// dev-harness app in the openrundev/apps repo (openrun/login), where a
// dev-mode install runs the tailwind watcher that generates style.css; see
// login_html/sync_from_app.sh.

//go:embed login_html/login.go.html login_html/logout.go.html
var loginTemplateFS embed.FS

//go:embed login_html/style.css
var loginStyleCSS []byte

//go:embed login_html/login_extra.css
var loginExtraCSS []byte

const (
	formLoginPath    = types.INTERNAL_URL_PREFIX + "/auth/login"
	formCompletePath = formLoginPath + "/complete"
	formStylePath    = formLoginPath + "/style.css"
	formExtraPath    = formLoginPath + "/extra.css"

	// CRED_FP_KEY stores a fingerprint of the bcrypt hash the session was
	// authenticated against; a password change invalidates the session
	CRED_FP_KEY = "cred_fp"
)

type FormLoginManager struct {
	*types.Logger
	getConfig   func() *types.ServerConfig
	cookieStore sessions.Store
	db          KVStore
	adminAuth   *AdminBasicAuth
	builtinAuth *BuiltinAuth
	tmpl        *template.Template
	styleHref   string
	extraHref   string
	styleEtag   string
	extraEtag   string

	// sessionHttpsOnly mirrors the cookie store's Secure attribute, which is
	// fixed at startup (oauth.Setup) and shared with OAuth/SAML. canStartFlow
	// reads this startup value, not the dynamic config, so its decision matches
	// the actual cookie behavior even if session_https_only is changed
	// dynamically (which does not reconfigure the store). session_https_only
	// and session_max_age are effectively restart-only for the cookie store
	sessionHttpsOnly bool
}

func NewFormLoginManager(logger *types.Logger, getConfig func() *types.ServerConfig, cookieStore sessions.Store,
	db KVStore, adminAuth *AdminBasicAuth, builtinAuth *BuiltinAuth, sessionHttpsOnly bool) (*FormLoginManager, error) {
	tmpl, err := template.ParseFS(loginTemplateFS, "login_html/*.go.html")
	if err != nil {
		return nil, err
	}

	styleHash := contentHash(loginStyleCSS)
	extraHash := contentHash(loginExtraCSS)
	return &FormLoginManager{
		Logger:           logger,
		getConfig:        getConfig,
		cookieStore:      cookieStore,
		db:               db,
		adminAuth:        adminAuth,
		builtinAuth:      builtinAuth,
		tmpl:             tmpl,
		styleHref:        formStylePath + "?v=" + styleHash,
		extraHref:        formExtraPath + "?v=" + extraHash,
		styleEtag:        `"` + styleHash + `"`,
		extraEtag:        `"` + extraHash + `"`,
		sessionHttpsOnly: sessionHttpsOnly,
	}, nil
}

func contentHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// credentialFingerprint returns a fingerprint of the current stored bcrypt
// hash for the user, or false when the user has no usable credential. The
// fingerprint is recorded in the session at login and re-checked on every
// request, so a password change (like a user delete or admin rename)
// invalidates existing form-login sessions immediately. The auto-generated
// admin password also writes its hash to the config at startup, so system
// sessions do not survive a restart that regenerates the password
func credentialFingerprint(config *types.ServerConfig, authType, username string) (string, bool) {
	var bcryptHash string
	if authType == string(types.AppAuthnSystem) {
		if username != config.AdminUser {
			return "", false
		}
		bcryptHash = config.Security.AdminPasswordBcrypt
	} else {
		bcryptHash = config.BuiltinAuth[username].Password
	}
	if bcryptHash == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(bcryptHash))
	return hex.EncodeToString(sum[:16]), true
}

// usesFormLogin reports whether an auth type is a candidate for the form login
// page (system or builtin). Whether the form is actually used also depends on
// enabled()
func usesFormLogin(authType string) bool {
	return authType == string(types.AppAuthnSystem) || authType == string(types.AppAuthnBuiltin)
}

// reservedAuthDomain resolves the configured auth callback domain, or
// ("", false) when it cannot be resolved (empty, or a bare "auth." prefix with
// no default_domain). A trailing "." on the configured value is a prefix
// combined with default_domain; otherwise the value is a full domain. This is
// resolved regardless of disable_login_form: the domain stays reserved (no apps
// served or created there) even while the form is off, so a config-propagation
// race between nodes cannot expose an app on the auth origin
func (s *FormLoginManager) reservedAuthDomain() (string, bool) {
	cfg := s.getConfig()
	domain := strings.TrimSpace(cfg.Security.AuthCallbackDomain)
	if domain == "" {
		return "", false
	}
	if strings.HasSuffix(domain, ".") {
		if cfg.System.DefaultDomain == "" {
			return "", false
		}
		return domain + cfg.System.DefaultDomain, true
	}
	return domain, true
}

// isReservedAuthHost reports whether a request host is the auth callback
// domain. No app (or fallback app) may be served on it, so app JavaScript is
// never same-origin with the credential form
func (s *FormLoginManager) isReservedAuthHost(host string) bool {
	domain, ok := s.reservedAuthDomain()
	if !ok {
		return false
	}
	return strings.EqualFold(host, domain)
}

// warnIfAuthDomainOccupied logs a warning if apps exist on the reserved auth
// callback domain. Those apps are no longer served (callApp 404s the host), so
// the same-origin isolation holds, but the operator should know
func (s *Server) warnIfAuthDomainOccupied() {
	if s.formLogin == nil {
		return
	}
	authDomain, ok := s.formLogin.reservedAuthDomain()
	if !ok {
		return
	}
	apps, err := s.db.GetAppsForDomain(authDomain)
	if err != nil {
		return
	}
	if len(apps) > 0 {
		s.Warn().Str("domain", authDomain).Int("apps", len(apps)).Msg(
			"apps exist on the auth callback domain and will no longer be served (reserved for the login page)")
	}
}

// authLoginDomain resolves the auth callback domain when the login form is
// active (not disabled and resolvable). The login page is served here
func (s *FormLoginManager) authLoginDomain() (string, bool) {
	if s.getConfig().Security.DisableLoginForm {
		return "", false
	}
	return s.reservedAuthDomain()
}

// enabled reports whether the HTML login page is active (form login is not
// disabled and an auth domain can be resolved)
func (s *FormLoginManager) enabled() bool {
	_, ok := s.authLoginDomain()
	return ok
}

// isAuthDomainRequest reports whether the request host is the auth callback
// domain (where the login page is served)
func (s *FormLoginManager) isAuthDomainRequest(r *http.Request) bool {
	domain, ok := s.authLoginDomain()
	if !ok {
		return false
	}
	return strings.EqualFold(system.GetHostname(r.Host), domain)
}

// canStartFlow reports whether the form login flow can complete for this app
// request. The pre-auth nonce cookie is Secure when session_https_only is set;
// over plain HTTP on a non-localhost host that cookie would not be returned to
// the complete step, so the flow would always fail nonce verification. In that
// case the caller keeps the Basic challenge instead. sessionHttpsOnly is the
// startup value the cookie store actually uses (see the struct field), so this
// decision cannot drift from the cookie's real Secure attribute
func (s *FormLoginManager) canStartFlow(r *http.Request) bool {
	if !s.sessionHttpsOnly {
		return true
	}
	if system.GetRequestScheme(r, s.getConfig().Security.TrustedProxies) == "https" {
		return true
	}
	// Plain-http exception for local development: the login redirect reuses
	// the request scheme, so the credential form must not end up on a remote
	// callback host over cleartext - the auth domain must be local as well
	if !isLocalhostHost(system.GetHostname(r.Host)) {
		return false
	}
	authDomain, ok := s.authLoginDomain()
	return ok && isLocalhostHost(authDomain)
}

// isLocalhostHost reports whether a host is local: localhost, loopback
// addresses and *.localhost (RFC 6761 reserves the localhost TLD; browsers
// resolve it to loopback)
func isLocalhostHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" ||
		strings.HasSuffix(host, ".localhost")
}

func (s *FormLoginManager) RegisterRoutes(csrfMiddleware *http.CrossOriginProtection, mux *chi.Mux) {
	// Login page + submit are served on the auth domain (host-checked in the
	// handlers). The submit URL is per auth type: distinct form identities
	// (action URL, field names, autocomplete section) keep browser password
	// managers from mixing up the admin account and builtin user credentials
	mux.Get(formLoginPath, s.loginPage)
	mux.Method("POST", formLoginPath+"/{authtype}", csrfMiddleware.Handler(http.HandlerFunc(s.loginSubmit)))
	// complete runs on the app domain, where the pre-auth nonce cookie lives
	mux.Get(formCompletePath, s.complete)
	mux.Get(formStylePath, s.serveCSS(loginStyleCSS, s.styleEtag))
	mux.Get(formExtraPath, s.serveCSS(loginExtraCSS, s.extraEtag))
}

func (s *FormLoginManager) serveCSS(content []byte, etag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The href carries a content hash, so the response can be cached hard
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(content)
	}
}

// setSecurityHeaders locks down the login page: the strict CSP (no scripts, no
// inline styles, self-only stylesheets) and framing/referrer protections keep
// credentials off any app-controlled surface. form-action is intentionally not
// set: the login POST redirects cross-origin to the complete endpoint on the
// app domain, which form-action 'self' would block. The page has no injection
// surface for a rogue form (no inline script, default-src 'none'), so omitting
// it does not weaken the protection meaningfully
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}

// render writes the login page. An empty state renders the "sign-in request
// has expired" variant without the credentials form
func (s *FormLoginManager) render(w http.ResponseWriter, authType, state, errorMsg string) {
	loginPath := ""
	if authType != "" {
		loginPath = formLoginPath + "/" + authType // form posts here (same origin)
	}
	data := map[string]any{
		"Data": map[string]any{
			"AuthType":  authType,
			"Error":     errorMsg,
			"State":     state,
			"StyleHref": s.styleHref,
			"ExtraHref": s.extraHref,
			"LoginPath": loginPath,
		},
	}
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "login.go.html", data); err != nil {
		s.Error().Err(err).Msg("error rendering login page")
	}
}

// loginRedirectTarget returns the URL to land on after login. For safe methods
// it is the request URL. For an unsafe method (only reached via an HTMX
// request, since non-HTMX unsafe methods do not start the flow) it is the
// validated same-host HX-Current-URL: the unsafe request must never be replayed
// as a post-login GET (which would drop its body). Returns false when no safe
// target is available, so the caller keeps the Basic challenge instead
func (s *FormLoginManager) loginRedirectTarget(r *http.Request) (string, bool) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return system.GetRequestUrl(r, s.getConfig().Security.TrustedProxies), true
	}
	current := r.Header.Get("HX-Current-URL")
	if current == "" {
		return "", false
	}
	parsed, err := url.Parse(current)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", false
	}
	if !strings.EqualFold(parsed.Host, r.Host) {
		return "", false
	}
	return current, true
}

// beginLogin starts the form login flow for an app request that has no valid
// session: store the login state in the KV store, set the short-lived pre-auth
// nonce cookie on the app domain and redirect the browser to the login page on
// the auth callback domain. Returns false without writing a response when the
// flow cannot be started (an unsafe-method request with no safe landing page),
// so the caller falls back to the Basic challenge
func (s *FormLoginManager) beginLogin(w http.ResponseWriter, r *http.Request, authType string) bool {
	authDomain, ok := s.authLoginDomain()
	if !ok {
		// enabled() is checked before calling beginLogin, this is defensive
		http.Error(w, "login form not available", http.StatusInternalServerError)
		return true
	}
	requestUrl, ok := s.loginRedirectTarget(r)
	if !ok {
		return false
	}

	sessionId, nonce, err := passwd.GenerateSessionNonce()
	if err != nil {
		http.Error(w, "error generating session nonce: "+err.Error(), http.StatusInternalServerError)
		return true
	}
	sessionId = types.FORM_LOGIN_KV_PREFIX + sessionId

	stateMap := map[string]any{
		AUTH_KEY:          false,
		PROVIDER_NAME_KEY: authType,
		REDIRECT_URL:      requestUrl,
		NONCE_KEY:         nonce,
	}
	expireAt := time.Now().Add(5 * time.Minute)
	if err := s.db.StoreKV(r.Context(), sessionId, stateMap, &expireAt); err != nil {
		http.Error(w, "error storing state: "+err.Error(), http.StatusInternalServerError)
		return true
	}

	// A stale/undecodable cookie returns an error along with a fresh session;
	// continue with the fresh session in that case
	session, _ := s.cookieStore.Get(r, genCookieName(authType))
	if session == nil {
		http.Error(w, "error getting session", http.StatusInternalServerError)
		return true
	}
	session.Values[AUTH_KEY] = false
	session.Values[PROVIDER_NAME_KEY] = authType
	session.Values[NONCE_KEY] = nonce
	session.Options.MaxAge = preAuthSessionMaxAge // short-lived until login completes
	if err := session.Save(r, w); err != nil {
		http.Error(w, "error saving session: "+err.Error(), http.StatusInternalServerError)
		return true
	}

	loginUrl := s.authDomainURL(r, authDomain, formLoginPath) +
		"?state=" + base64.URLEncoding.EncodeToString([]byte(sessionId))
	hxRedirect(w, r, loginUrl, http.StatusFound)
	return true
}

// authDomainURL builds an absolute URL on the auth callback domain, preserving
// the app request's scheme and port
func (s *FormLoginManager) authDomainURL(r *http.Request, authDomain, path string) string {
	scheme := system.GetRequestScheme(r, s.getConfig().Security.TrustedProxies)
	host := authDomain
	if _, port, err := net.SplitHostPort(r.Host); err == nil && port != "" {
		host = net.JoinHostPort(authDomain, port)
	}
	return scheme + "://" + host + path
}

// loadState fetches and validates the KV state entry for a login page state
// parameter, returning the KV key, the state's auth type and the state map
func (s *FormLoginManager) loadState(r *http.Request, state string) (string, string, map[string]any, bool) {
	sessionIdBytes, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		return "", "", nil, false
	}
	sessionId := string(sessionIdBytes)
	if !strings.HasPrefix(sessionId, types.FORM_LOGIN_KV_PREFIX) {
		// only form login state entries are valid here, a state token from
		// another flow (OAuth/SAML) must not be readable through this page
		return "", "", nil, false
	}
	stateMap, err := s.db.FetchKV(r.Context(), sessionId)
	if err != nil {
		return "", "", nil, false
	}
	authType, ok := stateValueString(stateMap, PROVIDER_NAME_KEY)
	if !ok || !usesFormLogin(authType) {
		return "", "", nil, false
	}
	return sessionId, authType, stateMap, true
}

func (s *FormLoginManager) loginPage(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthDomainRequest(r) {
		http.NotFound(w, r)
		return
	}
	state := r.URL.Query().Get("state")
	_, authType, _, ok := s.loadState(r, state)
	if !ok {
		s.render(w, "", "", "") // expired variant
		return
	}
	s.render(w, authType, state, "")
}

func (s *FormLoginManager) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthDomainRequest(r) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "error parsing form: "+err.Error(), http.StatusBadRequest)
		return
	}
	authType := chi.URLParam(r, "authtype")
	if !usesFormLogin(authType) {
		http.NotFound(w, r)
		return
	}

	state := r.PostFormValue("state")
	sessionId, stateAuthType, stateMap, ok := s.loadState(r, state)
	if !ok {
		s.render(w, "", "", "") // expired variant
		return
	}
	if stateAuthType != authType {
		s.render(w, "", "", "") // state from the other auth type's flow
		return
	}

	// The field names are per auth type, keeping browser password manager
	// entries for the two form variants distinct
	username := r.PostFormValue(authType + "-username")
	password := r.PostFormValue(authType + "-password")
	// Verify through the same code paths as basic auth, keeping their success
	// caching and failure throttling
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	authOk := false
	if authType == string(types.AppAuthnSystem) {
		authOk = s.adminAuth.authenticate(authHeader)
	} else {
		_, _, authOk = s.builtinAuth.authenticate(authHeader)
	}
	if !authOk {
		s.render(w, authType, state, "Invalid username or password")
		return
	}

	redirectUrl, ok := stateValueString(stateMap, REDIRECT_URL)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}
	redirectParsed, err := url.Parse(redirectUrl)
	if err != nil || (redirectParsed.Scheme != "http" && redirectParsed.Scheme != "https") {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}

	// The state token is ROTATED on successful login: the pre-login token is
	// visible in the login page URL, so whoever initiated the flow knows it.
	// If that token stayed valid at complete, an attacker could start a flow
	// (keeping the app-domain nonce cookie), hand the login URL to a victim,
	// and after the victim authenticates poll complete with the known state to
	// mint a session under the victim's identity. The fresh completion token
	// is only ever sent to the browser that submitted the credentials, and
	// complete additionally requires the nonce cookie of the browser that
	// initiated the flow - in the legitimate flow the same browser holds both.
	// Consuming the old key first is the atomic gate: a concurrent duplicate
	// submit of the same state cannot mint a second completion token
	consumed, err := s.db.DeleteKVIfPresent(r.Context(), sessionId)
	if err != nil {
		http.Error(w, "error updating state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !consumed {
		s.render(w, "", "", "") // already consumed by a concurrent submit
		return
	}
	completeKey, err := passwd.GenerateRandomKey(24)
	if err != nil {
		http.Error(w, "error generating state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	completeId := types.FORM_LOGIN_KV_PREFIX + base64.URLEncoding.EncodeToString(completeKey)

	// Mark the state authenticated with the resolved user; the app-domain
	// complete step (which holds the nonce cookie) turns this into a session.
	// The completion redirect is followed immediately, so the entry is
	// short-lived
	credFp, ok := credentialFingerprint(s.getConfig(), authType, username)
	if !ok {
		// defensive: the credential was verified just above, so it must resolve
		http.Error(w, "error resolving credentials", http.StatusInternalServerError)
		return
	}
	stateMap[AUTH_KEY] = true
	stateMap[USER_KEY] = username
	stateMap[CRED_FP_KEY] = credFp
	expireAt := time.Now().Add(1 * time.Minute)
	if err := s.db.StoreKV(r.Context(), completeId, stateMap, &expireAt); err != nil {
		http.Error(w, "error storing state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to complete on the app domain, where the pre-auth nonce cookie
	// was set, so the authenticated session cookie can be written there. This
	// is a cross-origin navigation from the form POST, so the login page CSP
	// does not set form-action (which would block it)
	completeUrl := redirectParsed.Scheme + "://" + redirectParsed.Host + formCompletePath +
		"?state=" + base64.URLEncoding.EncodeToString([]byte(completeId))
	http.Redirect(w, r, completeUrl, http.StatusFound)
}

// complete runs on the app domain. It validates the pre-auth nonce cookie
// against the authenticated KV state, then writes the session cookie and
// redirects back to the original app URL
func (s *FormLoginManager) complete(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	sessionId, authType, stateMap, ok := s.loadState(r, state)
	if !ok {
		s.renderExpiredOnAppDomain(w)
		return
	}

	if auth, _ := stateValueBool(stateMap, AUTH_KEY); !auth {
		s.renderExpiredOnAppDomain(w)
		return
	}

	session, err := s.cookieStore.Get(r, genCookieName(authType))
	if err != nil || session == nil {
		s.renderExpiredOnAppDomain(w)
		return
	}

	// A nonce mismatch must NOT delete the session: the pre-auth cookie is
	// shared per auth type, so a second tab (or an already-authenticated
	// session) may own the current cookie. A stale attempt just renders the
	// expired page; the pre-auth cookie self-expires at preAuthSessionMaxAge
	nonceFromCookie, ok := sessionValueString(session, NONCE_KEY)
	stateNonce, ok2 := stateValueString(stateMap, NONCE_KEY)
	if !ok || !ok2 || subtle.ConstantTimeCompare([]byte(stateNonce), []byte(nonceFromCookie)) != 1 {
		s.renderExpiredOnAppDomain(w)
		return
	}

	redirectUrl, ok := stateValueString(stateMap, REDIRECT_URL)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}
	username, ok := stateValueString(stateMap, USER_KEY)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}
	credFp, ok := stateValueString(stateMap, CRED_FP_KEY)
	if !ok {
		http.Error(w, "error matching session state", http.StatusBadRequest)
		return
	}

	// Consume the single-use state entry as an atomic gate: with two concurrent
	// completions (double submit, or a multi-node race) only one deletes the
	// row and mints a session; the loser renders the expired page
	consumed, err := s.db.DeleteKVIfPresent(r.Context(), sessionId)
	if err != nil {
		http.Error(w, "error deleting state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !consumed {
		s.renderExpiredOnAppDomain(w)
		return
	}

	// Promote the pre-auth session to an authenticated one. The session id is
	// rotated so a fixated pre-auth cookie does not remain valid. MaxAge is left
	// at the cookie store's startup value (which the securecookie codec agrees
	// with), not the dynamic config, to avoid codec max-age mismatches
	session.ID = ""
	session.Values[AUTH_KEY] = true
	session.Values[PROVIDER_NAME_KEY] = authType
	session.Values[USER_KEY] = username
	session.Values[CRED_FP_KEY] = credFp
	delete(session.Values, NONCE_KEY)
	if err := session.Save(r, w); err != nil {
		http.Error(w, "error saving session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectUrl, http.StatusFound)
}

// renderExpiredOnAppDomain shows the expired page for a failed complete. The
// login page normally serves from the auth domain, but the complete endpoint
// runs on the app domain; the strict security headers still apply
func (s *FormLoginManager) renderExpiredOnAppDomain(w http.ResponseWriter) {
	s.render(w, "", "", "")
}

// sessionAuth checks for an authenticated form login session for the system
// or builtin auth type. The username AND the credential fingerprint stored in
// the session are re-resolved against the current config on every request: a
// deleted builtin user, a changed admin username or a password change
// invalidates the session immediately, and builtin group changes take effect
// without a re-login. Returns false when the login form is disabled, so a
// stale cookie cannot outlive the feature
func (s *FormLoginManager) sessionAuth(r *http.Request, authType string) (string, []string, bool) {
	if !s.enabled() {
		return "", nil, false
	}
	session, err := s.cookieStore.Get(r, genCookieName(authType))
	if err != nil || session == nil {
		return "", nil, false
	}
	if auth, ok := session.Values[AUTH_KEY].(bool); !ok || !auth {
		return "", nil, false
	}
	if provider, ok := sessionValueString(session, PROVIDER_NAME_KEY); !ok || provider != authType {
		return "", nil, false
	}
	user, ok := sessionValueString(session, USER_KEY)
	if !ok || user == "" {
		return "", nil, false
	}

	// credentialFingerprint also verifies the user still exists (admin
	// username match / builtin entry present)
	config := s.getConfig()
	sessionFp, ok := sessionValueString(session, CRED_FP_KEY)
	if !ok {
		return "", nil, false
	}
	currentFp, ok := credentialFingerprint(config, authType, user)
	if !ok || subtle.ConstantTimeCompare([]byte(sessionFp), []byte(currentFp)) != 1 {
		return "", nil, false
	}

	if authType == string(types.AppAuthnSystem) {
		return types.ADMIN_USER, []string{}, true
	}
	groups := config.BuiltinAuth[user].Groups
	if groups == nil { // static entries can omit the groups field
		groups = []string{}
	}
	return string(types.AppAuthnBuiltin) + ":" + user, groups, true
}
