// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// The OAuth 2.1 authorization server for the remote API surfaces. OpenRun is
// its own minimal AS: the four endpoints under /_openrun/oauth plus the
// well-known metadata documents.
// The login step reuses the configured api.auth mechanisms; access and
// refresh tokens land in the same credentials table as PATs, so one verifier
// covers everything and revocation is immediate.
//
// v1 login mechanisms: "builtin" (builtin_auth users) and "admin". The
// [auth.*]/[saml.*] federated login step is a follow-on; configuring one
// logs a warning and that mechanism is skipped at login.

const (
	oauthCLIClientId = "openrun-cli" // pre-registered public client for openrun login
	oauthCodeTTL     = 2 * time.Minute
	oauthMaxClients  = 200 // DCR quota
)

// oauthState is the in-process AS state: pending authorization codes.
// Codes are short-lived and single-use; a restart drops pending logins,
// which simply restart. Embedded in Server
type oauthState struct {
	oauthMu    sync.Mutex
	oauthCodes map[string]*oauthCode

	oauthRateMu   sync.Mutex
	oauthRateHits map[string][]time.Time

	// staleGroupsAudited dedups the federated_groups_stale audit event to
	// once per identity per server lifetime
	staleGroupsAudited sync.Map
}

type oauthCode struct {
	clientId    string
	redirectUri string
	challenge   string // PKCE S256 challenge
	principal   string
	scopes      []string
	resource    string // logical surface name (rest/mcp)
	expires     time.Time
}

// apiExternalUrl returns the canonical https origin for the API surfaces:
// api.external_url, defaulting to security.callback_url. Empty when neither
// is configured
func (s *Server) apiExternalUrl() string {
	return strings.TrimSuffix(cmp.Or(s.Config().Api.ExternalUrl, s.Config().Security.CallbackUrl), "/")
}

// apiResourceURI returns the canonical resource URI for a surface. The rest
// resource is a logical identifier (the endpoints live under /_openrun); the
// mcp resource equals the real endpoint URL, since MCP clients derive the
// resource from the server URL they connect to
func (s *Server) apiResourceURI(surface string) string {
	external := s.apiExternalUrl()
	if external == "" {
		return ""
	}
	if surface == ApiResourceMCP {
		return external + types.INTERNAL_URL_PREFIX + "/mcp"
	}
	return external + "/rest"
}

// surfaceForResource maps a requested RFC 8707 resource URI to the logical
// surface name; "" when unknown. Exact canonical comparison, never a prefix
func (s *Server) surfaceForResource(resource string) string {
	switch strings.TrimSuffix(resource, "/") {
	case s.apiResourceURI(ApiResourceRest):
		return ApiResourceRest
	case s.apiResourceURI(ApiResourceMCP):
		return ApiResourceMCP
	}
	return ""
}

// apiAuthChallenge builds the WWW-Authenticate value for a surface's 401
// responses: realm plus, when the external url is configured, the protected
// resource metadata pointer and the surface's default scope ask (CLI gets *,
// MCP gets read-only by default - a single consent must not hand an AI
// client broad destructive authority)
func (s *Server) apiAuthChallenge(surface string) string {
	external := s.apiExternalUrl()
	if external == "" {
		return fmt.Sprintf(`Bearer realm="%s"`, REALM)
	}
	scope := "*"
	if surface == ApiResourceMCP {
		scope = "*:read"
	}
	return fmt.Sprintf(`Bearer realm="%s", resource_metadata="%s/.well-known/oauth-protected-resource/%s", scope="%s"`,
		REALM, external, surface, scope)
}

// serveOAuthMetadata handles the well-known documents: the RFC 8414
// authorization server metadata and the RFC 9728 protected resource
// metadata, one document per enabled surface
func (h *Handler) serveOAuthASMetadata(w http.ResponseWriter, r *http.Request) {
	external := h.server.apiExternalUrl()
	if external == "" {
		http.NotFound(w, r)
		return
	}
	writeOAuthJSON(w, http.StatusOK, map[string]any{
		"issuer":                                external,
		"authorization_endpoint":                external + types.INTERNAL_URL_PREFIX + "/oauth/authorize",
		"token_endpoint":                        external + types.INTERNAL_URL_PREFIX + "/oauth/token",
		"registration_endpoint":                 external + types.INTERNAL_URL_PREFIX + "/oauth/register",
		"revocation_endpoint":                   external + types.INTERNAL_URL_PREFIX + "/oauth/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

func (h *Handler) serveOAuthPRM(surface string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		external := h.server.apiExternalUrl()
		if external == "" || !apiSurfaceEnabled(h.server.Config(), surface) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		writeOAuthJSON(w, http.StatusOK, map[string]any{
			"resource":                 h.server.apiResourceURI(surface),
			"authorization_servers":    []string{external},
			"bearer_methods_supported": []string{"header"},
		})
	}
}

func writeOAuthJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, value)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeOAuthJSON(w, status, map[string]string{"error": code, "error_description": description})
}

// serveOAuth routes the /_openrun/oauth endpoints (mounted behind the
// transport gate; these are pre-authentication endpoints, so a per-client-IP
// rate limit guards password guessing and registration abuse)
func (h *Handler) serveOAuth() http.Handler {
	mux := http.NewServeMux()
	prefix := types.INTERNAL_URL_PREFIX + "/oauth"
	mux.HandleFunc("POST "+prefix+"/register", h.oauthRegister)
	mux.HandleFunc("GET "+prefix+"/authorize", h.oauthAuthorizeForm)
	mux.HandleFunc("POST "+prefix+"/authorize", h.oauthAuthorizeSubmit)
	mux.HandleFunc("POST "+prefix+"/token", h.oauthToken)
	mux.HandleFunc("POST "+prefix+"/revoke", h.oauthRevoke)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every AS response either carries or concerns credentials: RFC 6749
		// §5.1 requires no-store on token responses, and the login page must
		// never be cached either
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if !h.server.oauthRateAllow(system.GetClientIP(r, h.server.Config().Security.TrustedProxies)) {
			writeOAuthError(w, http.StatusTooManyRequests, "slow_down", "too many requests, retry later")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// oauthRateAllow is a fixed-window per-IP limiter for the AS endpoints
func (s *Server) oauthRateAllow(clientIP string) bool {
	const window = time.Minute
	const maxHits = 30
	now := time.Now()
	s.oauthRateMu.Lock()
	defer s.oauthRateMu.Unlock()
	if s.oauthRateHits == nil {
		s.oauthRateHits = map[string][]time.Time{}
	}
	hits := s.oauthRateHits[clientIP][:0:0]
	for _, hit := range s.oauthRateHits[clientIP] {
		if now.Sub(hit) < window {
			hits = append(hits, hit)
		}
	}
	if len(hits) >= maxHits {
		s.oauthRateHits[clientIP] = hits
		return false
	}
	s.oauthRateHits[clientIP] = append(hits, now)
	// Bound the map: drop other IPs' stale windows opportunistically
	if len(s.oauthRateHits) > 10000 {
		for ip, ipHits := range s.oauthRateHits {
			if len(ipHits) == 0 || now.Sub(ipHits[len(ipHits)-1]) > window {
				delete(s.oauthRateHits, ip)
			}
		}
	}
	return true
}

// oauthRegister implements RFC 7591 dynamic client registration: public
// clients only (PKCE, no secrets), https or loopback redirect uris, with a
// registration quota
func (h *Handler) oauthRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectUris []string `json:"redirect_uris"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := json.UnmarshalRead(r.Body, &req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	if len(req.RedirectUris) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, uri := range req.RedirectUris {
		parsed, err := url.Parse(uri)
		valid := err == nil && (parsed.Scheme == "https" ||
			(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())))
		if !valid {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri",
				fmt.Sprintf("redirect uri %q must be https or a loopback http url", uri))
			return
		}
	}
	count, err := h.server.db.CountOAuthClients(r.Context())
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if count >= oauthMaxClients {
		// Free quota slots held by stale registrations no live credential
		// references before refusing, so abandoned DCR clients cannot
		// permanently consume the quota
		pruned, pruneErr := h.server.db.PruneUnusedOAuthClients(r.Context(), time.Now().Add(-30*24*time.Hour).UTC())
		if pruneErr != nil {
			h.Error().Err(pruneErr).Msg("error pruning oauth clients")
		}
		if pruned == 0 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "client registration limit reached")
			return
		}
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	clientId := "orc_" + hex.EncodeToString(idBytes)
	if err := h.server.db.CreateOAuthClient(r.Context(), &metadata.OAuthClient{
		Id: clientId, Name: req.ClientName, RedirectUris: req.RedirectUris}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	h.server.auditOAuthEvent(r.Context(), "oauth_client_register", clientId, true)
	writeOAuthJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientId,
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectUris,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// oauthValidateAuthorizeParams validates the shared authorize parameters and
// resolves the client's redirect rules. Returns the logical surface for the
// requested resource
func (h *Handler) oauthValidateAuthorizeParams(ctx context.Context, clientId, redirectUri, challenge, method, resource string) (string, error) {
	if clientId == "" || redirectUri == "" {
		return "", fmt.Errorf("client_id and redirect_uri are required")
	}
	if challenge == "" || method != "S256" {
		return "", fmt.Errorf("PKCE with code_challenge_method=S256 is required")
	}
	if err := h.validateOAuthRedirect(ctx, clientId, redirectUri); err != nil {
		return "", err
	}
	surface := h.server.surfaceForResource(resource)
	if surface == "" {
		return "", fmt.Errorf("invalid_target: resource %q is not a canonical resource of this server", resource)
	}
	if !apiSurfaceEnabled(h.server.Config(), surface) {
		return "", fmt.Errorf("invalid_target: the %s surface is not enabled", surface)
	}
	return surface, nil
}

// validateOAuthRedirect checks the redirect uri against the client's
// registration. The pre-registered openrun-cli client allows loopback http
// redirects on any port (RFC 8252 §7.3); DCR clients require an exact match
func (h *Handler) validateOAuthRedirect(ctx context.Context, clientId, redirectUri string) error {
	if clientId == oauthCLIClientId {
		parsed, err := url.Parse(redirectUri)
		if err != nil || parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname()) || parsed.Path != "/callback" {
			return fmt.Errorf("openrun-cli redirect uri must be http://127.0.0.1:<port>/callback")
		}
		return nil
	}
	client, err := h.server.db.GetOAuthClient(ctx, clientId)
	if err != nil {
		return fmt.Errorf("unknown client_id")
	}
	for _, uri := range client.RedirectUris {
		if uri == redirectUri {
			return nil
		}
	}
	return fmt.Errorf("redirect_uri is not registered for this client")
}

var oauthLoginTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html><head><title>OpenRun Login</title><style>
body{font-family:system-ui,sans-serif;max-width:26rem;margin:4rem auto;padding:0 1rem;color:#222}
input,button{width:100%;padding:.5rem;margin:.25rem 0 .75rem;box-sizing:border-box}
button{background:#2563eb;color:#fff;border:0;border-radius:4px;padding:.6rem;cursor:pointer}
.err{color:#b91c1c}.meta{color:#555;font-size:.9rem}.warn{color:#92400e;font-size:.9rem}
</style></head><body>
<h2>OpenRun Login</h2>
<p class="meta">Application <b>{{.ClientName}}</b> is requesting access to the
<b>{{.Surface}}</b> API with scope <b>{{.Scope}}</b>.</p>
<p class="meta">After approval the access code is sent to <b>{{.RedirectUri}}</b>.</p>
{{if .DynamicClient}}<p class="warn">This application registered itself dynamically;
its name is self-reported and not verified. Check that the address above is the
application you intend to authorize.</p>{{end}}
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
{{range $k, $v := .Params}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<label>Username</label><input name="or_username" autocomplete="username" autofocus>
<label>Password</label><input name="or_password" type="password" autocomplete="current-password">
<label>Granted scope (narrow to limit this token)</label><input name="or_scope" value="{{.Scope}}">
<button type="submit">Log in and approve</button>
</form></body></html>`))

// oauthAuthorizeForm renders the login + consent page. The oauth request
// parameters are echoed as hidden fields; credentials go in the same POST so
// there is no cookie/session to CSRF
func (h *Handler) oauthAuthorizeForm(w http.ResponseWriter, r *http.Request) {
	h.renderOAuthLogin(w, r, r.URL.Query().Get, "")
}

func (h *Handler) renderOAuthLogin(w http.ResponseWriter, r *http.Request, get func(string) string, errMsg string) {
	clientId := get("client_id")
	surface, err := h.oauthValidateAuthorizeParams(r.Context(), clientId, get("redirect_uri"),
		get("code_challenge"), get("code_challenge_method"), get("resource"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if get("response_type") != "code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	scope := get("scope")
	if scope == "" {
		scope = "*"
		if surface == ApiResourceMCP {
			scope = "*:read"
		}
	}
	clientName := clientId
	if clientId != oauthCLIClientId {
		if client, err := h.server.db.GetOAuthClient(r.Context(), clientId); err == nil && client.Name != "" {
			clientName = client.Name
		}
	}
	params := map[string]string{}
	for _, name := range []string{"response_type", "client_id", "redirect_uri", "state",
		"code_challenge", "code_challenge_method", "resource"} {
		params[name] = get(name)
	}
	// The page collects credentials: same hardening as the form login page
	// (no scripts, no framing, no referrer, never cached). style-src allows
	// the page's own inline style block; there is no injection surface for it
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = oauthLoginTemplate.Execute(w, map[string]any{
		"ClientName":    clientName,
		"Surface":       surface,
		"Scope":         scope,
		"RedirectUri":   get("redirect_uri"),
		"DynamicClient": clientId != oauthCLIClientId,
		"Error":         errMsg,
		"Action":        types.INTERNAL_URL_PREFIX + "/oauth/authorize",
		"Params":        params,
	})
}

// oauthAuthorizeSubmit authenticates the posted credentials against the
// configured api.auth mechanisms, then issues a single-use authorization code
func (h *Handler) oauthAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	get := r.PostForm.Get
	surface, err := h.oauthValidateAuthorizeParams(r.Context(), get("client_id"), get("redirect_uri"),
		get("code_challenge"), get("code_challenge_method"), get("resource"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	principal, err := h.server.oauthAuthenticateUser(get("or_username"), get("or_password"))
	if err != nil {
		h.server.insertAuthFailureEvent(r, "oauth_authorize", err.Error())
		h.renderOAuthLogin(w, r, get, err.Error())
		return
	}

	scopes := parseScopeParam(get("or_scope"))
	if len(scopes) == 0 {
		scopes = []string{"*"}
	}
	if err := rbac.ValidateScopes(scopes); err != nil {
		h.renderOAuthLogin(w, r, get, err.Error())
		return
	}

	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	code := hex.EncodeToString(codeBytes)
	h.server.oauthMu.Lock()
	if h.server.oauthCodes == nil {
		h.server.oauthCodes = map[string]*oauthCode{}
	}
	// Opportunistic sweep of expired pending codes
	for existing, entry := range h.server.oauthCodes {
		if time.Now().After(entry.expires) {
			delete(h.server.oauthCodes, existing)
		}
	}
	h.server.oauthCodes[code] = &oauthCode{
		clientId:    get("client_id"),
		redirectUri: get("redirect_uri"),
		challenge:   get("code_challenge"),
		principal:   principal,
		scopes:      scopes,
		resource:    surface,
		expires:     time.Now().Add(oauthCodeTTL),
	}
	h.server.oauthMu.Unlock()

	redirect, _ := url.Parse(get("redirect_uri"))
	query := redirect.Query()
	query.Set("code", code)
	if state := get("state"); state != "" {
		query.Set("state", state)
	}
	redirect.RawQuery = query.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func parseScopeParam(scope string) []string {
	fields := strings.FieldsFunc(scope, func(r rune) bool { return r == ' ' || r == ',' })
	scopes := make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			scopes = append(scopes, field)
		}
	}
	return scopes
}

// oauthAuthenticateUser verifies the posted credentials against the
// configured api.auth mechanisms, returning the principal (provider:username
// or admin)
func (s *Server) oauthAuthenticateUser(username, password string) (string, error) {
	mechanisms := s.Config().Api.Auth
	if len(mechanisms) == 0 {
		return "", fmt.Errorf("api.auth is not configured: set the login mechanisms (builtin, admin) in the [api] section")
	}
	if username == "" || password == "" {
		return "", fmt.Errorf("username and password are required")
	}
	basicHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	for _, mechanism := range mechanisms {
		switch mechanism {
		case "builtin":
			if principal, _, ok := s.builtinAuth.authenticate(basicHeader); ok {
				return principal, nil
			}
		case "admin":
			if username == s.Config().AdminUser && s.authHandler.authenticate(basicHeader) {
				return types.ADMIN_USER, nil
			}
		default:
			// [auth.*]/[saml.*] federated login step is a follow-on
			s.Warn().Msgf("api.auth mechanism %q is not supported yet for the OAuth login page", mechanism)
		}
	}
	return "", fmt.Errorf("invalid username or password")
}

// oauthToken handles the token endpoint: authorization_code exchange and
// refresh_token rotation. Public clients, no client authentication
func (h *Handler) oauthToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		h.oauthTokenCode(w, r)
	case "refresh_token":
		h.oauthTokenRefresh(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (h *Handler) oauthTokenCode(w http.ResponseWriter, r *http.Request) {
	get := r.PostForm.Get
	code, clientId, verifier := get("code"), get("client_id"), get("code_verifier")

	h.server.oauthMu.Lock()
	entry := h.server.oauthCodes[code]
	delete(h.server.oauthCodes, code) // single use, success or not
	h.server.oauthMu.Unlock()

	if entry == nil || time.Now().After(entry.expires) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired authorization code")
		return
	}
	if entry.clientId != clientId || entry.redirectUri != get("redirect_uri") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id/redirect_uri mismatch")
		return
	}
	challenge := base64.RawURLEncoding.EncodeToString(func() []byte { s := sha256.Sum256([]byte(verifier)); return s[:] }())
	if verifier == "" || subtle.ConstantTimeCompare([]byte(challenge), []byte(entry.challenge)) != 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	grantBytes := make([]byte, 8)
	if _, err := rand.Read(grantBytes); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	grantId := "grt_" + hex.EncodeToString(grantBytes)
	// The absolute grant lifetime starts at consent; every token the grant
	// ever mints is clamped to it (refresh rotation slides within the bound)
	grantDeadline := time.Now().Add(h.server.apiGrantMaxTTL()).UTC()
	response, err := h.server.mintOAuthTokens(r.Context(), entry.principal, clientId, grantId, grantId,
		entry.scopes, entry.resource, "", grantDeadline)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	h.server.auditOAuthEvent(r.Context(), "oauth_token_grant", entry.principal, true)
	writeOAuthJSON(w, http.StatusOK, response)
}

// apiGrantMaxTTL returns the absolute OAuth grant lifetime
// (api.grant_max_ttl, default 90 days): the hard bound refresh rotation
// cannot slide past, after which a new interactive login is required
func (s *Server) apiGrantMaxTTL() time.Duration {
	ttl, err := time.ParseDuration(cmp.Or(s.Config().Api.GrantMaxTTL, "2160h"))
	if err != nil || ttl <= 0 {
		return 2160 * time.Hour
	}
	return ttl
}

// mintOAuthTokens creates the access + refresh token pair. rotateFrom names
// the consumed refresh token id for a rotation ("" for the initial grant).
// notAfter is the grant's absolute deadline: minted expiries are clamped to
// it so rotation cannot slide the grant past its lifetime
func (s *Server) mintOAuthTokens(ctx context.Context, principal, clientId, grantId, familyId string,
	scopes []string, surface string, rotateFrom string, notAfter time.Time) (map[string]any, error) {
	identity, err := s.resolveApiIdentity(ctx, principal)
	if err != nil {
		return nil, err
	}
	accessTTL, err := time.ParseDuration(cmp.Or(s.Config().Api.AccessTokenTTL, "1h"))
	if err != nil {
		accessTTL = time.Hour
	}
	refreshTTL, err := time.ParseDuration(cmp.Or(s.Config().Api.RefreshTokenTTL, "720h"))
	if err != nil {
		refreshTTL = 720 * time.Hour
	}
	// UTC strips the monotonic reading before the driver persists the time
	accessExpiry := time.Now().Add(accessTTL).UTC()
	refreshExpiry := time.Now().Add(refreshTTL).UTC()
	if !notAfter.IsZero() {
		if accessExpiry.After(notAfter) {
			accessExpiry = notAfter
			accessTTL = time.Until(notAfter)
		}
		if refreshExpiry.After(notAfter) {
			refreshExpiry = notAfter
		}
	}

	newCred := func(credType string, expiry time.Time) (*types.Credential, string, error) {
		id, secret, _, err := generateApiKey()
		if err != nil {
			return nil, "", err
		}
		prefix := apiTokenATPrefix
		if credType == types.CredentialTypeOAuthRefresh {
			prefix = apiTokenRTPrefix
		}
		return &types.Credential{
			Id:            id,
			SecretHash:    hashApiSecret(secret),
			Type:          credType,
			IdentityId:    identity.Id,
			Scopes:        scopes,
			Resources:     []string{surface},
			OAuthClientId: clientId,
			GrantId:       grantId,
			FamilyId:      familyId,
			ExpiresAt:     &expiry,
			CreatedBy:     principal,
		}, prefix + id + "_" + secret, nil
	}

	accessCred, accessToken, err := newCred(types.CredentialTypeOAuthAccess, accessExpiry)
	if err != nil {
		return nil, err
	}
	refreshCred, refreshToken, err := newCred(types.CredentialTypeOAuthRefresh, refreshExpiry)
	if err != nil {
		return nil, err
	}

	if rotateFrom != "" {
		if err := s.db.RotateRefreshToken(ctx, rotateFrom, refreshCred, accessCred); err != nil {
			return nil, err
		}
	} else {
		if err := s.db.CreateCredential(ctx, accessCred); err != nil {
			return nil, err
		}
		if err := s.db.CreateCredential(ctx, refreshCred); err != nil {
			return nil, err
		}
	}
	return map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL.Seconds()),
		"refresh_token": refreshToken,
		"scope":         strings.Join(scopes, " "),
		// Extension field: lets openrun login show who the session is for
		"principal": principal,
	}, nil
}

func (h *Handler) oauthTokenRefresh(w http.ResponseWriter, r *http.Request) {
	get := r.PostForm.Get
	credType, id, secret, err := parseApiToken(get("refresh_token"))
	if err != nil || credType != types.CredentialTypeOAuthRefresh {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "a refresh token is required")
		return
	}
	cred, identity, err := h.server.db.GetCredentialWithIdentity(r.Context(), id)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
		return
	}
	if subtle.ConstantTimeCompare([]byte(cred.SecretHash), []byte(hashApiSecret(secret))) != 1 ||
		cred.Type != types.CredentialTypeOAuthRefresh || cred.OAuthClientId != get("client_id") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}
	if cred.ConsumedAt != nil {
		// Reuse of a rotated refresh token: the whole grant is compromised.
		// Revoke every credential minted under it and audit prominently
		if err := h.server.db.RevokeGrantCredentials(r.Context(), cred.GrantId, "reuse_detected"); err != nil {
			h.Error().Err(err).Msg("error revoking grant on refresh token reuse")
		}
		h.server.auditOAuthEvent(r.Context(), "oauth_refresh_reuse_detected", identity.PrincipalName, false)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected, grant revoked")
		return
	}
	if cred.RevokedAt != nil || (cred.ExpiresAt != nil && time.Now().After(*cred.ExpiresAt)) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is revoked or expired")
		return
	}
	if identity.DisabledAt != nil {
		// The identity kill-switch invalidates refresh too, not just the
		// resource-endpoint verifier
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "identity is disabled")
		return
	}

	// Refresh can never expand the grant: same client, same resource, at
	// most the original scopes (a scope parameter may narrow, never add)
	scopes := cred.Scopes
	if requested := parseScopeParam(get("scope")); len(requested) > 0 {
		for _, scope := range requested {
			if !slices.Contains(cred.Scopes, scope) {
				writeOAuthError(w, http.StatusBadRequest, "invalid_scope",
					"refresh may narrow the granted scopes, not add to them")
				return
			}
		}
		scopes = requested
	}
	surface := ApiResourceRest
	if len(cred.Resources) > 0 {
		surface = cred.Resources[0]
	}
	if !apiSurfaceEnabled(h.server.Config(), surface) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			fmt.Sprintf("the %s surface is no longer enabled", surface))
		return
	}

	// Absolute grant lifetime: rotation slides the refresh window but never
	// past grant start + api.grant_max_ttl. Past the deadline the grant is
	// closed out and the user logs in again
	grantStart, err := h.server.db.GetGrantStartTime(r.Context(), cred.GrantId)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	grantDeadline := grantStart.Add(h.server.apiGrantMaxTTL())
	if time.Now().After(grantDeadline) {
		if err := h.server.db.RevokeGrantCredentials(r.Context(), cred.GrantId, "grant_expired"); err != nil {
			h.Error().Err(err).Msg("error revoking expired grant")
		}
		h.server.auditOAuthEvent(r.Context(), "oauth_grant_expired", identity.PrincipalName, false)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"the grant's maximum lifetime has passed, log in again")
		return
	}
	response, err := h.server.mintOAuthTokens(r.Context(), identity.PrincipalName, cred.OAuthClientId,
		cred.GrantId, cred.FamilyId, scopes, surface, cred.Id, grantDeadline.UTC())
	if err != nil {
		if errors.Is(err, metadata.ErrRefreshConsumed) {
			// A concurrent rotation won the race on this token: same
			// treatment as replaying an already-rotated token - the grant is
			// compromised, revoke the whole family
			if revokeErr := h.server.db.RevokeGrantCredentials(r.Context(), cred.GrantId, "reuse_detected"); revokeErr != nil {
				h.Error().Err(revokeErr).Msg("error revoking grant on concurrent refresh consumption")
			}
			h.server.auditOAuthEvent(r.Context(), "oauth_refresh_reuse_detected", identity.PrincipalName, false)
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected, grant revoked")
			return
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	writeOAuthJSON(w, http.StatusOK, response)
}

// oauthRevoke implements RFC 7009: revoking a refresh token revokes its
// whole grant; revoking an access token or PAT revokes that credential.
// Always 200, even for unknown tokens
func (h *Handler) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	credType, id, secret, err := parseApiToken(r.PostForm.Get("token"))
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	cred, identity, err := h.server.db.GetCredentialWithIdentity(r.Context(), id)
	if err != nil || subtle.ConstantTimeCompare([]byte(cred.SecretHash), []byte(hashApiSecret(secret))) != 1 ||
		cred.Type != credType {
		w.WriteHeader(http.StatusOK)
		return
	}
	if clientId := r.PostForm.Get("client_id"); clientId != "" && cred.OAuthClientId != "" && cred.OAuthClientId != clientId {
		// RFC 7009: a client may only revoke tokens issued to it. Unknown
		// tokens still return 200
		w.WriteHeader(http.StatusOK)
		return
	}
	if credType == types.CredentialTypeOAuthRefresh && cred.GrantId != "" {
		err = h.server.db.RevokeGrantCredentials(r.Context(), cred.GrantId, "logout")
	} else {
		err = h.server.db.RevokeCredential(r.Context(), cred.Id, "logout")
	}
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	h.server.auditOAuthEvent(r.Context(), "oauth_revoke", identity.PrincipalName, true)
	w.WriteHeader(http.StatusOK)
}

// auditOAuthEvent writes an audit row for the AS operations (registration,
// grants, revocation, reuse detection)
func (s *Server) auditOAuthEvent(ctx context.Context, operation, target string, success bool) {
	status := string(types.EventStatusSuccess)
	if !success {
		status = string(types.EventStatusFailure)
	}
	event := types.AuditEvent{
		CreateTime: time.Now(),
		UserId:     cmp.Or(target, types.ADMIN_USER),
		EventType:  types.EventTypeSystem,
		Operation:  operation,
		Target:     target,
		Status:     status,
		Detail:     "invoker=oauth",
	}
	if err := s.InsertAuditEvent(&event); err != nil {
		s.Error().Err(err).Msg("error inserting oauth audit event")
	}
}
