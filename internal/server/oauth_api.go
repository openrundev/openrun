// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
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
// The login step reuses the surface's configured [api.<surface>] auth mechanisms; access and
// refresh tokens land in the same credentials table as PATs, so one verifier
// covers everything and revocation is immediate.
//
// Login mechanisms: "builtin" (builtin_auth users) and "admin" on the password
// form, and the [auth.*]/[saml.*] providers through the federated login step
// (oauth_federated.go).

const (
	oauthMechanismParam = "mechanism"   // authorize request extension: the login mechanism to pre-select
	oauthCLIClientId    = "openrun-cli" // pre-registered public client for openrun login
	oauthCodeTTL        = 2 * time.Minute
	oauthMaxClients     = 200 // DCR quota
)

// oauthState is the in-process AS state. Pending authorization codes are
// NOT held here: the authorize redirect (browser) and the token exchange
// (MCP client / CLI) are separate HTTP clients that can reach different
// nodes of a multi-node (PostgreSQL) deployment, so codes live in the
// metadata keystore (oauth_code:<code>, expiring rows) and survive
// restarts. Embedded in Server
type oauthState struct {
	cimdState // Client ID Metadata Document cache (oauth_cimd.go)

	oauthRateMu   sync.Mutex
	oauthRateHits map[string][]time.Time

	// staleGroupsAudited dedups the federated_groups_stale audit event to
	// once per identity per server lifetime
	staleGroupsAudited sync.Map
}

// oauthCode is a pending authorization code, stored as JSON in the keystore
// under types.OAUTH_CODE_KV_PREFIX + code with delete_at = Expires
type oauthCode struct {
	ClientId    string    `json:"client_id"`
	RedirectUri string    `json:"redirect_uri"`
	Challenge   string    `json:"challenge"` // PKCE S256 challenge
	Principal   string    `json:"principal"`
	Scopes      []string  `json:"scopes"`
	Resource    string    `json:"resource"` // logical surface name (rest/mcp)
	Expires     time.Time `json:"expires"`
}

func oauthCodeKey(code string) string {
	return types.OAUTH_CODE_KV_PREFIX + code
}

// storeOAuthCode persists a pending code; the keystore expiry sweeper
// removes it if it is never exchanged
func (s *Server) storeOAuthCode(ctx context.Context, code string, entry *oauthCode) error {
	blob, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	expires := entry.Expires.UTC()
	return s.db.StoreKVBlob(ctx, oauthCodeKey(code), blob, &expires)
}

// consumeOAuthCode returns the pending code and removes it, or nil when it
// is unknown, expired or already consumed. Single use is enforced by the
// delete: with concurrent exchanges of the same code on any nodes, exactly
// one caller gets deleted=true and therefore the entry
func (s *Server) consumeOAuthCode(ctx context.Context, code string) (*oauthCode, error) {
	if code == "" {
		return nil, nil
	}
	key := oauthCodeKey(code)
	blob, err := s.db.FetchKVBlob(ctx, key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil // unknown or expired (FetchKVBlob excludes expired rows)
	}
	if err != nil {
		return nil, err // database failure, not a missing code
	}
	deleted, err := s.db.DeleteKVIfPresent(ctx, key)
	if err != nil {
		return nil, err
	}
	if !deleted {
		return nil, nil // consumed concurrently
	}
	var entry oauthCode
	if err := json.Unmarshal(blob, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// apiExternalUrl returns the canonical origin (the OAuth issuer) for the
// API surfaces and the MCP apps, see apiExternalUrlFor
func (s *Server) apiExternalUrl() string {
	return apiExternalUrlFor(s.Config())
}

// apiExternalUrlFor returns the canonical origin for the API surfaces and
// the MCP apps: api.external_url, else security.callback_url, else the
// listener-derived default of defaultApiExternalUrl. Empty when none
// applies. Always taken from config, never from a request Host
func apiExternalUrlFor(config *types.ServerConfig) string {
	if external := strings.TrimSuffix(cmp.Or(config.Api.ExternalUrl, config.Security.CallbackUrl), "/"); external != "" {
		return external
	}
	return defaultApiExternalUrl(config)
}

// defaultApiExternalUrl is the issuer origin used when neither
// api.external_url nor security.callback_url is set: the HTTPS listener on
// the default app domain, https://<system.default_domain>[:<https.port>].
// Empty when the HTTPS listener is off (or on an ephemeral port) or no
// default domain is configured, so a fresh install with the default https
// port serves MCP apps without any [api] configuration. Tokens are bound to
// this value like a configured one: setting the field later invalidates
// them
func defaultApiExternalUrl(config *types.ServerConfig) string {
	if config.Https.Port <= 0 || config.System.DefaultDomain == "" {
		return ""
	}
	host := strings.ToLower(config.System.DefaultDomain)
	if config.Https.Port != 443 {
		host += ":" + strconv.Itoa(config.Https.Port)
	}
	return "https://" + host
}

// apiExternalUrlIsDefault reports whether the issuer origin comes from
// defaultApiExternalUrl rather than configuration
func apiExternalUrlIsDefault(config *types.ServerConfig) bool {
	return config.Api.ExternalUrl == "" && config.Security.CallbackUrl == "" && defaultApiExternalUrl(config) != ""
}

// apiResourceURI returns the canonical resource URI for a surface, both
// under /_openrun so no app path can collide with them: the mcp resource
// equals the real endpoint URL (MCP clients derive the resource from the
// server URL they connect to); the rest resource <external>/_openrun/rest is
// a logical identifier for the management REST API served under /_openrun
func (s *Server) apiResourceURI(surface string) string {
	external := s.apiExternalUrl()
	if external == "" {
		return ""
	}
	return external + types.INTERNAL_URL_PREFIX + "/" + surface
}

// surfaceForResource maps a requested RFC 8707 resource URI to the logical
// surface name; "" when unknown. Exact canonical comparison, never a prefix
func (s *Server) surfaceForResource(resource string) string {
	// The query (the auth selection of a management surface url, see
	// surfaceAuthParam) is not part of the surface's identity
	resource, _, _ = strings.Cut(resource, "?")
	switch strings.TrimSuffix(resource, "/") {
	case s.apiResourceURI(ApiResourceRest):
		return ApiResourceRest
	case s.apiResourceURI(ApiResourceMCP):
		return ApiResourceMCP
	}
	return ""
}

// oauthResource is a resolved RFC 8707 resource: one of the two management
// surfaces (URI = the surface name, as stored on credentials since the
// first release) or an MCP app (URI = the app's canonical https resource)
type oauthResource struct {
	Surface string
	App     *types.AppInfo
	URI     string
	// Mechanism is the login mechanism the resource names with its auth
	// query param: for the app_mcp endpoint its one mechanism (part of the
	// audience, URI is the canonical resource), for a management surface a
	// selection among the surface's auth list ("" = all of them; the
	// audience stays the surface name)
	Mechanism string
}

// Label names the resource on the consent page
func (o *oauthResource) Label() string {
	if o.App != nil {
		return fmt.Sprintf("app %s (%s)", cmp.Or(o.App.Name, o.App.String()), o.URI)
	}
	if o.Surface == ApiResourceAppMCP {
		return "app actions"
	}
	return o.Surface + " API"
}

// resolveOAuthResource maps a requested resource to a surface or an MCP
// app, refusing surfaces that are disabled and unknown apps
func (s *Server) resolveOAuthResource(resource string) (*oauthResource, error) {
	if strings.TrimSpace(resource) == "" {
		// A client sends no resource when it found no protected resource
		// document: it started a login the endpoint did not ask for. That
		// is the case for the endpoints served without a token (an app with
		// auth none, /_openrun/app_mcp with the auth none default)
		return nil, fmt.Errorf("invalid_target: the request names no resource. The MCP endpoint did not ask for a login: " +
			"an endpoint served without a token (auth none) needs no authentication, reconnect the client instead of authenticating. " +
			"For /_openrun/app_mcp, add ?auth=<login> to the url to log in")
	}
	if mechanism, isAppMCP, err := s.aggMCPResourceMechanism(resource); isAppMCP {
		if !aggMCPEnabled(s.Config()) {
			return nil, fmt.Errorf("invalid_target: the %s endpoint is not enabled", ApiResourceAppMCP)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid_target: %w", err)
		}
		return &oauthResource{Surface: ApiResourceAppMCP, Mechanism: mechanism, URI: s.aggMCPResourceURI(mechanism)}, nil
	}
	if surface := s.surfaceForResource(resource); surface != "" {
		if !apiSurfaceEnabled(s.Config(), surface) {
			return nil, fmt.Errorf("invalid_target: the %s surface is not enabled", surface)
		}
		mechanism, err := s.surfaceAuthParam(surface, resourceAuthParam(resource))
		if err != nil {
			return nil, fmt.Errorf("invalid_target: %w", err)
		}
		return &oauthResource{Surface: surface, URI: surface, Mechanism: mechanism}, nil
	}
	if strings.Contains(resource, "://") {
		info, uri, err := s.resolveAppResource(resource)

		if err != nil {
			return nil, fmt.Errorf("invalid_target: %w", err)
		}
		return &oauthResource{App: info, URI: uri}, nil
	}
	return nil, fmt.Errorf("invalid_target: resource %q is not a canonical resource of this server", resource)
}

// oauthStoredResource resolves the value stored on a credential (surface
// name or app resource URI) for refresh: the surface must still be enabled,
// the app must still exist and still be an MCP app
func (s *Server) oauthStoredResource(stored string) (*oauthResource, error) {
	if mechanism, isAppMCP, err := s.aggMCPResourceMechanism(stored); isAppMCP {
		if !aggMCPEnabled(s.Config()) {
			return nil, fmt.Errorf("the %s endpoint is no longer enabled", ApiResourceAppMCP)
		}
		if err != nil || s.aggMCPResourceURI(mechanism) != stored {
			return nil, fmt.Errorf("the login mechanism of resource %s is no longer valid", stored)
		}
		return &oauthResource{Surface: ApiResourceAppMCP, Mechanism: mechanism, URI: stored}, nil
	}
	if stored == ApiResourceRest || stored == ApiResourceMCP {
		if !apiSurfaceEnabled(s.Config(), stored) {
			return nil, fmt.Errorf("the %s surface is no longer enabled", stored)
		}
		return &oauthResource{Surface: stored, URI: stored}, nil
	}
	info, uri, err := s.resolveAppResource(stored)
	if err != nil || uri != stored {
		return nil, fmt.Errorf("the app for resource %s is no longer an MCP app", stored)
	}
	return &oauthResource{App: info, URI: uri}, nil
}

// mcpDefaultScopes is the read-only scope set the MCP surface asks for and
// mints by default: every *:read permission plus app:read_detail (full app
// info: source, config, params, versions, files, logs), which the *:read
// glob does not cover since it is a distinct permission name. Still no
// writes, no reveal-class permissions
var mcpDefaultScopes = []string{"*:read", string(types.PermissionReadDetail)}

// apiAuthChallenge builds the WWW-Authenticate value for a surface's 401
// responses: realm plus, when the external url is configured, the protected
// resource metadata pointer and the surface's default scope ask (CLI gets *,
// MCP gets read-only by default - a single consent must not hand an AI
// client broad destructive authority)
func (s *Server) apiAuthChallenge(surface, mechanism string) string {
	external := s.apiExternalUrl()
	if external == "" {
		return fmt.Sprintf(`Bearer realm="%s"`, REALM)
	}
	scope := "*"
	if surface == ApiResourceMCP {
		scope = strings.Join(mcpDefaultScopes, " ")
	}
	query := ""
	if mechanism != "" {
		query = "?" + aggMCPAuthParam + "=" + url.QueryEscape(mechanism)
	}
	return fmt.Sprintf(`Bearer realm="%s", resource_metadata="%s/.well-known/oauth-protected-resource%s/%s%s", scope="%s"`,
		REALM, external, types.INTERNAL_URL_PREFIX, surface, query, scope)
}

// resourceAuthParam returns the auth query param of a resource url, ""
// when it has none
func resourceAuthParam(resource string) string {
	parsed, err := url.Parse(resource)
	if err != nil {
		return ""
	}
	return parsed.Query().Get(aggMCPAuthParam)
}

// surfaceAuthParam validates the auth query param of a management surface
// url (/_openrun/mcp?auth=<name>): the login to use, one of the surface's
// auth list ("system" is accepted for the admin account, the app auth
// spelling). The param selects the login page only; the token audience
// stays the surface, so existing credentials are unaffected. "" when the
// param is not set
func (s *Server) surfaceAuthParam(surface, param string) (string, error) {
	param = strings.TrimSpace(param)
	if param == "" {
		return "", nil
	}
	if param == string(types.AppAuthnSystem) {
		param = "admin"
	}
	surfaceConfig, _ := s.Config().Api.Surface(surface)
	if !slices.Contains(surfaceConfig.Auth, param) {
		return "", fmt.Errorf("auth %s is not a login mechanism of the %s surface (api.%s auth: %s)",
			param, surface, surface, strings.Join(surfaceConfig.Auth, ", "))
	}
	return param, nil
}

// serveOAuthMetadata handles the well-known documents: the RFC 8414
// authorization server metadata and the RFC 9728 protected resource
// metadata, one document per enabled surface
func (h *Handler) serveOAuthASMetadata(w http.ResponseWriter, r *http.Request) {
	external := h.server.apiExternalUrl()
	config := h.server.Config()
	if external == "" || (!apiSurfaceEnabled(config, ApiResourceRest) && !apiSurfaceEnabled(config, ApiResourceMCP) &&
		!aggMCPEnabled(config) && !h.server.hasMCPApps()) {
		// The AS exists only while a remote surface is enabled or an MCP
		// app is deployed (checked per request: [api] is dynamically
		// settable and apps come and go)
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
		"client_id_metadata_document_supported": true, // CIMD (oauth_cimd.go); DCR stays as the deprecated fallback
	})
}

func (h *Handler) serveOAuthPRM(surface string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		external := h.server.apiExternalUrl()
		if external == "" || !apiSurfaceEnabled(h.server.Config(), surface) {
			http.NotFound(w, r)
			return
		}
		// The login selection of the surface url (?auth=) travels in the
		// resource: the client sends it to the authorize endpoint verbatim
		mechanism, err := h.server.surfaceAuthParam(surface, r.URL.Query().Get(aggMCPAuthParam))
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		resource := h.server.apiResourceURI(surface)
		if mechanism != "" {
			resource += "?" + aggMCPAuthParam + "=" + url.QueryEscape(mechanism)
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		writeOAuthJSON(w, http.StatusOK, map[string]any{
			"resource":                 resource,
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
	// Federated login (oauth_federated.go): chooser -> provider/SAML login
	// -> continue (identity from the session cookie) -> consent -> code
	mux.HandleFunc("POST "+prefix+"/authorize/federated", h.oauthAuthorizeFederated)
	mux.HandleFunc("GET "+prefix+"/authorize/continue", h.oauthAuthorizeContinue)
	mux.HandleFunc("POST "+prefix+"/authorize/consent", h.oauthAuthorizeConsent)
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
func (h *Handler) oauthValidateAuthorizeParams(ctx context.Context, clientId, redirectUri, challenge, method, resource string) (*oauthResource, error) {
	if clientId == "" || redirectUri == "" {
		return nil, fmt.Errorf("client_id and redirect_uri are required")
	}
	if challenge == "" || method != "S256" {
		return nil, fmt.Errorf("PKCE with code_challenge_method=S256 is required")
	}
	if err := h.validateOAuthRedirect(ctx, clientId, redirectUri); err != nil {
		return nil, err
	}
	return h.server.resolveOAuthResource(resource)
}

// validateOAuthRedirect checks the redirect uri against the client's
// registration. The pre-registered openrun-cli client allows loopback http
// redirects on any port (RFC 8252 §7.3); CIMD clients (https client_id)
// and DCR clients require a match against their redirect list: exact,
// except that a registered loopback http uri matches on any port
func (h *Handler) validateOAuthRedirect(ctx context.Context, clientId, redirectUri string) error {
	if clientId == oauthCLIClientId {
		parsed, err := url.Parse(redirectUri)
		if err != nil || parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname()) || parsed.Path != "/callback" {
			return fmt.Errorf("openrun-cli redirect uri must be http://127.0.0.1:<port>/callback")
		}
		return nil
	}
	var registered []string
	if isCIMDClientId(clientId) {
		doc, err := h.server.resolveCIMD(ctx, clientId)
		if err != nil {
			return err
		}
		registered = doc.RedirectUris
	} else {
		client, err := h.server.db.GetOAuthClient(ctx, clientId)
		if err != nil {
			return fmt.Errorf("unknown client_id")
		}
		registered = client.RedirectUris
	}
	if slices.Contains(registered, redirectUri) || matchesLoopbackRedirect(registered, redirectUri) {
		return nil
	}
	return fmt.Errorf("redirect_uri is not registered for this client")
}

// matchesLoopbackRedirect reports whether redirectUri equals a registered
// loopback http redirect uri in everything but the port. Native clients
// listen on an ephemeral port chosen at request time and register the uri
// without one (http://localhost/callback), so the port is not compared
// (RFC 8252 §7.3). The host is: localhost and 127.0.0.1 are distinct
// registrations
func matchesLoopbackRedirect(registered []string, redirectUri string) bool {
	parsed, err := url.Parse(redirectUri)
	if err != nil || parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname()) || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	for _, uri := range registered {
		reg, err := url.Parse(uri)
		if err != nil || reg.Scheme != "http" || !isLoopbackHost(reg.Hostname()) {
			continue
		}
		if strings.EqualFold(reg.Hostname(), parsed.Hostname()) && reg.EscapedPath() == parsed.EscapedPath() &&
			reg.RawQuery == parsed.RawQuery && reg.User == nil {
			return true
		}
	}
	return false
}

// oauthClientDisplay resolves the client's display name and the consent
// notes for it (document client, loopback-only redirects)
func (h *Handler) oauthClientDisplay(ctx context.Context, clientId string) (name string, cimdClient, loopbackOnly bool) {
	name = clientId
	if isCIMDClientId(clientId) {
		// Already resolved (and cached) by the redirect validation
		if doc, err := h.server.resolveCIMD(ctx, clientId); err == nil {
			return doc.ClientName, true, doc.LoopbackOnly()
		}
		return name, true, false
	}
	if clientId != oauthCLIClientId {
		if client, err := h.server.db.GetOAuthClient(ctx, clientId); err == nil && client.Name != "" {
			name = client.Name
		}
	}
	return name, false, false
}

type federatedChoice struct {
	Name  string
	Label string
}

// oauthAuthorizeForm renders the login + consent page. The oauth request
// parameters are echoed as hidden fields; credentials go in the same POST so
// there is no cookie/session to CSRF
func (h *Handler) oauthAuthorizeForm(w http.ResponseWriter, r *http.Request) {
	h.renderOAuthLogin(w, r, r.URL.Query().Get, "")
}

func (h *Handler) renderOAuthLogin(w http.ResponseWriter, r *http.Request, get func(string) string, errMsg string) {
	clientId := get("client_id")
	res, err := h.oauthValidateAuthorizeParams(r.Context(), clientId, get("redirect_uri"),
		get("code_challenge"), get("code_challenge_method"), get("resource"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if get("response_type") != "code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	scope := strings.Join(h.server.oauthGrantScopes(res, parseScopeParam(get("scope"))), " ")
	if _, err := h.server.oauthLoginMechanisms(res); err != nil && errMsg == "" {
		// No usable login for this resource (app auth none, client certs,
		// unconfigured surface): say why instead of an empty page
		errMsg = err.Error()
	}
	passwordLogin := h.server.hasPasswordMechanism(res)
	federated := h.server.federatedMechanisms(res)
	if errMsg == "" && !passwordLogin && len(federated) == 1 && r.Method == http.MethodGet {
		// One federated mechanism and nothing to choose: go straight to it
		h.startFederatedLogin(w, r, get, federated[0])
		return
	}
	if hint := get(oauthMechanismParam); errMsg == "" && hint != "" && r.Method == http.MethodGet && slices.Contains(federated, hint) {
		// The client named the login to use (openrun login --auth): skip the
		// chooser. Only a mechanism configured for the resource is honored,
		// and the consent page still follows the login
		h.startFederatedLogin(w, r, get, hint)
		return
	}
	choices := make([]federatedChoice, 0, len(federated))
	for _, mechanism := range federated {
		choices = append(choices, federatedChoice{Name: mechanism, Label: mechanismLabel(mechanism)})
	}
	clientName, cimdClient, loopbackOnly := h.oauthClientDisplay(r.Context(), clientId)
	params := map[string]string{}
	for _, name := range []string{"response_type", "client_id", "redirect_uri", "state",
		"code_challenge", "code_challenge_method", "resource", "scope"} {
		params[name] = get(name)
	}
	h.server.formLogin.renderOAuthPage(w, "oauth_login.go.html", map[string]any{
		"ClientName":      clientName,
		"Resource":        res.Label(),
		"Scope":           scope,
		"RedirectUri":     get("redirect_uri"),
		"ClientId":        clientId,
		"DynamicClient":   clientId != oauthCLIClientId && !cimdClient,
		"CIMDClient":      cimdClient,
		"LoopbackOnly":    loopbackOnly,
		"Error":           errMsg,
		"Action":          types.INTERNAL_URL_PREFIX + "/oauth/authorize",
		"FederatedAction": types.INTERNAL_URL_PREFIX + "/oauth/authorize/federated",
		"Federated":       choices,
		"PasswordLogin":   passwordLogin,
		"Params":          params,
	})
}

// oauthAuthorizeSubmit authenticates the posted credentials against the
// login mechanisms of the requested surface, then issues a single-use authorization code
func (h *Handler) oauthAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	get := r.PostForm.Get
	res, err := h.oauthValidateAuthorizeParams(r.Context(), get("client_id"), get("redirect_uri"),
		get("code_challenge"), get("code_challenge_method"), get("resource"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if !h.server.hasPasswordMechanism(res) {
		msg := "password login is not available for this resource"
		if _, err := h.server.oauthLoginMechanisms(res); err != nil {
			msg = err.Error()
		}
		h.renderOAuthLogin(w, r, get, msg)
		return
	}
	principal, groups, err := h.server.oauthAuthenticateUser(res, get("or_username"), get("or_password"))
	if err != nil {
		h.server.insertAuthFailureEvent(r, "oauth_authorize", err.Error())
		h.renderOAuthLogin(w, r, get, err.Error())
		return
	}
	scopes, errMsg, err := h.validateOAuthConsent(r, res, principal, groups, parseScopeParam(get("or_scope")))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if errMsg != "" {
		h.renderOAuthLogin(w, r, get, errMsg)
		return
	}
	h.issueOAuthCode(w, r, res, principal, scopes, get("client_id"), get("redirect_uri"), get("code_challenge"), get("state"))
}

// validateOAuthConsent applies the consent-time checks: the granted scopes
// (RBAC scope syntax for surfaces, the app's vocabulary for apps) and, for
// apps, app:access - a token is minted only for an app the user may open,
// so a refused grant is visible here rather than as a later opaque 403.
// Returns the scopes to grant, or a page message for a recoverable problem
func (h *Handler) validateOAuthConsent(r *http.Request, res *oauthResource, principal string, groups []string,
	requestedScopes []string) ([]string, string, error) {
	scopes := h.server.oauthGrantScopes(res, requestedScopes)
	if res.App == nil {
		if err := rbac.ValidateScopes(scopes); err != nil {
			return nil, err.Error(), nil
		}
		return scopes, "", nil
	}
	authorized, err := h.server.rbacManager.AuthorizeAppAccess(principal,
		mainAppPathDomain(res.App.AppPathDomain, res.App.MainApp, res.App.LinkedAppPath), groups, res.App.UserID)
	if err != nil {
		return nil, "", err
	}
	if !authorized {
		h.server.insertAuthFailureEvent(r, "oauth_authorize", principal+" has no access to "+res.App.String())
		return nil, fmt.Sprintf("%s does not have access to %s", principal, res.App.AppPathDomain), nil
	}
	return scopes, "", nil
}

// issueOAuthCode stores a single-use code for validated consent and
// redirects the browser back to the client
func (h *Handler) issueOAuthCode(w http.ResponseWriter, r *http.Request, res *oauthResource, principal string,
	scopes []string, clientId, redirectUri, challenge, state string) {
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	code := hex.EncodeToString(codeBytes)
	if err := h.server.storeOAuthCode(r.Context(), code, &oauthCode{
		ClientId:    clientId,
		RedirectUri: redirectUri,
		Challenge:   challenge,
		Principal:   principal,
		Scopes:      scopes,
		Resource:    res.URI,
		Expires:     time.Now().Add(oauthCodeTTL),
	}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "error storing authorization code")
		return
	}

	redirect, _ := url.Parse(redirectUri)
	query := redirect.Query()
	query.Set("code", code)
	if state != "" {
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

// oauthLoginMechanisms returns the login mechanisms for a resource: the
// [api.<surface>] auth list for a surface; for an MCP app, the app's own
// auth setting (system -> admin, builtin -> builtin, an [auth.*] or
// [saml.*] name -> that federated login). Apps with auth none or client
// certs cannot issue tokens (no identity to bind them to); an auth none
// app serves its MCP region without one (serveMCPApp)
func (s *Server) oauthLoginMechanisms(res *oauthResource) ([]string, error) {
	if res.Surface == ApiResourceAppMCP {
		return aggMCPLoginMechanisms(res.Mechanism)
	}
	if res.App == nil {
		surfaceConfig, _ := s.Config().Api.Surface(res.Surface)
		if len(surfaceConfig.Auth) == 0 {
			return nil, fmt.Errorf("api.%s auth is not configured: set the login mechanisms (builtin, admin) for the surface", res.Surface)
		}
		if res.Mechanism != "" {
			// The url named one of the surface's logins (?auth=): the page
			// offers that one only, and credentials for another listed
			// mechanism are not accepted through it
			if !slices.Contains(surfaceConfig.Auth, res.Mechanism) {
				return nil, fmt.Errorf("auth %s is not a login mechanism of the %s surface (api.%s auth)", res.Mechanism, res.Surface, res.Surface)
			}
			return []string{res.Mechanism}, nil
		}
		return surfaceConfig.Auth, nil
	}
	coreAuth, _, err := s.checkAuthModifiers(resolveAppAuth(res.App.Auth, s.Config()))
	if err != nil {
		return nil, err
	}
	coreAuth = strings.TrimPrefix(coreAuth, rbac.RBAC_AUTH_PREFIX)
	switch {
	case coreAuth == string(types.AppAuthnSystem):
		return []string{"admin"}, nil
	case coreAuth == string(types.AppAuthnBuiltin):
		return []string{"builtin"}, nil
	case coreAuth == string(types.AppAuthnNone):
		return nil, fmt.Errorf("app %s has auth none: its MCP endpoint is served without a token, set an auth type on the app to bind MCP tokens to a user", res.App.AppPathDomain)
	case coreAuth == "cert" || strings.HasPrefix(coreAuth, "cert_"):
		return nil, fmt.Errorf("app %s uses client certificate auth, which cannot be used for the OAuth login page", res.App.AppPathDomain)
	}
	return []string{coreAuth}, nil
}

// oauthAuthenticateUser verifies the posted credentials against the login
// mechanisms of the resource, returning the principal (provider:username
// or admin) and its groups
func (s *Server) oauthAuthenticateUser(res *oauthResource, username, password string) (string, []string, error) {
	mechanisms, err := s.oauthLoginMechanisms(res)
	if err != nil {
		return "", nil, err
	}
	if username == "" || password == "" {
		return "", nil, fmt.Errorf("username and password are required")
	}
	basicHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	for _, mechanism := range mechanisms {
		switch mechanism {
		case "builtin":
			if principal, groups, ok := s.builtinAuth.authenticate(basicHeader); ok {
				return principal, groups, nil
			}
		case "admin":
			if username == s.Config().AdminUser && s.authHandler.authenticate(basicHeader) {
				return types.ADMIN_USER, []string{}, nil
			}
		default:
			// federated mechanisms are handled by the chooser
			// (oauth_federated.go), never by the password form
		}
	}
	return "", nil, fmt.Errorf("invalid username or password")
}

// oauthGrantScopes computes the scopes to grant for a resource from the
// requested list. Surfaces: the request, defaulting to * (CLI) or the
// read-only set mcpDefaultScopes (MCP surface). Apps: the intersection with the app's declared scopes
// (unknown scopes are dropped, the spec allows down-scoping), defaulting
// to the app's default scope; an app without declared scopes issues
// unscoped tokens
func (s *Server) oauthGrantScopes(res *oauthResource, requested []string) []string {
	if res.App == nil {
		if len(requested) > 0 {
			return requested
		}
		if res.Surface == ApiResourceAppMCP {
			return []string{aggMCPScope}
		}
		if res.Surface == ApiResourceMCP {
			return slices.Clone(mcpDefaultScopes)
		}
		return []string{"*"}
	}
	mcp := res.App.MCP
	granted := make([]string, 0, len(requested))
	for _, scope := range requested {
		if slices.Contains(mcp.Scopes, scope) && !slices.Contains(granted, scope) {
			granted = append(granted, scope)
		}
	}
	if len(granted) == 0 && mcp.DefaultScope != "" {
		granted = append(granted, mcp.DefaultScope)
	}
	return granted
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

	// Single use, success or not: the code is removed before any check
	entry, err := h.server.consumeOAuthCode(r.Context(), code)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "error reading authorization code")
		return
	}
	if entry == nil || time.Now().After(entry.Expires) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired authorization code")
		return
	}
	if entry.ClientId != clientId || entry.RedirectUri != get("redirect_uri") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id/redirect_uri mismatch")
		return
	}
	challenge := base64.RawURLEncoding.EncodeToString(func() []byte { s := sha256.Sum256([]byte(verifier)); return s[:] }())
	if verifier == "" || subtle.ConstantTimeCompare([]byte(challenge), []byte(entry.Challenge)) != 1 {
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
	response, err := h.server.mintOAuthTokens(r.Context(), entry.Principal, clientId, grantId, grantId,
		entry.Scopes, entry.Resource, "", grantDeadline)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	h.server.auditOAuthEvent(r.Context(), "oauth_token_grant", entry.Principal, true)
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
	if _, err := h.server.oauthStoredResource(surface); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
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
