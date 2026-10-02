// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// MCP apps: an app whose metadata carries an MCPConfig is an MCP server
// whose endpoint OpenRun protects with OAuth 2.1. OpenRun is the
// authorization server (oauth_api.go, shared with the management surfaces)
// and the resource server: the MCP region of the app accepts only OpenRun
// bearer credentials bound to this app instance, verifies them, applies
// RBAC app:access and the app's tool scopes, strips the token and forwards
// the request with the X-Openrun-* identity headers. An app with auth none
// has no login to bind a token to: its region is served without a token as
// the anonymous user and publishes no protected resource metadata, so
// clients connect with no OAuth flow. Design:
// arch/docs/mcp-app-auth-design.md

const (
	mcpPRMPrefix       = "/.well-known/oauth-protected-resource"
	mcpBodySniffLimit  = 1 << 20 // legacy clients send no Mcp-Method header; the body is read up to this size
	mcpClientIdAPIKey  = "apikey"
	mcpMethodToolsCall = "tools/call"
)

// appMCPExternalOrigin returns the scheme and the ":port" suffix of the
// issuer origin (apiExternalUrl): one listener serves every app domain, so
// an app's resource shares them. The scheme is https, or http when the
// issuer is a loopback http origin (local development, see
// validateApiExternalUrl); the port suffix is "" on the default port
func (s *Server) appMCPExternalOrigin() (scheme, port string) {
	parsed, err := url.Parse(s.apiExternalUrl())
	if err != nil || parsed.Scheme == "" {
		return "https", ""
	}
	if parsed.Port() != "" {
		port = ":" + parsed.Port()
	}
	return parsed.Scheme, port
}

// appMCPRegion is the request path prefix of the MCP region: the app path
// joined with the region path ("/" when the whole app is the endpoint)
func appMCPRegion(appPath string, mcp *types.MCPConfig) string {
	return path.Join("/", appPath, mcp.Path)
}

// inMCPRegion reports whether a request path (with the app path prefix)
// falls in the region
func inMCPRegion(requestPath, region string) bool {
	if region == "/" {
		return true
	}
	return requestPath == region || strings.HasPrefix(requestPath, region+"/")
}

// appMCPResource returns the canonical RFC 8707 resource URI of an app's
// MCP endpoint, derived from the app (effective domain, external port, app
// path, region path), never from the request: the token audience is one
// app instance. Lowercase, no trailing slash
func (s *Server) appMCPResource(appPath, domain string, mcp *types.MCPConfig) string {
	host := strings.ToLower(cmp.Or(domain, s.Config().System.DefaultDomain))
	region := appMCPRegion(appPath, mcp)
	if region == "/" {
		region = ""
	}
	scheme, port := s.appMCPExternalOrigin()
	return scheme + "://" + host + port + region
}

// appMCPPRMUrl is the path-inserted RFC 9728 metadata URL for the app,
// advertised in the 401 challenge. Uses the same origin as the resource so
// strict clients that derive the well-known path from the endpoint URL
// land on the same document
func (s *Server) appMCPPRMUrl(appPath, domain string, mcp *types.MCPConfig) string {
	resource, _ := url.Parse(s.appMCPResource(appPath, domain, mcp))
	return resource.Scheme + "://" + resource.Host + mcpPRMPrefix + resource.Path
}

// mcpAppAuthNone reports whether an MCP app's resolved auth type is none:
// the region is then open (no token needed) and has no OAuth flow
func (s *Server) mcpAppAuthNone(appAuth types.AppAuthnType) bool {
	baseType, _, _ := strings.Cut(resolveAppAuth(appAuth, s.Config()), types.AUTH_MODIFIER_DELIMITER)
	return baseType == string(types.AppAuthnNone)
}

// appMCPChallenge builds the WWW-Authenticate value for the region.
// withMetadata is false for an auth none app, which has no protected
// resource document to point at
func (s *Server) appMCPChallenge(appPath, domain string, mcp *types.MCPConfig, errCode, scope string, withMetadata bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, `Bearer realm="%s"`, REALM)
	if errCode != "" {
		fmt.Fprintf(&b, `, error="%s"`, errCode)
	}
	if withMetadata {
		fmt.Fprintf(&b, `, resource_metadata="%s"`, s.appMCPPRMUrl(appPath, domain, mcp))
	}
	if scope != "" {
		fmt.Fprintf(&b, `, scope="%s"`, scope)
	}
	return b.String()
}

// validateAppMCPResource refuses an MCP app whose canonical resource would
// equal a management surface's resource: the authorization server could
// not tell the two audiences apart. Both surface resources live under
// /_openrun, which no app path can occupy, so this is a defensive check
func (s *Server) validateAppMCPResource(appPath, domain string, mcp *types.MCPConfig) error {
	if mcp == nil || mcp.Disable {
		return nil
	}
	resource := s.appMCPResource(appPath, domain, mcp)
	for _, surface := range []string{ApiResourceRest, ApiResourceMCP} {
		if strings.EqualFold(resource, s.apiResourceURI(surface)) {
			return types.CreateRequestError(fmt.Sprintf("mcp app resource %s collides with the management %s API resource; "+
				"deploy the app at another path or domain", resource, surface), http.StatusBadRequest)
		}
	}
	return nil
}

// hasMCPApps reports whether any app is an MCP app: the OAuth endpoints and
// the AS metadata are served while one exists, even with both management
// surfaces disabled. A dev app counts by what it serves now (withLoadedMCP):
// its first action makes it an MCP endpoint without a deploy, and a client
// which finds its protected resource document must find the authorization
// server too
func (s *Server) hasMCPApps() bool {
	if s.apps == nil {
		return false
	}
	apps, err := s.apps.GetAllAppsInfo()
	if err != nil {
		return false
	}
	for _, info := range apps {
		s.withLoadedMCP(&info)
		if info.MCP != nil {
			return true
		}
	}
	return false
}

// hasMCPAppsUncached is hasMCPApps straight from the database, for callers
// that run before the effective config is published (dynamic config
// validation): the app store's domain index is built against
// system.default_domain, so it must not be populated with a value about
// to change
func (s *Server) hasMCPAppsUncached() bool {
	if s.db == nil {
		return false
	}
	apps, err := s.db.GetAllApps(true)
	if err != nil {
		return false
	}
	for _, info := range apps {
		// Apps which asked for MCP only. The implicit actions endpoint of
		// an app with actions is best effort (served where an issuer
		// exists): it must not pin the issuer config of nearly every server
		if info.MCP != nil && !info.MCPImplicit {
			return true
		}
	}
	return false
}

// withLoadedMCP fills in the effective MCP config of a dev app from the app
// loaded on this node. AppInfo derives the implicit actions endpoint from
// the action definitions stored with the app version; a dev app's source
// changes without a deploy, so its stored definitions can be behind
func (s *Server) withLoadedMCP(info *types.AppInfo) {
	if info.MCP != nil || !info.IsDev || info.MCPDisabled {
		return
	}
	if loaded, err := s.apps.GetApp(info.AppPathDomain); err == nil {
		if mcp := loaded.EffectiveMCP(); mcp != nil {
			info.MCP, info.MCPImplicit = mcp, true
		}
	}
}

// resolveAppResource maps an RFC 8707 resource URI (from an authorize

// request or an API key request) to an MCP app: the issuer's scheme (https,
// or http for a loopback development issuer), a host that is a registered
// app domain or the default domain (no unknown-domain fallback at the AS),
// and a path equal to the app's region. Returns the app and the canonical
// resource string to store on the credential
func (s *Server) resolveAppResource(resource string) (*types.AppInfo, string, error) {
	scheme, _ := s.appMCPExternalOrigin()
	parsed, err := url.Parse(strings.TrimSpace(resource))
	if err != nil || parsed.Scheme != scheme || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil {
		return nil, "", fmt.Errorf("resource %q is not an %s app url", resource, scheme)
	}
	host := strings.ToLower(parsed.Hostname())
	domains, err := s.apps.GetAllDomains()
	if err != nil {
		return nil, "", err
	}
	if !domains[host] && host != s.Config().System.DefaultDomain {
		return nil, "", fmt.Errorf("resource %q does not name a domain served here", resource)
	}
	info, err := s.MatchApp(host, cmp.Or(parsed.Path, "/"))
	if err == nil {
		s.withLoadedMCP(&info)
	}
	if err != nil || info.MCP == nil {
		return nil, "", fmt.Errorf("resource %q does not name an MCP app", resource)
	}
	if normalizePath(parsed.Path) != appMCPRegion(info.Path, info.MCP) {
		return nil, "", fmt.Errorf("resource %q is not the MCP endpoint of app %s", resource, info.AppPathDomain)
	}
	return &info, s.appMCPResource(info.Path, info.Domain, info.MCP), nil
}

// resolveAppReference maps an API key --resource app reference
// ("app:<path>", "app:<domain>:<path>" or the app's resource URI) to the
// canonical resource of an MCP app
func (s *Server) resolveAppReference(ref string) (*types.AppInfo, string, error) {
	if strings.Contains(ref, "://") {
		return s.resolveAppResource(ref)
	}
	spec, ok := strings.CutPrefix(ref, "app:")
	if !ok {
		return nil, "", fmt.Errorf("invalid resource %q: valid values are %s, %s, all, app:<path>, app:<domain>:<path> or the app's MCP url",

			ref, ApiResourceRest, ApiResourceMCP)
	}
	pathDomain, err := parseAppPath(spec)
	if err != nil {
		return nil, "", err
	}
	apps, err := s.apps.GetAllAppsInfo()
	if err != nil {
		return nil, "", err
	}
	for _, info := range apps {
		if info.Path == pathDomain.Path && info.Domain == pathDomain.Domain {
			s.withLoadedMCP(&info)
			if info.MCP == nil {
				return nil, "", fmt.Errorf("app %s is not an MCP app", pathDomain)
			}
			return &info, s.appMCPResource(info.Path, info.Domain, info.MCP), nil
		}
	}
	return nil, "", fmt.Errorf("app %s not found", pathDomain)
}

// mcpTransportAllowed: the MCP app paths exist over https (direct or via a
// trusted proxy) and, as a development convenience, over plaintext on
// loopback hosts only. The same gate covers everything an MCP client on
// http://localhost walks: the region, the app's protected resource
// document, the authorization server metadata and the OAuth endpoints
// (router.go). The management surfaces and their documents stay https-only
func (s *Server) mcpTransportAllowed(r *http.Request) bool {
	if system.GetRequestScheme(r, s.Config().Security.TrustedProxies) == "https" {
		return true
	}
	// The exception needs a loopback connection, not just a loopback Host
	// header: the Host is client-controlled, and an HTTP listener bound to
	// a routable address must not hand out login pages or tokens in
	// plaintext to a remote caller that says Host: localhost
	return isLoopbackHost(system.GetHostname(r.Host)) && isLoopbackRemote(r.RemoteAddr)
}

// isLoopbackRemote reports whether the connection's peer address is a
// loopback IP (RemoteAddr "ip:port"; anything unparseable, like a Unix
// socket peer, does not qualify)
func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// appPRMMatch resolves the MCP app whose region is the document suffix of
// the request on the request host, if any
func (h *Handler) appPRMMatch(r *http.Request) (types.AppInfo, bool) {
	suffix := normalizePath(cmp.Or(strings.TrimPrefix(r.URL.Path, mcpPRMPrefix), "/"))
	info, err := h.server.MatchApp(system.GetHostname(r.Host), suffix)
	if err == nil {
		h.server.withLoadedMCP(&info)
	}
	if err != nil || info.MCP == nil || suffix != appMCPRegion(info.Path, info.MCP) {
		return types.AppInfo{}, false
	}
	return info, true
}

// serveAppPRM serves the RFC 9728 protected resource metadata for MCP apps:
// the path-inserted form /.well-known/oauth-protected-resource<app path>
// <region path>, and the root form for an app at / whose region is /. An
// auth none app has no document: a client that probes for one before its
// first request would otherwise start an OAuth flow that cannot complete
func (h *Handler) serveAppPRM(w http.ResponseWriter, r *http.Request) {
	if !h.server.mcpTransportAllowed(r) {
		http.NotFound(w, r)
		return
	}
	info, ok := h.appPRMMatch(r)
	if !ok || h.server.mcpAppAuthNone(info.Auth) {
		http.NotFound(w, r)
		return
	}
	external := h.server.apiExternalUrl()
	if external == "" {
		http.NotFound(w, r)
		return
	}
	doc := map[string]any{
		"resource":                 h.server.appMCPResource(info.Path, info.Domain, info.MCP),
		"authorization_servers":    []string{external},
		"bearer_methods_supported": []string{"header"},
	}
	if info.Name != "" {
		doc["resource_name"] = info.Name
	}
	if len(info.MCP.Scopes) > 0 {
		doc["scopes_supported"] = info.MCP.Scopes
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeOAuthJSON(w, http.StatusOK, doc)
}

// mcpOp is one JSON-RPC operation of a request (a legacy batch may carry
// several)
type mcpOp struct {
	Method string
	Name   string
}

// mcpReadOperations determines the JSON-RPC operation(s) of a request from
// the body, never from the client-supplied Mcp-Method / Mcp-Name headers
// alone: policy is enforced here, so the headers are only checked for
// agreement with the body (a mismatch is refused, as the transport
// requires of intermediaries). POST bodies must be JSON and at most
// mcpBodySniffLimit bytes (larger requests are refused rather than
// forwarded truncated); the body is restored for the upstream. Non-POST
// requests (legacy GET streams, DELETE) carry no operation. Returns an
// HTTP status and message when the request must be refused
func mcpReadOperations(r *http.Request) ([]mcpOp, int, string) {
	if r.Method != http.MethodPost {
		return nil, 0, ""
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "json") {
		return nil, http.StatusUnsupportedMediaType, "MCP requests must be application/json"
	}
	if r.ContentLength > mcpBodySniffLimit {
		return nil, http.StatusRequestEntityTooLarge, fmt.Sprintf("MCP request body exceeds %d bytes", mcpBodySniffLimit)
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, mcpBodySniffLimit+1))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil {
		return nil, http.StatusBadRequest, "error reading MCP request body"
	}
	if len(data) > mcpBodySniffLimit {
		return nil, http.StatusRequestEntityTooLarge, fmt.Sprintf("MCP request body exceeds %d bytes", mcpBodySniffLimit)
	}
	type message struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
			Uri  string `json:"uri"`
		} `json:"params"`
	}
	var messages []message
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("[")) {
		if json.Unmarshal(trimmed, &messages) != nil {
			return nil, http.StatusBadRequest, "MCP request body is not a JSON-RPC batch"
		}
	} else {
		var single message
		if json.Unmarshal(trimmed, &single) != nil {
			return nil, http.StatusBadRequest, "MCP request body is not a JSON-RPC message"
		}
		messages = []message{single}
	}
	ops := make([]mcpOp, 0, len(messages))
	for _, msg := range messages {
		ops = append(ops, mcpOp{Method: msg.Method, Name: cmp.Or(msg.Params.Name, msg.Params.Uri)})
	}
	// Mirrored headers (2026-07-28 clients) must match the body they
	// describe; a batch cannot be described by one header pair
	if headerMethod := r.Header.Get("Mcp-Method"); headerMethod != "" {
		if len(ops) != 1 || ops[0].Method != headerMethod {
			return nil, http.StatusBadRequest, "Mcp-Method header does not match the request body"
		}
		if headerName := r.Header.Get("Mcp-Name"); headerName != "" && decodeMcpHeader(headerName) != ops[0].Name {
			return nil, http.StatusBadRequest, "Mcp-Name header does not match the request body"
		}
	}
	return ops, 0, ""
}

// decodeMcpHeader undoes the transport's =?base64?...?= sentinel encoding
func decodeMcpHeader(value string) string {
	if inner, ok := strings.CutPrefix(value, "=?base64?"); ok && strings.HasSuffix(inner, "?=") {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(inner, "?=")); err == nil {
			return string(decoded)
		}
	}
	return value
}

// requiredToolScope returns the scope a tools/call needs per the app's
// tool map, "" when none applies
func requiredToolScope(mcp *types.MCPConfig, method, name string) string {
	if method != mcpMethodToolsCall || name == "" {
		return ""
	}
	return mcp.Tools[name]
}

// credentialScoped reports whether a credential's scope list restricts it:
// API keys minted without --scopes are unscoped (RBAC alone governs); OAuth
// tokens always carry the consented set, so an empty list means no scope.
// A token-less call to an auth none app has no credential and is unscoped
func credentialScoped(cred *types.Credential) bool {
	if cred == nil {
		return false
	}
	if cred.Type == types.CredentialTypePAT {
		return len(cred.Scopes) > 0
	}
	return true
}

func originAllowed(origin string, allowed []string) bool {
	origin = strings.ToLower(strings.TrimSuffix(origin, "/"))
	return slices.Contains(allowed, origin)
}

// mcpBearerToken extracts the bearer token of a request. The scheme is
// matched case-insensitively (RFC 9110). presented reports whether the
// request carries any Authorization header at all, usable or not, so the
// caller can tell "no credential" from one it does not recognize
func mcpBearerToken(r *http.Request) (token string, presented bool) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", false
	}
	if len(values) > 1 {
		return "", true
	}
	scheme, rest, _ := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", true
	}
	return strings.TrimSpace(rest), true
}

// serveMCPApp is the request path for the MCP region of an MCP app (called
// from authenticateAndServeApp in place of the cookie/basic/SSO branches)
func (s *Server) serveMCPApp(w http.ResponseWriter, r *http.Request, application *app.App, mcp *types.MCPConfig) {
	appPath, domain := application.Path, application.Domain
	if !s.mcpTransportAllowed(r) {
		// Same rule as the management surface: no challenge on plaintext,
		// a token in the request has already leaked
		http.NotFound(w, r)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" && !originAllowed(origin, mcp.AllowedOrigins) {
		http.Error(w, "Forbidden: origin not allowed", http.StatusForbidden)
		return
	}
	// Responses OpenRun writes itself (challenges, refusals) carry CORS
	// headers for an allowed browser origin, and expose WWW-Authenticate so
	// a browser client can read the challenge; forwarded requests get the
	// app's own CORS headers instead
	deny := func(status int, msg string) {
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
		}
		http.Error(w, msg, status)
	}
	if r.Method == http.MethodOptions {
		// CORS preflight from an allowed origin carries no credential by
		// design; the app's own CORS handler answers it. Nothing is
		// executed and no identity is attached
		r.Header.Del("Authorization")
		r.Header.Del("Cookie")
		anon := &authContext{Context: r.Context(), userId: types.ANONYMOUS_USER, appId: string(application.Id),
			pathDomain: application.AppPathDomain(), appAuth: application.Metadata.AuthnType,
			groups: []string{}, customPerms: []string{}}
		application.ServeHTTP(w, r.WithContext(anon))
		return
	}
	resource := s.appMCPResource(appPath, domain, mcp)
	authNone := s.mcpAppAuthNone(application.Metadata.AuthnType)
	challenge := func(errCode string) {
		w.Header().Set("WWW-Authenticate", s.appMCPChallenge(appPath, domain, mcp, errCode, mcp.DefaultScope, !authNone))
		deny(http.StatusUnauthorized, "Unauthorized")
	}
	principal, groups := types.ANONYMOUS_USER, []string{}
	var cred *types.Credential
	var identity *types.Identity
	var err error
	token, presented := mcpBearerToken(r)
	if token != "" {
		// A presented token is always verified, on an auth none app too: an
		// API key bound to the app identifies its user there
		principal, groups, _, cred, identity, err = s.verifyApiToken(r.Context(), token, resource)
		if err != nil {
			detail := err.Error()
			if _, id, _, parseErr := parseApiToken(token); parseErr == nil {
				detail += " cred=" + id
			}
			s.Warn().Str("app", application.AppPathDomain().String()).Msg("MCP app bearer auth failed: " + detail)
			s.insertAuthFailureEvent(r, "mcp_app", detail)
			challenge("invalid_token")
			return
		}
	} else if presented || !authNone || s.Config().Security.AuthRequired {
		// An Authorization header that is not a usable bearer credential is
		// refused on an auth none app too: only a request that presents no
		// credential at all is anonymous
		detail := "missing bearer token"
		if presented {
			detail = "unrecognized authorization header"
		}
		s.insertAuthFailureEvent(r, "mcp_app", detail)
		challenge("")
		return
	}
	// else auth none app, no credential presented: served as the anonymous
	// user, as the rest of the app is. RBAC app:access below decides whether
	// anonymous may reach it; the app's tool scopes do not apply

	grantPathDomain := mainAppPathDomain(application.AppPathDomain(), application.MainApp, application.LinkedAppPath)
	authorized, err := s.rbacManager.AuthorizeAppAccess(principal, grantPathDomain, groups, application.UserID)
	if err != nil {
		deny(http.StatusInternalServerError, err.Error())
		return
	}
	if !authorized {
		s.Warn().Msgf("User %s is not authorized to access MCP app %s", principal, application.AppPathDomain())
		deny(http.StatusForbidden, fmt.Sprintf("Forbidden : %s does not have access to %s", principal, application.AppPathDomain()))
		return
	}

	ops, status, msg := mcpReadOperations(r)
	if status != 0 {
		deny(status, msg)
		return
	}
	// From here the request is audited as MCP calls (the mcp event type),
	// a call refused for a missing scope included
	if contextShared, ok := r.Context().Value(types.SHARED).(*ContextShared); ok {
		contextShared.UserId = principal
		contextShared.AppId = string(application.Id)
	}
	markMCPRequest(r.Context(), mcpEndpointApp, ops, cred, "app="+application.AppPathDomain().String())
	for _, op := range ops {
		if required := requiredToolScope(mcp, op.Method, op.Name); required != "" &&
			credentialScoped(cred) && !slices.Contains(cred.Scopes, required) {
			// Spec step-up: name only what this operation needs; the client
			// accumulates and re-consents
			w.Header().Set("WWW-Authenticate", s.appMCPChallenge(appPath, domain, mcp, "insufficient_scope", required, !authNone))
			deny(http.StatusForbidden, fmt.Sprintf("Forbidden: tool %s requires scope %s", op.Name, required))
			return
		}
	}
	// Federated identities carry the provider subject and verified email, so
	// the app sees the same X-Openrun-User-Id / -User-Email it gets from a
	// browser session of that user; builtin and admin have neither
	userSubject, userEmail := federatedSubjectEmail(identity)
	authCtx := &authContext{
		Context:     r.Context(),
		userId:      principal,
		userSubject: userSubject,
		userEmail:   userEmail,
		appId:       string(application.Id),
		pathDomain:  grantPathDomain,
		appAuth:     application.Metadata.AuthnType,
		groups:      groups,
		customPerms: make([]string, 0),
	}
	var ctx context.Context = authCtx
	appRBACEnabled := s.rbacManager.IsAppRBACEnabled(ctx)
	if appRBACEnabled || rbac.HasTestUrlPerms(ctx) {
		authCtx.customPerms, err = s.rbacManager.GetCustomPermissions(ctx)
		if err != nil {
			deny(http.StatusInternalServerError, err.Error())
			return
		}
	}
	authCtx.rbacEnabled = appRBACEnabled
	ctx = system.WithApiInvoker(ctx, types.API_INVOKER_MCP)
	if cred != nil {
		ctx = system.WithApiCredential(ctx, cred)
	}
	if credentialScoped(cred) {
		ctx = system.WithApiScopes(ctx, cred.Scopes)
	}
	r = r.WithContext(ctx)

	// The upstream never sees the OpenRun credential (the spec forbids
	// transiting it) and the region never honors cookies
	r.Header.Del("Authorization")
	r.Header.Del("Cookie")
	// Origin was checked above against the app's allow list; the browser
	// CSRF wrapper and the +forward_ modifier do not apply to bearer calls
	application.ServeHTTP(w, r)
}
