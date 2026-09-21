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
// the request with the X-Openrun-* identity headers. Design:
// arch/docs/mcp-app-auth-design.md

const (
	mcpPRMPrefix       = "/.well-known/oauth-protected-resource"
	mcpBodySniffLimit  = 1 << 20 // legacy clients send no Mcp-Method header; the body is read up to this size
	mcpClientIdAPIKey  = "apikey"
	mcpMethodToolsCall = "tools/call"
)

// appMCPExternalPort returns the ":port" suffix of api.external_url (one
// https port serves every app domain), "" when it uses the default port
func (s *Server) appMCPExternalPort() string {
	parsed, err := url.Parse(s.apiExternalUrl())
	if err != nil || parsed.Port() == "" {
		return ""
	}
	return ":" + parsed.Port()
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
	return "https://" + host + s.appMCPExternalPort() + region
}

// appMCPPRMUrl is the path-inserted RFC 9728 metadata URL for the app,
// advertised in the 401 challenge. Uses the same origin as the resource so
// strict clients that derive the well-known path from the endpoint URL
// land on the same document
func (s *Server) appMCPPRMUrl(appPath, domain string, mcp *types.MCPConfig) string {
	resource, _ := url.Parse(s.appMCPResource(appPath, domain, mcp))
	return resource.Scheme + "://" + resource.Host + mcpPRMPrefix + resource.Path
}

// appMCPChallenge builds the WWW-Authenticate value for the region
func (s *Server) appMCPChallenge(appPath, domain string, mcp *types.MCPConfig, errCode, scope string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `Bearer realm="%s"`, REALM)
	if errCode != "" {
		fmt.Fprintf(&b, `, error="%s"`, errCode)
	}
	fmt.Fprintf(&b, `, resource_metadata="%s"`, s.appMCPPRMUrl(appPath, domain, mcp))
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
	if mcp == nil {
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
// surfaces disabled
func (s *Server) hasMCPApps() bool {
	if s.apps == nil {
		return false
	}
	apps, err := s.apps.GetAllAppsInfo()
	if err != nil {
		return false
	}
	for _, info := range apps {
		if info.MCP != nil {
			return true
		}
	}
	return false
}

// resolveAppResource maps an RFC 8707 resource URI (from an authorize
// request or an API key request) to an MCP app: https scheme, a host that
// is a registered app domain or the default domain (no unknown-domain
// fallback at the AS), and a path equal to the app's region. Returns the
// app and the canonical resource string to store on the credential
func (s *Server) resolveAppResource(resource string) (*types.AppInfo, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(resource))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil {
		return nil, "", fmt.Errorf("resource %q is not an https app url", resource)
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
	if err != nil || info.MCP == nil {
		return nil, "", fmt.Errorf("resource %q does not name an MCP app", resource)
	}
	if normalizePath(parsed.Path) != appMCPRegion(info.Path, info.MCP) {
		return nil, "", fmt.Errorf("resource %q is not the MCP endpoint of app %s", resource, info.AppPathDomain)
	}
	return &info, s.appMCPResource(info.Path, info.Domain, info.MCP), nil
}

// resolveAppReference maps an API key --resource app reference
// ("app:<path>", "app:<domain>:<path>" or the https resource URI) to the
// canonical resource of an MCP app
func (s *Server) resolveAppReference(ref string) (*types.AppInfo, string, error) {
	if strings.HasPrefix(ref, "https://") {
		return s.resolveAppResource(ref)
	}
	spec, ok := strings.CutPrefix(ref, "app:")
	if !ok {
		return nil, "", fmt.Errorf("invalid resource %q: valid values are %s, %s, all, app:<path>, app:<domain>:<path> or the app's https MCP url",
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
			if info.MCP == nil {
				return nil, "", fmt.Errorf("app %s is not an MCP app", pathDomain)
			}
			return &info, s.appMCPResource(info.Path, info.Domain, info.MCP), nil
		}
	}
	return nil, "", fmt.Errorf("app %s not found", pathDomain)
}

// mcpTransportAllowed: the region exists over https (direct or via a
// trusted proxy) and, as a development convenience, over plaintext on
// loopback hosts only
func (s *Server) mcpTransportAllowed(r *http.Request) bool {
	if system.GetRequestScheme(r, s.Config().Security.TrustedProxies) == "https" {
		return true
	}
	return isLoopbackHost(system.GetHostname(r.Host))
}

// appPRMMatch resolves the MCP app whose region is the document suffix of
// the request on the request host, if any
func (h *Handler) appPRMMatch(r *http.Request) (types.AppInfo, bool) {
	suffix := normalizePath(cmp.Or(strings.TrimPrefix(r.URL.Path, mcpPRMPrefix), "/"))
	info, err := h.server.MatchApp(system.GetHostname(r.Host), suffix)
	if err != nil || info.MCP == nil || suffix != appMCPRegion(info.Path, info.MCP) {
		return types.AppInfo{}, false
	}
	return info, true
}

// serveAppPRM serves the RFC 9728 protected resource metadata for MCP apps:
// the path-inserted form /.well-known/oauth-protected-resource<app path>
// <region path>, and the root form for an app at / whose region is /
func (h *Handler) serveAppPRM(w http.ResponseWriter, r *http.Request) {
	if !h.server.mcpTransportAllowed(r) {
		http.NotFound(w, r)
		return
	}
	info, ok := h.appPRMMatch(r)
	if !ok {
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
// tokens always carry the consented set, so an empty list means no scope
func credentialScoped(cred *types.Credential) bool {
	if cred.Type == types.CredentialTypePAT {
		return len(cred.Scopes) > 0
	}
	return true
}

func originAllowed(origin string, allowed []string) bool {
	origin = strings.ToLower(strings.TrimSuffix(origin, "/"))
	return slices.Contains(allowed, origin)
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
	challenge := func(errCode string) {
		w.Header().Set("WWW-Authenticate", s.appMCPChallenge(appPath, domain, mcp, errCode, mcp.DefaultScope))
		deny(http.StatusUnauthorized, "Unauthorized")
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		s.insertAuthFailureEvent(r, "mcp_app", "missing bearer token")
		challenge("")
		return
	}
	principal, groups, _, cred, identity, err := s.verifyApiToken(r.Context(), token, resource)
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
	for _, op := range ops {
		if required := requiredToolScope(mcp, op.Method, op.Name); required != "" &&
			credentialScoped(cred) && !slices.Contains(cred.Scopes, required) {
			// Spec step-up: name only what this operation needs; the client
			// accumulates and re-consents
			w.Header().Set("WWW-Authenticate", s.appMCPChallenge(appPath, domain, mcp, "insufficient_scope", required))
			deny(http.StatusForbidden, fmt.Sprintf("Forbidden: tool %s requires scope %s", op.Name, required))
			return
		}
	}
	method, name := "", ""
	if len(ops) > 0 {
		method, name = ops[0].Method, ops[0].Name
	}

	// Federated identities carry the provider subject and verified email, so
	// the app sees the same X-Openrun-User-Id / -User-Email it gets from a
	// browser session of that user; builtin and admin have neither
	userSubject, userEmail := "", ""
	if identity.Provider != string(types.AppAuthnBuiltin) && identity.Provider != types.ADMIN_USER {
		userSubject, userEmail = identity.StableSubject, identity.Email
	}
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
	ctx = system.WithApiCredential(ctx, cred)
	if credentialScoped(cred) {
		ctx = system.WithApiScopes(ctx, cred.Scopes)
	}
	if contextShared := ctx.Value(types.SHARED); contextShared != nil {
		cs := contextShared.(*ContextShared)
		cs.UserId = principal
		cs.AppId = string(application.Id)
		cs.MCPMethod = method
		cs.MCPName = name
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
