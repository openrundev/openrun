// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// The aggregate app actions MCP endpoint, /_openrun/app_mcp: one endpoint
// whose tools are the actions of every app the caller can run, each action
// its own tool, named <app>__<action>. It is a third OAuth resource beside
// the management surfaces and the per-app MCP endpoints; no management tool
// is reachable with its tokens.
//
//	/_openrun/app_mcp[?apps=<glob>][&auth=<name>][&stage=true]
//
// apps is a view filter (default all), never part of the token audience.
// auth selects the login mechanism (default security.app_default_auth_type)
// and is part of the audience: the canonical resource is
// <external>/_openrun/app_mcp?auth=<mechanism>. With the mechanism none the
// endpoint is token-less and serves the anonymous user, as an auth none MCP
// app does. Per app the checks of run_action apply (app:access, provider
// match, the action's permit). Design: arch/docs/app-mcp-aggregate.md

const (
	ApiResourceAppMCP = "app_mcp" // config section [api.app_mcp] and the --resource name of API keys

	aggMCPAuthParam  = "auth"
	aggMCPAppsParam  = "apps"
	aggMCPStageParam = "stage"

	aggMCPNameSep        = "__" // between the app part and the action part of a tool name
	aggMCPHashMark       = "--" // before the hash of a hashed app part
	aggMCPAppPartMax     = 24
	aggMCPActionPartMax  = 38 // 24 + 2 + 38 = 64, the strictest client limit on tool names
	aggMCPHashLen        = 8
	aggMCPDefaultMax     = 300
	aggMCPDefaultListTTL = 3 * time.Minute
	aggMCPScope          = string(types.PermissionAccess)
)

var aggMCPEndpointPath = types.INTERNAL_URL_PREFIX + "/" + ApiResourceAppMCP

// aggMCPView is the view a request asks for, from its query params
type aggMCPView struct {
	glob      string
	stage     bool
	mechanism string
	ops       []mcpOp // the JSON-RPC operations of the request, the server is built for them
}

type aggMCPViewKey struct{}

// aggMCPState is the per-version cache of the tool sets, embedded in Server
type aggMCPState struct {
	appToolLists sync.Map // types.AppId -> *appToolListEntry
}

type appToolListEntry struct {
	version int
	tools   []appListedTool
}

// appListedTool is a tool as listed: the definition and the permit of its
// action (empty for the run tools and for unrestricted actions), evaluated
// per caller so that the cache is identity free
type appListedTool struct {
	tool   *mcp.Tool
	permit []string
}

// aggMCPEnabled reports whether the endpoint is served. It is on by default
// ([api.app_mcp] enable), so its prerequisites cannot be config errors: on
// a server with RBAC enforcement off (security.unsafe_disable_rbac) it is
// simply not served, the per app checks (app:access, the provider match)
// only run enforced. Without an OAuth issuer origin the token-less view
// (auth none) still works, a login cannot
func aggMCPEnabled(config *types.ServerConfig) bool {
	return config.Api.AppMCP.Enable && !config.Security.UnsafeDisableRBAC
}

// aggMCPMechanism resolves the auth param of a request or a resource to the
// login mechanism: none, system, builtin, an [auth.*] entry name or
// saml_<name>. Empty and "default" are the server default
// (security.app_default_auth_type), resolved as an app's default auth is.
// Client certificates and unknown names are refused: no browser flow
// produces those identities
func (s *Server) aggMCPMechanism(param string) (string, error) {
	config := s.Config()
	mechanism := resolveAppAuth(types.AppAuthnType(strings.TrimSpace(param)), config)
	mechanism, _, _ = strings.Cut(mechanism, types.AUTH_MODIFIER_DELIMITER)
	switch {
	case mechanism == string(types.AppAuthnNone), mechanism == string(types.AppAuthnSystem), mechanism == string(types.AppAuthnBuiltin):
	case mechanism == "cert" || strings.HasPrefix(mechanism, "cert_"):
		return "", fmt.Errorf("auth %s is client certificate auth, which cannot be used for an MCP login", mechanism)
	default:
		if !s.validFederatedMechanism(mechanism) {
			return "", fmt.Errorf("auth %q is not a login mechanism of this server (valid: none, system, builtin, an [auth.*] entry name or saml_<name>)", mechanism)
		}
	}
	if allowed := config.Api.AppMCP.AllowedAuth; len(allowed) > 0 && !slices.Contains(allowed, mechanism) {
		return "", fmt.Errorf("auth %s is not allowed for the app_mcp endpoint (api.app_mcp allowed_auth)", mechanism)
	}
	return mechanism, nil
}

// aggMCPResourceURI is the canonical resource of the endpoint for a login
// mechanism, the audience of its tokens. The mechanism is always explicit,
// also for the server default: a change of the default then invalidates the
// tokens minted under the old one instead of changing what they mean. ""
// without an issuer origin
func (s *Server) aggMCPResourceURI(mechanism string) string {
	external := s.apiExternalUrl()
	if external == "" {
		return ""
	}
	return external + aggMCPEndpointPath + "?" + aggMCPAuthParam + "=" + url.QueryEscape(mechanism)
}

// aggMCPResourceMechanism recognizes a requested resource as the endpoint
// (by origin and path; a client may send its whole connect url, the other
// query params are dropped) and returns the mechanism it names
func (s *Server) aggMCPResourceMechanism(resource string) (mechanism string, isAppMCP bool, err error) {
	external := s.apiExternalUrl()
	parsed, parseErr := url.Parse(strings.TrimSpace(resource))
	if external == "" || parseErr != nil || parsed.User != nil || parsed.Fragment != "" {
		return "", false, nil
	}
	if !strings.EqualFold(parsed.Scheme+"://"+parsed.Host, external) || strings.TrimSuffix(parsed.Path, "/") != aggMCPEndpointPath {
		return "", false, nil
	}
	mechanism, err = s.aggMCPMechanism(parsed.Query().Get(aggMCPAuthParam))
	return mechanism, true, err
}

// aggMCPKeyResource returns the canonical resource for an API key bound to
// the endpoint (--resource app_mcp[:<auth>])
func (s *Server) aggMCPKeyResource(auth string) (string, error) {
	if !aggMCPEnabled(s.Config()) {
		return "", fmt.Errorf("the %s endpoint is not enabled (api.app_mcp enable)", ApiResourceAppMCP)
	}
	mechanism, err := s.aggMCPMechanism(auth)
	if err != nil {
		return "", err
	}
	uri := s.aggMCPResourceURI(mechanism)
	if uri == "" {
		return "", fmt.Errorf("the %s endpoint needs the OAuth issuer origin (api.external_url)", ApiResourceAppMCP)
	}
	return uri, nil
}

// aggMCPLoginMechanisms maps the mechanism of the resource to the login
// mechanism vocabulary of the authorize page
func aggMCPLoginMechanisms(mechanism string) ([]string, error) {
	switch mechanism {
	case string(types.AppAuthnNone):
		return nil, fmt.Errorf("the app_mcp endpoint with auth none is served without a token: add ?auth=<login> to the url to log in")
	case string(types.AppAuthnSystem):
		return []string{"admin"}, nil
	}
	return []string{mechanism}, nil
}

// aggMCPChallenge is the WWW-Authenticate value of the endpoint
func (s *Server) aggMCPChallenge(mechanism, errCode string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `Bearer realm="%s"`, REALM)
	if errCode != "" {
		fmt.Fprintf(&b, `, error="%s"`, errCode)
	}
	if external := s.apiExternalUrl(); external != "" && mechanism != string(types.AppAuthnNone) {
		fmt.Fprintf(&b, `, resource_metadata="%s%s%s?%s=%s", scope="%s"`, external, mcpPRMPrefix, aggMCPEndpointPath,
			aggMCPAuthParam, url.QueryEscape(mechanism), aggMCPScope)
	}
	return b.String()
}

// serveAggMCPPRM serves the protected resource metadata of the endpoint, the
// path-inserted document; the mechanism comes from the query, which clients
// keep when they derive the document url from the endpoint url
func (h *Handler) serveAggMCPPRM(w http.ResponseWriter, r *http.Request) {
	external := h.server.apiExternalUrl()
	if !aggMCPEnabled(h.server.Config()) || external == "" || !h.server.mcpTransportAllowed(r) {
		http.NotFound(w, r)
		return
	}
	mechanism, err := h.server.aggMCPMechanism(r.URL.Query().Get(aggMCPAuthParam))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if mechanism == string(types.AppAuthnNone) {
		// Token-less: no document, a client which probes for one before its
		// first request must not start a login which cannot complete
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeOAuthJSON(w, http.StatusOK, map[string]any{
		"resource":                 h.server.aggMCPResourceURI(mechanism),
		"authorization_servers":    []string{external},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{aggMCPScope},
		"resource_name":            "OpenRun app actions",
	})
}

// aggMCPHTTPHandler serves the endpoint: transport and origin rules, the
// view from the query, the bearer credential (or the anonymous user for the
// mechanism none), then the streamable HTTP transport over a server built
// for the request
func (s *Server) aggMCPHTTPHandler() http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(s.buildAggMCPServer, &mcp.StreamableHTTPOptions{Stateless: true})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := s.Config()
		if !aggMCPEnabled(config) || !s.mcpTransportAllowed(r) {
			// No challenge on plaintext: a token in the request has leaked
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Origin") != "" {
			// Browser clients are not supported. This is the cross-site and
			// DNS rebinding protection of the transport, and for the
			// mechanism none the only thing between a web page and the open
			// actions of a server on a private network
			http.Error(w, "Forbidden: browser origins are not allowed on this endpoint", http.StatusForbidden)
			return
		}
		query := r.URL.Query()
		mechanism, err := s.aggMCPMechanism(query.Get(aggMCPAuthParam))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		view := &aggMCPView{glob: strings.TrimSpace(query.Get(aggMCPAppsParam)), mechanism: mechanism}
		view.glob = cmp.Or(view.glob, "all")
		switch strings.ToLower(query.Get(aggMCPStageParam)) {
		case "", "false":
		case "true":
			view.stage = true
		default:
			http.Error(w, "stage must be true or false", http.StatusBadRequest)
			return
		}
		if _, err := s.FilterApps(view.glob, false); err != nil {
			http.Error(w, "invalid apps glob: "+err.Error(), http.StatusBadRequest)
			return
		}

		challenge := func(errCode, detail string) {
			s.insertAuthFailureEvent(r, ApiResourceAppMCP, detail)
			w.Header().Set("WWW-Authenticate", s.aggMCPChallenge(mechanism, errCode))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
		authNone := mechanism == string(types.AppAuthnNone)
		var ctx context.Context
		token, presented := mcpBearerToken(r)
		switch {
		case token != "":
			// A presented token is always verified, for the mechanism none
			// too: an API key bound to the endpoint identifies its user
			principal, groups, scopes, cred, identity, err := s.verifyApiToken(r.Context(), token, s.aggMCPResourceURI(mechanism))
			if err != nil {
				detail := err.Error()
				if _, id, _, parseErr := parseApiToken(token); parseErr == nil {
					detail += " cred=" + id
				}
				s.Warn().Str("path", r.URL.Path).Msg("app_mcp bearer auth failed: " + detail)
				challenge("invalid_token", detail)
				return
			}
			ctx = s.apiTokenIdentityContext(r.Context(), principal, groups, scopes, InvokerMCP, cred, identity)
		case presented:
			challenge("", "unrecognized authorization header")
			return
		case !authNone || config.Security.AuthRequired:
			challenge("", "missing bearer token")
			return
		default:
			// The mechanism none, no credential presented: the anonymous
			// user. Only apps with auth none pass the provider match for it
			ctx = s.apiTokenIdentityContext(r.Context(), types.ANONYMOUS_USER, []string{}, nil, InvokerMCP, nil, nil)
		}

		ops, status, msg := mcpReadOperations(r)
		if status != 0 {
			http.Error(w, msg, status)
			return
		}
		view.ops = ops
		if contextShared := ctx.Value(types.SHARED); contextShared != nil {
			contextShared.(*ContextShared).UserId = system.GetContextUserId(ctx)
		}
		viewDetail := "auth=" + mechanism + " apps=" + view.glob
		if view.stage {
			viewDetail += " stage=true"
		}
		markMCPRequest(ctx, mcpEndpointApps, ops, system.GetContextApiCredential(ctx), viewDetail)
		// The endpoint never reads cookies and the credential goes no further
		r.Header.Del("Authorization")
		r.Header.Del("Cookie")
		streamable.ServeHTTP(w, r.WithContext(context.WithValue(ctx, aggMCPViewKey{}, view)))
	})
}

// buildAggMCPServer builds the MCP server of one request. The tool set
// differs by caller and by view, so there is no shared server: a list
// request gets the tools the caller can see, a call request the one tool it
// names, any other request (initialize, ping) none
func (s *Server) buildAggMCPServer(r *http.Request) *mcp.Server {
	ctx := r.Context()
	view, _ := ctx.Value(aggMCPViewKey{}).(*aggMCPView)
	maxTools := s.Config().Api.AppMCP.MaxTools
	if maxTools <= 0 {
		maxTools = aggMCPDefaultMax
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "openrun-apps", Version: types.GetVersion()}, &mcp.ServerOptions{
		Instructions: aggMCPInstructions(ctx, view),
		PageSize:     max(maxTools, mcp.DefaultPageSize),
		// The list is per caller and the transport stateless: no change
		// notifications, clients refresh within the ttl
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: false}},
	})
	if view == nil {
		return srv
	}
	// The status tool is always there, so a client (and its user) can tell
	// an empty view from a failed connection: who is connected, what the
	// view is and how many tools it holds
	srv.AddTool(aggMCPStatusTool, s.aggMCPStatusHandler(view))

	var listErr error
	listed := false
	for _, op := range view.ops {
		if op.Method != "tools/list" || listed {
			continue
		}
		listed = true
		tools, err := s.aggMCPListTools(ctx, view)
		if err == nil && len(tools) > maxTools {
			// Fail rather than truncate: a cut list would hide tools
			// without the user knowing
			err = fmt.Errorf("%d tools match, more than the limit of %d (api.app_mcp max_tools): narrow the view with the apps url param, like ?apps=/team/**",
				len(tools), maxTools)
		}
		if err != nil {
			listErr = err
			continue
		}
		for _, tool := range tools {
			srv.AddTool(tool, aggMCPNotCallable)
		}
	}
	for _, op := range view.ops {
		if op.Method != mcpMethodToolsCall || op.Name == "" {
			continue
		}
		if tool, handler := s.aggMCPResolveCall(ctx, view, op.Name); tool != nil {
			srv.AddTool(tool, handler)
		}
	}

	listTTL := aggMCPDefaultListTTL
	if d, err := time.ParseDuration(s.Config().Api.AppMCP.ListTTL); err == nil && d >= 0 && s.Config().Api.AppMCP.ListTTL != "" {
		listTTL = d
	}
	srv.AddReceivingMiddleware(s.mcpRecoverMiddleware)
	srv.AddReceivingMiddleware(mcpAuditMiddleware)
	srv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/list" && listErr != nil {
				return nil, listErr
			}
			result, err := next(ctx, method, req)
			if listResult, ok := result.(*mcp.ListToolsResult); ok && err == nil {
				// The list varies by caller: private to the caller's client
				listResult.CacheScope = "private"
				listResult.TTLMs = int(listTTL / time.Millisecond)
			}
			return result, err
		}
	})
	return srv
}

var aggMCPStatusTool = &mcp.Tool{
	Name:  aggMCPStatusToolName,
	Title: "OpenRun connection status",
	Description: "Report the connection to this OpenRun actions endpoint: the user and login it runs as, the view (apps glob, " +
		"staging) and how many action tools the view holds. Call it when the tool list is empty or a tool is missing.",
	InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false},
	Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
}

const aggMCPStatusToolName = "openrun_status" // no separator: never the name of an app's tool

// aggMCPStatusHandler answers the status tool for a request's view
func (s *Server) aggMCPStatusHandler(view *aggMCPView) mcp.ToolHandler {
	return func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		tools, err := s.aggMCPListTools(ctx, view)
		if err != nil {
			return aggMCPToolError("%s", err), nil
		}
		user := cmp.Or(system.GetContextUserId(ctx), types.ANONYMOUS_USER)
		status := map[string]any{
			"server":     s.apiExternalUrl(),
			"user":       user,
			"auth":       view.mechanism,
			"apps":       view.glob,
			"stage":      view.stage,
			"tool_count": len(tools),
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Connected to OpenRun as %s with login %s; view apps=%s", user, view.mechanism, view.glob)
		if view.stage {
			b.WriteString(" (staging instances)")
		}
		fmt.Fprintf(&b, "; %d action tools.", len(tools))
		switch {
		case len(tools) > 0:
			b.WriteString(" List the tools to see them.")
		case view.mechanism == string(types.AppAuthnNone):
			b.WriteString(" No login: only apps with auth none are visible. Add ?auth=<login> to the server url to log in and see your apps, or deploy an app with actions.")
		default:
			b.WriteString(" No app in the view has an action you may run: an action needs app:access on its app and, when restricted, " +
				"one of its permit permissions; apps with MCP disabled are not listed. Change the apps glob of the url, or deploy an app with actions.")
		}
		return &mcp.CallToolResult{StructuredContent: status, Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, nil
	}
}

// aggMCPInstructions is the instructions text of the endpoint for a
// request: who is connected and what the view is, so that a client (and its
// user) can tell an empty tool list from a failed connection and knows what
// to change
func aggMCPInstructions(ctx context.Context, view *aggMCPView) string {
	var b strings.Builder
	b.WriteString("Tools are the actions of the apps deployed on this OpenRun server which you can run, " +
		"named <app>" + aggMCPNameSep + "<action>; each tool description starts with its app. They run as the authenticated user. " +
		"Pass dry_run=true to a tool to validate its arguments without running it. " +
		"A tool named <app>" + aggMCPNameSep + "<action>_suggest, where present, suggests argument values.")
	if view == nil {
		return b.String()
	}
	fmt.Fprintf(&b, "\nConnected as %s", cmp.Or(system.GetContextUserId(ctx), types.ANONYMOUS_USER))
	if view.mechanism == string(types.AppAuthnNone) {
		b.WriteString(" (no login: only apps with auth none are visible; add ?auth=<login> to the url to log in and see your apps)")
	} else {
		fmt.Fprintf(&b, " (login %s: apps using that login and apps with auth none are visible)", view.mechanism)
	}
	fmt.Fprintf(&b, ", view apps=%s", view.glob)
	if view.stage {
		b.WriteString(" (staging instances)")
	}
	b.WriteString(". The " + aggMCPStatusToolName + " tool reports this connection and the number of action tools. " +
		"A view with no action tools means no app in it has an action you may run: " +
		"an action needs app:access on its app and, when restricted, one of its permit permissions; " +
		"apps with MCP disabled are not listed. Change the apps glob or the auth param of the url to change the view.")
	return b.String()
}

// aggMCPNotCallable backs the tools of a list request, which are never called
// on the server built for it
func aggMCPNotCallable(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return aggMCPToolError("the tool is not available"), nil
}

// aggMCPUnknownTool is the error the MCP server answers a call of a tool
// which is not registered with: a tool the caller may not use is reported
// the same way, so its existence is not confirmed
func aggMCPUnknownTool(name string) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown tool %q", name)}
}

func aggMCPToolError(format string, args ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}}}
}

// aggMCPExcluded reports whether an app stays out of the endpoint because of
// its stored mcp document: MCP disabled, or a tool scope map. The map is a
// vocabulary of the app's own resource which a token for this endpoint
// cannot carry; listing the app here would let an app:access token call
// tools which need an extra scope on the app's own endpoint
func aggMCPExcluded(stored *types.MCPConfig) bool {
	return stored != nil && (stored.Disable || len(stored.Tools) > 0)
}

// aggMCPInstance resolves the instance of an app the view holds (the stage
// instance for a staging view) and runs the checks which work from its
// metadata, before anything is loaded: the mcp document, app:access and the
// provider match. ok is false when the app is not part of the caller's view
func (s *Server) aggMCPInstance(ctx context.Context, view *aggMCPView, info types.AppInfo) (entry *types.AppEntry, target actionTarget, ok bool) {
	entry, err := s.resolveJobInstance(ctx, info.String(), view.stage)
	if err != nil {
		return nil, target, false
	}
	if view.stage && !strings.HasPrefix(string(entry.Id), types.ID_PREFIX_APP_STAGE) {
		return nil, target, false // no staging instance (a dev app)
	}
	target = actionTargetOfEntry(entry)
	if aggMCPExcluded(target.mcp) {
		return nil, target, false
	}
	if s.rbacManager.APIEnforced(ctx) {
		authorized, err := s.rbacManager.AuthorizeAPI(ctx, types.PermissionAccess, target.grantPath, target.owner)
		if err != nil || !authorized {
			return nil, target, false
		}
	}
	if s.actionProviderMatch(ctx, target) != nil {
		return nil, target, false
	}
	return entry, target, true
}

// aggMCPAppParts returns the app part of the tool names for every app of the
// server, and the parts more than one app produces. That takes a hash
// collision; the tools of all the apps involved are then left out (fail
// closed) rather than one app winning by order
func (s *Server) aggMCPAppParts() (parts map[types.AppId]string, duplicate map[string]bool, err error) {
	all, err := s.FilterApps("all", false)
	if err != nil {
		return nil, nil, err
	}
	parts = make(map[types.AppId]string, len(all))
	count := make(map[string]int, len(all))
	for _, info := range all {
		part := aggMCPAppPart(info.Domain, info.Path)
		parts[info.Id] = part
		count[part]++
	}
	duplicate = map[string]bool{}
	for part, n := range count {
		if n > 1 {
			duplicate[part] = true
			s.Warn().Str("name", part).Msg("app_mcp: more than one app maps to the tool name prefix, their tools are not served")
		}
	}
	return parts, duplicate, nil
}

// aggMCPListTools returns the tools of the view the caller can see, by app
// path
func (s *Server) aggMCPListTools(ctx context.Context, view *aggMCPView) ([]*mcp.Tool, error) {
	parts, duplicate, err := s.aggMCPAppParts()
	if err != nil {
		return nil, err
	}
	apps, err := s.FilterApps(view.glob, false)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(apps, func(a, b types.AppInfo) int { return strings.Compare(a.String(), b.String()) })

	results := make([][]*mcp.Tool, len(apps))
	err = forEachAppParallel(ctx, apps, func(ctx context.Context, i int, info types.AppInfo) error {
		part := parts[info.Id]
		if part == "" || duplicate[part] {
			return nil
		}
		entry, target, ok := s.aggMCPInstance(ctx, view, info)
		if !ok {
			return nil
		}
		if !entry.IsDev && entry.Metadata.DefinitionActions != nil && len(entry.Metadata.DefinitionActions) == 0 {
			return nil // known to have no actions, nothing to load
		}
		listed, err := s.aggMCPToolList(ctx, entry, info, part)
		if err != nil {
			s.Warn().Err(err).Str("app", info.String()).Msg("app_mcp: error loading the actions of the app, its tools are not listed")
			return nil
		}
		if len(listed) == 0 {
			return nil
		}
		appCtx, err := s.actionAppContext(ctx, target)
		if err != nil {
			return err
		}
		for _, tool := range listed {
			if len(tool.permit) > 0 {
				authorized, err := s.rbacManager.AuthorizeAny(appCtx, tool.permit)
				if err != nil {
					return err
				}
				if !authorized {
					continue
				}
			}
			results[i] = append(results[i], tool.tool)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	tools := make([]*mcp.Tool, 0)
	seen := map[string]int{}
	for _, result := range results {
		for _, tool := range result {
			seen[tool.Name]++
			tools = append(tools, tool)
		}
	}
	// A name two tools share is served for neither
	return slices.DeleteFunc(tools, func(tool *mcp.Tool) bool { return seen[tool.Name] > 1 }), nil
}

// aggMCPToolList returns the tool set of an app instance, from the cache for
// the app version or from the definition of the app (the app loaded on this
// node, else a definition only load: no container, nothing initialized).
// The stored action definitions cannot serve this, they omit the params.
// Dev apps are not cached, their source changes without a new version
func (s *Server) aggMCPToolList(ctx context.Context, entry *types.AppEntry, info types.AppInfo, appPart string) ([]appListedTool, error) {
	version := entry.Metadata.VersionMetadata.Version
	if !entry.IsDev {
		if cached, ok := s.appToolLists.Load(entry.Id); ok {
			if cachedEntry := cached.(*appToolListEntry); cachedEntry.version == version {
				return cachedEntry.tools, nil
			}
		}
	}
	application, release, err := s.definitionApp(ctx, entry)
	if err != nil {
		return nil, err
	}
	defer release()
	tools, err := application.AggregateMCPTools(aggMCPNamer(appPart))
	if err != nil {
		return nil, err
	}
	appName := cmp.Or(application.Name, info.String())
	listed := make([]appListedTool, 0, len(tools))
	for _, tool := range tools {
		// A copy: the title and the description carry the app here, the
		// tool the app keeps is the one which runs
		definition := *tool.Tool
		definition.Title = appName + ": " + cmp.Or(definition.Title, definition.Name)
		definition.Description = "App " + info.String() + "\n" + definition.Description
		var permit []string
		if tool.Action != nil {
			permit = tool.Action.Permit()
		}
		listed = append(listed, appListedTool{tool: &definition, permit: permit})
	}
	if entry.IsDev {
		s.appToolLists.Delete(entry.Id)
	} else {
		s.appToolLists.Store(entry.Id, &appToolListEntry{version: version, tools: listed})
	}
	return listed, nil
}

// aggMCPResolveCall resolves the tool a call names to its app and returns
// the tool to register for the request, nil when the name is not a tool of
// the caller's view: unknown names and apps the caller cannot use look the
// same. The checks which need no load run here; the app is loaded (and an
// idle container started, as run_action does) only when the tool is called
func (s *Server) aggMCPResolveCall(ctx context.Context, view *aggMCPView, name string) (*mcp.Tool, mcp.ToolHandler) {
	appPart, _, ok := strings.Cut(name, aggMCPNameSep)
	if !ok || appPart == "" {
		return nil, nil
	}
	parts, duplicate, err := s.aggMCPAppParts()
	if err != nil || duplicate[appPart] {
		return nil, nil
	}
	apps, err := s.FilterApps(view.glob, false)
	if err != nil {
		return nil, nil
	}
	index := slices.IndexFunc(apps, func(info types.AppInfo) bool { return parts[info.Id] == appPart })
	if index < 0 {
		return nil, nil
	}
	info := apps[index]
	entry, _, ok := s.aggMCPInstance(ctx, view, info)
	if !ok {
		return nil, nil
	}
	setMCPCallApp(ctx, name, entry.Id) // the audit event of the call links to the app

	// The definition registered for the request only routes the call, the
	// app's own tool validates the arguments
	stub := &mcp.Tool{Name: name, InputSchema: map[string]any{"type": "object"}}
	return stub, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		application, appCtx, release, err := s.actionApp(ctx, info.String(), view.stage, true)
		if err != nil {
			return aggMCPToolError("%s", err), nil
		}
		defer release()
		tools, err := application.AggregateMCPTools(aggMCPNamer(appPart))
		if err != nil {
			return aggMCPToolError("%s", err), nil
		}
		index := slices.IndexFunc(tools, func(tool *action.MCPTool) bool { return tool.Tool.Name == name })
		if index < 0 {
			return nil, aggMCPUnknownTool(name)
		}
		tool := tools[index]
		if tool.Action != nil {
			// A caller without the permit gets the answer an unknown tool gets
			if authorized, err := tool.Action.Authorized(appCtx); err != nil || !authorized {
				return nil, aggMCPUnknownTool(name)
			}
		}
		// The call does not pass through App.ServeHTTP: count it as app
		// activity, or the idle shutdown stops a container which is in use
		application.RecordActivity()
		return tool.Call(appCtx, req)
	}
}

// aggMCPNamer returns the name mapping of an app's tools: the app part, the
// separator and the bounded action part
func aggMCPNamer(appPart string) func(local string) string {
	return func(local string) string {
		return appPart + aggMCPNameSep + aggMCPActionPart(local)
	}
}

func aggMCPHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:aggMCPHashLen]
}

// aggMCPAppPart returns the app part of the tool names of an app, derived
// from the app alone: no other app can change it, so a tool name a client
// holds cannot come to mean another app.
//
// Plain form (no hash), for an app on the default domain whose path uses
// letters, digits and single hyphens only: the path with "/" as "_". The
// mapping is reversible, distinct paths give distinct names. Everything else
// (a path with "_", "." or other characters or with "--", an app on another
// domain, the root app) could clash with another path, so it carries its own
// discriminator: the slug, "--" and a hash of the domain and path. A plain
// name never contains "--". Longer than aggMCPAppPartMax: the tail of the
// slug with the hash
func aggMCPAppPart(domain, appPath string) string {
	hash := aggMCPHash(domain + ":" + appPath)
	plain := domain == "" && appPath != "/" && strings.HasPrefix(appPath, "/") && !strings.HasSuffix(appPath, "/") &&
		!strings.Contains(appPath, "//") && !strings.Contains(appPath, "--")
	if plain {
		for _, r := range appPath {
			allowed := r == '/' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !allowed {
				plain = false
				break
			}
		}
	}
	var slug string
	if plain {
		slug = strings.ReplaceAll(appPath[1:], "/", "_")
		if len(slug) <= aggMCPAppPartMax {
			return slug
		}
	} else {
		slug = aggMCPSlug(domain + "/" + appPath)
		if slug == "" {
			slug = "root"
		}
		if len(slug)+len(aggMCPHashMark)+aggMCPHashLen <= aggMCPAppPartMax {
			return slug + aggMCPHashMark + hash
		}
	}
	tail := slug[len(slug)-(aggMCPAppPartMax-len(aggMCPHashMark)-aggMCPHashLen):]
	return strings.TrimLeft(tail, "_-") + aggMCPHashMark + hash
}

// aggMCPSlug keeps letters and digits; every other run of characters becomes
// one "_", none at the ends. The result has no "__" and no "--"
func aggMCPSlug(value string) string {
	var b strings.Builder
	pendingSep := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			if pendingSep && b.Len() > 0 {
				b.WriteByte('_')
			}
			pendingSep = false
			b.WriteRune(r)
		} else {
			pendingSep = true
		}
	}
	return b.String()
}

// aggMCPActionPart bounds the tool name of an action (action.ToolNames has
// no length limit): a longer one keeps its head with a hash of the whole
func aggMCPActionPart(local string) string {
	if len(local) <= aggMCPActionPartMax {
		return local
	}
	return strings.TrimRight(local[:aggMCPActionPartMax-1-aggMCPHashLen], "_-") + "-" + aggMCPHash(local)
}
