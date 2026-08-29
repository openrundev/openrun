// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

const (
	DRY_RUN_ARG              = "dryRun"
	PROMOTE_ARG              = "promote"
	REAPPLY_ALL_ARG          = "reapplyAll"
	DELEGATE_BUILD_OP        = "delegate_build"
	MAX_DELEGATE_UPLOAD_SIZE = 512 << 20 // 512 MiB
	MAX_SECRET_UPLOAD_SIZE   = 8 << 20   // 8 MiB: values are capped at 1 MiB, but json escaping can inflate a text value up to 6x
)

var (
	COMPRESSION_ENABLED_MIME_TYPES = []string{
		"text/html",
		"text/css",
		"text/plain",
		"text/xml",
		"text/x-component",
		"text/javascript",
		"application/x-javascript",
		"application/javascript",
		"application/json",
		"application/manifest+json",
		"application/vnd.api+json",
		"application/xml",
		"application/xhtml+xml",
		"application/rss+xml",
		"application/atom+xml",
		"application/vnd.ms-fontobject",
		"application/x-font-ttf",
		"application/x-font-opentype",
		"application/x-font-truetype",
		"image/svg+xml",
		"image/x-icon",
		"image/vnd.microsoft.icon",
		"font/ttf",
		"font/eot",
		"font/otf",
		"font/opentype",
	}
)

const (
	REALM = "openrun"
)

type Handler struct {
	*types.Logger
	server *Server
	router *chi.Mux
}

func (h *Handler) panicRecovery(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				if rvr == http.ErrAbortHandler {
					// Deliberate connection abort (e.g. a download stream
					// failing mid-body): re-panic so net/http drops the
					// connection instead of finalizing the response
					panic(rvr)
				}
				msg := fmt.Sprint(rvr)
				fmt.Fprintf(os.Stderr, "Panic %s", msg)
				h.Error().Msgf("Panic %s: %s", msg, string(debug.Stack()))
				http.Error(w, msg, http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

// NewUDSHandler creates a new handler for admin APIs over the unix domain socket
func NewUDSHandler(logger *types.Logger, config *types.ServerConfig, server *Server) *Handler {
	router := chi.NewRouter()
	router.Use(server.handleStatus(types.ADMIN_USER))

	handler := &Handler{
		Logger: logger,
		server: server,
		router: router,
	}
	router.Use(handler.panicRecovery)
	router.Use(server.accessLogMiddleware)
	router.Use(middleware.CleanPath)

	router.Mount(types.INTERNAL_URL_PREFIX, handler.serveInternal(false))

	// App APIs are not mounted over UDS
	// No authentication middleware is added for UDS, the unix file permissions are used
	return handler
}

// NewTCPHandler creates a new handler for HTTP/HTTPS requests. App API's are mounted amd
// authentication is enabled. It also mounts the internal APIs if admin over TCP is enabled
func NewTCPHandler(logger *types.Logger, config *types.ServerConfig, server *Server) *Handler {
	router := chi.NewRouter()

	handler := &Handler{
		Logger: logger,
		server: server,
		router: router,
	}
	router.Use(handler.validateHostHeader)
	if config.Http.RedirectToHttps {
		router.Use(handler.httpsRedirectMiddleware)
	}
	router.Use(server.handleStatus("")) // no default user, TCP requests authenticate the user
	router.Use(handler.panicRecovery)
	router.Use(server.accessLogMiddleware)
	router.Use(middleware.CleanPath)

	if config.System.EnableCompression {
		router.Use(middleware.Compress(5, COMPRESSION_ENABLED_MIME_TYPES...))
	}

	if config.Builder.Mode == "delegate_server" {
		logger.Warn().Msg("Delegated build server mode is enabled")
		router.Mount(types.INTERNAL_URL_PREFIX, server.csrfMiddleware.Handler(handler.serveDelegatedBuild()))
	} else if apiSurfaceEnabled(config, string(types.ApiSurfaceRest)) || apiSurfaceEnabled(config, string(types.ApiSurfaceMCP)) {
		// Remote API surfaces ([api] enable): bearer-authenticated REST
		// management and/or MCP, served only over HTTPS or via a trusted
		// TLS-terminating proxy (the transport gate inside)
		router.Mount(types.INTERNAL_URL_PREFIX, server.csrfMiddleware.Handler(handler.serveRemoteInternal(config)))
		// OAuth well-known metadata documents (RFC 8414 / RFC 9728), behind
		// the same transport gate. One PRM document per enabled surface
		wellKnownGate := func(next http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				if system.GetRequestScheme(r, config.Security.TrustedProxies) != "https" {
					http.NotFound(w, r)
					return
				}
				next(w, r)
			}
		}
		router.Get("/.well-known/oauth-authorization-server", wellKnownGate(handler.serveOAuthASMetadata))
		router.Get("/.well-known/oauth-protected-resource/rest", wellKnownGate(handler.serveOAuthPRM(ApiResourceRest)))
		router.Get("/.well-known/oauth-protected-resource/mcp", wellKnownGate(handler.serveOAuthPRM(ApiResourceMCP)))
	} else {
		router.Mount(types.INTERNAL_URL_PREFIX, server.csrfMiddleware.Handler(http.NotFoundHandler())) // reserve the path
	}

	// Webhooks are always mounted, they are disabled at the app level by default
	router.Mount(types.WEBHOOK_URL_PREFIX, server.csrfMiddleware.Handler(handler.serveWebhooks()))

	server.oAuthManager.RegisterRoutes(server.csrfMiddleware, router)    // register OAuth routes
	server.samlManager.RegisterRoutes(router)                            // register SAML routes
	server.formLogin.RegisterRoutes(server.csrfMiddleware, router)       // register the system/builtin login page routes
	server.formLogin.RegisterLogoutRoutes(server.csrfMiddleware, router) // register the system/builtin logout page routes

	router.HandleFunc("/*", handler.callApp)
	router.HandleFunc(types.INTERNAL_URL_PREFIX+"/health",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("OK")) //nolint:errcheck
		})

	return handler
}

func (h *Handler) validateHostHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !system.ValidHostHeader(r.Host) {
			h.Warn().Str("host", r.Host).Msg("Rejecting request with invalid Host header")
			http.Error(w, "invalid Host header", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// httpsRedirectMiddleware checks if the request was made using HTTP (no TLS)
// and redirects it to the HTTPS version of the URL if so.
func (h *Handler) httpsRedirectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			if strings.HasPrefix(r.URL.Path, types.INTERNAL_URL_PREFIX) {
				// Management/webhook paths are never redirected to HTTPS: a
				// credential-bearing plaintext request has already leaked its
				// token, so the transport gate refuses it (404) instead; the
				// unauthenticated /_openrun/health probe stays served
				next.ServeHTTP(w, r)
				return
			}
			u := *r.URL
			u.Scheme = "https"
			u.Host = h.httpsRedirectHost(r.Host)

			// Redirect to the HTTPS version of the URL
			http.Redirect(w, r, u.String(), http.StatusPermanentRedirect) // 308 (301 does not keep method)
			return
		}

		// If it's already HTTPS, just proceed
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) httpsRedirectHost(requestHost string) string {
	redirectDomain := h.httpsRedirectDomain(system.GetHostname(requestHost))
	if _, _, err := net.SplitHostPort(requestHost); err == nil {
		return net.JoinHostPort(redirectDomain, strconv.Itoa(h.server.Config().Https.Port))
	}
	return formatRedirectHost(redirectDomain)
}

func (h *Handler) httpsRedirectDomain(requestDomain string) string {
	config := h.server.Config()
	if requestDomain == "" {
		return config.System.DefaultDomain
	}

	if h.isConfiguredRedirectDomain(requestDomain) {
		return requestDomain
	}

	if config.System.DefaultDomain != "" {
		return config.System.DefaultDomain
	}
	if config.System.RootServeListApps != "" &&
		config.System.RootServeListApps != "auto" &&
		config.System.RootServeListApps != "disable" {
		return config.System.RootServeListApps
	}
	return requestDomain
}

func (h *Handler) isConfiguredRedirectDomain(requestDomain string) bool {
	config := h.server.Config()
	if requestDomain == config.System.DefaultDomain {
		return true
	}
	if requestDomain == "127.0.0.1" && config.System.DefaultDomain == "localhost" {
		return true
	}
	if requestDomain == "localhost" && config.System.DefaultDomain == "127.0.0.1" {
		return true
	}
	if config.System.RootServeListApps != "" &&
		config.System.RootServeListApps != "auto" &&
		config.System.RootServeListApps != "disable" &&
		requestDomain == config.System.RootServeListApps {
		return true
	}

	allDomains, err := h.server.apps.GetAllDomains()
	if err != nil {
		h.Error().Err(err).Str("host", requestDomain).Msg("Error loading configured domains for https redirect")
		return false
	}
	return allDomains[requestDomain]
}

func formatRedirectHost(host string) string {
	if strings.Count(host, ":") > 1 && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func (h *Handler) callApp(w http.ResponseWriter, r *http.Request) {
	if h.Debug().Enabled() {
		h.Debug().Str("method", r.Method).Str("url", r.URL.String()).Msg("App Received request")
	}

	requestDomain := system.GetHostname(r.Host)

	// The auth callback domain serves only the login page (registered as
	// specific routes matched before this catch-all). Refuse to serve or fall
	// back to any app here, so app JavaScript is never same-origin with the
	// credential form - independent of MatchApp's FallbackUnknownDomains, and
	// of whether the login form is currently enabled on this node
	if h.server.formLogin.isReservedAuthHost(requestDomain) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	var serveListApps = false
	matchedApp, matchErr := h.server.MatchApp(requestDomain, r.URL.Path)
	if matchErr != nil {
		systemConfig := h.server.Config().System
		if systemConfig.RootServeListApps != "disable" {
			// No app is installed at root, use the list_apps app
			var serveAtDomain string
			if systemConfig.RootServeListApps == "auto" {
				serveAtDomain = systemConfig.DefaultDomain
			} else {
				serveAtDomain = systemConfig.RootServeListApps
			}
			if requestDomain == serveAtDomain || (serveAtDomain == "localhost" && requestDomain == "127.0.0.1") {
				serveListApps = true
			}
		}
	}

	if matchErr != nil && !serveListApps {
		h.Error().Err(matchErr).Str("path", r.URL.Path).Msg("No app matched request")
		http.Error(w, matchErr.Error(), http.StatusNotFound)
		return
	}

	var serveApp *app.App
	var err error
	if !serveListApps {
		newReq, dirErr := h.applyTestUrlDirectives(matchedApp, r)
		if dirErr != nil {
			h.Error().Err(dirErr).Str("path", r.URL.Path).Msg("Invalid _cl_ test url directive")
			http.Error(w, dirErr.Error(), http.StatusBadRequest)
			return
		}
		r = newReq
		serveApp, err = h.server.GetApp(r.Context(), matchedApp.AppPathDomain, true)
		if err != nil {
			h.Error().Err(err).Str("path", r.URL.Path).Msg("Error getting app")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		serveApp, err = h.server.GetListAppsApp(r.Context())
		if err != nil {
			h.Error().Err(err).Str("path", r.URL.Path).Msg("Error getting list_apps app")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	h.server.authenticateAndServeApp(w, r, serveApp)
}

func validatePathForCreate(inp string) error {
	if strings.Contains(inp, "/..") {
		return fmt.Errorf("path cannot contain '/..'")
	}
	if strings.Contains(inp, "../") {
		return fmt.Errorf("path cannot contain '../'")
	}
	if strings.Contains(inp, "/./") {
		return fmt.Errorf("path cannot contain '/./'")
	}
	if strings.HasSuffix(inp, "/.") {
		return fmt.Errorf("path cannot end with '/.'")
	}
	parts := strings.Split(inp, "/")
	lastPart := parts[len(parts)-1]
	if strings.Contains(lastPart, "_cl_") {
		return fmt.Errorf("last section of path cannot contain _cl_, openrun reserved path")
	}
	return nil
}

func (h *Handler) builderAuth(r *http.Request) error {
	if h.server.Config().System.BuilderAuthToken == "" {
		return fmt.Errorf("builder auth token is not configured")
	}
	token := r.Header.Get("Authorization")
	if token == "" {
		return fmt.Errorf("authorization header is required")
	}
	// Check bearer token
	if !strings.HasPrefix(token, "Bearer ") {
		return fmt.Errorf("authorization header with bearer token is required")
	}
	token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
	if token == "" {
		return fmt.Errorf("bearer token is required")
	}
	if subtle.ConstantTimeCompare([]byte(h.server.Config().System.BuilderAuthToken), []byte(token)) != 1 {
		return fmt.Errorf("invalid bearer token")
	}
	return nil
}

func (h *Handler) apiHandler(w http.ResponseWriter, r *http.Request, remote bool, operation string, apiFunc func(r *http.Request) (any, error), runVersionCleanup bool) {
	if remote {
		if operation == DELEGATE_BUILD_OP {
			// Builder auth is required for delegated builds
			err := h.builderAuth(r)
			if err != nil {
				h.server.insertAuthFailureEvent(r, operation, err.Error())
				w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s"`, REALM))
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		} else {
			// Remote REST surface: bearer credential (API key) auth. The
			// request runs as the credential's identity with RBAC enforced -
			// remote calls are never trusted-context
			authCtx, cred, ok := h.server.authenticateApiRequest(w, r, ApiResourceRest, operation)
			if !ok {
				return
			}
			if !h.server.apiOpEnabled(InvokerTCP, API_NAME(operation)) {
				// Refused attempts are audited: "what was tried and refused"
				// is a first-class query on the invoker-tagged trail
				refusedEvent := types.AuditEvent{
					RequestId:  system.GetContextRequestId(r.Context()),
					CreateTime: time.Now(),
					UserId:     system.GetContextUserId(authCtx),
					EventType:  types.EventTypeSystem,
					Operation:  operation,
					Status:     string(types.EventStatusFailure),
					Detail:     "invoker=" + InvokerTCP + " cred=" + cred.Id + " refused=op_disabled",
				}
				if auditErr := h.server.InsertAuditEvent(&refusedEvent); auditErr != nil {
					h.Error().Err(auditErr).Msg("error inserting audit event for refused call")
				}
				http.Error(w, fmt.Sprintf("operation %s is disabled for the tcp API surface", operation), http.StatusForbidden)
				return
			}
			r = r.WithContext(authCtx)
		}
	}

	if asUser := r.Header.Get(types.OPENRUN_HEADER_AS_USER); asUser != "" && !remote {
		// The CLI --as flag, over the unix domain socket only: the caller is
		// the administrator (unix file permissions), who chooses to run this
		// call as the given user with RBAC enforcement instead. Requires RBAC
		// to be enabled; the audit event below records the as user
		asCtx, err := h.server.asUserRequestContext(r.Context(), asUser)
		if err != nil {
			h.server.insertAuthFailureEvent(r, operation, err.Error())
			if reqError, ok := err.(types.RequestError); ok {
				http.Error(w, reqError.Error(), reqError.Code)
			} else {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			return
		}
		r = r.WithContext(asCtx)
	} else if !remote {
		// Unix socket calls are authenticated by filesystem permissions and are
		// the sole management API transport exempt from RBAC
		r = r.WithContext(system.WithTrustedOperation(system.WithApiInvoker(r.Context(), InvokerUDS)))
	} else if operation == DELEGATE_BUILD_OP {
		// Delegated builder requests use their separately scoped bearer-token API
		r = r.WithContext(system.WithTrustedOperation(r.Context()))
	}

	event := types.AuditEvent{
		RequestId:  system.GetContextRequestId(r.Context()),
		CreateTime: time.Now(),
		// Unattributed trusted APIs (UDS/delegated builder) audit as admin;
		// admin-over-TCP and --as contexts already carry their principal
		UserId:    cmp.Or(system.GetContextUserId(r.Context()), types.ADMIN_USER),
		AppId:     system.GetContextAppId(r.Context()),
		EventType: types.EventTypeSystem,
		Operation: operation,
		// Status starts as Failed so a panic in apiFunc is not recorded as a success
		Status: string(types.EventStatusFailure),
	}
	if detail := apiAuditDetail(r.Context()); detail != "" {
		// "what has MCP/remote CLI done", down to the specific credential,
		// is a single audit query
		event.Detail = detail
	}

	defer func() {
		if err := h.server.InsertAuditEvent(&event); err != nil {
			h.Error().Err(err).Msg("error inserting audit event")
		}
	}()

	resp, err := apiFunc(r)
	if err == nil {
		event.Status = string(types.EventStatusSuccess)
	}

	contextShared := r.Context().Value(types.SHARED)
	if contextShared != nil {
		cs := contextShared.(*ContextShared)
		if cs.Target != "" {
			event.Target = cs.Target
		}
		if cs.Operation != "" {
			event.Operation = cs.Operation
		}
		if cs.DryRun {
			event.Operation = fmt.Sprintf("%s_dryrun", event.Operation)
		}
	}

	h.Trace().Str("method", r.Method).Str("url", r.URL.String()).Err(err).Msg("API Received request")
	if err != nil {
		if reqError, ok := err.(types.RequestError); ok {
			w.Header().Add("Content-Type", "application/json")
			errStr, _ := json.Marshal(reqError)
			http.Error(w, string(errStr), reqError.Code)
			return
		}
		h.Error().Err(err).Msg("error in api func call")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if runVersionCleanup && contextShared != nil && !contextShared.(*ContextShared).DryRun {
		// Cleanup old versions of apps
		h.server.CleanupVersions()
	}

	if resp == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	err = json.MarshalWrite(w, resp)
	if err != nil {
		event.Status = string(types.EventStatusFailure)
		h.Error().Err(err).Msg("error encoding response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// webhookHandler does the bearer token auth check and calls the webhook api
func (h *Handler) webhookHandler(w http.ResponseWriter, r *http.Request, webhookType types.WebhookType) {
	appPath := r.URL.Query().Get("appPath")
	if appPath == "" {
		http.Error(w, "appPath is required for webhook call", http.StatusBadRequest)
		return
	}
	appPathDomain, err := parseAppPath(appPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	app, err := h.server.GetApp(r.Context(), appPathDomain, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	appToken := ""
	promote := false
	reload := false
	switch webhookType {
	case types.WebhookReload:
		reload = true
		appToken = app.Settings.WebhookTokens.Reload
	case types.WebhookReloadPromote:
		reload = true
		promote = true
		appToken = app.Settings.WebhookTokens.ReloadPromote
	case types.WebhookPromote:
		promote = true
		appToken = app.Settings.WebhookTokens.Promote
	default:
		http.Error(w, fmt.Sprintf("Invalid webhook type %s", webhookType), http.StatusInternalServerError)
		return
	}

	if appToken == "" {
		http.Error(w, fmt.Sprintf("%s webhook is not enabled for app", webhookType), http.StatusBadRequest)
		return
	}

	operation := fmt.Sprintf("webhook_%s", webhookType)
	authFailure := func(msg string) {
		h.server.insertAuthFailureEvent(r, operation, msg)
		http.Error(w, msg, http.StatusUnauthorized)
	}

	// Authenticate the request
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Using Authentication header, bearer token — validate before reading body
		if !strings.HasPrefix(authHeader, "Bearer ") {
			authFailure("Authorization header with bearer token is required")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if token == "" {
			authFailure("Bearer token is required")
			return
		}

		if subtle.ConstantTimeCompare([]byte(appToken), []byte(token)) != 1 {
			authFailure("Invalid bearer token")
			return
		}
	}

	const maxWebhookBody = 10 << 20 // 10 MiB
	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("error reading request body: %s", err), http.StatusBadRequest)
		return
	}

	if authHeader == "" {
		// Using signature auth — requires body for HMAC verification
		// https://docs.github.com/en/webhooks/webhook-events-and-payloads#delivery-headers
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			authFailure("No auth header and no signature found")
			return
		}

		err = validateSignature(appToken, signature, body)
		if err != nil {
			authFailure(err.Error())
			return
		}
	}

	// The webhook token authenticated the caller for this app's configured
	// operation; mark the context trusted so RBAC enforcement stays off (an
	// unmarked context fails closed when RBAC is enabled)
	r = r.WithContext(system.WithTrustedOperation(r.Context()))

	// Authenticated, all failures from here on are audited. Status starts as
	// Failed so early returns and panics are not recorded as a success
	event := types.AuditEvent{
		RequestId:  system.GetContextRequestId(r.Context()),
		CreateTime: time.Now(),
		UserId:     system.GetContextUserId(r.Context()),
		AppId:      app.Id,
		EventType:  types.EventTypeSystem,
		Operation:  operation,
		Target:     appPathDomain.String(),
		Status:     string(types.EventStatusFailure),
	}

	defer func() {
		if err := h.server.InsertAuditEvent(&event); err != nil {
			h.Error().Err(err).Msg("error inserting audit event")
		}
	}()

	h.Trace().Str("method", r.Method).Str("url", r.URL.String()).Msg("API Received request")

	var resp any
	if reload && system.IsGit(app.SourceUrl) {
		// validate branch name, it should match branch name in app metadata if app is using git
		payload := map[string]any{}
		err = json.Unmarshal(body, &payload)
		if err != nil {
			http.Error(w, "Error parsing request, expected JSON", http.StatusBadRequest)
			return
		}

		branch := payload["ref"]
		branchStr, ok := branch.(string)

		if !ok {
			h.Info().Msgf("Webhook call for reload failed, could not find ref")
			http.Error(w, "Could not find branch info in request payload, ref key should be present", http.StatusBadGateway)
			return
		}
		if strings.HasPrefix(branchStr, "refs/heads/") {
			branchStr = branchStr[len("refs/heads/"):]
			if branchStr != app.Metadata.VersionMetadata.GitBranch {
				h.Info().Msgf("Ignoring webhook call for reload, branch mismatch, found %s, expected %s", branchStr, app.Metadata.VersionMetadata.GitBranch)
				http.Error(w, fmt.Sprintf("branch mismatch, found %s, expected %s", branchStr, app.Metadata.VersionMetadata.GitBranch), http.StatusBadGateway)
				return
			}
		} else {
			h.Info().Msgf("Webhook call for reload failed, could not find branch")
			http.Error(w, "Could not find branch info in request payload, ref should start with \"refs/heads/\"", http.StatusBadGateway)
			return
		}
	}

	if reload {
		resp, err = h.server.ReloadApps(r.Context(), appPath, false, false, promote, "", "", "", true, false)
	} else {
		// promote operation
		resp, err = h.server.PromoteApps(r.Context(), appPath, false)
	}

	h.Info().Msgf("Webhook call for %s, appPath: %s, promote: %t, reload: %t, response %+v err %s",
		webhookType, appPath, promote, reload, resp, err)

	if err == nil {
		event.Status = string(types.EventStatusSuccess)
	}

	if err != nil {
		if reqError, ok := err.(types.RequestError); ok {
			w.Header().Add("Content-Type", "application/json")
			errStr, _ := json.Marshal(reqError)
			http.Error(w, string(errStr), reqError.Code)
			return
		}
		h.Error().Err(err).Msg("error in api func call")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		// Cleanup old versions of apps
		h.server.CleanupVersions()
	}

	w.Header().Add("Content-Type", "application/json")
	err = json.MarshalWrite(w, resp)
	if err != nil {
		h.Error().Err(err).Msg("error encoding response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func validateSignature(secret, signatureHeader string, body []byte) error {
	// Check header is valid
	signature_parts := strings.SplitN(signatureHeader, "=", 2)
	if len(signature_parts) != 2 {
		return fmt.Errorf("invalid signature header: '%s' does not contain =", signatureHeader)
	}

	// Ensure secret is a sha256 hash
	signature_type := signature_parts[0]
	signature_hash := signature_parts[1]
	if signature_type != "sha256" {
		return fmt.Errorf("signature should be a 'sha256' hash not '%s'", signature_type)
	}

	// Check that payload came from github
	// skip check if empty secret provided
	if !validatePayload(secret, signature_hash, body) {
		return fmt.Errorf("invalid payload, signature match failed")
	}

	return nil
}

func validatePayload(secret, headerHash string, payload []byte) bool {
	hash := hashPayload(secret, payload)
	return hmac.Equal(
		[]byte(hash),
		[]byte(headerHash),
	)
}

// see https://developer.github.com/webhooks/securing/#validating-payloads-from-github
func hashPayload(secret string, playloadBody []byte) string {
	hm := hmac.New(sha256.New, []byte(secret))
	hm.Write(playloadBody)
	sum := hm.Sum(nil)
	return fmt.Sprintf("%x", sum)
}

func parseBoolArg(arg string, defaultValue bool) (bool, error) {
	if arg != "" {
		ret, err := strconv.ParseBool(arg)
		if err != nil {
			return defaultValue, types.CreateRequestError(err.Error(), http.StatusBadRequest)
		}
		return ret, nil
	}
	return defaultValue, nil
}

func (h *Handler) getApps(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	internal, err := parseBoolArg(r.URL.Query().Get("internal"), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPathGlob, false)
	updateOperationInContext(r, "list_apps")

	filteredApps, err := h.server.GetApps(r.Context(), appPathGlob, internal)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return &types.AppListResponse{Apps: filteredApps}, nil
}

func (h *Handler) stopServer(r *http.Request) (any, error) {
	updateOperationInContext(r, "stop_server")
	return h.server.StopServer(r.Context())
}

// serverStatus reports "ok": reaching this handler means the connection and
// authentication both worked
func (h *Handler) serverStatus(_ *http.Request) (any, error) {
	return types.ServerStatusResponse{Status: "ok"}, nil
}

// serverVersion reports the server's build version and commit
func (h *Handler) serverVersion(r *http.Request) (any, error) {
	return h.server.ServerVersion(r.Context())
}

// metadataHealth reports operational connection and SQLite maintenance
// metrics. The database path and pool details are administrative metadata, so
// this requires full config read permission rather than the public status
// check or basic version permission.
func (h *Handler) metadataHealth(r *http.Request) (any, error) {
	if err := h.server.enforceGlobalPerm(r.Context(), types.PermissionConfigRead, ""); err != nil {
		return nil, err
	}
	return h.server.db.Health(r.Context()), nil
}

// restartServer performs a zero downtime in-place restart: a new server
// process takes over the listeners and this process drains. Blocks until the
// new process is ready or the restart has failed (in which case this process
// continues serving). Uses the server stop permission: restarting is a
// stop/start of the same server
func (h *Handler) restartServer(r *http.Request) (any, error) {
	updateOperationInContext(r, "restart_server")
	return h.server.RestartServer(r.Context())
}

func (h *Handler) createApp(r *http.Request) (any, error) {
	approve, err := parseBoolArg(r.URL.Query().Get("approve"), false)
	if err != nil {
		return nil, err
	}
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}

	var appRequest types.CreateAppRequest
	err = json.UnmarshalRead(r.Body, &appRequest)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	appPath := appRequest.Path
	updateTargetInContext(r, appPath, dryRun)
	updateOperationInContext(r, "create_app")

	results, err := h.server.CreateApp(r.Context(), appPath, approve, dryRun, &appRequest)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return results, nil
}

func (h *Handler) deleteApps(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}

	if appPathGlob == "" {
		return nil, types.CreateRequestError("appPathGlob is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, appPathGlob, dryRun)
	updateOperationInContext(r, "delete_apps")

	results, err := h.server.DeleteApps(r.Context(), appPathGlob, dryRun)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return results, nil
}

func (h *Handler) approveApps(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPathGlob, dryRun)
	promote, err := parseBoolArg(r.URL.Query().Get(PROMOTE_ARG), false)
	if err != nil {
		return nil, err
	}

	if appPathGlob == "" {
		return nil, types.CreateRequestError("appPathGlob is required", http.StatusBadRequest)
	}
	updateOperationInContext(r, genOperationName("approve_apps", promote, false))

	approveResult, err := h.server.ApproveApps(r.Context(), appPathGlob, dryRun, promote)
	return approveResult, err
}

func (h *Handler) accountLink(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPathGlob, dryRun)
	promote, err := parseBoolArg(r.URL.Query().Get(PROMOTE_ARG), false)
	if err != nil {
		return nil, err
	}

	if appPathGlob == "" {
		return nil, types.CreateRequestError("appPathGlob is required", http.StatusBadRequest)
	}
	updateOperationInContext(r, genOperationName("account_link", promote, false))

	args := map[string]any{
		"plugin":  r.URL.Query().Get("plugin"),
		"account": r.URL.Query().Get("account"),
	}

	linkResult, err := h.server.StagedUpdate(r.Context(), appPathGlob, dryRun, promote, h.server.accountLinkHandler, args, "account-link")
	return linkResult, err
}

func (h *Handler) updateParam(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPathGlob, dryRun)
	promote, err := parseBoolArg(r.URL.Query().Get(PROMOTE_ARG), false)
	if err != nil {
		return nil, err
	}
	updateOperationInContext(r, genOperationName("update_params", promote, false))

	if appPathGlob == "" {
		return nil, types.CreateRequestError("appPathGlob is required", http.StatusBadRequest)
	}

	updateResult, err := h.server.UpdateAppParams(r.Context(), appPathGlob, dryRun, promote,
		r.URL.Query().Get("paramName"), r.URL.Query().Get("paramValue"))
	return updateResult, err
}

func (h *Handler) reloadApps(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	approve, err := parseBoolArg(r.URL.Query().Get("approve"), false)
	if err != nil {
		return nil, err
	}

	forceReload, err := parseBoolArg(r.URL.Query().Get("forceReload"), false)
	if err != nil {
		return nil, err
	}
	verify, err := parseBoolArg(r.URL.Query().Get("verify"), false)
	if err != nil {
		return nil, err
	}

	if appPathGlob == "" {
		return nil, types.CreateRequestError("appPathGlob is required", http.StatusBadRequest)
	}
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPathGlob, dryRun)

	promote, err := parseBoolArg(r.URL.Query().Get("promote"), false)
	if err != nil {
		return nil, err
	}
	updateOperationInContext(r, genOperationName("reload_apps", promote, approve))

	ret, err := h.server.ReloadApps(r.Context(), appPathGlob, approve, dryRun, promote,
		r.URL.Query().Get("branch"), r.URL.Query().Get("commit"), r.URL.Query().Get("gitAuth"), forceReload, verify)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return ret, nil
}

func (h *Handler) promoteApps(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPathGlob, dryRun)

	if appPathGlob == "" {
		return nil, types.CreateRequestError("appPathGlob is required", http.StatusBadRequest)
	}
	updateOperationInContext(r, genOperationName("promote_apps", false, false))

	ret, err := h.server.PromoteApps(r.Context(), appPathGlob, dryRun)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return ret, nil
}

func (h *Handler) previewApp(r *http.Request) (any, error) {
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	appPath := r.URL.Query().Get("appPath")
	if appPath == "" {
		return nil, types.CreateRequestError("appPath is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, appPath, dryRun)
	commitId := r.URL.Query().Get("commitId")
	if commitId == "" {
		return nil, types.CreateRequestError("commitId is required", http.StatusBadRequest)
	}
	approve, err := parseBoolArg(r.URL.Query().Get("approve"), false)
	if err != nil {
		return nil, err
	}
	updateOperationInContext(r, genOperationName("preview_app", false, approve))

	ret, err := h.server.PreviewApp(r.Context(), appPath, commitId, approve, dryRun)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return ret, nil
}

func (h *Handler) getApp(r *http.Request) (any, error) {
	appPath := r.URL.Query().Get("appPath")
	if appPath == "" {
		return nil, types.CreateRequestError("appPath is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, appPath, false)
	updateOperationInContext(r, "get_app")

	ret, err := h.server.GetAppApi(r.Context(), appPath)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return ret, nil
}

func (h *Handler) updateAppSettings(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}

	if appPathGlob == "" {
		return nil, types.CreateRequestError("appPathGlob is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, appPathGlob, dryRun)
	updateOperationInContext(r, genOperationName("update_settings", false, false))

	var updateAppRequest types.UpdateAppRequest
	err = json.UnmarshalRead(r.Body, &updateAppRequest)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	ret, err := h.server.UpdateAppSettings(r.Context(), appPathGlob, dryRun, updateAppRequest)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return ret, nil
}

func (h *Handler) updateAppMetadata(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	promote, err := parseBoolArg(r.URL.Query().Get(PROMOTE_ARG), false)
	if err != nil {
		return nil, err
	}

	if appPathGlob == "" {
		return nil, types.CreateRequestError("appPathGlob is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, appPathGlob, dryRun)
	updateOperationInContext(r, genOperationName("update_metadata", promote, false))

	var updateAppRequest types.UpdateAppMetadataRequest
	err = json.UnmarshalRead(r.Body, &updateAppRequest)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	args := map[string]any{
		"metadata": updateAppRequest,
		"dryRun":   dryRun,
	}

	updateResult, err := h.server.StagedUpdate(r.Context(), appPathGlob, dryRun, promote, h.server.updateMetadataHandler, args, "update_metadata")
	return updateResult, err

}

func (h *Handler) versionList(r *http.Request) (any, error) {
	appPath := r.URL.Query().Get("appPath")
	if appPath == "" {
		return nil, types.CreateRequestError("appPath is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, appPath, false)
	updateOperationInContext(r, genOperationName("version_list", false, false))

	ret, err := h.server.VersionList(r.Context(), appPath)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return ret, nil
}

func (h *Handler) versionFiles(r *http.Request) (any, error) {
	appPath := r.URL.Query().Get("appPath")
	if appPath == "" {
		return nil, types.CreateRequestError("appPath is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, appPath, false)
	version := r.URL.Query().Get("version")
	updateOperationInContext(r, genOperationName("version_files", false, false))

	ret, err := h.server.VersionFiles(r.Context(), appPath, version)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return ret, nil
}

func (h *Handler) versionSwitch(r *http.Request) (any, error) {
	appPath := r.URL.Query().Get("appPath")
	if appPath == "" {
		return nil, types.CreateRequestError("appPath is required", http.StatusBadRequest)
	}
	version := r.URL.Query().Get("version")
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPath, dryRun)
	updateOperationInContext(r, genOperationName("version_switch", false, false))

	ret, err := h.server.VersionSwitch(r.Context(), appPath, dryRun, version)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return ret, nil
}

func (h *Handler) tokenList(r *http.Request) (any, error) {
	appPath := r.URL.Query().Get("appPath")
	if appPath == "" {
		return nil, types.CreateRequestError("appPath is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, appPath, false)
	updateOperationInContext(r, "token_list")

	ret, err := h.server.TokenList(r.Context(), appPath)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return ret, nil
}

func (h *Handler) tokenCreate(r *http.Request) (any, error) {
	appPath := r.URL.Query().Get("appPath")
	if appPath == "" {
		return nil, types.CreateRequestError("appPath is required", http.StatusBadRequest)
	}

	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPath, dryRun)
	updateOperationInContext(r, "token_create")

	tokenType := r.URL.Query().Get("webhookType")
	if appPath == "" {
		return nil, types.CreateRequestError("webhookType is required", http.StatusBadRequest)
	}

	ret, err := h.server.TokenCreate(r.Context(), appPath, types.WebhookType(tokenType), dryRun)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return ret, nil
}

func (h *Handler) tokenDelete(r *http.Request) (any, error) {
	appPath := r.URL.Query().Get("appPath")
	if appPath == "" {
		return nil, types.CreateRequestError("appPath is required", http.StatusBadRequest)
	}

	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPath, dryRun)
	updateOperationInContext(r, "token_delete")

	tokenType := r.URL.Query().Get("webhookType")
	if appPath == "" {
		return nil, types.CreateRequestError("webhookType is required", http.StatusBadRequest)
	}

	ret, err := h.server.TokenDelete(r.Context(), appPath, types.WebhookType(tokenType), dryRun)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return ret, nil
}

// apply is the handler for the apply API to apply app config
func (h *Handler) apply(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	if appPathGlob == "" {
		return nil, types.CreateRequestError("appPathGlob is required", http.StatusBadRequest)
	}
	applyPath := r.URL.Query().Get("applyPath")
	if applyPath == "" {
		return nil, types.CreateRequestError("applyPath is required", http.StatusBadRequest)
	}
	approve, err := parseBoolArg(r.URL.Query().Get("approve"), false)
	if err != nil {
		return nil, err
	}
	clobber, err := parseBoolArg(r.URL.Query().Get("clobber"), false)
	if err != nil {
		return nil, err
	}
	forceReload, err := parseBoolArg(r.URL.Query().Get("forceReload"), false)
	if err != nil {
		return nil, err
	}
	verify, err := parseBoolArg(r.URL.Query().Get("verify"), false)
	if err != nil {
		return nil, err
	}

	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPathGlob, dryRun)

	promote, err := parseBoolArg(r.URL.Query().Get("promote"), false)
	if err != nil {
		return nil, err
	}
	updateOperationInContext(r, genOperationName("apply", promote, approve))

	dev, err := parseBoolArg(r.URL.Query().Get("dev"), false)
	if err != nil {
		return nil, err
	}

	ret, _, err := h.server.Apply(r.Context(), types.Transaction{}, applyPath, appPathGlob, approve, dryRun, promote,
		types.AppReloadOption(r.URL.Query().Get("reload")),
		r.URL.Query().Get("branch"), r.URL.Query().Get("commit"), r.URL.Query().Get("gitAuth"),
		clobber, forceReload, verify, "", nil, dev)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusInternalServerError)
	}

	return ret, nil
}

// applyDelete is the handler for the declarative delete API which deletes the
// apps and bindings declared in an apply file that match the glob
func (h *Handler) applyDelete(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	if appPathGlob == "" {
		return nil, types.CreateRequestError("appPathGlob is required", http.StatusBadRequest)
	}
	applyPath := r.URL.Query().Get("applyPath")
	if applyPath == "" {
		return nil, types.CreateRequestError("applyPath is required", http.StatusBadRequest)
	}
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPathGlob, dryRun)
	updateOperationInContext(r, "apply_delete")

	ret, err := h.server.ApplyDelete(r.Context(), applyPath, appPathGlob, dryRun,
		r.URL.Query().Get("branch"), r.URL.Query().Get("commit"), r.URL.Query().Get("gitAuth"))
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusInternalServerError)
	}
	return ret, nil
}

// export is the handler for the export API which writes the current app and
// binding state as a declarative config file
func (h *Handler) export(r *http.Request) (any, error) {
	appPathGlob := cmp.Or(r.URL.Query().Get("appPathGlob"), "all")
	exactCommit, err := parseBoolArg(r.URL.Query().Get("exactCommit"), false)
	if err != nil {
		return nil, err
	}
	excludeDeclarative, err := parseBoolArg(r.URL.Query().Get("excludeDeclarative"), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, appPathGlob, false)
	updateOperationInContext(r, "export_apps")

	options := types.ExportOptions{
		ServiceRef:         r.URL.Query().Get("serviceRef"),
		GitAuthRef:         r.URL.Query().Get("gitAuthRef"),
		ExactCommit:        exactCommit,
		ExcludeDeclarative: excludeDeclarative,
	}
	config, err := h.server.Export(r.Context(), appPathGlob, options)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return &types.AppExportResponse{Config: config}, nil
}

// prettyPrint is the handler for the pretty-print API which reformats an
// existing declarative config file
func (h *Handler) prettyPrint(r *http.Request) (any, error) {
	if err := h.server.enforceGlobalPerm(r.Context(), types.PermissionConfigRead, ""); err != nil {
		return nil, err
	}

	applyPath := r.URL.Query().Get("applyPath")
	if applyPath == "" {
		return nil, types.CreateRequestError("applyPath is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, applyPath, false)
	updateOperationInContext(r, "pretty_print")

	config, err := h.server.PrettyPrint(r.Context(), applyPath)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return &types.AppExportResponse{Config: config}, nil
}

func (h *Handler) createSyncEntry(r *http.Request) (any, error) {
	path := r.URL.Query().Get("path")
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	scheduled, err := parseBoolArg(r.URL.Query().Get("scheduled"), false)
	if err != nil {
		return nil, err
	}

	var sync types.SyncMetadata
	err = json.UnmarshalRead(r.Body, &sync)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	updateTargetInContext(r, path, dryRun)
	updateOperationInContext(r, "sync_create")

	results, err := h.server.CreateSyncEntry(r.Context(), path, scheduled, dryRun, &sync)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return results, nil
}

func (h *Handler) runSyncEntry(r *http.Request) (any, error) {
	id := r.URL.Query().Get("id")
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}

	updateTargetInContext(r, id, dryRun)
	updateOperationInContext(r, "sync_run")

	results, err := h.server.RunSync(r.Context(), id, dryRun)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return results, nil
}

func (h *Handler) deleteSyncEntry(r *http.Request) (any, error) {
	id := r.URL.Query().Get("id")
	if id == "" {
		return nil, types.CreateRequestError("id is required", http.StatusBadRequest)
	}

	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}

	updateTargetInContext(r, id, dryRun)
	updateOperationInContext(r, "sync_delete")

	results, err := h.server.DeleteSyncEntry(r.Context(), id, dryRun)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return results, nil
}

func (h *Handler) listSyncEntries(r *http.Request) (any, error) {
	updateOperationInContext(r, "list_sync")
	results, err := h.server.ListSyncEntries(r.Context())
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return results, nil
}

func (h *Handler) createService(r *http.Request) (any, error) {
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}

	var service types.Service
	if err = json.UnmarshalRead(r.Body, &service); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if service.Name == "" || service.ServiceType == "" {
		return nil, types.CreateRequestError("name and service_type are required", http.StatusBadRequest)
	}

	updateTargetInContext(r, service.ServiceType+"/"+service.Name, dryRun)
	updateOperationInContext(r, "service_create")

	if err := h.server.CreateService(r.Context(), &service, dryRun); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return service, nil
}

func (h *Handler) updateService(r *http.Request) (any, error) {
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}

	var service types.Service
	if err = json.UnmarshalRead(r.Body, &service); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if service.Name == "" || service.ServiceType == "" {
		return nil, types.CreateRequestError("name and service_type are required", http.StatusBadRequest)
	}

	updateTargetInContext(r, service.ServiceType+"/"+service.Name, dryRun)
	updateOperationInContext(r, "service_update")

	if err := h.server.UpdateService(r.Context(), &service, dryRun); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return service, nil
}

func (h *Handler) deleteService(r *http.Request) (any, error) {
	name := r.URL.Query().Get("name")
	serviceType := r.URL.Query().Get("service_type")
	if name == "" || serviceType == "" {
		return nil, types.CreateRequestError("name and service_type are required", http.StatusBadRequest)
	}

	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}

	updateTargetInContext(r, serviceType+"/"+name, dryRun)
	updateOperationInContext(r, "service_delete")

	if err := h.server.DeleteService(r.Context(), name, serviceType, dryRun); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return map[string]any{"name": name, "service_type": serviceType, "dry_run": dryRun}, nil
}

func (h *Handler) serviceHealth(r *http.Request) (any, error) {
	name := r.URL.Query().Get("name")
	serviceType := r.URL.Query().Get("service_type")
	if name == "" || serviceType == "" {
		return nil, types.CreateRequestError("name and service_type are required", http.StatusBadRequest)
	}

	updateTargetInContext(r, serviceType+"/"+name, false)
	updateOperationInContext(r, "service_health")

	if err := h.server.ServiceHealth(r.Context(), serviceType, name); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return map[string]any{"name": name, "service_type": serviceType, "status": "healthy"}, nil
}

func (h *Handler) bindingHealth(r *http.Request) (any, error) {
	bindingName := r.URL.Query().Get("name")
	if bindingName == "" {
		return nil, types.CreateRequestError("name is required", http.StatusBadRequest)
	}
	useStaging, err := parseBoolArg(r.URL.Query().Get("staging"), false)
	if err != nil {
		return nil, err
	}

	updateTargetInContext(r, bindingName, false)
	updateOperationInContext(r, "binding_health")

	if err := h.server.BindingHealth(r.Context(), bindingName, useStaging); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return map[string]any{"name": bindingName, "staging": useStaging, "status": "healthy"}, nil
}

func (h *Handler) listServices(r *http.Request) (any, error) {
	updateOperationInContext(r, "list_services")
	serviceType := r.URL.Query().Get("service_type")
	name := r.URL.Query().Get("name")

	results, err := h.server.ListServices(r.Context(), serviceType, name)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return results, nil
}

func (h *Handler) installProvider(r *http.Request) (any, error) {
	var request types.ProviderInstallRequest
	if err := json.UnmarshalRead(r.Body, &request); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if request.Name == "" {
		return nil, types.CreateRequestError("name is required", http.StatusBadRequest)
	}
	if request.SourceURL == "" && request.Version == "" {
		return nil, types.CreateRequestError("either source_url or version is required", http.StatusBadRequest)
	}

	updateTargetInContext(r, request.Name, false)
	updateOperationInContext(r, "provider_install")

	provider, err := h.server.InstallProvider(r.Context(), &request)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return provider, nil
}

func (h *Handler) uninstallProvider(r *http.Request) (any, error) {
	name := r.URL.Query().Get("name")
	if name == "" {
		return nil, types.CreateRequestError("name is required", http.StatusBadRequest)
	}
	force, err := parseBoolArg(r.URL.Query().Get("force"), false)
	if err != nil {
		return nil, err
	}

	updateTargetInContext(r, name, false)
	updateOperationInContext(r, "provider_uninstall")

	if err := h.server.UninstallProvider(r.Context(), name, force); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return map[string]any{"name": name}, nil
}

func (h *Handler) listProviders(r *http.Request) (any, error) {
	updateOperationInContext(r, "list_providers")
	results, err := h.server.ListProviders(r.Context())
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return results, nil
}

func (h *Handler) createBinding(r *http.Request) (any, error) {
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}

	var createRequest types.CreateBindingRequest
	if err = json.UnmarshalRead(r.Body, &createRequest); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if createRequest.Path == "" {
		return nil, types.CreateRequestError("path is required", http.StatusBadRequest)
	}

	updateTargetInContext(r, createRequest.Path, dryRun)
	updateOperationInContext(r, "binding_create")

	binding, err := h.server.CreateBinding(r.Context(), &createRequest, dryRun)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return redactBindingAccount(binding), nil
}

func (h *Handler) updateBinding(r *http.Request) (any, error) {
	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	promote, err := parseBoolArg(r.URL.Query().Get(PROMOTE_ARG), false)
	if err != nil {
		return nil, err
	}
	reapplyAll, err := parseBoolArg(r.URL.Query().Get(REAPPLY_ALL_ARG), false)
	if err != nil {
		return nil, err
	}

	var updateRequest types.UpdateBindingRequest
	if err = json.UnmarshalRead(r.Body, &updateRequest, json.RejectUnknownMembers(true)); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if updateRequest.Path == "" {
		return nil, types.CreateRequestError("path is required", http.StatusBadRequest)
	}

	updateTargetInContext(r, updateRequest.Path, dryRun)
	updateOperationInContext(r, "binding_update")

	binding, err := h.server.UpdateBinding(r.Context(), updateRequest, dryRun, promote, reapplyAll)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return redactBindingAccount(binding), nil
}

func (h *Handler) deleteBinding(r *http.Request) (any, error) {
	path := r.URL.Query().Get("path")
	if path == "" {
		return nil, types.CreateRequestError("path is required", http.StatusBadRequest)
	}

	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}

	updateTargetInContext(r, path, dryRun)
	updateOperationInContext(r, "binding_delete")

	if err := h.server.DeleteBinding(r.Context(), path, dryRun); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return map[string]any{"path": path, "dry_run": dryRun}, nil
}

func (h *Handler) getBinding(r *http.Request) (any, error) {
	path := r.URL.Query().Get("path")
	if path == "" {
		return nil, types.CreateRequestError("path is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, path, false)
	updateOperationInContext(r, "binding_get")

	binding, err := h.server.GetBinding(r.Context(), path)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return binding, nil
}

func (h *Handler) getBindingAccount(r *http.Request) (any, error) {
	path := r.URL.Query().Get("path")
	if path == "" {
		return nil, types.CreateRequestError("path is required", http.StatusBadRequest)
	}
	useStaging, err := parseBoolArg(r.URL.Query().Get("staging"), false)
	if err != nil {
		return nil, err
	}

	updateTargetInContext(r, path, false)
	updateOperationInContext(r, "binding_show_account")

	account, err := h.server.GetBindingAccount(r.Context(), path, useStaging)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return account, nil
}

func (h *Handler) listBindings(r *http.Request) (any, error) {
	updateOperationInContext(r, "list_bindings")
	source := r.URL.Query().Get("source")

	results, err := h.server.ListBindings(r.Context(), source)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return results, nil
}

func (h *Handler) replicationStatus(r *http.Request) (any, error) {
	updateOperationInContext(r, "replication_status")
	refresh := r.URL.Query().Get("refresh") == "true"
	entries, err := h.server.ReplicationStatus(r.Context(), refresh)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return entries, nil
}

func (h *Handler) runBindingCommand(r *http.Request) (any, error) {
	var runRequest types.RunBindingCommandRequest
	if err := json.UnmarshalRead(r.Body, &runRequest); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if runRequest.BindingName == "" {
		return nil, types.CreateRequestError("binding_name is required", http.StatusBadRequest)
	}
	if strings.TrimSpace(runRequest.Command) == "" {
		return nil, types.CreateRequestError("command is required", http.StatusBadRequest)
	}

	updateTargetInContext(r, runRequest.BindingName, false)
	updateOperationInContext(r, "binding_run_command")

	result, err := h.server.RunBindingCommand(r.Context(), runRequest.BindingName, runRequest.UseStaging, runRequest.Command)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return result, nil
}

func (h *Handler) createSecret(r *http.Request) (any, error) {
	update, err := parseBoolArg(r.URL.Query().Get("update"), false)
	if err != nil {
		return nil, err
	}

	var createRequest types.CreateSecretRequest
	if err = json.UnmarshalRead(r.Body, &createRequest, json.RejectUnknownMembers(true)); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	updateTargetInContext(r, cmp.Or(createRequest.Name, createRequest.Prefix), false)
	updateOperationInContext(r, "secret_create")

	response, err := h.server.CreateSecret(r.Context(), &createRequest, update)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	// Record the generated name as the audit target so the create event
	// correlates with later reveal/delete events for the same secret
	updateTargetInContext(r, response.Name, false)
	return response, nil
}

func (h *Handler) deleteSecret(r *http.Request) (any, error) {
	name := r.URL.Query().Get("name")
	if name == "" {
		return nil, types.CreateRequestError("name is required", http.StatusBadRequest)
	}

	updateTargetInContext(r, name, false)
	updateOperationInContext(r, "secret_delete")

	if err := h.server.DeleteSecret(r.Context(), r.URL.Query().Get("provider"), name); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return types.SecretDeleteResponse{Name: name}, nil
}

func (h *Handler) listSecrets(r *http.Request) (any, error) {
	updateOperationInContext(r, "list_secrets")

	results, err := h.server.ListSecrets(r.Context(), r.URL.Query().Get("provider"), r.URL.Query().Get("glob"))
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return types.SecretListResponse{Secrets: results}, nil
}

func (h *Handler) getSecret(r *http.Request) (any, error) {
	name := r.URL.Query().Get("name")
	if name == "" {
		return nil, types.CreateRequestError("name is required", http.StatusBadRequest)
	}
	reveal, err := parseBoolArg(r.URL.Query().Get("reveal"), false)
	if err != nil {
		return nil, err
	}

	updateTargetInContext(r, name, false)
	if reveal {
		updateOperationInContext(r, "secret_reveal")
	} else {
		updateOperationInContext(r, "secret_get")
	}

	response, err := h.server.GetSecret(r.Context(), r.URL.Query().Get("provider"), name, reveal)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return response, nil
}

func (h *Handler) rekeySecrets(r *http.Request) (any, error) {
	updateOperationInContext(r, "secret_rekey")

	response, err := h.server.RekeySecrets(r.Context(), r.URL.Query().Get("provider"))
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return response, nil
}

func (h *Handler) userUpdate(r *http.Request) (any, error) {
	username := r.URL.Query().Get("username")
	update, err := parseBoolArg(r.URL.Query().Get("update"), false)
	if err != nil {
		return nil, err
	}

	updateTargetInContext(r, username, false)
	if update {
		updateOperationInContext(r, "user_update")
	} else {
		updateOperationInContext(r, "user_add")
	}

	var updateRequest types.UserUpdateRequest
	if err := json.UnmarshalRead(r.Body, &updateRequest); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	updated, err := h.server.CreateUpdateUser(r.Context(), username, updateRequest.Password, updateRequest.Groups, update)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return types.UserUpdateResponse{Username: username, Updated: updated}, nil
}

func (h *Handler) userDelete(r *http.Request) (any, error) {
	username := r.URL.Query().Get("username")
	updateTargetInContext(r, username, false)
	updateOperationInContext(r, "user_delete")

	if err := h.server.DeleteUser(r.Context(), username); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return types.UserDeleteResponse{Username: username}, nil
}

func (h *Handler) userList(r *http.Request) (any, error) {
	updateOperationInContext(r, "user_list")

	users, err := h.server.ListUsers(r.Context())
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return types.UserListResponse{Users: users}, nil
}

func (h *Handler) configGet(r *http.Request) (any, error) {
	updateOperationInContext(r, "config_get")
	return h.server.GetConfigResponse(r.Context())
}

func (h *Handler) configUpdate(r *http.Request) (any, error) {
	updateOperationInContext(r, "config_update")
	var dynamicConfig types.DynamicConfig
	force, err := parseBoolArg(r.URL.Query().Get("force"), false)
	if err != nil {
		return nil, err
	}
	err = json.UnmarshalRead(r.Body, &dynamicConfig)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	newConfig, err := h.server.UpdateDynamicConfig(r.Context(), &dynamicConfig, force)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return types.ConfigResponse{DynamicConfig: *newConfig}, nil
}

// serveInternal builds the management API router from the operation
// registry: every routed operation contributes exactly one method+path
// handled through the shared apiHandler wrapper, so the registry is the
// single source of truth for the REST surface (auth, invoker policy, audit
// and MCP tools all key on the same entries). chi panics on a duplicate
// method+path at startup, which doubles as a registry sanity check.
// Registry entries with an empty Path are logical operations resolved
// inside a handler (secret_reveal, create_apikey_other, ...) and get no
// route of their own
func (h *Handler) serveInternal(remote bool) http.Handler {
	r := chi.NewRouter()
	for name, op := range apiRegistry {
		if op.Path == "" {
			continue
		}
		operation, entry := name, op
		r.MethodFunc(entry.Method, entry.Path, func(w http.ResponseWriter, req *http.Request) {
			if entry.MaxBodyBytes > 0 {
				req.Body = http.MaxBytesReader(w, req.Body, entry.MaxBodyBytes)
			}
			h.apiHandler(w, req, remote, string(operation), func(req *http.Request) (any, error) {
				return entry.ApiFunc(h, req)
			}, entry.RunVersionCleanup)
		})
	}
	return r
}

// serveRemoteInternal wraps the internal APIs for the TCP listeners: a
// transport gate (HTTPS or trusted TLS-terminating proxy; anything else gets
// a plain 404 - never a redirect and never auth metadata, a plaintext bearer
// token is already leaked by the time a response is written), then dispatch
// to the MCP endpoint or the REST management APIs per the enabled surfaces
func (h *Handler) serveRemoteInternal(config *types.ServerConfig) http.Handler {
	restHandler := http.NotFoundHandler()
	if apiSurfaceEnabled(config, string(types.ApiSurfaceRest)) {
		restHandler = h.serveInternal(true)
	}
	mcpHandler := http.NotFoundHandler()
	if apiSurfaceEnabled(config, string(types.ApiSurfaceMCP)) {
		mcpHandler = h.server.mcpHTTPHandler()
	}
	oauthHandler := h.serveOAuth()
	mcpPath := types.INTERNAL_URL_PREFIX + "/mcp"
	oauthPrefix := types.INTERNAL_URL_PREFIX + "/oauth/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if system.GetRequestScheme(r, config.Security.TrustedProxies) != "https" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == mcpPath {
			mcpHandler.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, oauthPrefix) {
			// The OAuth AS endpoints are pre-authentication: they mint the
			// credentials the other paths require
			oauthHandler.ServeHTTP(w, r)
			return
		}
		restHandler.ServeHTTP(w, r)
	})
}

// serveDelegatedBuild returns a handler for the delegated build API
func (h *Handler) serveDelegatedBuild() http.Handler {
	// These API's are mounted at /_openrun
	r := chi.NewRouter()

	// API to delegate build
	r.Post("/delegate_build", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MAX_DELEGATE_UPLOAD_SIZE)
		h.apiHandler(w, r, true, DELEGATE_BUILD_OP, func(r *http.Request) (any, error) {
			return container.DelegateHandler(r, h.server.Config(), h.Logger)
		}, false)
	}))

	return r
}

// serveWebhooks returns a handler for the app webhooks for reload and other events.
// webhooks are always mounted, even if admin over TCP is not enabled. At the app
// level, webhooks are disabled by default and need to be enabled by the user
func (h *Handler) serveWebhooks() http.Handler {
	// These API's are mounted at /_openrun_webhook
	r := chi.NewRouter()

	// Reload app
	r.Post("/reload", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.webhookHandler(w, r, types.WebhookReload)
	}))

	// Reload and Promote app
	r.Post("/reload_promote", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.webhookHandler(w, r, types.WebhookReloadPromote)
	}))

	// Promote app
	r.Post("/promote", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.webhookHandler(w, r, types.WebhookPromote)
	}))

	return r
}

func genOperationName(op string, promote, approve bool) string {
	if promote && approve {
		return fmt.Sprintf("%s_%s_%s", op, "promote", "approve")
	} else if promote {
		return fmt.Sprintf("%s_%s", op, "promote")
	} else if approve {
		return fmt.Sprintf("%s_%s", op, "approve")
	}
	return op
}
