// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

const (
	DRY_RUN_ARG = "dryRun"
	PROMOTE_ARG = "promote"
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
	config *types.ServerConfig
	server *Server
	router *chi.Mux
}

func panicRecovery(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil && rvr != http.ErrAbortHandler {
				msg := fmt.Sprint(rvr)
				fmt.Fprintf(os.Stderr, "Panic %s: %s\n", msg, string(debug.Stack()))
				// TODO log
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

	router.Use(server.handleStatus)
	router.Use(panicRecovery)

	handler := &Handler{
		Logger: logger,
		config: config,
		server: server,
		router: router,
	}

	router.Use(middleware.Logger)
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
		config: config,
		server: server,
		router: router,
	}
	if config.Http.RedirectToHttps {
		router.Use(handler.httpsRedirectMiddleware)
	}
	router.Use(server.handleStatus)
	router.Use(panicRecovery)
	router.Use(middleware.Logger)
	router.Use(middleware.CleanPath)
	if config.System.EnableCompression {
		router.Use(middleware.Compress(5, COMPRESSION_ENABLED_MIME_TYPES...))
	}

	if config.Security.AdminOverTCP {
		// Mount the internal API's only if admin over TCP is enabled
		logger.Warn().Msg("Admin API access over TCP is enabled, enable 2FA for admin user account")
		router.Mount(types.INTERNAL_URL_PREFIX, handler.serveInternal(true))
	} else {
		router.Mount(types.INTERNAL_URL_PREFIX, http.NotFoundHandler()) // reserve the path
	}

	// Webhooks are always mounted, they are disabled at the app level by default
	router.Mount(types.WEBHOOK_URL_PREFIX, handler.serveWebhooks())

	server.oAuthManager.RegisterRoutes(router) // register OAuth routes
	server.samlManager.RegisterRoutes(router)  // register SAML routes

	router.HandleFunc("/*", handler.callApp)
	router.HandleFunc("/testperf", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`)) //nolint:errcheck
	})
	return handler
}

// httpsRedirectMiddleware checks if the request was made using HTTP (no TLS)
// and redirects it to the HTTPS version of the URL if so.
func (h *Handler) httpsRedirectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			u := *r.URL
			u.Scheme = "https"
			u.Host = r.Host

			host, _, err := net.SplitHostPort(r.Host)
			if err == nil {
				// update https port
				u.Host = fmt.Sprintf("%s:%d", host, h.server.config.Https.Port)
			}

			// Redirect to the HTTPS version of the URL
			http.Redirect(w, r, u.String(), http.StatusPermanentRedirect) // 308 (301 does not keep method)
			return
		}

		// If it's already HTTPS, just proceed
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) callApp(w http.ResponseWriter, r *http.Request) {
	if h.Debug().Enabled() {
		h.Debug().Str("method", r.Method).Str("url", r.URL.String()).Msg("App Received request")
	}

	requestDomain, _, _ := strings.Cut(r.Host, ":")
	var serveListApps = false
	matchedApp, matchErr := h.server.MatchApp(requestDomain, r.URL.Path)
	if matchErr != nil {
		systemConfig := h.server.config.System
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
		serveApp, err = h.server.GetApp(matchedApp.AppPathDomain, true)
		if err != nil {
			h.Error().Err(err).Str("path", r.URL.Path).Msg("Error getting app")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		serveApp, err = h.server.GetListAppsApp()
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

func (h *Handler) apiHandler(w http.ResponseWriter, r *http.Request, enableBasicAuth bool, operation string, apiFunc func(r *http.Request) (any, error)) {
	if enableBasicAuth {
		authStatus := h.server.authHandler.authenticate(r.Header.Get("Authorization"))
		if !authStatus {
			w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, REALM))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	event := types.AuditEvent{
		RequestId:  system.GetContextRequestId(r.Context()),
		CreateTime: time.Now(),
		UserId:     system.GetContextUserId(r.Context()),
		AppId:      system.GetContextAppId(r.Context()),
		EventType:  types.EventTypeSystem,
		Operation:  operation,
		Status:     string(types.EventStatusSuccess),
	}

	defer func() {
		if err := h.server.InsertAuditEvent(&event); err != nil {
			h.Error().Err(err).Msg("error inserting audit event")
		}
	}()

	resp, err := apiFunc(r)

	contextShared := r.Context().Value(types.SHARED)
	if contextShared != nil {
		cs := contextShared.(*ContextShared)
		event.Target = cs.Target
		event.Operation = cs.Operation
		if cs.DryRun {
			event.Operation = fmt.Sprintf("%s_dryrun", event.Operation)
		}
	}

	h.Trace().Str("method", r.Method).Str("url", r.URL.String()).Err(err).Msg("API Received request")
	if err != nil {
		event.Status = string(types.EventStatusFailure)
		if reqError, ok := err.(types.RequestError); ok {
			w.Header().Add("Content-Type", "application/json")
			errStr, _ := json.Marshal(reqError)
			http.Error(w, string(errStr), reqError.Code)
			return
		}
		h.Error().Err(err).Msg("error in api func call")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if resp == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(resp)
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

	app, err := h.server.GetApp(appPathDomain, false)
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

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("error reading request body: %s", err), http.StatusUnauthorized)
		return
	}

	// Authenticate the request
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Using Authentication header, bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Authorization header with bearer token is required", http.StatusUnauthorized)
			return
		}
		authHeader = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if authHeader == "" {
			http.Error(w, "Bearer token is required", http.StatusUnauthorized)
			return
		}

		if subtle.ConstantTimeCompare([]byte(appToken), []byte(authHeader)) != 1 {
			http.Error(w, "Invalid bearer token", http.StatusUnauthorized)
			return
		}
	} else {
		// Using signature auth
		// https://docs.github.com/en/webhooks/webhook-events-and-payloads#delivery-headers
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			http.Error(w, "No auth header and no signature found", http.StatusUnauthorized)
			return
		}

		err = validateSignature(appToken, signature, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
	}

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
		resp, err = h.server.ReloadApps(r.Context(), appPath, false, false, promote, "", "", "", true)
	} else {
		// promote operation
		resp, err = h.server.PromoteApps(r.Context(), appPath, false)
	}

	h.Info().Msgf("Webhook call for %s, appPath: %s, promote: %t, reload: %t, response %+v err %s",
		webhookType, appPath, promote, reload, resp, err)

	event := types.AuditEvent{
		RequestId:  system.GetContextRequestId(r.Context()),
		CreateTime: time.Now(),
		UserId:     system.GetContextUserId(r.Context()),
		AppId:      system.GetContextAppId(r.Context()),
		EventType:  types.EventTypeSystem,
		Operation:  fmt.Sprintf("webhook_%s", webhookType),
		Target:     appPathDomain.String(),
		Status:     "Success",
	}

	defer func() {
		if err := h.server.InsertAuditEvent(&event); err != nil {
			h.Error().Err(err).Msg("error inserting audit event")
		}
	}()

	if err != nil {
		event.Status = string(types.EventStatusFailure)
		if reqError, ok := err.(types.RequestError); ok {
			w.Header().Add("Content-Type", "application/json")
			errStr, _ := json.Marshal(reqError)
			http.Error(w, string(errStr), reqError.Code)
			return
		}
		h.Error().Err(err).Msg("error in api func call")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(resp)
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

	// Ensure secret is a sha1 hash
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

	filteredApps, err := h.server.GetApps(r.Context(), appPathGlob, internal)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return &types.AppListResponse{Apps: filteredApps}, nil
}

func (h *Handler) stopServer(r *http.Request) (any, error) {
	h.Warn().Msgf("Server stop called")
	err := h.server.Stop(r.Context())
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return map[string]any{}, nil
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
	err = json.NewDecoder(r.Body).Decode(&appRequest)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	appPath := appRequest.Path
	updateTargetInContext(r, appPath, dryRun)

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

	approveResult, err := h.server.StagedUpdate(r.Context(), appPathGlob, dryRun, promote, h.server.auditHandler, map[string]any{}, "approve")
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

	args := map[string]any{
		"paramName":  r.URL.Query().Get("paramName"),
		"paramValue": r.URL.Query().Get("paramValue"),
	}

	updateResult, err := h.server.StagedUpdate(r.Context(), appPathGlob, dryRun, promote, h.server.updateParamHandler, args, "update-param")
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
		r.URL.Query().Get("branch"), r.URL.Query().Get("commit"), r.URL.Query().Get("gitAuth"), forceReload)
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
	err = json.NewDecoder(r.Body).Decode(&updateAppRequest)
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
	err = json.NewDecoder(r.Body).Decode(&updateAppRequest)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	args := map[string]any{
		"metadata": updateAppRequest,
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

	dryRun, err := parseBoolArg(r.URL.Query().Get(DRY_RUN_ARG), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, "", dryRun)

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
		clobber, forceReload, "", nil, dev)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusInternalServerError)
	}

	return ret, nil
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
	err = json.NewDecoder(r.Body).Decode(&sync)
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
	results, err := h.server.ListSyncEntries(r.Context())
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return results, nil
}

func (h *Handler) configGet(r *http.Request) (any, error) {
	return types.ConfigResponse{DynamicConfig: h.server.GetDynamicConfig()}, nil
}

func (h *Handler) configUpdate(r *http.Request) (any, error) {
	var dynamicConfig types.DynamicConfig
	force, err := parseBoolArg(r.URL.Query().Get("force"), false)
	if err != nil {
		return nil, err
	}
	err = json.NewDecoder(r.Body).Decode(&dynamicConfig)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	newConfig, err := h.server.UpdateDynamicConfig(r.Context(), &dynamicConfig, force)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return types.ConfigResponse{DynamicConfig: *newConfig}, nil
}

// serveInternal returns a handler for the internal APIs for app admin and management
func (h *Handler) serveInternal(enableBasicAuth bool) http.Handler {
	// These API's are mounted at /_openrun
	r := chi.NewRouter()

	// Get apps
	r.Post("/stop", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "stop_server", h.stopServer)
	}))

	// Get apps
	r.Get("/apps", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "list_apps", h.getApps)
	}))

	// Get app
	r.Get("/app", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "get_app", h.getApp)
	}))

	// Create app
	r.Post("/app", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "create_app", h.createApp)
	}))

	// Delete app
	r.Delete("/app", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "delete_apps", h.deleteApps)
	}))

	// API to approve the plugin usage and permissions for the app
	r.Post("/approve", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "approve_apps", h.approveApps)
	}))

	// API to reload apps
	r.Post("/reload", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "reload_apps", h.reloadApps)
	}))

	// API to promote apps
	r.Post("/promote", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "promote_apps", h.promoteApps)
	}))

	// API to create a preview version of an app
	r.Post("/preview", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "create_preview", h.previewApp)
	}))

	// API to update app settings
	r.Post("/app_settings", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "update_settings", h.updateAppSettings)
	}))

	// API to update app metadata
	r.Post("/app_metadata", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "update_metadata", h.updateAppMetadata)
	}))

	// API to change account links
	r.Post("/link_account", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "update_links", h.accountLink)
	}))

	// API to update param values
	r.Post("/update_param", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "update_params", h.updateParam)
	}))

	// API to list versions for an app
	r.Get("/version", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "list_versions", h.versionList)
	}))

	// API to list files in a version
	r.Get("/version/files", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "list_files", h.versionFiles)
	}))

	// API to switch version for an app
	r.Post("/version", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "version_switch", h.versionSwitch)
	}))

	// Token list
	r.Get("/app_webhook_token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "list_webhooks", h.tokenList)
	}))

	// Token create
	r.Post("/app_webhook_token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "token_create", h.tokenCreate)
	}))

	// Token delete
	r.Delete("/app_webhook_token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "token_delete", h.tokenDelete)
	}))

	// API to apply app config
	r.Post("/apply", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "apply", h.apply)
	}))

	// API to create sync entry
	r.Post("/sync", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "sync_create", h.createSyncEntry)
	}))

	// API to run sync
	r.Post("/sync/run", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "sync_run", h.runSyncEntry)
	}))

	// API to delete sync entry
	r.Delete("/sync", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "sync_delete", h.deleteSyncEntry)
	}))

	// API to get sync entries
	r.Get("/sync", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "list_sync", h.listSyncEntries)
	}))

	// API to get config
	r.Get("/config", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "config_get", h.configGet)
	}))

	// API to update config
	r.Post("/config", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.apiHandler(w, r, enableBasicAuth, "config_update", h.configUpdate)
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
