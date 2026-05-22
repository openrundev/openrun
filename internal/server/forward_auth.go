// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

var hopByHopForwardAuthHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
	"Content-Length":      {},
}

// forwardAuthMiddleware checks each request with the configured forward auth endpoint before it reaches the app handler.
func (s *Server) forwardAuthMiddleware(next http.Handler, forwardConfig *types.ForwardConfig) http.Handler {
	if forwardConfig == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if forwardConfig.AuthUrl == "" {
			s.Error().Str("method", r.Method).Str("path", r.URL.Path).Msg("forward auth auth_url is not configured")
			http.Error(w, "forward auth auth_url is not configured", http.StatusInternalServerError)
			return
		}

		s.Trace().Str("method", r.Method).Str("path", r.URL.Path).Str("auth_url", forwardConfig.AuthUrl).Msg("Starting forward auth check")

		authReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, forwardConfig.AuthUrl, nil)
		if err != nil {
			s.Error().Err(err).Str("method", r.Method).Str("path", r.URL.Path).Str("auth_url", forwardConfig.AuthUrl).Msg("Error creating forward auth request")
			http.Error(w, fmt.Sprintf("error creating forward auth request: %s", err), http.StatusInternalServerError)
			return
		}

		copyForwardAuthRequestHeaders(authReq, r, forwardConfig.ForwardHeaders)
		setForwardAuthHeaders(authReq.Header, r, s.config)
		setForwardAuthOpenRunHeaders(authReq.Header, r)

		authResp, err := s.forwardAuthHTTPClient.Do(authReq)
		if err != nil {
			s.Warn().Err(err).Str("method", r.Method).Str("path", r.URL.Path).Str("auth_url", authReq.URL.Redacted()).Msg("Forward auth request failed")
			http.Error(w, fmt.Sprintf("forward auth request failed: %s", err), http.StatusBadGateway)
			return
		}
		defer authResp.Body.Close() //nolint:errcheck

		if authResp.StatusCode >= http.StatusOK && authResp.StatusCode < http.StatusMultipleChoices {
			s.Trace().Int("status", authResp.StatusCode).Str("method", r.Method).Str("path", r.URL.Path).Str("auth_url", authReq.URL.Redacted()).Msg("Forward auth allowed request")
			copyForwardAuthResponseHeaders(r.Header, authResp.Header, forwardConfig.CopyResponseHeaders)
			next.ServeHTTP(w, r)
			return
		}

		s.Warn().Int("status", authResp.StatusCode).Str("method", r.Method).Str("path", r.URL.Path).Str("auth_url", authReq.URL.Redacted()).Msg("Forward auth denied request")
		copyHeaders(w.Header(), authResp.Header)
		w.WriteHeader(authResp.StatusCode)
		_, _ = io.Copy(w, authResp.Body)
	})
}

// newForwardAuthHTTPClient creates a forward auth client that returns redirects to the caller.
func newForwardAuthHTTPClient(config *types.ServerConfig) *http.Client {
	secs := config.System.ForwardAuthTimeoutSecs
	if secs <= 0 {
		secs = 30
	}
	return &http.Client{
		Timeout: time.Duration(secs) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// copyForwardAuthRequestHeaders copies configured original request headers to the auth request.
func copyForwardAuthRequestHeaders(authReq *http.Request, originalReq *http.Request, forwardHeaders []string) {
	if len(forwardHeaders) == 0 {
		// copy all headers
		copyHeaders(authReq.Header, originalReq.Header)
		return
	}

	for _, headerName := range forwardHeaders {
		headerName = http.CanonicalHeaderKey(strings.TrimSpace(headerName))
		if headerName == "" {
			continue
		}
		if headerName == "Host" {
			authReq.Host = originalReq.Host
			continue
		}
		if shouldSkipForwardAuthHeader(headerName) {
			continue
		}
		if values, ok := originalReq.Header[headerName]; ok {
			authReq.Header[headerName] = append([]string(nil), values...)
		}
	}
}

// setForwardAuthHeaders sets the standard forward-auth request context headers for the auth endpoint.
func setForwardAuthHeaders(header http.Header, r *http.Request, config *types.ServerConfig) {
	clientIP := system.GetClientIP(r, config.Security.TrustedProxies)
	requestScheme := system.GetRequestScheme(r, config.Security.TrustedProxies)
	requestHost := r.Host
	if requestHost == "" {
		requestHost = r.URL.Host
	}

	header.Del("Forwarded")
	header.Del("X-Forwarded-For")
	header.Del("X-Forwarded-Host")
	header.Del("X-Forwarded-Method")
	header.Del("X-Forwarded-Proto")
	header.Del("X-Forwarded-Uri")
	header.Del("X-Real-IP")
	header.Set("X-Forwarded-Method", r.Method)
	header.Set("X-Forwarded-Proto", requestScheme)
	header.Set("X-Forwarded-Host", requestHost)
	header.Set("X-Forwarded-Uri", r.URL.RequestURI())
	if clientIP != "" {
		header.Set("X-Forwarded-For", clientIP)
		header.Set("X-Real-IP", clientIP)
	}
}

// setForwardAuthOpenRunHeaders adds OpenRun's authenticated identity and authorization context to the auth request.
func setForwardAuthOpenRunHeaders(header http.Header, r *http.Request) {
	deleteForwardAuthOpenRunHeaders(header)

	user := system.GetContextUserId(r.Context())
	userStripped := user
	if strings.Contains(user, ":") {
		userStripped = strings.SplitN(user, ":", 2)[1]
	}
	header.Set(types.OPENRUN_HEADER_USER, user)
	header.Set(types.OPENRUN_HEADER_USER_STRIPPED, userStripped)
	if userSubject := system.GetContextUserSubject(r.Context()); userSubject != "" {
		header.Set(types.OPENRUN_HEADER_USER_ID, userSubject)
	}
	if userEmail := system.GetContextUserEmail(r.Context()); userEmail != "" {
		header.Set(types.OPENRUN_HEADER_USER_EMAIL, userEmail)
	}
	customPerms := system.GetCustomPerms(r.Context())
	header.Set(types.OPENRUN_HEADER_PERMS, strings.Join(customPerms, ","))
	header.Set(types.OPENRUN_HEADER_APP_RBAC_ENABLED, strconv.FormatBool(system.IsAppRBACEnabled(r.Context())))
}

// deleteForwardAuthOpenRunHeaders removes client-supplied OpenRun identity headers before setting trusted values.
func deleteForwardAuthOpenRunHeaders(header http.Header) {
	for key := range header {
		if strings.HasPrefix(strings.ToLower(key), strings.ToLower(types.OPENRUN_HEADER_PREFIX)) {
			header.Del(key)
		}
	}
}

// copyForwardAuthResponseHeaders copies configured successful auth response headers onto the request sent to the app.
func copyForwardAuthResponseHeaders(requestHeader http.Header, responseHeader http.Header, copyResponseHeaders []string) {
	if len(copyResponseHeaders) == 0 {
		return
	}

	for _, headerName := range copyResponseHeaders {
		sourceHeaderName, targetHeaderName := parseForwardAuthHeaderCopy(headerName)
		if sourceHeaderName == "" || targetHeaderName == "" || shouldSkipForwardAuthHeader(sourceHeaderName) || shouldSkipForwardAuthHeader(targetHeaderName) {
			continue
		}
		requestHeader.Del(targetHeaderName)
		if values, ok := responseHeader[sourceHeaderName]; ok {
			requestHeader[targetHeaderName] = append([]string(nil), values...)
		}
	}
}

// parseForwardAuthHeaderCopy parses a response header copy rule, including Caddy-style Source>Target renames.
func parseForwardAuthHeaderCopy(headerCopy string) (string, string) {
	sourceHeaderName, targetHeaderName, renamed := strings.Cut(headerCopy, ">")
	sourceHeaderName = http.CanonicalHeaderKey(strings.TrimSpace(sourceHeaderName))
	if !renamed {
		return sourceHeaderName, sourceHeaderName
	}
	return sourceHeaderName, http.CanonicalHeaderKey(strings.TrimSpace(targetHeaderName))
}

// copyHeaders copies HTTP headers while omitting hop-by-hop headers that should not cross proxy boundaries.
func copyHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		key = http.CanonicalHeaderKey(key)
		if key == "" || shouldSkipForwardAuthHeader(key) {
			continue
		}
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// shouldSkipForwardAuthHeader reports whether a header is hop-by-hop or otherwise unsafe to copy.
func shouldSkipForwardAuthHeader(headerName string) bool {
	_, ok := hopByHopForwardAuthHeaders[http.CanonicalHeaderKey(headerName)]
	return ok
}
