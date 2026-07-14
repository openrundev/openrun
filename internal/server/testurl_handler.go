// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/types"
)

// resolveAppAuth resolves an app's auth setting. The auth string has the form
// [rbac:]<type>[+forward_<name>]. The legacy rbac: prefix is stripped (it has
// no effect, RBAC applies to every app when enabled) and the "default"/empty
// type is resolved to the configured app_default_auth_type BEFORE extracting
// the +forward_ modifier, because the configured default may itself carry an
// rbac: prefix and/or a modifier. The returned coreAuth may still carry the
// +forward_ modifier.
func resolveAppAuth(appAuth types.AppAuthnType, config *types.ServerConfig) (coreAuth string) {
	coreAuth = strings.TrimPrefix(string(appAuth), rbac.RBAC_AUTH_PREFIX)
	baseType, _, _ := strings.Cut(coreAuth, types.AUTH_MODIFIER_DELIMITER)
	if baseType == "" || baseType == string(types.AppAuthnDefault) {
		coreAuth = strings.TrimPrefix(config.Security.AppDefaultAuthType, rbac.RBAC_AUTH_PREFIX)
	}
	if coreAuth == "" { // no default auth type set, default to system admin user auth
		coreAuth = string(types.AppAuthnSystem)
	}
	return coreAuth
}

// testUrlSegPrefix marks a path segment as a _cl_ test URL directive
const testUrlSegPrefix = "/" + types.INTERNAL_APP_DELIM

// applyTestUrlDirectives handles _cl_ test URL directives (like
// /myapp/_cl_perm=app:read/page). When the request carries directive path
// segments and they are allowed, it returns a new request with the directive
// segments stripped from the URL and the parsed directives stored in the
// context. Directives are honored only when all of these hold: the
// security.unsafe_enable_testurl_rbac config is set, the matched app is a dev mode
// app, its resolved auth type is none (anonymous user) and RBAC is not
// active for the app. In every other case the request is returned unchanged
// (directive segments pass through to the app as normal path segments). A
// non-nil error means a recognized directive was malformed; the caller
// responds with 400.
func (h *Handler) applyTestUrlDirectives(matchedApp types.AppInfo, r *http.Request) (*http.Request, error) {
	config := h.server.Config()
	if !config.Security.UnsafeEnableTestUrlRbac || !matchedApp.IsDev {
		return r, nil
	}
	remainder := testUrlRemainder(matchedApp.Path, r.URL.Path)
	if !strings.HasPrefix(remainder, testUrlSegPrefix) {
		return r, nil
	}
	coreAuth := resolveAppAuth(matchedApp.Auth, config)
	baseType, _, _ := strings.Cut(coreAuth, types.AUTH_MODIFIER_DELIMITER)
	if baseType != string(types.AppAuthnNone) {
		return r, nil // only none auth (anonymous user) apps support test directives
	}
	if h.server.rbacManager.ConfigEnabled() {
		// RBAC applies to every app when enabled, so real enforcement is active
		// and simulation is off: the simulated set may only ever replace
		// allow-all, never a real grant evaluation
		return r, nil
	}

	parsed, err := parseTestUrlDirectives(matchedApp.Path, r.URL.Path)
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		return r, nil
	}
	dirs, err := h.server.rbacManager.BuildUrlDirectives(parsed.perms, parsed.roles, parsed.extendedPrefix)
	if err != nil {
		return nil, err
	}

	newRawPath := ""
	if r.URL.RawPath != "" {
		// Directive values are restricted to characters that URL escaping
		// leaves unchanged, so the extended prefix must appear literally in
		// the escaped form too; strip the same prefix from it
		if !strings.HasPrefix(r.URL.RawPath, parsed.extendedPrefix) {
			return nil, fmt.Errorf("url encoding is not supported in _cl_ directives")
		}
		newRawPath = strippedAppPath(matchedApp.Path) + r.URL.RawPath[len(parsed.extendedPrefix):]
		if newRawPath == "" {
			newRawPath = "/"
		}
	}

	newReq := r.Clone(context.WithValue(r.Context(), types.TESTURL_DIRECTIVES, dirs))
	newReq.URL.Path = parsed.strippedPath
	newReq.URL.RawPath = newRawPath
	// The app's router reuses the chi RouteContext set while the server routed
	// this request, and chi matches on RouteContext.RoutePath (still the
	// original, directive-laden path) in preference to r.URL.Path. Update it to
	// the stripped path so the directive segments do not leak into app route
	// matching (which would 404 every directive URL).
	if rctx := chi.RouteContext(newReq.Context()); rctx != nil {
		rctx.RoutePath = parsed.strippedPath
	}
	return newReq, nil
}

// strippedAppPath returns the app path as a URL prefix: "" for the root app
func strippedAppPath(appPath string) string {
	if appPath == "/" {
		return ""
	}
	return appPath
}

// testUrlRemainder returns the URL path portion after the app path, "" when
// the URL is the app path itself
func testUrlRemainder(appPath, urlPath string) string {
	return urlPath[len(strippedAppPath(appPath)):]
}

// testUrlParseResult holds the raw parsed _cl_ directive values before role
// resolution (roles are resolved against the RBAC manager by the caller)
type testUrlParseResult struct {
	perms          []string // _cl_perm values, merged across segments, deduplicated
	roles          []string // _cl_role values, merged across segments, deduplicated
	extendedPrefix string   // app path plus the raw directive segments
	strippedPath   string   // URL path with the directive segments stripped
}

// parseTestUrlDirectives parses the consecutive _cl_ directive segments
// immediately following the app path. Returns nil when the path has no
// directive segments. A segment starting with _cl_ that is not a wellformed,
// known directive is an error (fail closed, so future directive keys can
// never collide with app routes).
func parseTestUrlDirectives(appPath, urlPath string) (*testUrlParseResult, error) {
	base := strippedAppPath(appPath)
	remainder := testUrlRemainder(appPath, urlPath)

	var perms, roles []string
	permSeen := map[string]bool{}
	roleSeen := map[string]bool{}
	consumed := 0 // byte length of the directive segments, including the leading "/"

	for strings.HasPrefix(remainder[consumed:], testUrlSegPrefix) {
		seg := remainder[consumed+1:]
		if idx := strings.IndexByte(seg, '/'); idx >= 0 {
			seg = seg[:idx]
		}
		key, value, found := strings.Cut(seg[len(types.INTERNAL_APP_DELIM):], "=")
		if !found {
			return nil, fmt.Errorf("unknown _cl_ directive %q, _cl_ is an openrun reserved path prefix", seg)
		}
		switch key {
		case "perm":
			segPerms, err := parseTestUrlList(key, value)
			if err != nil {
				return nil, err
			}
			for _, perm := range segPerms {
				if !permSeen[perm] {
					permSeen[perm] = true
					perms = append(perms, perm)
				}
			}
		case "role":
			segRoles, err := parseTestUrlList(key, value)
			if err != nil {
				return nil, err
			}
			for _, role := range segRoles {
				if !roleSeen[role] {
					roleSeen[role] = true
					roles = append(roles, role)
				}
			}
		default:
			return nil, fmt.Errorf("unknown _cl_ directive key %q, supported: perm, role", key)
		}
		consumed += 1 + len(seg)
	}

	if consumed == 0 {
		return nil, nil
	}

	strippedPath := base + remainder[consumed:]
	if strippedPath == "" {
		strippedPath = "/"
	}
	return &testUrlParseResult{
		perms:          perms,
		roles:          roles,
		extendedPrefix: base + remainder[:consumed],
		strippedPath:   strippedPath,
	}, nil
}

// parseTestUrlList parses a _cl_<key> directive value: a non-empty comma
// separated list. Entries are restricted to characters that URL path
// escaping leaves unchanged, so the directive reads the same in the decoded
// and escaped URL forms.
func parseTestUrlList(key, value string) ([]string, error) {
	if value == "" {
		return nil, fmt.Errorf("_cl_%s directive value cannot be empty", key)
	}
	entries := strings.Split(value, ",")
	for _, entry := range entries {
		if entry == "" {
			return nil, fmt.Errorf("empty entry in _cl_%s directive value %q", key, value)
		}
		for _, ch := range entry {
			if !isTestUrlPermChar(ch) {
				return nil, fmt.Errorf("unsupported character %q in _cl_%s entry %q", ch, key, entry)
			}
		}
	}
	return entries, nil
}

// isTestUrlPermChar reports whether ch is allowed in a _cl_perm permission
// name: alphanumerics plus : _ . * $ @ - (all characters that URL path
// escaping leaves unchanged)
func isTestUrlPermChar(ch rune) bool {
	switch {
	case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		return true
	case ch == ':' || ch == '_' || ch == '.' || ch == '*' || ch == '$' || ch == '@' || ch == '-':
		return true
	}
	return false
}
