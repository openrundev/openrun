// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/openrundev/openrun/internal/types"
)

// Universal logout page. A single endpoint that signs the user out regardless
// of how they logged in (system, builtin, OAuth/OIDC or SAML): every auth type
// stores its session as a per-provider OpenRun cookie on the app domain
// (system_openrun_session, github_prod_openrun_session, okta_openrun_saml_session,
// ...), so the page clears whichever OpenRun session cookies the request
// carries without needing to know the provider name.
//
// Unlike the login page - which is served cross-origin on the isolated auth
// callback domain because it collects credentials - the logout page runs on the
// app domain, where the cookies live: clearing them requires a Set-Cookie sent
// from that domain. No credentials are involved, so there is no cross-domain
// handshake. Apps link to /_openrun/logout (optionally with ?redirect=<app
// path> for the return link).
//
// GET  /_openrun/logout   -> confirmation page (or the signed-out /
//                            not-signed-in variants)
// POST /_openrun/logout   -> clears all OpenRun session cookies, redirects to
//                            the signed-out page
//
// The low-level POST /_openrun/logout/{provider} route (oauth.go) remains for
// callers that want to target one provider.
//
// Note on SSO: clearing the local cookie ends the OpenRun session. It does not
// perform IdP-side single logout (SAML SLO / OIDC end-session), so a subsequent
// login may complete silently via the IdP's own session.

const formLogoutPath = types.INTERNAL_URL_PREFIX + "/logout"

func (s *FormLoginManager) RegisterLogoutRoutes(csrfMiddleware *http.CrossOriginProtection, mux *chi.Mux) {
	mux.Get(formLogoutPath, s.logoutPage)
	mux.Method("POST", formLogoutPath, csrfMiddleware.Handler(http.HandlerFunc(s.logoutSubmit)))
}

// validLogoutRedirect sanitizes the return target for the logout page links.
// Only an origin-relative path is allowed, so the page cannot be turned into an
// open redirect and cannot downgrade the scheme. Rejected forms fall back to
// "/": scheme-relative "//host", the backslash trick "/\host" (which WHATWG URL
// parsing resolves to "//host"), and any absolute URL (scheme or host present)
func validLogoutRedirect(raw string) string {
	if raw == "" {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsRune(raw, '\\') {
		return "/"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" {
		return "/"
	}
	return raw
}

// sessionIdentity returns the display identity of an authenticated OpenRun
// session (provider:user, matching the RBAC user id form), or false if the
// session is not authenticated
func sessionIdentity(session *sessions.Session) (string, bool) {
	if auth, ok := session.Values[AUTH_KEY].(bool); !ok || !auth {
		return "", false
	}
	user, ok := sessionValueString(session, USER_KEY)
	if !ok || user == "" {
		return "", false
	}
	if provider, ok := sessionValueString(session, PROVIDER_NAME_KEY); ok && provider != "" {
		return provider + ":" + user, true
	}
	return user, true
}

// signedInIdentities reads the display identities of every authenticated
// OpenRun session cookie on the request (any auth type). Reads the cookies
// directly, so a lingering session is shown regardless of the login form's
// enabled state
func (s *FormLoginManager) signedInIdentities(r *http.Request) []string {
	ids := make([]string, 0, 2)
	seen := make(map[string]bool)
	for _, c := range r.Cookies() {
		if !isOpenRunCookieName(c.Name) {
			continue
		}
		session, err := s.cookieStore.Get(r, c.Name)
		if err != nil || session == nil {
			continue
		}
		if id, ok := sessionIdentity(session); ok && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// clearSessionCookies clears every OpenRun session cookie present on the
// request - across all auth types - so the user is logged out regardless of how
// they logged in. Save with MaxAge<0 deletes the server-side KV row and clears
// the browser cookie. If deleting the server-side row fails, the store does NOT
// expire the browser cookie (the session stays valid on every replica), so such
// failures are aggregated and returned: the caller must not report success
func (s *FormLoginManager) clearSessionCookies(w http.ResponseWriter, r *http.Request) error {
	var errs []error
	for _, c := range r.Cookies() {
		if !isOpenRunCookieName(c.Name) {
			continue
		}
		session, _ := s.cookieStore.Get(r, c.Name)
		if session == nil {
			continue
		}
		session.Options.MaxAge = -1
		if err := session.Save(r, w); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (s *FormLoginManager) logoutPage(w http.ResponseWriter, r *http.Request) {
	redirect := validLogoutRedirect(r.URL.Query().Get("redirect"))

	// The signed-out ("done") page must reflect reality: only show it when no
	// authenticated session remains, so opening ?done=1 with a live session
	// cannot display a false "signed out" state
	users := s.signedInIdentities(r)
	if len(users) == 0 {
		if r.URL.Query().Get("done") == "1" {
			s.renderLogout(w, "done", "", redirect)
		} else {
			s.renderLogout(w, "none", "", redirect)
		}
		return
	}
	s.renderLogout(w, "confirm", strings.Join(users, ", "), redirect)
}

func (s *FormLoginManager) logoutSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "error parsing form: "+err.Error(), http.StatusBadRequest)
		return
	}
	redirect := validLogoutRedirect(r.PostFormValue("redirect"))

	// A failed deletion leaves the session usable, so never report success then
	if err := s.clearSessionCookies(w, r); err != nil {
		s.Error().Err(err).Msg("error clearing session cookies on logout")
		http.Error(w, "Sign out failed, please try again.", http.StatusInternalServerError)
		return
	}

	target := formLogoutPath + "?done=1"
	if redirect != "/" {
		target += "&redirect=" + url.QueryEscape(redirect)
	}
	// See-other so the browser issues a GET for the signed-out page
	hxRedirect(w, r, target, http.StatusSeeOther)
}

// renderLogout writes the logout page. mode is "confirm" (signed in, offer sign
// out), "done" (signed out) or "none" (not signed in)
func (s *FormLoginManager) renderLogout(w http.ResponseWriter, mode, user, redirect string) {
	data := map[string]any{
		"Data": map[string]any{
			"Mode":       mode,
			"User":       user,
			"Redirect":   redirect,
			"LogoutPath": formLogoutPath,
			"StyleHref":  s.styleHref,
			"ExtraHref":  s.extraHref,
		},
	}
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "logout.go.html", data); err != nil {
		s.Error().Err(err).Msg("error rendering logout page")
	}
}
