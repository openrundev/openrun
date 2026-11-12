// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// Session lifetime: an idle timeout with sliding renewal, under an absolute
// cap.
//
// security.session_max_age is the idle lifetime: a session that keeps being
// used is re-issued so that it expires session_max_age after its last renewal
// rather than after the login. Re-issuing a session means re-saving it: the
// KV row gets a new delete_at, the cookie a new Max-Age, and both the cookie
// and the row payload get fresh securecookie timestamps (the codecs reject
// payloads older than the store max-age, so every layer has to be refreshed
// together). To keep that from being a write per request, a session is only
// renewed once it is past half of its lifetime; the effective idle timeout is
// therefore between session_max_age/2 and session_max_age, and the cost is
// bounded to two writes per lifetime. The session id is not rotated on
// renewal.
//
// security.session_absolute_max_age caps the total lifetime from login: no
// renewal extends a session past login + absolute max age (the cookie and row
// expiry are truncated to that deadline), and a session past it is rejected
// even if its cookie is still valid, so lowering the cap takes effect on
// existing sessions. 0 disables the cap. Both settings are read at startup.

const (
	// SESSION_ISSUED_KEY holds the unix time (seconds) the session was last
	// issued or renewed. Sessions without it (created before sliding expiry)
	// are renewed on their next use, which also stamps them
	SESSION_ISSUED_KEY = "issued_at"

	// LOGIN_AT_KEY holds the unix time (seconds) of the login that created the
	// session; never changed by renewals, it anchors the absolute cap.
	// Sessions without it are stamped at their next renewal
	LOGIN_AT_KEY = "login_at"
	// SESSION_HOST_KEY holds the host the login was completed for (the host
	// of the post-login redirect). The session is valid on that host only:
	// the login completion token is sent to the redirect host, and when that
	// host name does not resolve to this server (a stage or app domain whose
	// DNS someone else controls) whoever receives it can mint a session. The
	// binding limits such a session to that one host, it is not accepted on
	// the other app domains or the auth domain. Sessions saved before the
	// key existed have no binding and are accepted until they expire
	SESSION_HOST_KEY = "session_host"
)

// normalizeSessionHost returns the host name a session is bound to or checked
// against: lower case, without port and trailing dot, with the loopback
// addresses treated as localhost (as app matching does)
func normalizeSessionHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(system.GetHostname(host)), ".")
	if host == "127.0.0.1" || host == "::1" {
		return "localhost"
	}
	return host
}

// sessionHostOfUrl returns the normalized host of an absolute url, empty for
// a relative or unparseable one
func sessionHostOfUrl(rawUrl string) string {
	parsed, err := url.Parse(rawUrl)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return normalizeSessionHost(parsed.Host)
}

// sessionHostMatches reports whether an authenticated session may be used
// for the request: the session is not bound to a host, or it is bound to the
// host of the request
func sessionHostMatches(session *sessions.Session, r *http.Request) bool {
	bound, ok := session.Values[SESSION_HOST_KEY].(string)
	if !ok || bound == "" {
		return true
	}
	return bound == normalizeSessionHost(r.Host)
}

// markSessionLogin stamps a newly authenticated session with its login and
// issue time and caps its max-age to the absolute lifetime. Call it whenever
// an authenticated session is saved at login
func markSessionLogin(session *sessions.Session, absoluteMaxAge int, redirectUrl string) {
	now := time.Now()
	if host := sessionHostOfUrl(redirectUrl); host != "" {
		session.Values[SESSION_HOST_KEY] = host
	} else {
		delete(session.Values, SESSION_HOST_KEY)
	}
	session.Values[LOGIN_AT_KEY] = now.Unix()
	session.Values[SESSION_ISSUED_KEY] = now.Unix()
	session.Options.MaxAge = cappedMaxAge(session.Options.MaxAge, now.Unix(), absoluteMaxAge, now)
}

// cappedMaxAge returns the max-age (seconds) to issue a session with: the
// idle max-age, truncated so the session does not outlive
// loginAt + absoluteMaxAge. Zero or negative means the absolute lifetime is
// already used up. An absoluteMaxAge of 0 means no cap
func cappedMaxAge(idleMaxAge int, loginAt int64, absoluteMaxAge int, now time.Time) int {
	if absoluteMaxAge <= 0 || idleMaxAge <= 0 {
		return idleMaxAge
	}
	remaining := loginAt + int64(absoluteMaxAge) - now.Unix()
	if remaining < int64(idleMaxAge) {
		return int(remaining)
	}
	return idleMaxAge
}

// sessionWithinAbsoluteLifetime reports whether the session's login is within
// absoluteMaxAge of now (0 = no cap). Sessions without a login stamp are
// accepted; they get stamped at their next renewal, from which point the cap
// applies
func sessionWithinAbsoluteLifetime(session *sessions.Session, absoluteMaxAge int, now time.Time) bool {
	if absoluteMaxAge <= 0 {
		return true
	}
	loginAt, ok := session.Values[LOGIN_AT_KEY].(int64)
	if !ok {
		return true
	}
	return now.Unix() < loginAt+int64(absoluteMaxAge)
}

// sessionNeedsRenewal reports whether an authenticated session is past half of
// its idle lifetime (or has no issue stamp) and should be re-issued. Sessions
// with no positive max-age (browser-session cookies) never renew
func sessionNeedsRenewal(session *sessions.Session, now time.Time) bool {
	maxAge := session.Options.MaxAge
	if maxAge <= 0 {
		return false
	}
	issued, ok := session.Values[SESSION_ISSUED_KEY].(int64)
	if !ok {
		return true
	}
	return now.Unix()-issued >= int64(maxAge)/2
}

// renewSession re-issues an authenticated session when it is due (see
// sessionNeedsRenewal), with its expiry capped to the absolute lifetime.
// Called after the session has been validated for the request (including
// sessionWithinAbsoluteLifetime), and before any response body is written
// since it sets a cookie. A failed renewal is logged and ignored: the current
// session is still valid until its existing expiry, so the request proceeds
func renewSession(logger *types.Logger, w http.ResponseWriter, r *http.Request, session *sessions.Session, absoluteMaxAge int) {
	now := time.Now()
	if !sessionNeedsRenewal(session, now) {
		return
	}
	loginAt, ok := session.Values[LOGIN_AT_KEY].(int64)
	if !ok {
		// pre-existing session from before the absolute cap: the cap counts
		// from this first renewal
		loginAt = now.Unix()
		session.Values[LOGIN_AT_KEY] = loginAt
	}
	maxAge := cappedMaxAge(session.Options.MaxAge, loginAt, absoluteMaxAge, now)
	if maxAge <= 0 {
		// at the absolute deadline: nothing left to extend to, the session
		// ends with its current expiry (and is rejected from now on by
		// sessionWithinAbsoluteLifetime)
		return
	}
	session.Values[SESSION_ISSUED_KEY] = now.Unix()
	session.Options.MaxAge = maxAge
	if err := session.Save(r, w); err != nil {
		logger.Warn().Err(err).Str("cookie", session.Name()).Msg("session renewal failed, keeping the current expiry")
	}
}

// freshPreAuthSession returns the session a login start writes its pre-auth
// values (nonce, redirect) into. A cookie that fails to decode, or one
// naming an expired or missing keystore row, must not stop a login from
// starting: the session comes back along with the error (the registry
// caches it for the request), and is reset to a fresh one, with a new id
// (a fixated id must not be continued) and no values, keeping the store's
// cookie options. Returns false after writing the response when the store
// returned no session at all
func freshPreAuthSession(w http.ResponseWriter, r *http.Request, store sessions.Store, cookieName string) (*sessions.Session, bool) {
	session, err := store.Get(r, cookieName)
	if session == nil {
		http.Error(w, "error getting session", http.StatusInternalServerError)
		return nil, false
	}
	if err != nil {
		session.ID = ""
		session.IsNew = true
		session.Values = make(map[any]any)
	}
	return session, true
}
