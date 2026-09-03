// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"time"

	"github.com/gorilla/sessions"
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
)

// markSessionLogin stamps a newly authenticated session with its login and
// issue time and caps its max-age to the absolute lifetime. Call it whenever
// an authenticated session is saved at login
func markSessionLogin(session *sessions.Session, absoluteMaxAge int) {
	now := time.Now()
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
