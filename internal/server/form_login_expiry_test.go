// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/crypto/bcrypt"
)

// newFlowTestManager builds a form login manager over an in-memory keystore
// with a system admin account (password "secret") and auth.localhost as the
// login domain
func newFlowTestManager(t *testing.T, sessionMaxAge, absoluteMaxAge int) (*FormLoginManager, *InmemoryKVStore, *KVSessionStore) {
	t.Helper()
	db := NewInmemoryKVStore()
	store := NewKVSessionStore(db,
		[]byte("test-session-key-32bytes-long!!!"),
		[]byte("test-session-block-32bytes-key!!"),
	)
	store.Options.Secure = false
	store.MaxAge(sessionMaxAge)

	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &types.ServerConfig{}
	cfg.AdminUser = "admin"
	cfg.Security.AdminPasswordBcrypt = string(hash)
	cfg.Security.AuthCallbackDomain = "auth."
	cfg.System.DefaultDomain = "localhost"
	cfg.Security.SessionAbsoluteMaxAge = absoluteMaxAge

	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	manager, err := NewFormLoginManager(logger, func() *types.ServerConfig { return cfg },
		store, db, NewAdminBasicAuth(logger, cfg), nil, false)
	if err != nil {
		t.Fatalf("NewFormLoginManager failed: %v", err)
	}
	return manager, db, store
}

// beginTestFlow starts a login for http://localhost:25222/app1 and returns the
// state token from the login redirect and the pre-auth cookies
func beginTestFlow(t *testing.T, manager *FormLoginManager) (string, []*http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://localhost:25222/app1", nil)
	if !manager.beginLogin(rec, req, "system") {
		t.Fatal("beginLogin did not start the flow")
	}
	loginURL, err := url.Parse(rec.Result().Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := loginURL.Query().Get("state")
	if state == "" {
		t.Fatal("login redirect carries no state")
	}
	return state, rec.Result().Cookies()
}

func submitTestForm(t *testing.T, manager *FormLoginManager, state, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("state", state)
	form.Set("system-username", "admin")
	form.Set("system-password", password)
	req := httptest.NewRequest("POST", "http://auth.localhost:25222"+formLoginPath+"/system",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("authtype", "system")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	manager.loginSubmit(rec, req)
	return rec
}

// setStateDeadline rewrites a login state entry's deadline (unix seconds)
func setStateDeadline(t *testing.T, db *InmemoryKVStore, state string, deadline int64) {
	t.Helper()
	keyBytes, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		t.Fatal(err)
	}
	values, err := db.FetchKV(context.Background(), string(keyBytes))
	if err != nil {
		t.Fatalf("state entry missing: %v", err)
	}
	values[LOGIN_DEADLINE_KEY] = deadline
	if err := db.UpdateKV(context.Background(), string(keyBytes), values); err != nil {
		t.Fatal(err)
	}
}

func assertExpiredWithLink(t *testing.T, what string, rec *httptest.ResponseRecorder, wantLink bool) {
	t.Helper()
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "expired") {
		t.Fatalf("%s: expected the expired page, got status %d: %s", what, rec.Code, body)
	}
	if strings.Contains(body, "<form") {
		t.Errorf("%s: expired page must not render the credentials form", what)
	}
	hasLink := strings.Contains(body, `href="http://localhost:25222/app1"`)
	if hasLink != wantLink {
		t.Errorf("%s: link back present = %v, want %v; body: %s", what, hasLink, wantLink, body)
	}
	if !wantLink && !strings.Contains(body, "reload the page") {
		t.Errorf("%s: expired page without a link must tell the user to go back and reload", what)
	}
}

// The login state row outlives its login deadline so the expired page can
// link back to the app the login was started from. Past the deadline the
// state must be unusable for signing in on every endpoint
func TestFormLoginExpiredPageLinksBack(t *testing.T) {
	manager, db, _ := newFlowTestManager(t, 3600, 0)

	// state row expiry: kept for the retention window beyond the deadline
	state, _ := beginTestFlow(t, manager)
	keyBytes, _ := base64.URLEncoding.DecodeString(state)
	values, err := db.FetchKV(context.Background(), string(keyBytes))
	if err != nil {
		t.Fatal(err)
	}
	deadline, ok := stateValueInt64(values, LOGIN_DEADLINE_KEY)
	if !ok {
		t.Fatal("state entry has no login deadline")
	}
	if until := time.Until(time.Unix(deadline, 0)); until < preAuthStateMaxAge-time.Minute || until > preAuthStateMaxAge {
		t.Errorf("login deadline %v from now, want ~%v", until, preAuthStateMaxAge)
	}
	if rowExpiry := db.deleteAt[string(keyBytes)]; rowExpiry == nil ||
		rowExpiry.Before(time.Unix(deadline, 0).Add(expiredStateRetention-time.Minute)) {
		t.Errorf("state row expiry %v does not outlive the deadline by the retention window", rowExpiry)
	}

	// login page with a valid state renders the form, no back link
	pageReq := httptest.NewRequest("GET", "http://auth.localhost:25222"+formLoginPath+"?state="+state, nil)
	pageRec := httptest.NewRecorder()
	manager.loginPage(pageRec, pageReq)
	if !strings.Contains(pageRec.Body.String(), "<form") || strings.Contains(pageRec.Body.String(), "Sign in again") {
		t.Fatalf("valid state must render the form without the back link: %s", pageRec.Body.String())
	}

	// past the deadline: login page and submit render the expired page with
	// the link back, and correct credentials are not accepted
	setStateDeadline(t, db, state, time.Now().Unix()-1)
	pageRec = httptest.NewRecorder()
	manager.loginPage(pageRec, pageReq)
	assertExpiredWithLink(t, "login page", pageRec, true)
	assertExpiredWithLink(t, "submit", submitTestForm(t, manager, state, "secret"), true)

	// unknown state: expired page without a link
	missing := base64.URLEncoding.EncodeToString([]byte(types.FORM_LOGIN_KV_PREFIX + "nosuchstate"))
	pageRec = httptest.NewRecorder()
	manager.loginPage(pageRec, httptest.NewRequest("GET", "http://auth.localhost:25222"+formLoginPath+"?state="+missing, nil))
	assertExpiredWithLink(t, "missing state", pageRec, false)

	// complete with a pre-login (unauthenticated) state on the app domain:
	// expired page, linking back
	state2, _ := beginTestFlow(t, manager)
	completeRec := httptest.NewRecorder()
	manager.complete(completeRec, httptest.NewRequest("GET", "http://localhost:25222"+formCompletePath+"?state="+state2, nil))
	assertExpiredWithLink(t, "complete with pre-login state", completeRec, true)

	// a consumed pre-login state (duplicate submit of the same form) leaves a
	// tombstone: expired page with the link back, and no second completion
	stateDup, _ := beginTestFlow(t, manager)
	if rec := submitTestForm(t, manager, stateDup, "secret"); rec.Code != http.StatusFound {
		t.Fatalf("first submit status = %d: %s", rec.Code, rec.Body.String())
	}
	assertExpiredWithLink(t, "duplicate submit", submitTestForm(t, manager, stateDup, "secret"), true)
	pageRec = httptest.NewRecorder()
	manager.loginPage(pageRec, httptest.NewRequest("GET", "http://auth.localhost:25222"+formLoginPath+"?state="+stateDup, nil))
	assertExpiredWithLink(t, "login page for consumed state", pageRec, true)

	// a completion token past its deadline is rejected, with the link back
	state3, cookies := beginTestFlow(t, manager)
	submitRec := submitTestForm(t, manager, state3, "secret")
	if submitRec.Code != http.StatusFound {
		t.Fatalf("loginSubmit status = %d: %s", submitRec.Code, submitRec.Body.String())
	}
	completeLoc := submitRec.Result().Header.Get("Location")
	completeURL, _ := url.Parse(completeLoc)
	setStateDeadline(t, db, completeURL.Query().Get("state"), time.Now().Unix()-1)
	good := httptest.NewRequest("GET", completeLoc, nil)
	for _, c := range cookies {
		good.AddCookie(c)
	}
	completeRec = httptest.NewRecorder()
	manager.complete(completeRec, good)
	assertExpiredWithLink(t, "expired completion token", completeRec, true)
}

// A back URL is only ever the validated app URL from the state entry
func TestLoginStateBackURL(t *testing.T) {
	var nilState *loginState
	if nilState.backURL() != "" {
		t.Error("nil state must have no back URL")
	}
	for raw, want := range map[string]string{
		"http://localhost:25222/app1?x=1": "http://localhost:25222/app1?x=1",
		"https://app.example.com/":        "https://app.example.com/",
		"javascript:alert(1)":             "",
		"/relative/path":                  "",
		"":                                "",
	} {
		st := &loginState{values: map[string]any{REDIRECT_URL: raw}}
		if got := st.backURL(); got != want {
			t.Errorf("backURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

// Sessions are renewed (re-issued with a fresh expiry) once past half of
// their lifetime, and left alone before that
func TestFormLoginSlidingRenewal(t *testing.T) {
	const maxAge = 3600
	manager, db, store := newFlowTestManager(t, maxAge, 0)

	// full login: the minted session carries an issue stamp
	state, cookies := beginTestFlow(t, manager)
	submitRec := submitTestForm(t, manager, state, "secret")
	completeLoc := submitRec.Result().Header.Get("Location")
	good := httptest.NewRequest("GET", completeLoc, nil)
	for _, c := range cookies {
		good.AddCookie(c)
	}
	completeRec := httptest.NewRecorder()
	manager.complete(completeRec, good)
	if completeRec.Code != http.StatusFound {
		t.Fatalf("complete status = %d: %s", completeRec.Code, completeRec.Body.String())
	}
	sessionCookies := completeRec.Result().Cookies()

	// Back navigation onto the consumed complete URL: expired page with the
	// link back, and the session already minted is untouched
	replay := httptest.NewRequest("GET", completeLoc, nil)
	for _, c := range sessionCookies {
		replay.AddCookie(c)
	}
	replayRec := httptest.NewRecorder()
	manager.complete(replayRec, replay)
	assertExpiredWithLink(t, "complete replay", replayRec, true)

	appReq := func() *http.Request {
		r := httptest.NewRequest("GET", "http://localhost:25222/app1", nil)
		for _, c := range sessionCookies {
			r.AddCookie(c)
		}
		return r
	}
	sessionCookieSet := func(rec *httptest.ResponseRecorder) *http.Cookie {
		for _, c := range rec.Result().Cookies() {
			if c.Name == genCookieName("system") {
				return c
			}
		}
		return nil
	}

	// fresh session: authenticated, not renewed
	rec := httptest.NewRecorder()
	if _, _, ok := manager.sessionAuth(rec, appReq(), "system"); !ok {
		t.Fatal("fresh session rejected")
	}
	if sessionCookieSet(rec) != nil {
		t.Error("a fresh session must not be re-issued")
	}

	// age the session past half its lifetime by rewinding the issue stamp in
	// the stored row
	session, err := store.Get(appReq(), genCookieName("system"))
	if err != nil {
		t.Fatal(err)
	}
	session.Values[SESSION_ISSUED_KEY] = time.Now().Unix() - maxAge/2 - 1
	if err := store.save(appReq(), session); err != nil {
		t.Fatal(err)
	}
	rowKey := store.kvKey(session)
	oldExpiry := *db.deleteAt[rowKey]

	rec = httptest.NewRecorder()
	if _, _, ok := manager.sessionAuth(rec, appReq(), "system"); !ok {
		t.Fatal("aged session rejected")
	}
	renewed := sessionCookieSet(rec)
	if renewed == nil {
		t.Fatal("aged session was not re-issued")
	}
	if renewed.MaxAge != maxAge {
		t.Errorf("renewed cookie Max-Age = %d, want %d", renewed.MaxAge, maxAge)
	}
	if newExpiry := db.deleteAt[rowKey]; newExpiry == nil || !newExpiry.After(oldExpiry) {
		t.Errorf("session row expiry not extended: old %v new %v", oldExpiry, newExpiry)
	}

	// the renewed cookie keeps working, and is not renewed again right away
	sessionCookies = []*http.Cookie{renewed}
	rec = httptest.NewRecorder()
	if _, _, ok := manager.sessionAuth(rec, appReq(), "system"); !ok {
		t.Fatal("renewed session rejected")
	}
	if sessionCookieSet(rec) != nil {
		t.Error("a just-renewed session must not be re-issued again")
	}

	// a pre-existing session without an issue stamp is renewed on first use
	session, err = store.Get(appReq(), genCookieName("system"))
	if err != nil {
		t.Fatal(err)
	}
	delete(session.Values, SESSION_ISSUED_KEY)
	if err := store.save(appReq(), session); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	if _, _, ok := manager.sessionAuth(rec, appReq(), "system"); !ok {
		t.Fatal("unstamped session rejected")
	}
	if sessionCookieSet(rec) == nil {
		t.Error("a session without an issue stamp must be re-issued")
	}
}

func TestSessionNeedsRenewal(t *testing.T) {
	now := time.Now()
	mk := func(maxAge int, issuedAgo int64, stamped bool) *sessions.Session {
		s := sessions.NewSession(nil, "test_session")
		s.Options = &sessions.Options{MaxAge: maxAge}
		if stamped {
			s.Values[SESSION_ISSUED_KEY] = now.Unix() - issuedAgo
		}
		return s
	}
	cases := []struct {
		name string
		s    *sessions.Session
		want bool
	}{
		{"browser-session cookie never renews", mk(0, 100000, true), false},
		{"young session", mk(3600, 100, true), false},
		{"just under half", mk(3600, 1799, true), false},
		{"at half", mk(3600, 1800, true), true},
		{"old session", mk(3600, 3000, true), true},
		{"no stamp", mk(3600, 0, false), true},
	}
	for _, tc := range cases {
		if got := sessionNeedsRenewal(tc.s, now); got != tc.want {
			t.Errorf("%s: sessionNeedsRenewal = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The absolute cap bounds the total lifetime from login: the cookie issued at
// login and every renewal are truncated to the login deadline, and a session
// past it is rejected even while its cookie is still valid
func TestFormLoginAbsoluteLifetime(t *testing.T) {
	const idle, absolute = 3600, 600
	manager, _, store := newFlowTestManager(t, idle, absolute)

	state, cookies := beginTestFlow(t, manager)
	submitRec := submitTestForm(t, manager, state, "secret")
	completeLoc := submitRec.Result().Header.Get("Location")
	good := httptest.NewRequest("GET", completeLoc, nil)
	for _, c := range cookies {
		good.AddCookie(c)
	}
	completeRec := httptest.NewRecorder()
	manager.complete(completeRec, good)
	if completeRec.Code != http.StatusFound {
		t.Fatalf("complete status = %d: %s", completeRec.Code, completeRec.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range completeRec.Result().Cookies() {
		if c.Name == genCookieName("system") {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie issued")
	}
	// the login cookie is capped to the absolute lifetime, not the idle one
	if sessionCookie.MaxAge != absolute {
		t.Errorf("login cookie Max-Age = %d, want the absolute cap %d", sessionCookie.MaxAge, absolute)
	}

	appReq := func() *http.Request {
		r := httptest.NewRequest("GET", "http://localhost:25222/app1", nil)
		r.AddCookie(sessionCookie)
		return r
	}
	rewind := func(loginAgo, issuedAgo int64) {
		session, err := store.Get(appReq(), genCookieName("system"))
		if err != nil {
			t.Fatal(err)
		}
		session.Values[LOGIN_AT_KEY] = time.Now().Unix() - loginAgo
		session.Values[SESSION_ISSUED_KEY] = time.Now().Unix() - issuedAgo
		if err := store.save(appReq(), session); err != nil {
			t.Fatal(err)
		}
	}

	// renewal late in the absolute lifetime: extended only up to the deadline
	rewind(absolute-100, idle) // logged in 500s ago, renewal overdue
	rec := httptest.NewRecorder()
	if _, _, ok := manager.sessionAuth(rec, appReq(), "system"); !ok {
		t.Fatal("session within the absolute lifetime rejected")
	}
	var renewed *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == genCookieName("system") {
			renewed = c
		}
	}
	if renewed == nil {
		t.Fatal("overdue session was not renewed")
	}
	if renewed.MaxAge < 95 || renewed.MaxAge > 100 {
		t.Errorf("renewed cookie Max-Age = %d, want ~100 (time left until the absolute deadline)", renewed.MaxAge)
	}

	// past the absolute deadline: rejected even though the row is present
	rewind(absolute+1, 0)
	rec = httptest.NewRecorder()
	if _, _, ok := manager.sessionAuth(rec, appReq(), "system"); ok {
		t.Fatal("session past its absolute lifetime must be rejected")
	}
}

func TestCappedMaxAge(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	cases := []struct {
		name     string
		idle     int
		loginAgo int64
		absolute int
		want     int
	}{
		{"no cap", 3600, 100000, 0, 3600},
		{"idle within remaining", 3600, 1000, 86400, 3600},
		{"remaining shorter than idle", 3600, 86000, 86400, 400},
		{"at the deadline", 3600, 86400, 86400, 0},
		{"past the deadline", 3600, 90000, 86400, -3600},
		{"browser-session cookie", 0, 100, 86400, 0},
	}
	for _, tc := range cases {
		if got := cappedMaxAge(tc.idle, now.Unix()-tc.loginAgo, tc.absolute, now); got != tc.want {
			t.Errorf("%s: cappedMaxAge = %d, want %d", tc.name, got, tc.want)
		}
	}

	stamped := sessions.NewSession(nil, "s")
	stamped.Values[LOGIN_AT_KEY] = now.Unix() - 500
	unstamped := sessions.NewSession(nil, "s")
	if !sessionWithinAbsoluteLifetime(stamped, 0, now) || !sessionWithinAbsoluteLifetime(stamped, 501, now) ||
		sessionWithinAbsoluteLifetime(stamped, 500, now) || !sessionWithinAbsoluteLifetime(unstamped, 10, now) {
		t.Error("sessionWithinAbsoluteLifetime boundary conditions wrong")
	}
}
