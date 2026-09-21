// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

// Federated login for the OAuth authorization server: when a resource's
// login mechanism is an [auth.*] provider or a [saml.*] provider, the
// authorize page cannot collect a password. Instead the pending authorize
// request is stored (metadata KV, multi-node safe), the browser is sent
// through the existing provider / SAML login flow with a return URL on the
// AS host, the provider session cookie set by that flow identifies the user
// on return, and a session-backed consent page (nonce-protected) issues the
// code. The provider callback already records the identity row and group
// snapshot (observeFederatedIdentity), so the token verifier needs nothing
// new.

const (
	oauthAuthzTTL      = 10 * time.Minute
	oauthAuthzKVPrefix = "oauth_authz:"
)

// oauthAuthzRequest is a pending authorize request awaiting a federated
// login and consent
type oauthAuthzRequest struct {
	ClientId     string    `json:"client_id"`
	RedirectUri  string    `json:"redirect_uri"`
	State        string    `json:"state"`
	Challenge    string    `json:"code_challenge"`
	Method       string    `json:"code_challenge_method"`
	Resource     string    `json:"resource"`
	Scope        string    `json:"scope"`
	ResponseType string    `json:"response_type"`
	Mechanism    string    `json:"mechanism"` // the provider or saml_<name> chosen
	Nonce        string    `json:"nonce"`     // consent form token, bound to this record
	Expires      time.Time `json:"expires"`
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) storeOAuthAuthz(ctx context.Context, id string, req *oauthAuthzRequest) error {
	blob, err := json.Marshal(req)
	if err != nil {
		return err
	}
	expires := req.Expires.UTC()
	return s.db.StoreKVBlob(ctx, oauthAuthzKVPrefix+id, blob, &expires)
}

// fetchOAuthAuthz returns the pending request, nil when unknown or expired
func (s *Server) fetchOAuthAuthz(ctx context.Context, id string) (*oauthAuthzRequest, error) {
	if id == "" {
		return nil, nil
	}
	blob, err := s.db.FetchKVBlob(ctx, oauthAuthzKVPrefix+id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var req oauthAuthzRequest
	if err := json.Unmarshal(blob, &req); err != nil {
		return nil, err
	}
	if time.Now().After(req.Expires) {
		return nil, nil
	}
	return &req, nil
}

// consumeOAuthAuthz removes the record; single use across nodes
func (s *Server) consumeOAuthAuthz(ctx context.Context, id string) (bool, error) {
	return s.db.DeleteKVIfPresent(ctx, oauthAuthzKVPrefix+id)
}

// isPasswordMechanism: mechanisms the authorize page authenticates itself
func isPasswordMechanism(mechanism string) bool {
	return mechanism == "builtin" || mechanism == "admin"
}

// federatedMechanisms returns the configured federated mechanisms of a
// resource (provider names and saml_<name>), skipping unknown entries with
// a warning
func (s *Server) federatedMechanisms(res *oauthResource) []string {
	mechanisms, err := s.oauthLoginMechanisms(res)
	if err != nil {
		return nil
	}
	federated := make([]string, 0, len(mechanisms))
	for _, mechanism := range mechanisms {
		if isPasswordMechanism(mechanism) {
			continue
		}
		if s.validFederatedMechanism(mechanism) {
			federated = append(federated, mechanism)
		} else {
			s.Warn().Msgf("login mechanism %q for resource %s is not a configured auth or saml provider", mechanism, res.URI)
		}
	}
	return federated
}

func (s *Server) validFederatedMechanism(mechanism string) bool {
	if strings.HasPrefix(mechanism, SAML_AUTH_PREFIX) {
		return s.samlManager != nil && s.samlManager.ValidateSAMLProvider(mechanism)
	}
	return s.oAuthManager != nil && s.oAuthManager.ValidateProviderName(mechanism)
}

// hasPasswordMechanism reports whether the resource accepts the password
// form (builtin or admin)
func (s *Server) hasPasswordMechanism(res *oauthResource) bool {
	mechanisms, err := s.oauthLoginMechanisms(res)
	if err != nil {
		return false
	}
	for _, mechanism := range mechanisms {
		if isPasswordMechanism(mechanism) {
			return true
		}
	}
	return false
}

// mechanismLabel names a mechanism on the chooser
func mechanismLabel(mechanism string) string {
	if name, ok := strings.CutPrefix(mechanism, SAML_AUTH_PREFIX); ok {
		return name + " (SAML)"
	}
	return mechanism
}

// startFederatedLogin stores the authorize request and sends the browser
// into the provider or SAML login with a return URL on the AS host
func (h *Handler) startFederatedLogin(w http.ResponseWriter, r *http.Request, get func(string) string, mechanism string) {
	s := h.server
	res, err := h.oauthValidateAuthorizeParams(r.Context(), get("client_id"), get("redirect_uri"),
		get("code_challenge"), get("code_challenge_method"), get("resource"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if get("response_type") != "code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	allowed := false
	for _, configured := range s.federatedMechanisms(res) {
		if configured == mechanism {
			allowed = true
		}
	}
	if !allowed {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("login mechanism %q is not available for this resource", mechanism))
		return
	}
	id, err := randomHex(16)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	nonce, err := randomHex(16)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if err := s.storeOAuthAuthz(r.Context(), id, &oauthAuthzRequest{
		ClientId: get("client_id"), RedirectUri: get("redirect_uri"), State: get("state"),
		Challenge: get("code_challenge"), Method: get("code_challenge_method"), Resource: get("resource"),
		Scope: get("scope"), ResponseType: get("response_type"), Mechanism: mechanism, Nonce: nonce,
		Expires: time.Now().Add(oauthAuthzTTL),
	}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "error storing authorization request")
		return
	}
	// The login flow returns to the AS host; the provider session cookie is
	// then set on that host and read by the continue handler
	returnUrl := s.apiExternalUrl() + types.INTERNAL_URL_PREFIX + "/oauth/authorize/continue?authz=" + url.QueryEscape(id)
	if strings.HasPrefix(mechanism, SAML_AUTH_PREFIX) {
		s.samlManager.login(w, r, mechanism, returnUrl)
		return
	}
	s.oAuthManager.beginLogin(w, r, mechanism, returnUrl)
}

// oauthAuthorizeFederated is the chooser's POST: start the selected login
func (h *Handler) oauthAuthorizeFederated(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	h.startFederatedLogin(w, r, r.PostForm.Get, r.PostForm.Get("mechanism"))
}

// federatedIdentity reads the user from the provider/SAML session cookie
// on the AS host. Returns done=true when a response (login redirect or
// error) was already written
func (h *Handler) federatedIdentity(w http.ResponseWriter, r *http.Request, mechanism string) (principal string, groups []string, done bool) {
	s := h.server
	if strings.HasPrefix(mechanism, SAML_AUTH_PREFIX) {
		principal, groups, err := s.samlManager.CheckSAMLAuth(w, r, mechanism)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return "", nil, true
		}
		return principal, groups, principal == ""
	}
	info, err := s.oAuthManager.CheckAuthInfo(w, r, mechanism)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return "", nil, true
	}
	return info.UserId, info.Groups, info.UserId == ""
}

// loadOAuthAuthz fetches and re-validates a pending request by id; a nil
// result means an error response was written
func (h *Handler) loadOAuthAuthz(w http.ResponseWriter, r *http.Request, id string) (*oauthAuthzRequest, *oauthResource) {
	authz, err := h.server.fetchOAuthAuthz(r.Context(), id)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "error reading authorization request")
		return nil, nil
	}
	if authz == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown or expired authorization request, start the login again")
		return nil, nil
	}
	get := func(name string) string {
		switch name {
		case "client_id":
			return authz.ClientId
		case "redirect_uri":
			return authz.RedirectUri
		case "code_challenge":
			return authz.Challenge
		case "code_challenge_method":
			return authz.Method
		case "resource":
			return authz.Resource
		}
		return ""
	}
	res, err := h.oauthValidateAuthorizeParams(r.Context(), get("client_id"), get("redirect_uri"),
		get("code_challenge"), get("code_challenge_method"), get("resource"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return nil, nil
	}
	return authz, res
}

// oauthAuthorizeContinue is the return point of the federated login: read
// the identity from the session cookie and render consent
func (h *Handler) oauthAuthorizeContinue(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("authz")
	authz, res := h.loadOAuthAuthz(w, r, id)
	if authz == nil {
		return
	}
	principal, groups, done := h.federatedIdentity(w, r, authz.Mechanism)
	if done {
		return
	}
	h.renderOAuthConsent(w, r, id, authz, res, principal, groups, "")
}

var oauthConsentTemplate = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html><head><title>OpenRun Login</title><style>
body{font-family:system-ui,sans-serif;max-width:26rem;margin:4rem auto;padding:0 1rem;color:#222}
input,button{width:100%;padding:.5rem;margin:.25rem 0 .75rem;box-sizing:border-box}
button{background:#2563eb;color:#fff;border:0;border-radius:4px;padding:.6rem;cursor:pointer}
.err{color:#b91c1c}.meta{color:#555;font-size:.9rem}.warn{color:#92400e;font-size:.9rem}
</style></head><body>
<h2>Approve access</h2>
<p class="meta">Signed in as <b>{{.Principal}}</b>.</p>
<p class="meta">Application <b>{{.ClientName}}</b> is requesting access to
<b>{{.Resource}}</b>{{if .Scope}} with scope <b>{{.Scope}}</b>{{end}}.</p>
<p class="meta">After approval the access code is sent to <b>{{.RedirectUri}}</b>.</p>
{{if .DynamicClient}}<p class="warn">This application registered itself dynamically;
its name is self-reported and not verified. Check that the address above is the
application you intend to authorize.</p>{{end}}
{{if .CIMDClient}}<p class="meta">This application identifies itself by the document at
<b>{{.ClientId}}</b>; its name is taken from that document.</p>{{end}}
{{if .LoopbackOnly}}<p class="warn">This application only redirects to your own computer
(localhost). Any website can publish such a document and claim to be a local application;
approve only if you started this login from an application you trust.</p>{{end}}
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
<input type="hidden" name="authz" value="{{.Authz}}">
<input type="hidden" name="nonce" value="{{.Nonce}}">
<label>Granted scope (narrow to limit this token)</label><input name="or_scope" value="{{.Scope}}">
<button type="submit">Approve</button>
</form></body></html>`))

func (h *Handler) renderOAuthConsent(w http.ResponseWriter, r *http.Request, id string, authz *oauthAuthzRequest,
	res *oauthResource, principal string, groups []string, errMsg string) {
	scope := strings.Join(h.server.oauthGrantScopes(res, parseScopeParam(authz.Scope)), " ")
	clientName, cimdClient, loopbackOnly := h.oauthClientDisplay(r.Context(), authz.ClientId)
	setOAuthPageHeaders(w)
	_ = oauthConsentTemplate.Execute(w, map[string]any{
		"Principal":     principal,
		"ClientName":    clientName,
		"Resource":      res.Label(),
		"Scope":         scope,
		"RedirectUri":   authz.RedirectUri,
		"ClientId":      authz.ClientId,
		"DynamicClient": authz.ClientId != oauthCLIClientId && !cimdClient,
		"CIMDClient":    cimdClient,
		"LoopbackOnly":  loopbackOnly,
		"Error":         errMsg,
		"Action":        types.INTERNAL_URL_PREFIX + "/oauth/authorize/consent",
		"Authz":         id,
		"Nonce":         authz.Nonce,
	})
}

// oauthAuthorizeConsent issues the code for a federated login: the record
// is single use, the nonce binds the form to it, and the identity is read
// again from the session cookie (never from the form)
func (h *Handler) oauthAuthorizeConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	id := r.PostForm.Get("authz")
	authz, res := h.loadOAuthAuthz(w, r, id)
	if authz == nil {
		return
	}
	if nonce := r.PostForm.Get("nonce"); nonce == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(authz.Nonce)) != 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "consent form token mismatch")
		return
	}
	principal, groups, done := h.federatedIdentity(w, r, authz.Mechanism)
	if done {
		return
	}
	// Recoverable problems (a bad scope, no app access) are shown on the
	// form with the record intact, so the user can correct and resubmit;
	// only a valid consent consumes the single-use record
	scopes, errMsg, err := h.validateOAuthConsent(r, res, principal, groups, parseScopeParam(r.PostForm.Get("or_scope")))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if errMsg != "" {
		h.renderOAuthConsent(w, r, id, authz, res, principal, groups, errMsg)
		return
	}
	consumed, err := h.server.consumeOAuthAuthz(r.Context(), id)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "error consuming authorization request")
		return
	}
	if !consumed {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "authorization request already used")
		return
	}
	h.issueOAuthCode(w, r, res, principal, scopes, authz.ClientId, authz.RedirectUri, authz.Challenge, authz.State)
}
