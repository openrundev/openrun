// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// API keys and the shared bearer credential verifier for the remote API
// surfaces. Token wire format is orun_<type>_<id>_<secret> with type pat
// (API key), at (OAuth access) or rt (OAuth refresh): the id is embedded for
// O(1) lookup, the prefix makes leaked tokens greppable and identifies the
// type before any DB access, and the secret is stored only as a SHA-256 hash
// (secrets are 256-bit random, no key stretching needed).

const (
	apiTokenPrefix    = "orun_"
	apiTokenPATPrefix = "orun_pat_"
	apiTokenATPrefix  = "orun_at_" // OAuth access token
	apiTokenRTPrefix  = "orun_rt_" // OAuth refresh token, never valid at a resource endpoint

	// Logical resource surface names stored on credentials. The rest surface
	// is /_openrun over TCP (remote CLI), mcp is /_openrun/mcp
	ApiResourceRest = "rest"
	ApiResourceMCP  = "mcp"
)

// generateApiKey returns (id, secret, wireToken). The wire token is shown
// once; only sha256(secret) is stored
func generateApiKey() (string, string, string, error) {
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", "", err
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", "", err
	}
	id := hex.EncodeToString(idBytes)
	secret := hex.EncodeToString(secretBytes)
	return id, secret, apiTokenPATPrefix + id + "_" + secret, nil
}

func hashApiSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])
}

// parseApiToken splits a wire token into (credentialType, id, secret).
// Refresh tokens carry a distinct prefix so a resource endpoint can reject
// them before any DB lookup (they are only valid at the token/revoke
// endpoints); the caller checks the returned type against what it accepts
func parseApiToken(token string) (string, string, string, error) {
	if !strings.HasPrefix(token, apiTokenPrefix) {
		return "", "", "", fmt.Errorf("not an OpenRun API token")
	}
	var credType, prefix string
	switch {
	case strings.HasPrefix(token, apiTokenPATPrefix):
		credType, prefix = types.CredentialTypePAT, apiTokenPATPrefix
	case strings.HasPrefix(token, apiTokenATPrefix):
		credType, prefix = types.CredentialTypeOAuthAccess, apiTokenATPrefix
	case strings.HasPrefix(token, apiTokenRTPrefix):
		credType, prefix = types.CredentialTypeOAuthRefresh, apiTokenRTPrefix
	default:
		return "", "", "", fmt.Errorf("unsupported API token type")
	}
	rest := strings.TrimPrefix(token, prefix)
	id, secret, found := strings.Cut(rest, "_")
	if !found || id == "" || secret == "" {
		return "", "", "", fmt.Errorf("malformed API token")
	}
	return credType, id, secret, nil
}

// parseExpiresIn parses the --expires value: "" means the configured default,
// "never" means no expiry, "Nd" is N days, otherwise a Go duration
func (s *Server) parseExpiresIn(value string) (*time.Time, error) {
	if value == "never" {
		return nil, nil
	}
	if value == "" {
		value = cmp.Or(s.Config().Api.PatDefaultTTL, "2160h")
	}
	var duration time.Duration
	if strings.HasSuffix(value, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
		if err != nil || days <= 0 {
			return nil, types.CreateRequestError(
				fmt.Sprintf("invalid expiry %q: use a Go duration, <N>d for days, or \"never\"", value), http.StatusBadRequest)
		}
		duration = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		duration, err = time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return nil, types.CreateRequestError(
				fmt.Sprintf("invalid expiry %q: use a Go duration, <N>d for days, or \"never\"", value), http.StatusBadRequest)
		}
	}
	// UTC strips the monotonic clock reading (the sqlite driver stores
	// time.Time via String(), which would otherwise persist the "m=+..."
	// suffix) and keeps the column consistent with the UTC create_time
	expiry := time.Now().Add(duration).UTC()
	return &expiry, nil
}

// normalizeApiPrincipal validates a target user id for an API key: "admin",
// builtin:<user> (must exist), or any other provider:<user> (federated
// identities may be pre-provisioned before their first login)
func (s *Server) normalizeApiPrincipal(principal string) (provider string, subject string, err error) {
	if principal == types.ADMIN_USER {
		return types.ADMIN_USER, types.ADMIN_USER, nil
	}
	provider, subject, found := strings.Cut(principal, ":")
	if !found || provider == "" || subject == "" {
		return "", "", types.CreateRequestError(
			fmt.Sprintf("invalid user %q: the format is <provider>:<username>, like builtin:alice, or admin", principal),
			http.StatusBadRequest)
	}
	if provider == string(types.AppAuthnBuiltin) {
		if _, exists := s.Config().BuiltinAuth[subject]; !exists {
			return "", "", types.CreateRequestError(
				fmt.Sprintf("builtin user %s is not configured", subject), http.StatusBadRequest)
		}
	}
	return provider, subject, nil
}

// resolveApiIdentity returns the identity row for the principal, creating it
// when missing
func (s *Server) resolveApiIdentity(ctx context.Context, principal string) (*types.Identity, error) {
	identity, err := s.db.GetIdentityByPrincipal(ctx, principal)
	if err == nil {
		return identity, nil
	}
	provider, subject, err := s.normalizeApiPrincipal(principal)
	if err != nil {
		return nil, err
	}
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	identity = &types.Identity{
		Id:            "idn_" + hex.EncodeToString(idBytes),
		Provider:      provider,
		StableSubject: subject,
		PrincipalName: principal,
		Groups:        []string{},
	}
	if err := s.db.CreateIdentity(ctx, identity); err != nil {
		return nil, err
	}
	return identity, nil
}

// apiCallerPrincipal returns the identity of the caller for apikey self
// operations. Unattributed trusted calls (UDS) act as the admin principal,
// matching audit attribution
func apiCallerPrincipal(ctx context.Context) string {
	return cmp.Or(system.GetContextUserId(ctx), types.ADMIN_USER)
}

// apiCallerPrincipalChecked is apiCallerPrincipal for credential-issuing
// paths: a remote (tcp/mcp) call always carries the credential's identity, so
// an empty user id there indicates a context-propagation bug - fail closed
// instead of silently attributing (and minting for) the admin principal
func apiCallerPrincipalChecked(ctx context.Context) (string, error) {
	userId := system.GetContextUserId(ctx)
	if userId == "" {
		if invoker := system.GetContextApiInvoker(ctx); invoker == InvokerRest || invoker == InvokerMCP {
			return "", types.CreateRequestError(
				"internal error: remote API call carries no identity", http.StatusInternalServerError)
		}
		return types.ADMIN_USER, nil
	}
	return userId, nil
}

// CreateApiKey mints a new PAT. Minting for one's own identity requires
// apikey:manage:self; minting for another user requires admin and audits as
// create_apikey_other
func (s *Server) CreateApiKey(ctx context.Context, req *types.ApiKeyCreateRequest) (*types.ApiKeyCreateResponse, error) {
	caller, err := apiCallerPrincipalChecked(ctx)
	if err != nil {
		return nil, err
	}
	target := cmp.Or(req.User, caller)

	if target == caller {
		if err := s.enforceGlobalPerm(ctx, types.PermissionApiKeyManageSelf, ""); err != nil {
			return nil, err
		}
	} else {
		// Creating a credential for ANOTHER user is deliberately
		// administrative and prominently audited
		if err := s.enforceGlobalPerm(ctx, types.PermissionAdmin, ""); err != nil {
			return nil, err
		}
		updateApiOperation(ctx, "create_apikey_other", target)
		if err := s.checkApiOpEnabled(ctx, API_CREATE_APIKEY_OTHER); err != nil {
			return nil, err
		}
	}

	if _, _, err := s.normalizeApiPrincipal(target); err != nil {
		return nil, err
	}

	expiresAt, err := s.parseExpiresIn(req.ExpiresIn)
	if err != nil {
		return nil, err
	}

	var scopes []string
	if len(req.Scopes) > 0 {
		if err := rbac.ValidateScopes(req.Scopes); err != nil {
			return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
		}
		scopes = req.Scopes
	}

	resources := req.Resources
	if len(resources) == 0 {
		resources = []string{ApiResourceRest}
	}
	for _, resource := range resources {
		if resource != ApiResourceRest && resource != ApiResourceMCP {
			return nil, types.CreateRequestError(
				fmt.Sprintf("invalid resource %q: valid values are %s and %s", resource, ApiResourceRest, ApiResourceMCP),
				http.StatusBadRequest)
		}
	}
	if scopes == nil && len(resources) == 1 && resources[0] == ApiResourceMCP {
		// An MCP-only key with no explicit scopes defaults to read-only,
		// matching the OAuth consent default for the MCP surface: an AI
		// client should not receive the user's full write authority
		// implicitly. Write-capable keys need an explicit --scopes (like
		// "*"; reveal-class and config:update scopes stay literal-only)
		scopes = []string{"*:read"}
	}

	// Attenuation: a bearer credential can only mint credentials at most as
	// powerful as itself - scopes and resources must be subsets, and the new
	// key must not outlive the minting credential. UDS and console callers
	// carry no credential and are unrestricted
	if parent := system.GetContextApiCredential(ctx); parent != nil {
		expiresAt, err = validateApiKeyAttenuation(parent, scopes, resources, expiresAt)
		if err != nil {
			return nil, err
		}
	}

	identity, err := s.resolveApiIdentity(ctx, target)
	if err != nil {
		return nil, err
	}

	id, secret, wireToken, err := generateApiKey()
	if err != nil {
		return nil, err
	}
	cred := &types.Credential{
		Id:          id,
		SecretHash:  hashApiSecret(secret),
		Type:        types.CredentialTypePAT,
		IdentityId:  identity.Id,
		Scopes:      scopes,
		Resources:   resources,
		Description: req.Description,
		ExpiresAt:   expiresAt,
		CreatedBy:   caller,
	}
	if err := s.db.CreateCredential(ctx, cred); err != nil {
		return nil, err
	}

	s.Info().Str("id", id).Str("user", target).Str("created_by", caller).Msg("API key created")
	return &types.ApiKeyCreateResponse{
		Id:        id,
		Key:       wireToken,
		User:      target,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
	}, nil
}

// ListApiKeys lists the caller's API keys, or every key with all=true (admin)
func (s *Server) ListApiKeys(ctx context.Context, all bool) (*types.ApiKeyListResponse, error) {
	principal, err := apiCallerPrincipalChecked(ctx)
	if err != nil {
		return nil, err
	}
	if all {
		if err := s.enforceGlobalPerm(ctx, types.PermissionAdmin, ""); err != nil {
			return nil, err
		}
		principal = ""
	} else {
		if err := s.enforceGlobalPerm(ctx, types.PermissionApiKeyManageSelf, ""); err != nil {
			return nil, err
		}
	}
	keys, err := s.db.ListCredentials(ctx, principal)
	if err != nil {
		return nil, err
	}
	return &types.ApiKeyListResponse{Keys: keys}, nil
}

// DeleteApiKey removes an API key: one's own with apikey:manage:self,
// another user's with admin (audited as delete_apikey_other). The action is
// type aware: PATs are hard-deleted; deleting an OAuth refresh token revokes
// its whole grant, and an access token is revoked - OAuth rows are never
// hard-deleted, preserving the rotation family's replay evidence
func (s *Server) DeleteApiKey(ctx context.Context, id string) (*types.ApiKeyDeleteResponse, error) {
	cred, identity, err := s.db.GetCredentialWithIdentity(ctx, id)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusNotFound)
	}
	caller, err := apiCallerPrincipalChecked(ctx)
	if err != nil {
		return nil, err
	}
	if identity.PrincipalName == caller {
		if err := s.enforceGlobalPerm(ctx, types.PermissionApiKeyManageSelf, ""); err != nil {
			return nil, err
		}
	} else {
		if err := s.enforceGlobalPerm(ctx, types.PermissionAdmin, ""); err != nil {
			return nil, err
		}
		updateApiOperation(ctx, "delete_apikey_other", identity.PrincipalName)
		if err := s.checkApiOpEnabled(ctx, API_DELETE_APIKEY_OTHER); err != nil {
			return nil, err
		}
	}
	switch cred.Type {
	case types.CredentialTypePAT:
		if err := s.db.DeleteCredential(ctx, id); err != nil {
			return nil, err
		}
	case types.CredentialTypeOAuthRefresh:
		if cred.GrantId == "" {
			return nil, types.CreateRequestError("refresh token has no grant", http.StatusInternalServerError)
		}
		if err := s.db.RevokeGrantCredentials(ctx, cred.GrantId, "deleted"); err != nil {
			return nil, err
		}
	default:
		if err := s.db.RevokeCredential(ctx, id, "deleted"); err != nil {
			return nil, err
		}
	}
	s.Info().Str("id", id).Str("type", cred.Type).Str("user", identity.PrincipalName).
		Str("deleted_by", caller).Msg("API key deleted/revoked")
	return &types.ApiKeyDeleteResponse{Id: id, User: identity.PrincipalName}, nil
}

// validateApiKeyAttenuation enforces that a credential-authenticated caller
// mints only credentials at most as powerful as its own: child scopes and
// resources must be subsets of the parent's, and the child must not outlive
// the parent. This also preserves the literal-only protections: a parent
// scoped "*" cannot mint a key carrying secret:reveal or admin
func validateApiKeyAttenuation(parent *types.Credential, scopes []string, resources []string, expiresAt *time.Time) (*time.Time, error) {
	if parent.Scopes != nil {
		if scopes == nil {
			return nil, types.CreateRequestError(
				"a scoped credential cannot mint an unscoped key: pass --scopes at most as broad as the caller's",
				http.StatusForbidden)
		}
		for _, scope := range scopes {
			if !rbac.ScopeCovered(parent.Scopes, scope) {
				return nil, types.CreateRequestError(
					fmt.Sprintf("scope %q exceeds the calling credential's scopes", scope), http.StatusForbidden)
			}
		}
	}
	for _, resource := range resources {
		if !slices.Contains(parent.Resources, resource) {
			return nil, types.CreateRequestError(
				fmt.Sprintf("resource %q exceeds the calling credential's resources", resource), http.StatusForbidden)
		}
	}
	if parent.ExpiresAt != nil {
		if expiresAt == nil {
			// An explicit --expires=never must not outlive the parent
			return nil, types.CreateRequestError(
				"the new key must not outlive the calling credential", http.StatusForbidden)
		}
		if expiresAt.After(*parent.ExpiresAt) {
			// Clamp instead of rejecting: the default 90d expiry would
			// otherwise land marginally past a parent minted with the same
			// TTL. The bound is what matters, not the requested value
			clamped := *parent.ExpiresAt
			expiresAt = &clamped
		}
	}
	return expiresAt, nil
}

// updateApiOperation renames the audit operation for the current request and
// records the target principal, used for the prominently audited
// *_apikey_other operations
func updateApiOperation(ctx context.Context, operation string, target string) {
	if contextShared := ctx.Value(types.SHARED); contextShared != nil {
		if cs, ok := contextShared.(*ContextShared); ok {
			cs.Operation = operation
			cs.Target = target
		}
	}
}

// verifyApiToken authenticates a bearer token for the given surface (rest or
// mcp) and returns the principal, its RBAC groups and the credential. The
// scope ceiling (nil = unscoped) comes back separately so the caller can
// attach it to the request context
func (s *Server) verifyApiToken(ctx context.Context, token string, surface string) (string, []string, []string, *types.Credential, error) {
	credType, id, secret, err := parseApiToken(token)
	if err != nil {
		return "", nil, nil, nil, err
	}
	if credType == types.CredentialTypeOAuthRefresh {
		// Refresh tokens are not resource credentials: rejected by prefix
		// before any DB lookup, valid only at the token/revoke endpoints
		return "", nil, nil, nil, fmt.Errorf("refresh tokens are not valid at API endpoints")
	}
	cred, identity, err := s.db.GetCredentialWithIdentity(ctx, id)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("unknown API token")
	}
	if subtle.ConstantTimeCompare([]byte(cred.SecretHash), []byte(hashApiSecret(secret))) != 1 {
		return "", nil, nil, nil, fmt.Errorf("invalid API token")
	}
	if cred.Type != credType {
		return "", nil, nil, nil, fmt.Errorf("token type %s is not valid at this endpoint", cred.Type)
	}
	if cred.RevokedAt != nil {
		return "", nil, nil, nil, fmt.Errorf("API token has been revoked")
	}
	if cred.ExpiresAt != nil && time.Now().After(*cred.ExpiresAt) {
		return "", nil, nil, nil, fmt.Errorf("API token has expired")
	}
	if !slices.Contains(cred.Resources, surface) {
		// Resource binding: exact surface membership, never a prefix match
		return "", nil, nil, nil, fmt.Errorf("API token is not valid for the %s surface", surface)
	}
	if identity.DisabledAt != nil {
		return "", nil, nil, nil, fmt.Errorf("identity is disabled")
	}

	groups, err := s.apiIdentityGroups(ctx, identity)
	if err != nil {
		return "", nil, nil, nil, err
	}

	// Best effort last-used stamp; verification must not fail on it
	if err := s.db.UpdateCredentialLastUsed(ctx, cred.Id); err != nil {
		s.Warn().Err(err).Str("id", cred.Id).Msg("error updating API key last used time")
	}
	return identity.PrincipalName, groups, cred.Scopes, cred, nil
}

// apiIdentityGroups resolves the RBAC groups for an identity: builtin (and
// admin) groups are re-resolved live from config on every request; federated
// groups are the login-time snapshot, dropped once older than
// api.federated_identity_ttl (RBAC is additive, so dropping only reduces
// authority; the next interactive login refreshes the snapshot)
func (s *Server) apiIdentityGroups(ctx context.Context, identity *types.Identity) ([]string, error) {
	switch identity.Provider {
	case types.ADMIN_USER:
		return []string{}, nil
	case string(types.AppAuthnBuiltin):
		entry, exists := s.Config().BuiltinAuth[identity.StableSubject]
		if !exists {
			return nil, fmt.Errorf("builtin user %s is no longer configured", identity.StableSubject)
		}
		if entry.Groups == nil {
			return []string{}, nil
		}
		return entry.Groups, nil
	default:
		ttlStr := cmp.Or(s.Config().Api.FederatedIdentityTTL, "720h")
		ttl, err := time.ParseDuration(ttlStr)
		if err != nil {
			ttl = 720 * time.Hour
		}
		if identity.GroupsObservedAt == nil || time.Since(*identity.GroupsObservedAt) > ttl {
			// Stale snapshot: provider groups no longer apply; direct
			// principal grants keep working. The degradation is audited once
			// per identity per server lifetime so it is visible
			if _, already := s.staleGroupsAudited.LoadOrStore(identity.Id, true); !already {
				event := types.AuditEvent{
					CreateTime: time.Now(),
					UserId:     identity.PrincipalName,
					EventType:  types.EventTypeSystem,
					Operation:  "federated_groups_stale",
					Target:     identity.PrincipalName,
					Status:     string(types.EventStatusFailure),
					Detail:     "invoker=verify provider group snapshot expired, groups dropped until next interactive login",
				}
				if err := s.InsertAuditEvent(&event); err != nil {
					s.Error().Err(err).Msg("error inserting stale groups audit event")
				}
			}
			return []string{}, nil
		}
		return identity.Groups, nil
	}
}

// apiTokenRequestContext builds the management API request context for a
// verified bearer credential: attributed principal, groups, live RBAC
// enforcement, plus the scope ceiling and invoker marker
func (s *Server) apiTokenRequestContext(ctx context.Context, principal string, groups []string,
	scopes []string, invoker string, cred *types.Credential) context.Context {
	authCtx := &managementAPIContext{
		Context:     ctx,
		userId:      principal,
		groups:      groups,
		rbacEnabled: s.rbacManager.ConfigEnabled(),
	}
	result := system.WithApiInvoker(authCtx, invoker)
	if cred != nil {
		result = system.WithApiCredential(result, cred)
	}
	if scopes != nil {
		result = system.WithApiScopes(result, scopes)
	}
	return result
}

// authenticateApiRequest verifies the bearer credential for a remote surface
// and returns the attributed request context (identity, groups, scope
// ceiling, invoker marker, credential). On failure it writes the response -
// 401 with the surface's WWW-Authenticate challenge, or 403 when RBAC is
// disabled - and returns ok=false
func (s *Server) authenticateApiRequest(w http.ResponseWriter, r *http.Request,
	surface string, operation string) (context.Context, *types.Credential, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		s.insertAuthFailureEvent(r, operation, "missing bearer token")
		w.Header().Add("WWW-Authenticate", s.apiAuthChallenge(surface))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil, nil, false
	}
	principal, groups, scopes, cred, err := s.verifyApiToken(r.Context(), token, surface)
	if err != nil {
		// Name the failing credential id (public token half, never the
		// secret) so audit rows and logs distinguish which token failed;
		// the audit event dedupes per minute, the log line does not
		detail := err.Error()
		if _, id, _, parseErr := parseApiToken(token); parseErr == nil {
			detail += " cred=" + id
		}
		s.Warn().Str("path", r.URL.Path).Str("surface", surface).Msg("API bearer auth failed: " + detail)
		s.insertAuthFailureEvent(r, operation, detail)
		w.Header().Add("WWW-Authenticate", s.apiAuthChallenge(surface))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil, nil, false
	}
	// RBAC enforcement is structurally guaranteed here: an enabled surface
	// is rejected (startup and config update) when
	// security.unsafe_disable_rbac is set, so an authenticated remote
	// request always runs under RBAC
	invoker := InvokerRest
	if surface == ApiResourceMCP {
		invoker = InvokerMCP
	}
	return s.apiTokenRequestContext(r.Context(), principal, groups, scopes, invoker, cred), cred, true
}

// credentialRetention is how long expired or revoked credential rows are kept
// before the hourly prune deletes them. The window preserves rotation replay
// evidence (consumed refresh tokens) and revocation reasons for a full family
// expiry cycle before the rows go away
const credentialRetention = 30 * 24 * time.Hour

// pruneApiCredentials deletes credential rows whose evidence-retention window
// has passed: expired or revoked longer than credentialRetention ago.
// Non-expiring, unrevoked PATs are never touched. Runs on the hourly
// maintenance tick; errors are logged and retried on the next tick
func (s *Server) pruneApiCredentials() {
	if s.db == nil {
		return
	}
	cutoff := time.Now().Add(-credentialRetention).UTC()
	deleted, err := s.db.PruneCredentials(context.Background(), cutoff)
	if err != nil {
		s.Error().Err(err).Msg("error pruning credentials")
		return
	}
	if deleted > 0 {
		s.Info().Msgf("credential cleanup: deleted %d expired/revoked rows", deleted)
	}
}

// apiAuditDetail builds the audit event detail for an API invocation:
// the invoker type plus the authenticating credential's id, so an operation
// can be traced to the specific token that performed it
func apiAuditDetail(ctx context.Context) string {
	detail := ""
	if invoker := system.GetContextApiInvoker(ctx); invoker != "" {
		detail = "invoker=" + invoker
	}
	if cred := system.GetContextApiCredential(ctx); cred != nil {
		if detail != "" {
			detail += " "
		}
		detail += "cred=" + cred.Id
	}
	return detail
}
