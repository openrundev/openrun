// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha512"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/crypto/bcrypt"
)

// BUILTIN_AUTH_SECTION is the config section holding the builtin auth users,
// [builtin_auth.<username>] in openrun.toml. Entries can also be managed as
// dynamic config entries (openrun user add/update/delete), which take effect
// immediately and shadow a static entry of the same name
const BUILTIN_AUTH_SECTION = "builtin_auth"

// BuiltinAuth implements the "builtin" app auth type: HTTP Basic auth checked
// against the [builtin_auth.*] entries of the effective config (static
// openrun.toml entries merged with dynamic config entries). The user id is
// builtin:<username>, matching the <provider>:<user> form the SSO auth types
// produce; the entry's groups feed RBAC group: matching like SSO groups do.
// Like AdminBasicAuth, the sha of a successfully authenticated Authorization
// header is cached to skip the bcrypt cost on subsequent requests; the cache
// is reset when the builtin_auth config changes
type BuiltinAuth struct {
	*types.Logger
	getConfig func() *types.ServerConfig

	mu        sync.RWMutex
	authCache map[string]string // sha512 of the auth header -> authenticated username
}

func NewBuiltinAuth(logger *types.Logger, getConfig func() *types.ServerConfig) *BuiltinAuth {
	return &BuiltinAuth{
		Logger:    logger,
		getConfig: getConfig,
		authCache: map[string]string{},
	}
}

// authenticate checks the Authorization header against the builtin_auth user
// entries, returning the user id (builtin:<username>) and the user's groups
func (a *BuiltinAuth) authenticate(authHeader string) (userId string, groups []string, ok bool) {
	if authHeader == "" {
		return "", nil, false
	}
	user, pass, ok := parseBasicAuth(authHeader)
	if !ok {
		return "", nil, false
	}

	entry, ok := a.getConfig().BuiltinAuth[user]
	if !ok {
		a.Warn().Msgf("builtin auth user %s is not configured", user)
		time.Sleep(100 * time.Millisecond) // slow down brute force attacks
		return "", nil, false
	}

	inputSha := sha512.Sum512([]byte(authHeader))
	shaKey := string(inputSha[:])
	a.mu.RLock()
	cachedUser, cached := a.authCache[shaKey]
	a.mu.RUnlock()
	if !cached || cachedUser != user {
		if err := bcrypt.CompareHashAndPassword([]byte(entry.Password), []byte(pass)); err != nil {
			a.Warn().Err(err).Msgf("builtin auth password match failed for user %s", user)
			time.Sleep(100 * time.Millisecond) // slow down brute force attacks
			return "", nil, false
		}
		a.mu.Lock()
		a.authCache[shaKey] = user
		a.mu.Unlock()
	}

	groups = entry.Groups
	if groups == nil { // static entries can omit the groups field
		groups = []string{}
	}
	return string(types.AppAuthnBuiltin) + ":" + user, groups, true
}

// ResetCache drops the cached auth headers, called when the builtin_auth
// config changes (a password change or user delete must take effect
// immediately)
func (a *BuiltinAuth) ResetCache() {
	a.mu.Lock()
	a.authCache = map[string]string{}
	a.mu.Unlock()
}

// validateUsername checks a builtin auth username: basic auth encodes
// user:password, so the username cannot contain a colon (or whitespace,
// which only invites confusion)
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if strings.ContainsAny(username, ": \t\n") {
		return fmt.Errorf("username cannot contain ':' or whitespace")
	}
	return nil
}

// CreateUpdateUser creates or updates one builtin auth user as a dynamic
// config entry (shadowing a static openrun.toml entry of the same name). The
// change is written as a new config version and takes effect immediately.
// passwordHash is the bcrypt hash of the password; empty on an update keeps
// the current hash. groups nil on an update keeps the current groups. Returns
// whether an existing user was updated
func (s *Server) CreateUpdateUser(ctx context.Context, username, passwordHash string,
	groups []string, update bool) (bool, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return false, err
	}
	if err := validateUsername(username); err != nil {
		return false, err
	}

	existing, exists := s.Config().BuiltinAuth[username]
	if !update && exists {
		return false, fmt.Errorf("user %s already exists, use user update to change it", username)
	}
	if update && !exists {
		return false, fmt.Errorf("user %s does not exist, use user add to create it", username)
	}

	if passwordHash == "" {
		if !update {
			return false, fmt.Errorf("password is required to create a user")
		}
		passwordHash = existing.Password // keep the current password
	}
	if _, err := bcrypt.Cost([]byte(passwordHash)); err != nil {
		return false, fmt.Errorf("password must be a bcrypt hash: %w", err)
	}
	if groups == nil && update {
		groups = existing.Groups // keep the current groups
	}
	if groups == nil {
		groups = []string{}
	}

	values := map[string]any{"password": passwordHash, "groups": groups}
	if _, err := s.SetConfigEntry(ctx, BUILTIN_AUTH_SECTION, username, values, ""); err != nil {
		return false, err
	}
	return exists, nil
}

// DeleteUser removes one dynamic builtin auth user entry, immediately
// reverting to the static entry of the same name if one exists. Static
// entries cannot be deleted through the API
func (s *Server) DeleteUser(ctx context.Context, username string) error {
	_, err := s.DeleteConfigEntry(ctx, BUILTIN_AUTH_SECTION, username, "")
	return err
}

// ListUsers returns the builtin auth users, both the static openrun.toml
// entries and the dynamic config entries, sorted by username. Password
// hashes are not returned
func (s *Server) ListUsers(ctx context.Context) ([]types.BuiltinUserInfo, error) {
	entries, err := s.GetConfigEntries(ctx, []string{BUILTIN_AUTH_SECTION})
	if err != nil {
		return nil, err
	}

	users := make([]types.BuiltinUserInfo, 0, len(entries[BUILTIN_AUTH_SECTION]))
	for _, entry := range entries[BUILTIN_AUTH_SECTION] {
		users = append(users, types.BuiltinUserInfo{
			Username:   entry.Name,
			Groups:     valueStringSlice(entry.Values["groups"]),
			Source:     entry.Source,
			Overridden: entry.Overridden,
		})
	}
	sort.Slice(users, func(i, j int) bool {
		if users[i].Username != users[j].Username {
			return users[i].Username < users[j].Username
		}
		return users[i].Source < users[j].Source // dynamic before static
	})
	return users, nil
}

// valueStringSlice converts an entry field value to a string list. Static
// entries surface groups as []string (toml round trip), dynamic entries as
// []any (json round trip)
func valueStringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return []string{}
}
