// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/segmentio/ksuid"
)

// Builtin users: the accounts of the "builtin" app auth type, rows of the
// builtin_users table (design: arch/docs/builtin-users.md). The user id in
// RBAC grants is builtin:<username>, matching the <provider>:<user> form the
// SSO auth types produce; the row's groups feed RBAC group: matching like SSO
// groups. Passwords are verified against the row's hash (argon2id, or bcrypt
// for imported rows which are upgraded on their next login); the sha of a
// successfully authenticated Authorization header is cached, tagged with the
// row id and credential version, so a password change, disable or delete on
// any node of a cluster invalidates it as soon as the row is reloaded

const (
	// loginLockThreshold consecutive password failures lock the account for
	// loginLockDuration; the counter resets on a success or when the lock
	// is set
	loginLockThreshold = 10
	loginLockDuration  = 15 * time.Minute
	// userCacheTTL bounds how long a cached row is used without a reload: the
	// safety net for a missed cross-node notification
	userCacheTTL = 60 * time.Second
	// loginFailureDelay slows down password guessing; applied uniformly to
	// unknown users, wrong passwords and locked accounts
	loginFailureDelay = 100 * time.Millisecond
	// lastLoginGranularity bounds the last_login_at writes of a sign-in that
	// hits the verified-header cache: the stamp is advanced when it is older
	// than this, so an API client that authenticates on every request does
	// not write on every request while the stamp still tracks its activity
	lastLoginGranularity = time.Minute
)

// userStore is the persistence the UserManager needs (implemented by
// metadata.Metadata; tests use an in-memory store)
type userStore interface {
	GetBuiltinUser(ctx context.Context, username string) (*types.BuiltinUser, error)
	ListBuiltinUsers(ctx context.Context) ([]types.BuiltinUser, error)
	CreateBuiltinUser(ctx context.Context, user *types.BuiltinUser) error
	UpdateBuiltinUser(ctx context.Context, user *types.BuiltinUser) error
	DeleteBuiltinUser(ctx context.Context, username string) error
	ImportBuiltinUser(ctx context.Context, user *types.BuiltinUser) (bool, error)
	UnlockBuiltinUser(ctx context.Context, id string) error
	RecordBuiltinLoginSuccess(ctx context.Context, id string, verifiedHash, rehash string) error
	RecordBuiltinLoginFailure(ctx context.Context, id string, threshold int, lockUntil time.Time) (bool, error)
}

type cachedUser struct {
	user     *types.BuiltinUser
	loadedAt time.Time
}

// authCacheEntry ties a verified header to the exact account row (the id,
// never just the name: a deleted and recreated user of the same name is a
// new row) at the credential version it was verified against
type authCacheEntry struct {
	username string
	id       string
	version  int
}

// UserManager authenticates builtin users and caches their rows
type UserManager struct {
	*types.Logger
	store userStore
	// notify tells the other nodes of a cluster that rows changed (nil when
	// not clustered)
	notify func(usernames []string)
	now    func() time.Time
	// failDelay is loginFailureDelay, zero in tests
	failDelay time.Duration

	mu        sync.RWMutex
	rows      map[string]cachedUser
	authCache map[string]authCacheEntry // sha512 of the auth header -> verified user + credential version
	verifySem chan struct{}             // bounds concurrent argon2id verifications (memory)
}

func NewUserManager(logger *types.Logger, store userStore) *UserManager {
	return &UserManager{
		Logger:    logger,
		store:     store,
		now:       time.Now,
		failDelay: loginFailureDelay,
		rows:      map[string]cachedUser{},
		authCache: map[string]authCacheEntry{},
		verifySem: make(chan struct{}, max(runtime.GOMAXPROCS(0), 1)),
	}
}

// lookup returns the user row (cached), false when there is no such user.
// Nil-safe: a server without a user manager has no users
func (m *UserManager) lookup(username string) (*types.BuiltinUser, bool) {
	if m == nil || username == "" {
		return nil, false
	}
	now := m.now()
	m.mu.RLock()
	cached, ok := m.rows[username]
	m.mu.RUnlock()
	if ok && now.Sub(cached.loadedAt) < userCacheTTL {
		return cached.user, true
	}

	user, err := m.store.GetBuiltinUser(context.Background(), username)
	if err != nil {
		if !errors.Is(err, types.ErrUserNotFound) {
			m.Error().Err(err).Msgf("error loading builtin user %s", username)
		}
		return nil, false
	}
	m.mu.Lock()
	m.rows[username] = cachedUser{user: user, loadedAt: now}
	m.mu.Unlock()
	return user, true
}

// activeUser returns the user row when the user exists and is not disabled:
// the lookup every grant of authority goes through (login, sessions, API
// keys, scheduled jobs, --as impersonation)
func (m *UserManager) activeUser(username string) (*types.BuiltinUser, bool) {
	user, ok := m.lookup(username)
	if !ok || user.Disabled() {
		return nil, false
	}
	return user, true
}

// groups resolves the current group membership of an active user, false for
// a missing or disabled user (which must lose all authority)
func (m *UserManager) groups(username string) ([]string, bool) {
	user, ok := m.activeUser(username)
	if !ok {
		return nil, false
	}
	return user.GroupList(), true
}

// invalidate drops the cached rows and cached authenticated headers of the
// named users
func (m *UserManager) invalidate(usernames ...string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, name := range usernames {
		delete(m.rows, name)
	}
	for key, entry := range m.authCache {
		for _, name := range usernames {
			if entry.username == name {
				delete(m.authCache, key)
				break
			}
		}
	}
}

// authenticate checks a Basic Authorization header against the users table,
// returning the principal (builtin:<username>) and the user's groups
func (m *UserManager) authenticate(authHeader string) (userId string, groups []string, ok bool) {
	if m == nil || authHeader == "" {
		return "", nil, false
	}
	username, password, ok := parseBasicAuth(authHeader)
	if !ok {
		return "", nil, false
	}

	user, ok := m.activeUser(username)
	if !ok {
		// Same cost as a real verification so timing does not reveal whether
		// the account exists (or is disabled)
		m.verify(passwd.DummyHash(), password) //nolint:errcheck
		m.Warn().Msgf("builtin auth user %s is not configured or is disabled", username)
		m.delay()
		return "", nil, false
	}
	now := m.now()
	if user.Locked(now) {
		m.Warn().Msgf("builtin auth user %s is locked until %s", username, user.LockedUntil.UTC().Format(time.RFC3339))
		m.delay()
		return "", nil, false
	}

	inputSha := sha512.Sum512([]byte(authHeader))
	shaKey := string(inputSha[:])
	m.mu.RLock()
	cached, hit := m.authCache[shaKey]
	m.mu.RUnlock()
	if !hit || cached.id != user.Id || cached.version != user.CredentialVersion {
		matched, err := m.verify(user.PasswordHash, password)
		if err != nil {
			m.Error().Err(err).Msgf("builtin auth: unusable password hash for user %s", username)
			m.delay()
			return "", nil, false
		}
		if !matched {
			m.recordFailure(user, now)
			m.delay()
			return "", nil, false
		}
		rehash := ""
		if passwd.NeedsRehash(user.PasswordHash) {
			if rehash, err = passwd.HashPassword(password); err != nil {
				m.Warn().Err(err).Msgf("could not rehash the password of builtin user %s", username)
				rehash = ""
			}
		}
		if err := m.store.RecordBuiltinLoginSuccess(context.Background(), user.Id, user.PasswordHash, rehash); err != nil {
			m.Error().Err(err).Msgf("error recording login for builtin user %s", username)
		}
		m.changed(username)
		m.mu.Lock()
		m.authCache[shaKey] = authCacheEntry{username: user.Username, id: user.Id, version: user.CredentialVersion}
		m.mu.Unlock()
	} else if user.LastLoginAt == nil || now.Sub(*user.LastLoginAt) >= lastLoginGranularity {
		m.stampLogin(user, now)
	}

	return string(types.AppAuthnBuiltin) + ":" + user.Username, user.GroupList(), true
}

// stampLogin records a sign-in that was authenticated from the cache: the
// password was not verified again, but it is a new login of the account, so
// last_login_at advances (and the failure counter resets). The cached row is
// patched in place rather than invalidated, which would drop the cached
// header and force a verification on the next request; the other nodes see
// the stamp when their row cache expires
func (m *UserManager) stampLogin(user *types.BuiltinUser, now time.Time) {
	if err := m.store.RecordBuiltinLoginSuccess(context.Background(), user.Id, user.PasswordHash, ""); err != nil {
		m.Error().Err(err).Msgf("error recording login for builtin user %s", user.Username)
		return
	}
	stamped := *user
	stamped.LastLoginAt, stamped.FailedAttempts, stamped.LockedUntil = &now, 0, nil
	m.mu.Lock()
	if cached, ok := m.rows[user.Username]; ok && cached.user == user {
		m.rows[user.Username] = cachedUser{user: &stamped, loadedAt: cached.loadedAt}
	}
	m.mu.Unlock()
}

// verify runs a password verification under the concurrency bound
func (m *UserManager) verify(hash, password string) (bool, error) {
	m.verifySem <- struct{}{}
	defer func() { <-m.verifySem }()
	return passwd.VerifyPassword(hash, password)
}

func (m *UserManager) delay() {
	if m.failDelay > 0 {
		time.Sleep(m.failDelay)
	}
}

// recordFailure counts a wrong password in the database (atomically, so
// concurrent failures cannot slip past the threshold), locking the account
// when the threshold is reached, and drops the cached row
func (m *UserManager) recordFailure(user *types.BuiltinUser, now time.Time) {
	locked, err := m.store.RecordBuiltinLoginFailure(context.Background(), user.Id, loginLockThreshold, now.Add(loginLockDuration))
	if err != nil {
		m.Error().Err(err).Msgf("error recording login failure for builtin user %s", user.Username)
	}
	if locked {
		m.Warn().Msgf("builtin auth user %s locked after %d failed logins", user.Username, loginLockThreshold)
	} else {
		m.Warn().Msgf("builtin auth password match failed for user %s", user.Username)
	}
	m.changed(user.Username)
}

// changed invalidates the local cache for the users and notifies the other
// nodes
func (m *UserManager) changed(usernames ...string) {
	m.invalidate(usernames...)
	if m.notify != nil {
		m.notify(usernames)
	}
}

// userNotifyHandler handles the cluster notification that user rows changed
// on another node
func (s *Server) userNotifyHandler(payload types.UserUpdatePayload) {
	if payload.ServerId == types.CurrentServerId {
		return
	}
	s.Debug().Str("server_id", string(payload.ServerId)).Msgf("Received user update notification for %v", payload.Usernames)
	s.users.invalidate(payload.Usernames...)
}

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]*$`)

// validateUsername checks a new builtin username: 1-64 characters, a letter
// or digit followed by letters, digits and . _ @ + - (basic auth encodes
// user:password, so a colon is impossible; whitespace only invites
// confusion). The names of the fixed principals and the openrun- prefix are
// reserved
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(username) > 64 {
		return fmt.Errorf("username cannot be longer than 64 characters")
	}
	if !usernamePattern.MatchString(username) {
		return fmt.Errorf("username must start with a letter or digit and contain only letters, digits and . _ @ + -")
	}
	lower := strings.ToLower(username)
	if lower == types.ADMIN_USER || lower == types.ANONYMOUS_USER || strings.HasPrefix(lower, "openrun-") {
		return fmt.Errorf("username %q is reserved", username)
	}
	return nil
}

// callerPrincipal is the user id recorded as the creator of a row: the
// request's user, or admin for trusted (UDS) calls without an identity
func callerPrincipal(ctx context.Context) string {
	return cmp.Or(system.GetContextUserId(ctx), types.ADMIN_USER)
}

func userInfo(u *types.BuiltinUser) types.BuiltinUserInfo {
	info := types.BuiltinUserInfo{
		Username:          u.Username,
		Groups:            u.GroupList(),
		Disabled:          u.Disabled(),
		CreatedBy:         u.CreatedBy,
		CreateTime:        u.CreateTime,
		PasswordUpdatedAt: u.PasswordUpdatedAt,
		LastLoginAt:       u.LastLoginAt,
	}
	if u.Locked(time.Now()) {
		info.LockedUntil = u.LockedUntil
	}
	return info
}

// CreateUpdateUser creates (update false) or updates (update true) one
// builtin user. The password is hashed here; empty on an update keeps the
// current hash. Groups nil on an update keeps the current groups. A password
// set, disable or enable bumps the credential version, which revokes the
// user's form-login sessions. Returns whether an existing user was updated
func (s *Server) CreateUpdateUser(ctx context.Context, username string, req types.UserUpdateRequest, update bool) (bool, error) {
	perm := types.PermissionUserCreate
	if update {
		perm = types.PermissionUserUpdate
	}
	if err := s.enforceGlobalPerm(ctx, perm, ""); err != nil {
		return false, err
	}

	if !update {
		if err := validateUsername(username); err != nil {
			return false, err
		}
		if err := s.enforceAdminGroupChange(ctx, nil, req.Groups); err != nil {
			return false, err
		}
		if req.Password == "" {
			return false, fmt.Errorf("password is required to create a user")
		}
		if err := passwd.ValidatePassword(req.Password, username); err != nil {
			return false, err
		}
		hash, err := passwd.HashPassword(req.Password)
		if err != nil {
			return false, err
		}
		user := &types.BuiltinUser{
			Id:           types.ID_PREFIX_USER + ksuid.New().String(),
			Username:     username,
			PasswordHash: hash,
			Groups:       req.Groups,
			CreatedBy:    callerPrincipal(ctx),
		}
		if user.Groups == nil {
			user.Groups = []string{}
		}
		if req.Disabled != nil && *req.Disabled {
			now := time.Now().UTC()
			user.DisabledAt = &now
		}
		if err := s.db.CreateBuiltinUser(ctx, user); err != nil {
			if errors.Is(err, metadata.ErrUserExists) {
				return false, fmt.Errorf("user %s already exists, use user update to change it", username)
			}
			return false, err
		}
		s.users.changed(username)
		return false, nil
	}

	if req.Password != "" {
		if err := passwd.ValidatePassword(req.Password, username); err != nil {
			return false, err
		}
	}
	// The account fields are written conditionally on the row version read
	// here; a concurrent update (another administrator, a login lockout does
	// not count) makes the write fail and the edit is re-applied to the
	// fresh row, so no concurrent change is silently undone
	for attempt := 0; ; attempt++ {
		user, err := s.db.GetBuiltinUser(ctx, username)
		if err != nil {
			if errors.Is(err, types.ErrUserNotFound) {
				return false, fmt.Errorf("user %s does not exist, use user add to create it", username)
			}
			return false, err
		}
		if req.Groups != nil {
			if err := s.enforceAdminGroupChange(ctx, user.Groups, req.Groups); err != nil {
				return false, err
			}
		}
		changed, err := applyUserUpdate(user, req)
		if err != nil {
			return false, err
		}
		if changed {
			if err := s.db.UpdateBuiltinUser(ctx, user); err != nil {
				if errors.Is(err, metadata.ErrUserConflict) && attempt < 3 {
					continue
				}
				return false, err
			}
		}
		if req.Unlock {
			if err := s.db.UnlockBuiltinUser(ctx, user.Id); err != nil {
				return false, err
			}
		}
		break
	}
	s.users.changed(username)
	return true, nil
}

// enforceAdminGroupChange rejects a builtin user group change which adds the
// user to, or removes the user from, a group that confers the admin
// permission under the live RBAC config, unless the caller holds
// admin:manage (or admin). user:create/user:update alone must not be a route
// to admin, matching the config update check (enforceAdminSurfaceChange)
func (s *Server) enforceAdminGroupChange(ctx context.Context, oldGroups, newGroups []string) error {
	if !s.rbacManager.APIEnforced(ctx) {
		return nil
	}
	oldAdmin := s.rbacManager.AdminGroupsIn(oldGroups)
	newAdmin := s.rbacManager.AdminGroupsIn(newGroups)
	if slices.Equal(oldAdmin, newAdmin) {
		return nil
	}
	if err := s.enforceGlobalPerm(ctx, types.PermissionAdminManage, ""); err != nil {
		return fmt.Errorf("groups %v confer the admin permission: changing a user's membership in them requires the admin:manage permission: %w",
			slices.Concat(oldAdmin, newAdmin), err)
	}
	return nil
}

// applyUserUpdate applies the request to the row, reporting whether any
// account field changed. A password set, disable or enable bumps the
// credential version, which revokes the user's form-login sessions
func applyUserUpdate(user *types.BuiltinUser, req types.UserUpdateRequest) (bool, error) {
	changed := false
	now := time.Now().UTC()
	if req.Password != "" {
		hash, err := passwd.HashPassword(req.Password)
		if err != nil {
			return false, err
		}
		user.PasswordHash = hash
		user.PasswordUpdatedAt = now
		user.CredentialVersion++
		changed = true
	}
	if req.Groups != nil {
		user.Groups = req.Groups
		changed = true
	}
	if req.Disabled != nil && *req.Disabled != user.Disabled() {
		if *req.Disabled {
			user.DisabledAt = &now
		} else {
			user.DisabledAt = nil
		}
		user.CredentialVersion++
		changed = true
	}
	return changed, nil
}

// DeleteUser removes a builtin user. The user's API keys and OAuth tokens
// are revoked in the same transaction as the row, so a user of the same
// name created later never inherits them
func (s *Server) DeleteUser(ctx context.Context, username string) error {
	if err := s.enforceGlobalPerm(ctx, types.PermissionUserDelete, ""); err != nil {
		return err
	}
	if err := s.db.DeleteBuiltinUser(ctx, username); err != nil {
		if errors.Is(err, types.ErrUserNotFound) {
			return fmt.Errorf("user %s does not exist", username)
		}
		return err
	}
	s.users.changed(username)
	return nil
}

// ListUsers returns the builtin users sorted by username, without hashes
func (s *Server) ListUsers(ctx context.Context) ([]types.BuiltinUserInfo, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionUserRead, ""); err != nil {
		return nil, err
	}
	users, err := s.db.ListBuiltinUsers(ctx)
	if err != nil {
		return nil, err
	}
	infos := make([]types.BuiltinUserInfo, 0, len(users))
	for i := range users {
		infos = append(infos, userInfo(&users[i]))
	}
	return infos, nil
}

// GetUser returns one builtin user, without the hash
func (s *Server) GetUser(ctx context.Context, username string) (*types.BuiltinUserInfo, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionUserRead, ""); err != nil {
		return nil, err
	}
	user, err := s.db.GetBuiltinUser(ctx, username)
	if err != nil {
		if errors.Is(err, types.ErrUserNotFound) {
			return nil, fmt.Errorf("user %s does not exist", username)
		}
		return nil, err
	}
	info := userInfo(user)
	return &info, nil
}

// importStaticBuiltinUsers inserts the deprecated [builtin_auth.*] entries of
// openrun.toml as users when no user of that name exists. An existing row is
// never changed by the static entry: the table is the source of truth
func (s *Server) importStaticBuiltinUsers(ctx context.Context) {
	entries := s.staticConfig.BuiltinAuth
	if len(entries) == 0 {
		return
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	imported := 0
	for _, name := range names {
		entry := entries[name]
		if !passwd.IsPasswordHash(entry.Password) {
			s.Warn().Msgf("[builtin_auth.%s] password is not a bcrypt or argon2id hash, entry skipped", name)
			continue
		}
		inserted, err := s.db.ImportBuiltinUser(ctx, &types.BuiltinUser{
			Id:           types.ID_PREFIX_USER + ksuid.New().String(),
			Username:     name,
			PasswordHash: entry.Password,
			Groups:       entry.Groups,
			CreatedBy:    "config",
		})
		if err != nil {
			s.Warn().Err(err).Msgf("error importing [builtin_auth.%s]", name)
			continue
		}
		if inserted {
			imported++
			s.users.changed(name)
		}
	}
	s.Warn().Msgf("[builtin_auth.*] in openrun.toml is deprecated: %d of %d entries imported as users "+
		"(existing users are not updated from the config); manage users with \"openrun user\" and remove the section",
		imported, len(names))
}
