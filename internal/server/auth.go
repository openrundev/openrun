// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/crypto/bcrypt"
)

// AdminBasicAuth implements basic auth for the admin user account.
// Cache the success auth header to avoid the bcrypt hash check penalty
// Basic auth is supported for admin user only, and changing it requires service restart.
// Caching the sha of the successful auth header allows us to skip the bcrypt check
// which significantly improves performance.
type AdminBasicAuth struct {
	*types.Logger
	config    *types.ServerConfig
	getConfig func() *types.ServerConfig // current (dynamic) config; the admin hash can change at runtime
	// generated is the hash of the admin password generated at startup, set
	// when the config has no admin_password_bcrypt
	generated *adminPasswordHash

	mu                sync.RWMutex
	authShaCached     string // sha of the last accepted header
	authShaCachedHash string // the password hash it was accepted against
}

// adminPasswordHash is the bcrypt hash of the admin password generated at
// startup, computed in the background: the server starts accepting
// connections without waiting for the bcrypt cost, and the first admin
// authentication waits for the hash instead
type adminPasswordHash struct {
	done chan struct{}
	hash string
}

func newAdminPasswordHash(logger *types.Logger, password string) *adminPasswordHash {
	h := &adminPasswordHash{done: make(chan struct{})}
	go func() {
		defer close(h.done)
		bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), passwd.BCRYPT_COST)
		if err != nil {
			// The admin account stays unusable (no hash matches); the
			// server keeps running for the other auth types
			logger.Error().Err(err).Msg("error hashing the generated admin password, admin login is not available")
			return
		}
		h.hash = string(bcryptHash)
	}()
	return h
}

// get waits for the hash to be computed
func (h *adminPasswordHash) get() string {
	<-h.done
	return h.hash
}

// passwordHash returns the admin password bcrypt hash: the configured one,
// or the one generated at startup (waiting for it on the first use). Empty
// when the admin account has no usable credential
func (a *AdminBasicAuth) passwordHash() string {
	if hash := a.getConfig().Security.AdminPasswordBcrypt; hash != "" {
		return hash
	}
	if a.generated != nil {
		return a.generated.get()
	}
	return ""
}

func NewAdminBasicAuth(logger *types.Logger, config *types.ServerConfig) *AdminBasicAuth {
	return &AdminBasicAuth{
		Logger:    logger,
		config:    config,
		getConfig: func() *types.ServerConfig { return config },
	}
}

func (a *AdminBasicAuth) authenticate(authHeader string) bool {
	// security.admin_password_bcrypt is dynamic config: a header cached
	// against a previous hash must not keep authenticating after a change
	passwordHash := a.passwordHash()
	a.mu.RLock()
	authShaCopy := a.authShaCached
	if a.authShaCachedHash != passwordHash {
		authShaCopy = ""
	}
	a.mu.RUnlock()

	if authShaCopy != "" {
		inputSha := sha512.Sum512([]byte(authHeader))
		inputShaSlice := inputSha[:]

		if subtle.ConstantTimeCompare(inputShaSlice, []byte(authShaCopy)) != 1 {
			a.Warn().Msg("Auth header cache check failed")
			time.Sleep(300 * time.Millisecond) // slow down brute force attacks
			return false
		}

		// Cached header matches, so we can skip the rest of the auth checks
		return true
	}

	user, pass, ok := a.BasicAuth(authHeader)
	if !ok {
		return false
	}

	adminUser := a.getConfig().AdminUser
	if adminUser == "" {
		a.Warn().Msg("No admin username specified, basic auth not available")
		return false
	}

	if subtle.ConstantTimeCompare([]byte(adminUser), []byte(user)) != 1 {
		// Same cost as a wrong password (the bcrypt compare is run against
		// the configured hash and discarded), so the response time does not
		// tell a wrong username from a wrong password
		a.Warn().Msg("Admin username does not match")
		bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(pass)) //nolint:errcheck
		time.Sleep(100 * time.Millisecond)
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(pass))
	if err != nil {
		a.Warn().Err(err).Msg("Password match failed")
		time.Sleep(100 * time.Millisecond) // slow down brute force attacks
		return false
	}

	// Successful request, so we can cache the auth header (for this hash)
	a.mu.Lock()
	if a.authShaCached == "" || a.authShaCachedHash != passwordHash {
		inputSha := sha512.Sum512([]byte(authHeader))
		a.authShaCached = string(inputSha[:])
		a.authShaCachedHash = passwordHash
	}
	a.mu.Unlock()
	return true
}

func (a *AdminBasicAuth) BasicAuth(authHeader string) (username, password string, ok bool) {
	if authHeader == "" {
		return "", "", false
	}
	return parseBasicAuth(authHeader)
}

// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) {
		return "", "", false
	}

	if subtle.ConstantTimeCompare([]byte(auth[:len(prefix)]), []byte(prefix)) != 1 {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}
