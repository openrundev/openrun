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
	config *types.ServerConfig

	mu            sync.RWMutex
	authShaCached string
}

func NewAdminBasicAuth(logger *types.Logger, config *types.ServerConfig) *AdminBasicAuth {
	return &AdminBasicAuth{
		Logger: logger,
		config: config,
	}
}

func (a *AdminBasicAuth) authenticate(authHeader string) bool {
	a.mu.RLock()
	authShaCopy := a.authShaCached
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

	if a.config.AdminUser == "" {
		a.Warn().Msg("No admin username specified, basic auth not available")
		return false
	}

	if subtle.ConstantTimeCompare([]byte(a.config.AdminUser), []byte(user)) != 1 {
		a.Warn().Msg("Admin username does not match")
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(a.config.Security.AdminPasswordBcrypt), []byte(pass))
	if err != nil {
		a.Warn().Err(err).Msg("Password match failed")
		time.Sleep(100 * time.Millisecond) // slow down brute force attacks
		return false
	}

	a.mu.RLock()
	authShaCopy = a.authShaCached
	a.mu.RUnlock()
	if authShaCopy == "" {
		// Successful request, so we can cache the auth header
		a.mu.Lock()
		inputSha := sha512.Sum512([]byte(authHeader))
		a.authShaCached = string(inputSha[:])
		a.mu.Unlock()
	}
	return true
}

func (a *AdminBasicAuth) BasicAuth(authHeader string) (username, password string, ok bool) {
	if authHeader == "" {
		return "", "", false
	}
	return a.parseBasicAuth(authHeader)
}

// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func (a *AdminBasicAuth) parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
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
