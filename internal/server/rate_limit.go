// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// ipRateLimiter is a fixed-window per-client-IP hit limiter. The map of
// IPs is pruned of stale windows at most once per window once it exceeds
// maxIPs, so a spray of distinct source IPs cannot make every call scan the
// whole map; its size is then bounded by the hit rate over one window
type ipRateLimiter struct {
	window time.Duration
	maxIPs int

	mu        sync.Mutex
	hits      map[string][]time.Time
	lastPrune time.Time
}

func newIPRateLimiter(window time.Duration, maxIPs int) *ipRateLimiter {
	return &ipRateLimiter{window: window, maxIPs: maxIPs, hits: map[string][]time.Time{}}
}

// allow records a hit for the IP and reports whether it is within maxHits
// per window; a maxHits of 0 or less allows everything
func (l *ipRateLimiter) allow(ip string, maxHits int) bool {
	return l.allowAt(ip, maxHits, time.Now())
}

func (l *ipRateLimiter) allowAt(ip string, maxHits int, now time.Time) bool {
	if maxHits <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	hits := l.hits[ip][:0:0]
	for _, hit := range l.hits[ip] {
		if now.Sub(hit) < l.window {
			hits = append(hits, hit)
		}
	}
	if len(hits) >= maxHits {
		l.hits[ip] = hits
		return false
	}
	l.hits[ip] = append(hits, now)
	if len(l.hits) > l.maxIPs && now.Sub(l.lastPrune) >= l.window {
		l.lastPrune = now
		for other, otherHits := range l.hits {
			if len(otherHits) == 0 || now.Sub(otherHits[len(otherHits)-1]) >= l.window {
				delete(l.hits, other)
			}
		}
	}
	return true
}

// overLimit reports whether the IP already has maxHits hits in the current
// window, without recording a hit; a maxHits of 0 or less never limits
func (l *ipRateLimiter) overLimit(ip string, maxHits int) bool {
	if maxHits <= 0 {
		return false
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	count := 0
	for _, hit := range l.hits[ip] {
		if now.Sub(hit) < l.window {
			count++
		}
	}
	return count >= maxHits
}

// record adds a hit for the IP (the hit is kept whether or not the IP is
// over its limit, so a client that keeps trying stays limited)
func (l *ipRateLimiter) record(ip string) {
	l.allowAt(ip, math.MaxInt, time.Now())
}

// passwordCheckAllowed applies security.login_failure_rate_limit before a
// password is verified: once the client IP has had that many failed checks
// in the window, further checks are refused without touching the password
// store, so an online guessing attack is bounded per source address
// independently of the per-account lockout (which an attacker could
// otherwise use to lock users out) and of the bcrypt/argon2 cost
func passwordCheckAllowed(limiter *ipRateLimiter, config *types.ServerConfig, r *http.Request) bool {
	if limiter == nil {
		return true
	}
	return !limiter.overLimit(system.GetClientIP(r, config.Security.TrustedProxies), config.Security.LoginFailureRateLimit)
}

// recordPasswordFailure counts a failed password check against the client IP
func recordPasswordFailure(limiter *ipRateLimiter, config *types.ServerConfig, r *http.Request) {
	if limiter == nil || config.Security.LoginFailureRateLimit <= 0 {
		return
	}
	limiter.record(system.GetClientIP(r, config.Security.TrustedProxies))
}

// tooManyPasswordFailures writes the response of a refused password check
func tooManyPasswordFailures(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	http.Error(w, "too many failed login attempts, retry later", http.StatusTooManyRequests)
}

// loginStartAllowed applies security.login_start_rate_limit (login starts
// per client IP per minute) to a request starting a login handshake: a
// start writes keystore rows (the state and the pre-auth session, retained
// for up to an hour) and, for SAML, signs a request, which an anonymous
// client must not be able to do at an arbitrary rate
func loginStartAllowed(limiter *ipRateLimiter, config *types.ServerConfig, r *http.Request) bool {
	if limiter == nil {
		return true
	}
	return limiter.allow(system.GetClientIP(r, config.Security.TrustedProxies), config.Security.LoginStartRateLimit)
}

// tooManyLoginStarts writes the response of a refused login start
func tooManyLoginStarts(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	http.Error(w, "too many login attempts, retry later", http.StatusTooManyRequests)
}
