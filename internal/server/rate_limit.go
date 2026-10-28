// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
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
