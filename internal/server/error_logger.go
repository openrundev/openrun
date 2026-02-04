// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

// tlsErrorEntry tracks occurrences of a specific TLS error
type tlsErrorEntry struct {
	firstSeen   time.Time
	lastLogged  time.Time
	count       int
	suppressKey string
}

// RateLimitedErrorLogger wraps an io.Writer and rate-limits repeated TLS handshake errors.
// It logs the first occurrence immediately, then suppresses for a configurable duration.
// After the suppression period, it logs again with the count of suppressed occurrences.
type RateLimitedErrorLogger struct {
	out              io.Writer
	suppressDuration time.Duration
	mu               sync.Mutex
	errors           map[string]*tlsErrorEntry
	// regex to match TLS handshake errors: "http: TLS handshake error from <addr>: <message>"
	tlsErrorRegex *regexp.Regexp
	stopCleanup   chan struct{}
}

// NewRateLimitedErrorLogger creates a new rate-limited error logger.
// It starts a background goroutine that cleans up old entries every 30 minutes.
func NewRateLimitedErrorLogger(out io.Writer) *RateLimitedErrorLogger {
	r := &RateLimitedErrorLogger{
		out:              out,
		suppressDuration: 5 * time.Minute,
		errors:           make(map[string]*tlsErrorEntry),
		// Match "http: TLS handshake error from <IP:port>: <error message>"
		// We extract the error message part to group similar errors
		tlsErrorRegex: regexp.MustCompile(`http: TLS handshake error from [^:]+:\d+: (.+)`),
		stopCleanup:   make(chan struct{}),
	}

	// Start background cleanup goroutine
	go r.cleanupLoop()
	return r
}

// Write implements io.Writer. It rate-limits TLS handshake errors while passing
// through other messages unchanged.
func (r *RateLimitedErrorLogger) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))

	// Check if this is a TLS handshake error
	matches := r.tlsErrorRegex.FindStringSubmatch(msg)
	if matches == nil {
		// Not a TLS handshake error, pass through
		return r.out.Write(p)
	}

	// Extract the error type as the suppression key (e.g., "certificate is not allowed for server name...")
	suppressKey := matches[1]
	// Further normalize by removing specific IP addresses/hostnames from the key
	suppressKey = normalizeErrorKey(suppressKey)

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	entry, exists := r.errors[suppressKey]

	if !exists {
		// First occurrence, log it and create entry
		r.errors[suppressKey] = &tlsErrorEntry{
			firstSeen:   now,
			lastLogged:  now,
			count:       1,
			suppressKey: suppressKey,
		}
		return r.out.Write(p)
	}

	// Entry exists, check if we should log again
	entry.count++

	if now.Sub(entry.lastLogged) >= r.suppressDuration {
		// Suppression period has elapsed, log with count
		entry.lastLogged = now
		suppressedCount := entry.count - 1 // -1 because we're about to log this one
		entry.count = 1                    // Reset count after logging

		if suppressedCount > 0 {
			// Log with count of suppressed occurrences
			summaryMsg := fmt.Sprintf("%s (repeated %d times in last %d minutes)\n",
				msg, suppressedCount, int(r.suppressDuration.Minutes()))
			return r.out.Write([]byte(summaryMsg))
		}
		// No suppressed messages, just log normally
		return r.out.Write(p)
	}

	// Within suppression period, suppress this message
	return len(p), nil
}

// normalizeErrorKey removes specific values (like IP addresses) from the error message
// to group similar errors together
func normalizeErrorKey(key string) string {
	// Remove specific server names/IPs that might vary
	// Pattern: "certificate is not allowed for server name X.X.X.X" -> normalize
	ipPattern := regexp.MustCompile(`server name [0-9.]+`)
	key = ipPattern.ReplaceAllString(key, "server name <IP>")

	hostnamePattern := regexp.MustCompile(`server name [a-zA-Z0-9.-]+`)
	key = hostnamePattern.ReplaceAllString(key, "server name <host>")

	return key
}

// cleanupLoop runs in a goroutine and periodically cleans up old entries
func (r *RateLimitedErrorLogger) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.cleanup(1 * time.Hour)
		case <-r.stopCleanup:
			return
		}
	}
}

// Stop stops the background cleanup goroutine
func (r *RateLimitedErrorLogger) Stop() {
	close(r.stopCleanup)
}

// cleanup removes old entries that haven't been seen in a while.
func (r *RateLimitedErrorLogger) cleanup(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for key, entry := range r.errors {
		if now.Sub(entry.lastLogged) > maxAge {
			delete(r.errors, key)
		}
	}
}
