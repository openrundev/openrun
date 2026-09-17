// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Client ID Metadata Documents (CIMD, draft-ietf-oauth-client-id-metadata-
// document-00, MCP spec 2026-07-28 client-registration): an OAuth client
// uses an https URL as its client_id; the URL serves a JSON document with
// the client's name and redirect uris. The AS fetches the document on
// demand instead of holding a registration row, so CIMD clients never
// touch the oauth_clients table or the DCR quota. Dynamic registration
// (RFC 7591) stays available as the deprecated fallback.

const (
	cimdMaxDocSize      = 64 * 1024        // metadata documents are small; cap the body read
	cimdFetchTimeout    = 10 * time.Second // whole fetch, including dial and TLS
	cimdDefaultCacheTTL = 5 * time.Minute  // when the response carries no usable max-age
	cimdMaxCacheTTL     = 24 * time.Hour   // ceiling on a served max-age
	cimdMaxCacheEntries = 512
)

// cimdDocument is the subset of the client metadata document the AS uses
type cimdDocument struct {
	ClientId                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ClientUri               string   `json:"client_uri"`
	RedirectUris            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// LoopbackOnly reports whether every redirect uri targets loopback: the
// consent page warns then, since a document at any https address can claim
// to be a local application (spec security considerations)
func (d *cimdDocument) LoopbackOnly() bool {
	for _, uri := range d.RedirectUris {
		parsed, err := url.Parse(uri)
		if err != nil || !isLoopbackHost(parsed.Hostname()) {
			return false
		}
	}
	return len(d.RedirectUris) > 0
}

type cimdCacheEntry struct {
	doc     *cimdDocument
	expires time.Time
}

// cimdState is the in-process document cache. Embedded in oauthState; a
// cold cache after a restart or on another node only costs a refetch
type cimdState struct {
	cimdMu    sync.Mutex
	cimdCache map[string]cimdCacheEntry

	// cimdTLSConfig overrides the client TLS config (tests: trust the
	// httptest certificate). The SSRF dial guard applies regardless
	cimdTLSConfig *tls.Config
}

// isCIMDClientId reports whether the client id has the shape the draft
// requires of a metadata document URL: https, a host, a path component,
// no fragment and no credentials. Anything else is treated as an opaque
// (pre-registered or DCR) client id
func isCIMDClientId(clientId string) bool {
	if !strings.HasPrefix(clientId, "https://") {
		return false
	}
	parsed, err := url.Parse(clientId)
	if err != nil {
		return false
	}
	return parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil &&
		parsed.Fragment == "" && parsed.Path != "" && parsed.Path != "/"
}

// cimdDomainAllowed applies the operator's api.cimd_allowed_domains /
// api.cimd_denied_domains policy. An entry matches the host exactly or as
// a parent domain ("example.com" covers app.example.com). Deny wins; an
// empty allow list admits every domain
func (s *Server) cimdDomainAllowed(host string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	matches := func(entry string) bool {
		entry = strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(entry, "."), "."))
		return entry != "" && (host == entry || strings.HasSuffix(host, "."+entry))
	}
	config := s.Config().Api
	for _, entry := range config.CIMDDeniedDomains {
		if matches(entry) {
			return fmt.Errorf("client domain %q is denied by api.cimd_denied_domains", host)
		}
	}
	if len(config.CIMDAllowedDomains) == 0 {
		return nil
	}
	for _, entry := range config.CIMDAllowedDomains {
		if matches(entry) {
			return nil
		}
	}
	return fmt.Errorf("client domain %q is not in api.cimd_allowed_domains", host)
}

// isPrivateOrLocalIP is the SSRF guard: the AS must never be steered into
// loopback, private, link-local (incl. cloud metadata 169.254.169.254),
// carrier-grade NAT, unspecified or multicast addresses by a client id
func isPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 64 {
		return true // 100.64.0.0/10
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// cimdHTTPClient builds the fetch client: redirects are refused (a redirect
// is the classic SSRF pivot, and the draft does not require following
// them), and the dial control rejects private targets after DNS resolution
// unless api.cimd_allow_private_hosts is set (dev/air-gapped setups).
// Fetches go direct, never through HTTPS_PROXY: with a proxy the dial
// guard would only ever see the proxy's address while the proxy resolves
// and connects to the (possibly internal) document host. The transport is
// per fetch; the caller closes its idle connections when done
func (s *Server) cimdHTTPClient() (*http.Client, *http.Transport) {
	allowPrivate := s.Config().Api.CIMDAllowPrivateHosts
	dialer := &net.Dialer{
		Timeout: cimdFetchTimeout,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if !allowPrivate && isPrivateOrLocalIP(net.ParseIP(host)) {
				return fmt.Errorf("client metadata host resolves to a private or local address %s", host)
			}
			return nil
		},
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       s.cimdTLSConfig,
		TLSHandshakeTimeout:   cimdFetchTimeout,
		ResponseHeaderTimeout: cimdFetchTimeout,
		Proxy:                 nil, // direct only, see above
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       cimdFetchTimeout,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   cimdFetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, transport
}

// resolveCIMD returns the validated metadata document for a CIMD client id,
// from cache or by fetching it. Validation follows the draft: the document
// must be JSON, its client_id must equal the URL exactly, it must name the
// client and list at least one redirect uri, and (OpenRun policy, matching
// DCR) every redirect uri must be https or loopback http. Only public
// clients are supported: token_endpoint_auth_method must be absent or none
func (s *Server) resolveCIMD(ctx context.Context, clientId string) (*cimdDocument, error) {
	parsed, err := url.Parse(clientId)
	if err != nil || !isCIMDClientId(clientId) {
		return nil, fmt.Errorf("client_id is not a valid client metadata document url")
	}
	if err := s.cimdDomainAllowed(parsed.Hostname()); err != nil {
		return nil, err
	}

	s.cimdMu.Lock()
	entry, cached := s.cimdCache[clientId]
	s.cimdMu.Unlock()
	if cached && time.Now().Before(entry.expires) {
		return entry.doc, nil
	}

	doc, ttl, err := s.fetchCIMD(ctx, clientId)
	if err != nil {
		s.auditOAuthEvent(ctx, "oauth_cimd_fetch", clientId, false)
		return nil, fmt.Errorf("client metadata document %s: %w", clientId, err)
	}
	if !cached {
		// First sight of this client: audited like a DCR registration
		s.auditOAuthEvent(ctx, "oauth_cimd_fetch", clientId, true)
	}
	if ttl > 0 {
		s.cimdMu.Lock()
		if s.cimdCache == nil {
			s.cimdCache = map[string]cimdCacheEntry{}
		}
		if len(s.cimdCache) >= cimdMaxCacheEntries {
			s.pruneCIMDCacheLocked()
		}
		s.cimdCache[clientId] = cimdCacheEntry{doc: doc, expires: time.Now().Add(ttl)}
		s.cimdMu.Unlock()
	}
	return doc, nil
}

// pruneCIMDCacheLocked drops expired entries, then (if still full) the
// entries closest to expiry. Caller holds cimdMu
func (s *Server) pruneCIMDCacheLocked() {
	now := time.Now()
	for key, entry := range s.cimdCache {
		if !now.Before(entry.expires) {
			delete(s.cimdCache, key)
		}
	}
	for len(s.cimdCache) >= cimdMaxCacheEntries {
		var oldestKey string
		var oldest time.Time
		for key, entry := range s.cimdCache {
			if oldestKey == "" || entry.expires.Before(oldest) {
				oldestKey, oldest = key, entry.expires
			}
		}
		delete(s.cimdCache, oldestKey)
	}
}

// fetchCIMD performs the GET and validation, returning the document and
// the cache lifetime derived from the response (0 = do not cache)
func (s *Server) fetchCIMD(ctx context.Context, clientId string) (*cimdDocument, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, cimdFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientId, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "openrun-oauth-as")
	client, transport := s.cimdHTTPClient()
	// The transport is disposable: drop the kept-alive connection (and its
	// read loop goroutine) once the document is read, rather than leaving
	// it pooled on a transport nothing references again
	defer transport.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("fetch returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxDocSize+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read failed: %w", err)
	}
	if len(body) > cimdMaxDocSize {
		return nil, 0, fmt.Errorf("document exceeds %d bytes", cimdMaxDocSize)
	}
	var doc cimdDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("document is not valid JSON: %w", err)
	}
	if err := validateCIMDDocument(clientId, &doc); err != nil {
		return nil, 0, err
	}
	return &doc, cimdCacheTTL(resp.Header), nil
}

func validateCIMDDocument(clientId string, doc *cimdDocument) error {
	if doc.ClientId != clientId {
		return fmt.Errorf("document client_id %q does not match the document url", doc.ClientId)
	}
	if strings.TrimSpace(doc.ClientName) == "" {
		return fmt.Errorf("document has no client_name")
	}
	if len(doc.RedirectUris) == 0 {
		return fmt.Errorf("document has no redirect_uris")
	}
	for _, uri := range doc.RedirectUris {
		parsed, err := url.Parse(uri)
		valid := err == nil && parsed.Fragment == "" && (parsed.Scheme == "https" ||
			(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())))
		if !valid {
			return fmt.Errorf("redirect uri %q must be https or a loopback http url", uri)
		}
	}
	if method := doc.TokenEndpointAuthMethod; method != "" && method != "none" {
		return fmt.Errorf("token_endpoint_auth_method %q is not supported (public clients only)", method)
	}
	if len(doc.GrantTypes) > 0 {
		hasCode := false
		for _, grant := range doc.GrantTypes {
			if grant == "authorization_code" {
				hasCode = true
			}
		}
		if !hasCode {
			return fmt.Errorf("document grant_types must include authorization_code")
		}
	}
	return nil
}

// cimdCacheTTL honors Cache-Control: no-store/no-cache disable caching,
// max-age sets the lifetime (capped), otherwise a short default applies.
// Cache-Control is a list header and may be sent as several fields, so
// every value is inspected (a trailing no-store must win over an earlier
// max-age)
func cimdCacheTTL(header http.Header) time.Duration {
	ttl := cimdDefaultCacheTTL
	for _, directive := range strings.Split(strings.Join(header.Values("Cache-Control"), ","), ",") {
		directive = strings.TrimSpace(strings.ToLower(directive))
		switch {
		case directive == "no-store" || directive == "no-cache":
			return 0
		case strings.HasPrefix(directive, "max-age="):
			if secs, err := strconv.Atoi(strings.TrimPrefix(directive, "max-age=")); err == nil {
				ttl = time.Duration(secs) * time.Second
			}
		}
	}
	return min(max(ttl, 0), cimdMaxCacheTTL)
}
