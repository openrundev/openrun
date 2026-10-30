// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// ErrPrivateAddress is wrapped by the errors refusing a fetch of a private or
// local address
var ErrPrivateAddress = errors.New("private or local address")

// IsPrivateOrLocalIP is the SSRF guard for outbound fetches of untrusted
// urls: they must never be steered into loopback, private, link-local (incl.
// cloud metadata 169.254.169.254), carrier-grade NAT, unspecified or
// multicast addresses
func IsPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1]&0xc0 == 64 {
			return true // 100.64.0.0/10
		}
		if ip4[0] == 0 {
			return true // 0.0.0.0/8 ("this network", routed to local on some stacks)
		}
	} else if nat64 := net.ParseIP("64:ff9b::"); nat64 != nil && ip.Mask(net.CIDRMask(96, 128)).Equal(nat64) {
		// 64:ff9b::/96 (NAT64) embeds an IPv4 address, which may be private
		return IsPrivateOrLocalIP(net.IPv4(ip[12], ip[13], ip[14], ip[15]))
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// PublicOnlyDialControl is a net.Dialer Control function refusing a
// connection to a private or local address. It runs after DNS resolution,
// on the address actually dialed, so a public name resolving (or rebinding)
// to an internal address is refused too. what names the fetch in the error
func PublicOnlyDialControl(what string) func(network, address string, _ syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if IsPrivateOrLocalIP(net.ParseIP(host)) {
			return fmt.Errorf("%s host resolves to a %w %s", what, ErrPrivateAddress, host)
		}
		return nil
	}
}

// CheckPublicHost refuses a host which is, or resolves to, a private or local
// address. It is for a fetch whose connection is made by a proxy, where the
// dial check sees only the proxy's address. It is best effort: the proxy
// does its own lookup, so a name rebinding between the two lookups is not
// caught, and a name which does not resolve here (the proxy may resolve
// names the server cannot) is allowed. The proxy's egress policy covers those
func CheckPublicHost(ctx context.Context, what, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if IsPrivateOrLocalIP(ip) {
			return fmt.Errorf("%s host is a %w %s", what, ErrPrivateAddress, host)
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if IsPrivateOrLocalIP(addr.IP) {
			return fmt.Errorf("%s host %s resolves to a %w %s", what, host, ErrPrivateAddress, addr.IP)
		}
	}
	return nil
}

// PublicOnlyTransport routes each request (each redirect hop is a separate
// request) to one of two transports, so that whether a connection is checked
// is fixed by the transport making it, not by state shared between requests.
// direct never uses a proxy and dials public addresses only. proxied dials
// only the proxy, which may be on a private address: its Proxy function
// fails a request the proxy does not apply to instead of letting it dial
// direct, and the target host is checked before the request is handed to it
type PublicOnlyTransport struct {
	what    string
	proxy   func(*http.Request) (*url.URL, error)
	direct  *http.Transport
	proxied *http.Transport
}

// NewPublicOnlyTransport returns a transport refusing private or local
// targets. what names the fetch in errors. proxy is the proxy policy
// (http.ProxyFromEnvironment, or nil for direct connections only).
// newTransport builds a transport with the caller's timeouts from the proxy
// function and dial control it must use; it is called once per inner
// transport. CloseIdleConnections releases both
func NewPublicOnlyTransport(what string, proxy func(*http.Request) (*url.URL, error),
	newTransport func(proxy func(*http.Request) (*url.URL, error),
		control func(network, address string, c syscall.RawConn) error) *http.Transport) *PublicOnlyTransport {
	if proxy == nil {
		proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	}
	t := &PublicOnlyTransport{what: what, proxy: proxy}
	t.direct = newTransport(nil, PublicOnlyDialControl(what))
	t.proxied = newTransport(func(req *http.Request) (*url.URL, error) {
		proxyURL, err := proxy(req)
		if err == nil && proxyURL == nil {
			err = fmt.Errorf("%s fetch of %s is not proxied", what, req.URL.Host)
		}
		return proxyURL, err
	}, nil)
	return t
}

func (t *PublicOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	proxyURL, err := t.proxy(req)
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		return t.direct.RoundTrip(req)
	}
	// The proxy dials the target, the host is checked here, as the transport
	// sends it, so a fullwidth １０.１.２.３ is checked as 10.1.2.3
	if err := CheckPublicHost(req.Context(), t.what, CanonicalHost(req.URL)); err != nil {
		return nil, err
	}
	return t.proxied.RoundTrip(req)
}

// CloseIdleConnections closes the idle connections of both inner transports
func (t *PublicOnlyTransport) CloseIdleConnections() {
	t.direct.CloseIdleConnections()
	t.proxied.CloseIdleConnections()
}

// CanonicalHost is u's host as net/http sends it in a proxy CONNECT (its
// canonicalAddr): a non-ASCII host is mapped through IDNA, so a fullwidth
// １２７.０.０.１ becomes 127.0.0.1
func CanonicalHost(u *url.URL) string {
	host := u.Hostname()
	if !isASCII(host) {
		if v, err := idna.Lookup.ToASCII(host); err == nil {
			host = v
		}
	}
	return host
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
