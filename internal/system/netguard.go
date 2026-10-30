// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
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
