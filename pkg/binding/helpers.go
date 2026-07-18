// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strings"
)

// RandomHex returns n random bytes hex-encoded, for generated account passwords.
func RandomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// VerifyKeys validates a service config's keys against the binding's required
// and optional key lists.
func VerifyKeys(inputKeys []string, requiredKeys []string, optionalKeys []string) error {
	for _, key := range inputKeys {
		if !slices.Contains(requiredKeys, key) && !slices.Contains(optionalKeys, key) {
			return fmt.Errorf("unknown config key: %s", key)
		}
	}

	for _, key := range requiredKeys {
		if !slices.Contains(inputKeys, key) {
			return fmt.Errorf("required config key %s is missing", key)
		}
	}

	return nil
}

// ServiceConfigWithLocalhostBindingHostname returns the service config with
// binding_hostname defaulted to the runtime's localhost binding hostname when
// the service URL points at localhost and no explicit binding_hostname is set.
func ServiceConfigWithLocalhostBindingHostname(serviceConfig map[string]string, serviceURL string, runtime ServiceBindingRuntime) map[string]string {
	if serviceConfig["binding_hostname"] != "" || runtime.LocalhostBindingHostname == "" {
		return serviceConfig
	}

	parsedURL, err := url.Parse(serviceURL)
	if err != nil || !IsLocalBindingHost(parsedURL.Hostname()) {
		return serviceConfig
	}

	effectiveConfig := make(map[string]string, len(serviceConfig)+1)
	maps.Copy(effectiveConfig, serviceConfig)
	effectiveConfig["binding_hostname"] = runtime.LocalhostBindingHostname
	return effectiveConfig
}

// IsLocalBindingHost reports whether host refers to the local host.
func IsLocalBindingHost(host string) bool {
	return strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1"
}

// ParseGrants parses a list of "type:target" grant strings.
func ParseGrants(grants []string, supportedGrantTypes []GrantType) ([]BindingGrant, error) {
	parsedGrants := make([]BindingGrant, 0, len(grants))
	for _, grant := range grants {
		parsedGrant, err := ParseGrant(grant, supportedGrantTypes)
		if err != nil {
			return nil, err
		}
		parsedGrants = append(parsedGrants, parsedGrant)
	}
	return parsedGrants, nil
}

// UnionGrants returns base plus any grants from extra not already present, preserving order.
func UnionGrants(base, extra []BindingGrant) []BindingGrant {
	merged := append([]BindingGrant{}, base...)
	for _, grant := range extra {
		if !slices.Contains(merged, grant) {
			merged = append(merged, grant)
		}
	}
	return merged
}

// SubtractGrants returns the grants in list that are not in remove, preserving order.
func SubtractGrants(list, remove []BindingGrant) []BindingGrant {
	ret := make([]BindingGrant, 0, len(list))
	for _, grant := range list {
		if !slices.Contains(remove, grant) {
			ret = append(ret, grant)
		}
	}
	return ret
}

// DiffGrants returns the grants to revoke (in currentGrants but not newGrants)
// and the grants to apply (in newGrants but not currentGrants).
func DiffGrants(currentGrants []BindingGrant, newGrants []BindingGrant) ([]BindingGrant, []BindingGrant) {
	revokeGrants := []BindingGrant{}
	applyGrants := []BindingGrant{}
	for _, appliedGrant := range currentGrants {
		if !slices.Contains(newGrants, appliedGrant) {
			revokeGrants = append(revokeGrants, appliedGrant)
		}
	}
	for _, newGrant := range newGrants {
		if !slices.Contains(currentGrants, newGrant) {
			applyGrants = append(applyGrants, newGrant)
		}
	}
	return revokeGrants, applyGrants
}

// SetURLHostname replaces the hostname in u, preserving the port. A hostname of
// "" or "disable" leaves the URL unchanged.
func SetURLHostname(u *url.URL, hostname string) {
	if hostname == "" || strings.EqualFold(hostname, BindingHostnameDisable) {
		return
	}
	hostname = strings.TrimPrefix(strings.TrimSuffix(hostname, "]"), "[")

	port := u.Port()
	if port == "" {
		if strings.Contains(hostname, ":") {
			u.Host = "[" + hostname + "]"
			return
		}
		u.Host = hostname
		return
	}
	u.Host = net.JoinHostPort(hostname, port)
}
