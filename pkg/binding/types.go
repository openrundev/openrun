// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// Package binding is the SDK for OpenRun binding providers: out-of-process
// plugins that implement service bindings (account and grant management on
// external services like databases). A provider implements the ServiceBinding
// interface for one or more service types and calls Serve from its main
// function. The OpenRun server launches the provider executable on demand and
// communicates with it over gRPC using hashicorp/go-plugin.
//
// This package is a separate Go module so that providers only depend on the
// SDK's small dependency tree, not on the OpenRun server. It is distinct from
// the server embedding API in pkg/api.
package binding

import (
	"fmt"
	"slices"
	"strings"
)

// BindingMetadata is the metadata of one binding entry, as stored by the
// OpenRun server and passed to provider calls.
type BindingMetadata struct {
	Grants        []string          `json:"grants"`
	GrantsApplied []BindingGrant    `json:"grants_applied"`
	Config        map[string]string `json:"config"`
	Account       map[string]string `json:"account,omitempty"`
	ApplyInfo     []byte            `json:"apply_info"`
}

type GrantType string

const (
	GrantTypeRead   GrantType = "READ"
	GrantTypeCreate GrantType = "CREATE"
	GrantTypeFull   GrantType = "FULL"
)

const (
	GrantTargetAll = "*"
)

// ParseGrant parses a "type:target" grant string, verifying the type against
// the service's supported grant types.
func ParseGrant(grant string, supportedGrantTypes []GrantType) (BindingGrant, error) {
	grantType, grantTarget, ok := strings.Cut(grant, ":")
	if !ok || grantType == "" {
		return BindingGrant{}, fmt.Errorf("invalid grant format, expected type:<target>, got: %s", grant)
	}
	grantType = strings.ToUpper(strings.TrimSpace(grantType))
	if !slices.Contains(supportedGrantTypes, GrantType(grantType)) {
		supportedGrantTypesStr := make([]string, len(supportedGrantTypes))
		for i, gt := range supportedGrantTypes {
			supportedGrantTypesStr[i] = string(gt)
		}
		return BindingGrant{}, fmt.Errorf("unsupported grant type: %s, supported types: %s", grantType, strings.Join(supportedGrantTypesStr, ", "))
	}
	return BindingGrant{
		GrantType:   GrantType(grantType),
		GrantTarget: strings.TrimSpace(grantTarget),
	}, nil
}

type BindingGrant struct {
	GrantType   GrantType `json:"grant_type"`
	GrantTarget string    `json:"grant_target"`
}

func (g BindingGrant) String() string {
	return fmt.Sprintf("%s:%s", g.GrantType, g.GrantTarget)
}
