// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/openrundev/openrun/internal/types"
)

type ServiceBinding interface {
	InitService(ctx context.Context, logger *types.Logger, serviceConfig map[string]string) error                              // Initialize the service with the given config
	InitBinding(ctx context.Context, binding *types.Binding, baseBinding *types.Binding, grants []string) error                // Initialize the binding against service with the given config
	GenerateAccount(ctx context.Context, bindingConfig map[string]string, isStaging bool) (map[string]string, []string, error) // Generate the account based on the binding config
}

type ServiceBindingBuilder func() ServiceBinding

var (
	initMutex       sync.Mutex
	ServiceBindings = map[string]ServiceBindingBuilder{}
)

// RegisterServiceBinding registers a service binding
func RegisterServiceBinding(name string, serviceBindingBuilder ServiceBindingBuilder) {
	initMutex.Lock()
	defer initMutex.Unlock()
	ServiceBindings[name] = serviceBindingBuilder
}

func verifyKeys(inputKeys []string, requiredKeys []string, optionalKeys []string) error {
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

type GrantType string

const (
	GrantTypeRead   GrantType = "READ"
	GrantTypeCreate GrantType = "CREATE"
	GrantTypeFull   GrantType = "FULL"
)

const (
	GrantTargetAll = "*"
)

func parseGrant(grant string, supportedGrantTypes []GrantType) (GrantType, string, error) {
	grantType, grantTarget, ok := strings.Cut(grant, ":")
	if !ok || grantType == "" {
		return "", "", fmt.Errorf("invalid grant format, expected type:<target>, got: %s", grant)
	}
	grantType = strings.ToUpper(grantType)
	if !slices.Contains(supportedGrantTypes, GrantType(grantType)) {
		supportedGrantTypesStr := make([]string, len(supportedGrantTypes))
		for i, gt := range supportedGrantTypes {
			supportedGrantTypesStr[i] = string(gt)
		}
		return "", "", fmt.Errorf("unsupported grant type: %s, supported types: %s", grantType, strings.Join(supportedGrantTypesStr, ", "))
	}
	return GrantType(grantType), grantTarget, nil
}
