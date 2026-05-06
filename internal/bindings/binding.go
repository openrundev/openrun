// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"fmt"
	"slices"
	"sync"
)

type ServiceBinding interface {
	InitService(ctx context.Context, serviceConfig map[string]string) error  // Initialize the service with the given config
	InitRootBinding(ctx context.Context, bindingConfig map[string]any) error // Initialize the root binding against service with the given config
	GenerateAccount(ctx context.Context) map[string]any                      // Generate the account based on the binding config
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

func verifyKeys(inputKeys []string, requiredKeys []string) error {
	for _, key := range inputKeys {
		if !slices.Contains(requiredKeys, key) {
			return fmt.Errorf("unknown config key: %s", key)
		}
	}

	for _, key := range requiredKeys {
		if !slices.Contains(inputKeys, key) {
			return fmt.Errorf("required config key %s is required", key)
		}
	}

	return nil
}
