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
	InitService(ctx context.Context, serviceConfig map[string]string) error                           // Initialize the service with the given config
	InitBaseBinding(ctx context.Context, bindingConfig map[string]string) error                       // Initialize the base binding against service with the given config
	InitDerivedBinding(ctx context.Context, grants []string, bindingConfig map[string]string) error   // Initialize the derived binding against service with the given config
	GenerateAccount(ctx context.Context, bindingId string, isStaging bool) (map[string]string, error) // Generate the account based on the binding config
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
			return fmt.Errorf("required config key %s is required", key)
		}
	}

	return nil
}
