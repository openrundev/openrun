// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/openrundev/openrun/internal/types"
)

const BindingHostnameDisable = "disable"

type ServiceBindingRuntime struct {
	LocalhostBindingHostname string
}

type ArtifactType string

const (
	ArtifactRole     ArtifactType = "role"
	ArtifactSchema   ArtifactType = "schema"
	ArtifactUser     ArtifactType = "user"
	ArtifactDatabase ArtifactType = "database"
)

// Artifact identifies one object created on the service by GenerateAccount, such as a
// role/schema (postgres) or user/database (mysql). The caller tracks the created
// artifacts and passes them back to DeleteArtifact to undo the creation on rollback.
type Artifact struct {
	Type ArtifactType
	Name string
}

type ServiceBinding interface {
	// Initialize the service with the given config. This is called when the service binding is created.
	InitializeService(ctx context.Context, logger *types.Logger, serviceConfig map[string]string, runtime ServiceBindingRuntime) error

	// Close the service connection. This is called when the service binding is no longer needed.
	CloseService(ctx context.Context) error

	// Generate the account based on the binding config. This is called once when the binding is created, after the service is initialized.
	// The account and its backing artifacts (role/schema, user/database) are created on the endpoint specified in the service config
	// and are persisted immediately. The artifacts that were created are returned in creation order; pre-existing objects that the
	// account merely references (like the base binding's schema for a derived binding) must not be included. If creation fails
	// partway and already-created artifacts cannot be rolled back internally, they are returned along with the error so the
	// caller can clean them up.
	GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata types.BindingMetadata,
		derivedFromMetadata *types.BindingMetadata, isStaging bool) (map[string]string, []Artifact, error)

	// Delete one artifact previously reported as created by GenerateAccount. The caller only passes back artifacts
	// created during the current operation; the implementation must delete only the named artifact.
	DeleteArtifact(ctx context.Context, artifact Artifact) error

	// Apply the grants to the account. This is called when the binding is created, after the account is generated.
	// The grants are applied to the account on the endpoint specified in the service config and are persisted immediately.
	// It can be called again if the grants are changed.
	ApplyGrants(ctx context.Context, account map[string]string,
		bindingMetadata, derivedFromMetadata types.BindingMetadata, reapplyAll bool) ([]types.BindingGrant, error)

	// Run a command on the endpoint specified in the service config as the binding account.
	RunCommand(ctx context.Context, bindingMetadata types.BindingMetadata, command string) (map[string]any, error)
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

func serviceConfigWithLocalhostBindingHostname(serviceConfig map[string]string, serviceURL string, runtime ServiceBindingRuntime) map[string]string {
	if serviceConfig["binding_hostname"] != "" || runtime.LocalhostBindingHostname == "" {
		return serviceConfig
	}

	parsedURL, err := url.Parse(serviceURL)
	if err != nil || !isLocalBindingHost(parsedURL.Hostname()) {
		return serviceConfig
	}

	effectiveConfig := make(map[string]string, len(serviceConfig)+1)
	for k, v := range serviceConfig {
		effectiveConfig[k] = v
	}
	effectiveConfig["binding_hostname"] = runtime.LocalhostBindingHostname
	return effectiveConfig
}

func isLocalBindingHost(host string) bool {
	return strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1"
}

func parseGrants(grants []string, supportedGrantTypes []types.GrantType) ([]types.BindingGrant, error) {
	parsedGrants := make([]types.BindingGrant, 0, len(grants))
	for _, grant := range grants {
		parsedGrant, err := types.ParseGrant(grant, supportedGrantTypes)
		if err != nil {
			return nil, err
		}
		parsedGrants = append(parsedGrants, parsedGrant)
	}
	return parsedGrants, nil
}

func diffGrants(currentGrants []types.BindingGrant, newGrants []types.BindingGrant) ([]types.BindingGrant, []types.BindingGrant) {
	revokeGrants := []types.BindingGrant{}
	applyGrants := []types.BindingGrant{}
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

func setURLHostname(u *url.URL, hostname string) {
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
