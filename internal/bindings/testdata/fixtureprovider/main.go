// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// fixtureprovider is a test-only binding provider used by the OpenRun server
// e2e tests to exercise the out-of-process provider protocol, including
// crash/respawn recovery.
package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/openrundev/openrun/pkg/binding"
)

type fixtureBinding struct {
	serviceConfig map[string]string
}

func (f *fixtureBinding) GetAccountEnv(ctx context.Context) ([]string, []string, error) {
	return []string{"user"}, []string{"fixture_opt"}, nil
}

func (f *fixtureBinding) InitializeService(ctx context.Context, logger *binding.Logger, serviceConfig map[string]string, runtime binding.ServiceBindingRuntime) error {
	if serviceConfig["fail_init"] != "" {
		return errors.New(serviceConfig["fail_init"])
	}
	f.serviceConfig = serviceConfig
	return nil
}

func (f *fixtureBinding) CloseService(ctx context.Context) error {
	return nil
}

func (f *fixtureBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata binding.BindingMetadata,
	derivedFromMetadata *binding.BindingMetadata, isStaging bool) (map[string]string, []binding.Artifact, error) {
	artifacts := []binding.Artifact{{Type: binding.ArtifactUser, Name: "fx_" + bindingId}}
	if bindingMetadata.Config["partial_failure"] != "" {
		return nil, artifacts, errors.New("fixture partial failure")
	}
	return map[string]string{"user": "fx_" + bindingId}, artifacts, nil
}

func (f *fixtureBinding) DeleteArtifact(ctx context.Context, artifact binding.Artifact) error {
	return nil
}

func (f *fixtureBinding) ApplyGrants(ctx context.Context, account map[string]string,
	bindingMetadata, derivedFromMetadata binding.BindingMetadata, reapplyAll bool) (binding.GrantApplyResult, error) {
	return binding.GrantApplyResult{}, nil
}

func (f *fixtureBinding) RevokeGrants(ctx context.Context, account map[string]string,
	derivedFromMetadata binding.BindingMetadata, revokes, regrants []binding.BindingGrant) error {
	return nil
}

func (f *fixtureBinding) RunCommand(ctx context.Context, bindingMetadata binding.BindingMetadata, command string) (map[string]any, error) {
	switch {
	case strings.HasPrefix(command, "echo:"):
		return map[string]any{"echo": strings.TrimPrefix(command, "echo:"), "url": f.serviceConfig["url"]}, nil
	case strings.HasPrefix(command, "crash_once:"):
		// Crash the provider process the first time, succeed after the server
		// respawns it: the marker file records that the crash already happened.
		marker := strings.TrimPrefix(command, "crash_once:")
		if _, err := os.Stat(marker); err != nil {
			_ = os.WriteFile(marker, []byte("crashed"), 0o600)
			os.Exit(1)
		}
		return map[string]any{"recovered": true}, nil
	case command == "fail":
		return nil, errors.New("fixture command failed")
	}
	return map[string]any{}, nil
}

func main() {
	binding.Serve(&binding.ServeConfig{
		ProviderVersion: "v0.0.0-fixture",
		Bindings: map[string]binding.Builder{
			"fixture": func() binding.ServiceBinding { return &fixtureBinding{} },
		},
	})
}
