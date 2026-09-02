// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func TestValidateBindingCreatePathRejectsAutoPrefix(t *testing.T) {
	tests := []string{
		"/auto",
		"/auto/app",
	}

	for _, bindingPath := range tests {
		t.Run(bindingPath, func(t *testing.T) {
			err := validateBindingCreatePath(bindingPath, false)
			if err == nil {
				t.Fatalf("validateBindingCreatePath(%q) should fail", bindingPath)
			}
			if !strings.Contains(err.Error(), "/auto is reserved for autobindings") {
				t.Fatalf("error = %q, want reserved autobindings message", err.Error())
			}
		})
	}
}

func TestValidateBindingCreatePathAllowsNonAutoPath(t *testing.T) {
	tests := []string{
		"/apps/b1",
		"/autobind",
		"/automation",
	}

	for _, bindingPath := range tests {
		t.Run(bindingPath, func(t *testing.T) {
			if err := validateBindingCreatePath(bindingPath, false); err != nil {
				t.Fatalf("validateBindingCreatePath returned error: %v", err)
			}
		})
	}
}

func TestValidateBindingCreatePathAllowsInternalAutoPath(t *testing.T) {
	if err := validateBindingCreatePath("/auto/app", true); err != nil {
		t.Fatalf("validateBindingCreatePath returned error: %v", err)
	}
}

// secretCaptureServiceBinding records the service config passed to
// InitializeService, for asserting secret reference resolution.
type secretCaptureServiceBinding struct {
	applyTestServiceBinding
	initConfig *map[string]string
}

func (b *secretCaptureServiceBinding) InitializeService(_ context.Context, _ *types.Logger, serviceConfig map[string]string, _ bindings.ServiceBindingRuntime) error {
	*b.initConfig = serviceConfig
	return nil
}

func TestServiceConfigSecretResolution(t *testing.T) {
	ctx := context.Background()
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{
		Metadata: types.MetadataConfig{
			DBConnection: "sqlite:" + filepath.Join(t.TempDir(), "metadata.db"),
			AutoUpgrade:  true,
		},
		Secret: map[string]types.SecretConfig{"env": {}},
	}
	db, err := metadata.NewMetadata(logger, config)
	if err != nil {
		t.Fatalf("new metadata: %v", err)
	}
	defer db.Close()

	secretsManager, err := system.NewSecretManager(ctx, config.Secret, config.AppConfig.Security.DefaultSecretsProvider, config)
	if err != nil {
		t.Fatalf("new secret manager: %v", err)
	}
	server := &Server{
		Logger:       logger,
		staticConfig: config,
		db:           db,
	}
	server.secretsManager.Store(secretsManager)
	rbacDisabledConfig := *config
	rbacDisabledConfig.Security.UnsafeDisableRBAC = true
	rbacManager, err := rbac.NewRBACHandler(logger, &types.RBACConfig{}, &rbacDisabledConfig)
	if err != nil {
		t.Fatalf("new rbac manager: %v", err)
	}
	server.rbacManager = rbacManager

	t.Setenv("CL_TEST_SERVICE_PASSWORD", "resolved-secret-value")

	var initConfig map[string]string
	previousBuilder, hadPreviousBuilder := bindings.GetServiceBinding("secrettest")
	bindings.SetServiceBinding("secrettest", func() bindings.ServiceBinding {
		return &secretCaptureServiceBinding{initConfig: &initConfig}
	})
	defer func() {
		if !hadPreviousBuilder {
			previousBuilder = nil
		}
		bindings.SetServiceBinding("secrettest", previousBuilder)
	}()

	service := &types.Service{
		Name:        "svc1",
		ServiceType: "secrettest",
		Config: map[string]string{
			"url":      "test://host/db",
			"password": `{{secret_from "env" "CL_TEST_SERVICE_PASSWORD"}}`,
			"literal":  "brace {{ but not a secret ref }}",
		},
	}
	if err := server.CreateService(ctx, service, false); err != nil {
		t.Fatalf("CreateService returned error: %v", err)
	}

	if got := initConfig["password"]; got != "resolved-secret-value" {
		t.Fatalf("password passed to InitializeService = %q, want resolved value", got)
	}
	if got := initConfig["literal"]; got != "brace {{ but not a secret ref }}" {
		t.Fatalf("non-secret value with braces was modified: %q", got)
	}
	if got := initConfig["url"]; got != "test://host/db" {
		t.Fatalf("url passed to InitializeService = %q, want unchanged", got)
	}

	// The stored config keeps the reference, not the resolved value
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	stored, err := db.GetService(ctx, tx, "secrettest", "svc1")
	if err != nil {
		t.Fatalf("GetService returned error: %v", err)
	}
	if got := stored.Config["password"]; got != `{{secret_from "env" "CL_TEST_SERVICE_PASSWORD"}}` {
		t.Fatalf("stored password = %q, want the secret reference", got)
	}
}
