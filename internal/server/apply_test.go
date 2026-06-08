// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

type applyTestServiceBinding struct{}

func (b *applyTestServiceBinding) InitializeService(context.Context, *types.Logger, map[string]string, bindings.ServiceBindingRuntime) error {
	return nil
}

func (b *applyTestServiceBinding) CloseService(context.Context) error {
	return nil
}

func (b *applyTestServiceBinding) BeginTransaction(ctx context.Context) (context.Context, error) {
	return ctx, nil
}

func (b *applyTestServiceBinding) CommitTransaction(context.Context) error {
	return nil
}

func (b *applyTestServiceBinding) RollbackTransaction(context.Context) error {
	return nil
}

func (b *applyTestServiceBinding) GenerateAccount(_ context.Context, bindingId, bindingPath string, _ types.BindingMetadata,
	derivedFromMetadata *types.BindingMetadata, isStaging bool) (map[string]string, error) {
	if derivedFromMetadata != nil && derivedFromMetadata.Account["role"] == "" {
		return nil, fmt.Errorf("derived binding account not visible")
	}

	mode := "prod"
	if isStaging {
		mode = "stage"
	}
	accountName := strings.TrimPrefix(bindingPath, "/")
	return map[string]string{
		"role":   bindingId + "_" + mode,
		"schema": strings.ReplaceAll(accountName, "/", "_") + "_" + mode,
	}, nil
}

func (b *applyTestServiceBinding) ApplyGrants(_ context.Context, _ map[string]string, bindingMetadata, derivedFromMetadata types.BindingMetadata,
	_ bool) ([]types.BindingGrant, error) {
	if derivedFromMetadata.Account["role"] == "" {
		return nil, fmt.Errorf("derived binding account not visible")
	}
	if len(bindingMetadata.Grants) == 0 {
		return nil, nil
	}
	return []types.BindingGrant{{GrantType: types.GrantTypeRead, GrantTarget: "*"}}, nil
}

func (b *applyTestServiceBinding) RunCommand(context.Context, types.BindingMetadata, string) (map[string]any, error) {
	return nil, nil
}

func TestApplyCreatesDerivedBindingFromBaseCreatedInSameApply(t *testing.T) {
	ctx := context.Background()
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{
		Metadata: types.MetadataConfig{
			DBConnection: "sqlite:" + filepath.Join(t.TempDir(), "metadata.db"),
			AutoUpgrade:  true,
		},
	}
	db, err := metadata.NewMetadata(logger, config)
	if err != nil {
		t.Fatalf("new metadata: %v", err)
	}
	defer db.Close()

	previousBuilder, hadPreviousBuilder := bindings.ServiceBindings["applytest"]
	bindings.ServiceBindings["applytest"] = func() bindings.ServiceBinding {
		return &applyTestServiceBinding{}
	}
	defer func() {
		if hadPreviousBuilder {
			bindings.ServiceBindings["applytest"] = previousBuilder
		} else {
			delete(bindings.ServiceBindings, "applytest")
		}
	}()

	secretsManager, err := system.NewSecretManager(ctx, config.Secret, config.AppConfig.Security.DefaultSecretsProvider, config)
	if err != nil {
		t.Fatalf("new secret manager: %v", err)
	}
	server := &Server{
		Logger:         logger,
		config:         config,
		db:             db,
		secretsManager: secretsManager,
		notifyClose:    make(chan types.AppPathDomain),
	}
	server.apps = NewAppStore(logger, server)

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	service := &types.Service{
		Id:          types.ID_PREFIX_SERVICE + "applytest",
		Name:        "primary",
		ServiceType: "applytest",
		IsDefault:   true,
		Config:      map[string]string{},
	}
	if err := db.CreateService(ctx, tx, service); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit service: %v", err)
	}

	applyDir := t.TempDir()
	appSourceDir := filepath.Join(applyDir, "app")
	if err := os.Mkdir(appSourceDir, 0700); err != nil {
		t.Fatalf("create app source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appSourceDir, "app.star"), []byte(`app = ace.app("testApp")
`), 0600); err != nil {
		t.Fatalf("write app.star: %v", err)
	}

	applyPath := filepath.Join(applyDir, "bindings.ace")
	applyData := []byte(fmt.Sprintf(`binding("/apps/base", "applytest/primary")
binding("/apps/derived", "/apps/base", grants=["read:*"])
app("/apps/uses-derived", %q, bindings=["/apps/derived"])
`, appSourceDir))
	if err := os.WriteFile(applyPath, applyData, 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}

	response, _, sideEffects, err := server.Apply(ctx, types.Transaction{}, applyPath, "/apps/**", false, false, false,
		types.AppReloadOptionNone, "", "", "", false, false, "", nil, false)
	if sideEffects != nil {
		defer sideEffects.rollbackAndClose()
	}
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(response.CreateBindingResults) != 2 {
		t.Fatalf("created bindings = %v, want 2 bindings", response.CreateBindingResults)
	}
	if response.CreateBindingResults[0] != "/apps/base" || response.CreateBindingResults[1] != "/apps/derived" {
		t.Fatalf("created bindings = %v, want declared order", response.CreateBindingResults)
	}
	if len(response.CreateResults) != 1 {
		t.Fatalf("created apps = %v, want 1 app", response.CreateResults)
	}
	if len(response.CreateResults[0].ApproveResults) == 0 {
		t.Fatal("created app did not include approval results")
	}
	approveResult := response.CreateResults[0].ApproveResults[0]
	if !approveResult.NeedsApproval {
		t.Fatal("created app with derived binding did not require approval")
	}
	if !slices.Contains(approveResult.NewBindingSourcePerms, "/apps/base") {
		t.Fatalf("binding source perms = %v, want /apps/base", approveResult.NewBindingSourcePerms)
	}

	readTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer readTx.Rollback() //nolint:errcheck
	derived, err := db.GetBinding(ctx, readTx, "/apps/derived")
	if err != nil {
		t.Fatalf("get derived binding: %v", err)
	}
	if derived.DerivedFrom != "/apps/base" {
		t.Fatalf("derived from = %q, want /apps/base", derived.DerivedFrom)
	}
	if derived.Metadata.Account["role"] == "" {
		t.Fatal("derived binding prod account was not stored")
	}
	if derived.StagedMetadata.Account["role"] == "" {
		t.Fatal("derived binding staged account was not stored")
	}
}
