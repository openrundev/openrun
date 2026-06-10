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

type applyPendingGrantServiceBinding struct {
	grantAvailable    *bool
	pendingApplyCalls *int
	reapplyAllCalls   *int
}

func (b *applyPendingGrantServiceBinding) InitializeService(context.Context, *types.Logger, map[string]string, bindings.ServiceBindingRuntime) error {
	return nil
}

func (b *applyPendingGrantServiceBinding) CloseService(context.Context) error {
	return nil
}

func (b *applyPendingGrantServiceBinding) BeginTransaction(ctx context.Context) (context.Context, error) {
	return ctx, nil
}

func (b *applyPendingGrantServiceBinding) CommitTransaction(context.Context) error {
	return nil
}

func (b *applyPendingGrantServiceBinding) RollbackTransaction(context.Context) error {
	return nil
}

func (b *applyPendingGrantServiceBinding) GenerateAccount(_ context.Context, bindingId, bindingPath string, _ types.BindingMetadata,
	_ *types.BindingMetadata, isStaging bool) (map[string]string, error) {
	mode := "prod"
	if isStaging {
		mode = "stage"
	}
	return map[string]string{
		"role":   bindingId + "_" + mode,
		"schema": strings.TrimPrefix(bindingPath, "/") + "_" + mode,
	}, nil
}

func (b *applyPendingGrantServiceBinding) ApplyGrants(_ context.Context, _ map[string]string, bindingMetadata, _ types.BindingMetadata,
	reapplyAll bool) ([]types.BindingGrant, error) {
	if reapplyAll {
		*b.reapplyAllCalls = *b.reapplyAllCalls + 1
	}
	if !*b.grantAvailable || len(bindingMetadata.Grants) == 0 {
		return append([]types.BindingGrant{}, bindingMetadata.GrantsApplied...), nil
	}
	grant := types.BindingGrant{GrantType: types.GrantTypeRead, GrantTarget: "late_table"}
	if !reapplyAll && slices.Contains(bindingMetadata.GrantsApplied, grant) {
		return append([]types.BindingGrant{}, bindingMetadata.GrantsApplied...), nil
	}
	*b.pendingApplyCalls = *b.pendingApplyCalls + 1
	grantsApplied := append([]types.BindingGrant{}, bindingMetadata.GrantsApplied...)
	if !slices.Contains(grantsApplied, grant) {
		grantsApplied = append(grantsApplied, grant)
	}
	return grantsApplied, nil
}

func (b *applyPendingGrantServiceBinding) RunCommand(context.Context, types.BindingMetadata, string) (map[string]any, error) {
	return nil, nil
}

func newApplyTestServer(t *testing.T) (*Server, *metadata.Metadata, context.Context) {
	t.Helper()
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
	return server, db, ctx
}

func TestApplyCreatesDerivedBindingFromBaseCreatedInSameApply(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
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
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
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

func TestLoadApplyInfoParsesAppVerify(t *testing.T) {
	server, db, _ := newApplyTestServer(t)
	defer db.Close()

	apps, _, err := server.loadApplyInfo("verify.ace", []byte(`app("/apps/verify-one", "/tmp/app", verify=True)
app("/apps/default", "/tmp/app")
`), "", false)
	if err != nil {
		t.Fatalf("load apply info: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("apps = %d, want 2", len(apps))
	}
	if !apps[0].Verify {
		t.Fatal("verify=True was not parsed")
	}
	if apps[1].Verify {
		t.Fatal("verify default = true, want false")
	}
}

func TestApplyVerifiesCreatedAppWithoutCountingInternalReload(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	applyDir := t.TempDir()
	t.Setenv("OPENRUN_HOME", applyDir)
	appSourceDir := filepath.Join(applyDir, "app")
	if err := os.Mkdir(appSourceDir, 0700); err != nil {
		t.Fatalf("create app source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appSourceDir, "app.star"), []byte(`app = ace.app("verifiedCreate")
`), 0600); err != nil {
		t.Fatalf("write app.star: %v", err)
	}

	applyPath := filepath.Join(applyDir, "app.ace")
	applyData := []byte(fmt.Sprintf(`app("/apps/new-verify", %q, verify=True)
`, appSourceDir))
	if err := os.WriteFile(applyPath, applyData, 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}

	response, _, sideEffects, err := server.Apply(ctx, types.Transaction{}, applyPath, "all", false, false, false,
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
	if sideEffects != nil {
		defer sideEffects.rollbackAndClose()
	}
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(response.CreateResults) != 1 {
		t.Fatalf("created apps = %v, want 1 app", response.CreateResults)
	}
	if len(response.ReloadResults) != 0 {
		t.Fatalf("reload results = %v, want created-app verification not counted", response.ReloadResults)
	}
}

func TestReapplyPendingBindingGrantsAppliesOnlyCurrentPendingGrants(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	grantAvailable := false
	pendingApplyCalls := 0
	reapplyAllCalls := 0
	previousBuilder, hadPreviousBuilder := bindings.ServiceBindings["pendingtest"]
	bindings.ServiceBindings["pendingtest"] = func() bindings.ServiceBinding {
		return &applyPendingGrantServiceBinding{
			grantAvailable:    &grantAvailable,
			pendingApplyCalls: &pendingApplyCalls,
			reapplyAllCalls:   &reapplyAllCalls,
		}
	}
	defer func() {
		if hadPreviousBuilder {
			bindings.ServiceBindings["pendingtest"] = previousBuilder
		} else {
			delete(bindings.ServiceBindings, "pendingtest")
		}
	}()

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	service := &types.Service{
		Id:          types.ID_PREFIX_SERVICE + "pendingtest",
		Name:        "primary",
		ServiceType: "pendingtest",
		IsDefault:   true,
		Config:      map[string]string{},
	}
	if err := db.CreateService(ctx, tx, service); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit service: %v", err)
	}

	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path:   "/apps/base",
		Source: "pendingtest/primary",
		Config: map[string]string{},
	}, false); err != nil {
		t.Fatalf("create base binding: %v", err)
	}
	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path:   "/apps/derived",
		Source: "/apps/base",
		Grants: []string{"read:late_table"},
		Config: map[string]string{},
	}, false); err != nil {
		t.Fatalf("create derived binding: %v", err)
	}
	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path:   "/apps/outside-apply",
		Source: "/apps/base",
		Grants: []string{"read:late_table"},
		Config: map[string]string{},
	}, false); err != nil {
		t.Fatalf("create outside apply binding: %v", err)
	}

	readTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	derived, err := db.GetBinding(ctx, readTx, "/apps/derived")
	if err != nil {
		t.Fatalf("get derived binding: %v", err)
	}
	if len(derived.Metadata.GrantsApplied) != 0 || len(derived.StagedMetadata.GrantsApplied) != 0 {
		t.Fatalf("initial grants applied = prod %v stage %v, want pending", derived.Metadata.GrantsApplied, derived.StagedMetadata.GrantsApplied)
	}
	outsideApply, err := db.GetBinding(ctx, readTx, "/apps/outside-apply")
	if err != nil {
		t.Fatalf("get outside apply binding: %v", err)
	}
	if len(outsideApply.Metadata.GrantsApplied) != 0 || len(outsideApply.StagedMetadata.GrantsApplied) != 0 {
		t.Fatalf("outside apply initial grants applied = prod %v stage %v, want pending", outsideApply.Metadata.GrantsApplied, outsideApply.StagedMetadata.GrantsApplied)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatalf("rollback read transaction: %v", err)
	}

	grantAvailable = true
	pendingApplyCalls = 0
	reapplyAllCalls = 0
	updateTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin update transaction: %v", err)
	}
	grantTxs := server.newBindingGrantTxManager(ctx, false)
	if err := server.reapplyPendingBindingGrants(ctx, updateTx, grantTxs, []string{"/apps/base", "/apps/derived"}); err != nil {
		t.Fatalf("reapply grants: %v", err)
	}
	if err := grantTxs.commit(); err != nil {
		t.Fatalf("commit grant txs: %v", err)
	}
	if err := updateTx.Commit(); err != nil {
		t.Fatalf("commit metadata: %v", err)
	}
	grantTxs.rollbackAndClose()

	verifyTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin verify transaction: %v", err)
	}
	derived, err = db.GetBinding(ctx, verifyTx, "/apps/derived")
	if err != nil {
		t.Fatalf("get derived binding: %v", err)
	}
	outsideApply, err = db.GetBinding(ctx, verifyTx, "/apps/outside-apply")
	if err != nil {
		t.Fatalf("get outside apply binding: %v", err)
	}
	wantGrant := types.BindingGrant{GrantType: types.GrantTypeRead, GrantTarget: "late_table"}
	if !slices.Contains(derived.Metadata.GrantsApplied, wantGrant) {
		t.Fatalf("prod grants applied = %v, want %v", derived.Metadata.GrantsApplied, wantGrant)
	}
	if !slices.Contains(derived.StagedMetadata.GrantsApplied, wantGrant) {
		t.Fatalf("staged grants applied = %v, want %v", derived.StagedMetadata.GrantsApplied, wantGrant)
	}
	if len(outsideApply.Metadata.GrantsApplied) != 0 || len(outsideApply.StagedMetadata.GrantsApplied) != 0 {
		t.Fatalf("outside apply grants applied = prod %v stage %v, want still pending", outsideApply.Metadata.GrantsApplied, outsideApply.StagedMetadata.GrantsApplied)
	}
	if pendingApplyCalls != 2 {
		t.Fatalf("pending grant apply calls = %d, want 2 for staging and production", pendingApplyCalls)
	}
	if reapplyAllCalls != 0 {
		t.Fatalf("reapply-all calls = %d, want 0", reapplyAllCalls)
	}
	if err := verifyTx.Rollback(); err != nil {
		t.Fatalf("rollback verify transaction: %v", err)
	}

	retryTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin retry transaction: %v", err)
	}
	grantTxs = server.newBindingGrantTxManager(ctx, false)
	if err := server.reapplyPendingBindingGrants(ctx, retryTx, grantTxs, []string{"/apps/derived"}); err != nil {
		t.Fatalf("second reapply grants: %v", err)
	}
	if err := grantTxs.commit(); err != nil {
		t.Fatalf("commit second grant txs: %v", err)
	}
	if err := retryTx.Commit(); err != nil {
		t.Fatalf("commit second metadata: %v", err)
	}
	grantTxs.rollbackAndClose()
	if pendingApplyCalls != 2 {
		t.Fatalf("pending grant apply calls after second retry = %d, want still 2", pendingApplyCalls)
	}
	if reapplyAllCalls != 0 {
		t.Fatalf("reapply-all calls after second retry = %d, want 0", reapplyAllCalls)
	}
}
