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
	"time"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/builder"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/rbac"
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

func (b *applyTestServiceBinding) DeleteArtifact(context.Context, bindings.Artifact) error {
	return nil
}

func (b *applyTestServiceBinding) GenerateAccount(_ context.Context, bindingId, bindingPath string, _ types.BindingMetadata,
	derivedFromMetadata *types.BindingMetadata, isStaging bool) (map[string]string, []bindings.Artifact, error) {
	if derivedFromMetadata != nil && derivedFromMetadata.Account["role"] == "" {
		return nil, nil, fmt.Errorf("derived binding account not visible")
	}

	mode := "prod"
	if isStaging {
		mode = "stage"
	}
	accountName := strings.TrimPrefix(bindingPath, "/")
	role := bindingId + "_" + mode
	return map[string]string{
		"role":   role,
		"schema": strings.ReplaceAll(accountName, "/", "_") + "_" + mode,
	}, []bindings.Artifact{{Type: bindings.ArtifactRole, Name: role}}, nil
}

func (b *applyTestServiceBinding) ApplyGrants(_ context.Context, _ map[string]string, bindingMetadata, derivedFromMetadata types.BindingMetadata,
	_ bool) (bindings.GrantApplyResult, error) {
	if derivedFromMetadata.Account["role"] == "" {
		return bindings.GrantApplyResult{}, fmt.Errorf("derived binding account not visible")
	}
	if len(bindingMetadata.Grants) == 0 {
		return bindings.GrantApplyResult{}, nil
	}
	grant := types.BindingGrant{GrantType: types.GrantTypeRead, GrantTarget: "*"}
	return bindings.GrantApplyResult{
		GrantsApplied: []types.BindingGrant{grant},
		Granted:       []types.BindingGrant{grant},
	}, nil
}

func (b *applyTestServiceBinding) RevokeGrants(context.Context, map[string]string, types.BindingMetadata, []types.BindingGrant, []types.BindingGrant) error {
	return nil
}

func TestLoadApplyInfoStageAt(t *testing.T) {
	t.Parallel()

	server := &Server{
		Logger:       types.NewLogger(&types.LogConfig{Level: "WARN"}),
		staticConfig: &types.ServerConfig{},
	}
	apps, _, err := server.loadApplyInfo("stage_at.ace", []byte(`app("/apps/stage-at", "/tmp/app", stage_at="stage.example.com")`), "", false)
	if err != nil {
		t.Fatalf("loadApplyInfo returned error: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("apps length = %d, want 1", len(apps))
	}
	if apps[0].StageAt != "stage.example.com" {
		t.Fatalf("StageAt = %q, want %q", apps[0].StageAt, "stage.example.com")
	}
}

func (b *applyTestServiceBinding) RunCommand(context.Context, types.BindingMetadata, string) (map[string]any, error) {
	return nil, nil
}

type applyPendingGrantServiceBinding struct {
	grantAvailable    *bool
	pendingApplyCalls *int
	reapplyAllCalls   *int
}

type applyAccountTrackingServiceBinding struct {
	generateCalls    *int
	failAfterCreate  *bool
	deletedArtifacts *[]bindings.Artifact
	closed           *int
}

func (b *applyAccountTrackingServiceBinding) InitializeService(context.Context, *types.Logger, map[string]string, bindings.ServiceBindingRuntime) error {
	return nil
}

func (b *applyAccountTrackingServiceBinding) CloseService(context.Context) error {
	*b.closed = *b.closed + 1
	return nil
}

func (b *applyAccountTrackingServiceBinding) GenerateAccount(_ context.Context, bindingId, _ string, _ types.BindingMetadata,
	_ *types.BindingMetadata, isStaging bool) (map[string]string, []bindings.Artifact, error) {
	*b.generateCalls = *b.generateCalls + 1
	mode := "prod"
	if isStaging {
		mode = "stage"
	}
	role := bindingId + "_role_" + mode
	schema := bindingId + "_schema_" + mode
	artifacts := []bindings.Artifact{
		{Type: bindings.ArtifactRole, Name: role},
		{Type: bindings.ArtifactSchema, Name: schema},
	}
	if b.failAfterCreate != nil && *b.failAfterCreate {
		// Partial failure: the role was created but the schema creation failed
		return nil, artifacts[:1], fmt.Errorf("simulated partial account creation failure")
	}
	return map[string]string{"role": role, "schema": schema}, artifacts, nil
}

func (b *applyAccountTrackingServiceBinding) DeleteArtifact(_ context.Context, artifact bindings.Artifact) error {
	*b.deletedArtifacts = append(*b.deletedArtifacts, artifact)
	return nil
}

func (b *applyAccountTrackingServiceBinding) ApplyGrants(context.Context, map[string]string, types.BindingMetadata,
	types.BindingMetadata, bool) (bindings.GrantApplyResult, error) {
	return bindings.GrantApplyResult{}, nil
}

func (b *applyAccountTrackingServiceBinding) RevokeGrants(context.Context, map[string]string, types.BindingMetadata, []types.BindingGrant, []types.BindingGrant) error {
	return nil
}

func (b *applyAccountTrackingServiceBinding) RunCommand(context.Context, types.BindingMetadata, string) (map[string]any, error) {
	return nil, nil
}

func (b *applyPendingGrantServiceBinding) InitializeService(context.Context, *types.Logger, map[string]string, bindings.ServiceBindingRuntime) error {
	return nil
}

func (b *applyPendingGrantServiceBinding) CloseService(context.Context) error {
	return nil
}

func (b *applyPendingGrantServiceBinding) DeleteArtifact(context.Context, bindings.Artifact) error {
	return nil
}

func (b *applyPendingGrantServiceBinding) GenerateAccount(_ context.Context, bindingId, bindingPath string, _ types.BindingMetadata,
	_ *types.BindingMetadata, isStaging bool) (map[string]string, []bindings.Artifact, error) {
	mode := "prod"
	if isStaging {
		mode = "stage"
	}
	role := bindingId + "_" + mode
	return map[string]string{
		"role":   role,
		"schema": strings.TrimPrefix(bindingPath, "/") + "_" + mode,
	}, []bindings.Artifact{{Type: bindings.ArtifactRole, Name: role}}, nil
}

func (b *applyPendingGrantServiceBinding) ApplyGrants(_ context.Context, _ map[string]string, bindingMetadata, _ types.BindingMetadata,
	reapplyAll bool) (bindings.GrantApplyResult, error) {
	if reapplyAll {
		*b.reapplyAllCalls = *b.reapplyAllCalls + 1
	}
	if !*b.grantAvailable || len(bindingMetadata.Grants) == 0 {
		return bindings.GrantApplyResult{GrantsApplied: append([]types.BindingGrant{}, bindingMetadata.GrantsApplied...)}, nil
	}
	grant := types.BindingGrant{GrantType: types.GrantTypeRead, GrantTarget: "late_table"}
	if !reapplyAll && slices.Contains(bindingMetadata.GrantsApplied, grant) {
		return bindings.GrantApplyResult{GrantsApplied: append([]types.BindingGrant{}, bindingMetadata.GrantsApplied...)}, nil
	}
	*b.pendingApplyCalls = *b.pendingApplyCalls + 1
	grantsApplied := append([]types.BindingGrant{}, bindingMetadata.GrantsApplied...)
	granted := []types.BindingGrant{}
	if !slices.Contains(grantsApplied, grant) {
		grantsApplied = append(grantsApplied, grant)
		granted = append(granted, grant)
	}
	return bindings.GrantApplyResult{GrantsApplied: grantsApplied, Granted: granted}, nil
}

func (b *applyPendingGrantServiceBinding) RevokeGrants(context.Context, map[string]string, types.BindingMetadata, []types.BindingGrant, []types.BindingGrant) error {
	return nil
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
		System: types.SystemConfig{
			DefaultDomain: "localhost",
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
		Logger:       logger,
		staticConfig: config,
		db:           db,
		notifyClose:  make(chan types.AppPathDomain),
	}
	server.secretsManager.Store(secretsManager)
	server.apps = NewAppStore(logger, server)
	rbacManager, err := rbac.NewRBACHandler(logger, &types.RBACConfig{Enabled: false}, config)
	if err != nil {
		t.Fatalf("new rbac manager: %v", err)
	}
	server.rbacManager = rbacManager
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

	response, _, err := server.Apply(ctx, types.Transaction{}, applyPath, "/apps/**", false, false, false,
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
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
	if approveResult.NeedsApproval {
		t.Fatal("app with no plugin permissions should not require approval (binding access is RBAC gated, not approval gated)")
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

	response, _, err := server.Apply(ctx, types.Transaction{}, applyPath, "all", false, false, false,
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
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

func TestBindingAccountManagerRollbackDeletesUncommittedArtifacts(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	generateCalls := 0
	failAfterCreate := false
	deletedArtifacts := []bindings.Artifact{}
	closed := 0
	previousBuilder, hadPreviousBuilder := bindings.ServiceBindings["accounttest"]
	bindings.ServiceBindings["accounttest"] = func() bindings.ServiceBinding {
		return &applyAccountTrackingServiceBinding{
			generateCalls:    &generateCalls,
			failAfterCreate:  &failAfterCreate,
			deletedArtifacts: &deletedArtifacts,
			closed:           &closed,
		}
	}
	defer func() {
		if hadPreviousBuilder {
			bindings.ServiceBindings["accounttest"] = previousBuilder
		} else {
			delete(bindings.ServiceBindings, "accounttest")
		}
	}()

	service := &types.Service{
		Name:        "primary",
		ServiceType: "accounttest",
		Config:      map[string]string{},
	}
	binding := &types.Binding{
		Id:   types.ID_PREFIX_BINDING + "account",
		Path: "/apps/account",
		Metadata: types.BindingMetadata{
			Config: map[string]string{},
		},
		StagedMetadata: types.BindingMetadata{
			Config: map[string]string{},
		},
	}

	// Artifacts created without a commit are deleted on rollback, in reverse creation order
	accounts := server.newBindingAccountManager(false)
	if _, _, err := accounts.generateAccount(ctx, service, binding, nil, true, true); err != nil {
		t.Fatalf("generate staging account: %v", err)
	}
	if _, _, err := accounts.generateAccount(ctx, service, binding, nil, false, true); err != nil {
		t.Fatalf("generate prod account: %v", err)
	}
	accounts.rollbackAndClose(ctx)
	wantDeleted := []bindings.Artifact{
		{Type: bindings.ArtifactSchema, Name: binding.Id + "_schema_prod"},
		{Type: bindings.ArtifactRole, Name: binding.Id + "_role_prod"},
		{Type: bindings.ArtifactSchema, Name: binding.Id + "_schema_stage"},
		{Type: bindings.ArtifactRole, Name: binding.Id + "_role_stage"},
	}
	if !slices.Equal(deletedArtifacts, wantDeleted) {
		t.Fatalf("deleted artifacts = %v, want %v in reverse creation order", deletedArtifacts, wantDeleted)
	}
	if closed != 1 {
		t.Fatalf("close calls = %d, want 1 for the cached service connection", closed)
	}

	// Committed artifacts are kept on rollback
	deletedArtifacts = nil
	accounts = server.newBindingAccountManager(false)
	if _, _, err := accounts.generateAccount(ctx, service, binding, nil, false, true); err != nil {
		t.Fatalf("generate account: %v", err)
	}
	accounts.commit()
	accounts.rollbackAndClose(ctx)
	if len(deletedArtifacts) != 0 {
		t.Fatalf("deleted artifacts = %v, want none after commit", deletedArtifacts)
	}

	// Artifacts created before a partial GenerateAccount failure are deleted on rollback
	deletedArtifacts = nil
	failAfterCreate = true
	accounts = server.newBindingAccountManager(false)
	if _, _, err := accounts.generateAccount(ctx, service, binding, nil, false, true); err == nil {
		t.Fatal("generate account did not return the partial failure")
	}
	accounts.rollbackAndClose(ctx)
	wantDeleted = []bindings.Artifact{{Type: bindings.ArtifactRole, Name: binding.Id + "_role_prod"}}
	if !slices.Equal(deletedArtifacts, wantDeleted) {
		t.Fatalf("deleted artifacts after partial failure = %v, want %v", deletedArtifacts, wantDeleted)
	}
	failAfterCreate = false

	// Dry run creates no artifacts
	generateCalls = 0
	accounts = server.newBindingAccountManager(true)
	account, _, err := accounts.generateAccount(ctx, service, binding, nil, false, true)
	if err != nil {
		t.Fatalf("dry run generate account: %v", err)
	}
	if account != nil || generateCalls != 0 {
		t.Fatalf("dry run account = %v with %d generate calls, want no account generation", account, generateCalls)
	}
	accounts.rollbackAndClose(ctx)
}

func TestCreateSyncEntryKeepsBindingAccountsAfterOuterCommit(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	generateCalls := 0
	failAfterCreate := false
	deletedArtifacts := []bindings.Artifact{}
	closed := 0
	previousBuilder, hadPreviousBuilder := bindings.ServiceBindings["syncaccounttest"]
	bindings.ServiceBindings["syncaccounttest"] = func() bindings.ServiceBinding {
		return &applyAccountTrackingServiceBinding{
			generateCalls:    &generateCalls,
			failAfterCreate:  &failAfterCreate,
			deletedArtifacts: &deletedArtifacts,
			closed:           &closed,
		}
	}
	defer func() {
		if hadPreviousBuilder {
			bindings.ServiceBindings["syncaccounttest"] = previousBuilder
		} else {
			delete(bindings.ServiceBindings, "syncaccounttest")
		}
	}()

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	service := &types.Service{
		Id:          types.ID_PREFIX_SERVICE + "syncaccounttest",
		Name:        "primary",
		ServiceType: "syncaccounttest",
		IsDefault:   true,
		Config:      map[string]string{},
	}
	if err := db.CreateService(ctx, tx, service); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit service: %v", err)
	}

	applyPath := filepath.Join(t.TempDir(), "sync-bindings.ace")
	if err := os.WriteFile(applyPath, []byte(`binding("/apps/synced", "syncaccounttest/primary")
`), 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}

	response, err := server.CreateSyncEntry(ctx, applyPath, true, false, &types.SyncMetadata{})
	if err != nil {
		t.Fatalf("create sync entry: %v", err)
	}
	if len(response.SyncJobStatus.ApplyResponse.CreateBindingResults) != 1 ||
		response.SyncJobStatus.ApplyResponse.CreateBindingResults[0] != "/apps/synced" {
		t.Fatalf("created bindings = %v, want [/apps/synced]", response.SyncJobStatus.ApplyResponse.CreateBindingResults)
	}
	if len(deletedArtifacts) != 0 {
		t.Fatalf("deleted artifacts after successful sync = %v, want none", deletedArtifacts)
	}

	readTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer readTx.Rollback() //nolint:errcheck
	binding, err := db.GetBinding(ctx, readTx, "/apps/synced")
	if err != nil {
		t.Fatalf("get synced binding: %v", err)
	}
	if binding.Metadata.Account["role"] == "" || binding.StagedMetadata.Account["role"] == "" {
		t.Fatalf("synced binding account metadata = prod %v stage %v, want populated accounts",
			binding.Metadata.Account, binding.StagedMetadata.Account)
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
	grantAccounts := server.newBindingAccountManager(false)
	if err := server.reapplyPendingBindingGrants(ctx, updateTx, grantAccounts, []string{"/apps/base", "/apps/derived"}); err != nil {
		t.Fatalf("reapply grants: %v", err)
	}
	if err := updateTx.Commit(); err != nil {
		t.Fatalf("commit metadata: %v", err)
	}
	grantAccounts.commit()
	grantAccounts.rollbackAndClose(ctx)

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
	grantAccounts = server.newBindingAccountManager(false)
	if err := server.reapplyPendingBindingGrants(ctx, retryTx, grantAccounts, []string{"/apps/derived"}); err != nil {
		t.Fatalf("second reapply grants: %v", err)
	}
	if err := retryTx.Commit(); err != nil {
		t.Fatalf("commit second metadata: %v", err)
	}
	grantAccounts.commit()
	grantAccounts.rollbackAndClose(ctx)
	if pendingApplyCalls != 2 {
		t.Fatalf("pending grant apply calls after second retry = %d, want still 2", pendingApplyCalls)
	}
	if reapplyAllCalls != 0 {
		t.Fatalf("reapply-all calls after second retry = %d, want 0", reapplyAllCalls)
	}
}

// grantLifecycleServiceBinding tracks grant and revoke executions with realistic
// diff behavior: ApplyGrants executes only the additive diff and reports the
// no-longer-desired grants as pending revokes, like the real service bindings.
type grantLifecycleServiceBinding struct {
	grantCalls   *[]string
	revokeCalls  *[]string
	regrantCalls *[]string
	revokeHook   *func(context.Context)
}

func grantCallMode(role string) string {
	if strings.HasSuffix(role, "_stage") {
		return "stage"
	}
	return "prod"
}

func (b *grantLifecycleServiceBinding) InitializeService(context.Context, *types.Logger, map[string]string, bindings.ServiceBindingRuntime) error {
	return nil
}

func (b *grantLifecycleServiceBinding) CloseService(context.Context) error {
	return nil
}

func (b *grantLifecycleServiceBinding) DeleteArtifact(context.Context, bindings.Artifact) error {
	return nil
}

func (b *grantLifecycleServiceBinding) GenerateAccount(_ context.Context, bindingId, bindingPath string, _ types.BindingMetadata,
	derivedFromMetadata *types.BindingMetadata, isStaging bool) (map[string]string, []bindings.Artifact, error) {
	mode := "prod"
	if isStaging {
		mode = "stage"
	}
	schema := strings.ReplaceAll(strings.TrimPrefix(bindingPath, "/"), "/", "_") + "_" + mode
	if derivedFromMetadata != nil {
		schema = derivedFromMetadata.Account["schema"]
	}
	role := bindingId + "_" + mode
	return map[string]string{
		"role":   role,
		"schema": schema,
	}, []bindings.Artifact{{Type: bindings.ArtifactRole, Name: role}}, nil
}

func (b *grantLifecycleServiceBinding) ApplyGrants(_ context.Context, account map[string]string, bindingMetadata, _ types.BindingMetadata,
	_ bool) (bindings.GrantApplyResult, error) {
	desired := make([]types.BindingGrant, 0, len(bindingMetadata.Grants))
	for _, grantStr := range bindingMetadata.Grants {
		grant, err := types.ParseGrant(grantStr, []types.GrantType{types.GrantTypeRead, types.GrantTypeCreate, types.GrantTypeFull})
		if err != nil {
			return bindings.GrantApplyResult{}, err
		}
		desired = append(desired, grant)
	}
	granted := []types.BindingGrant{}
	for _, grant := range desired {
		if !slices.Contains(bindingMetadata.GrantsApplied, grant) {
			granted = append(granted, grant)
			*b.grantCalls = append(*b.grantCalls, grantCallMode(account["role"])+"|"+grant.String())
		}
	}
	pendingRevokes := []types.BindingGrant{}
	for _, grant := range bindingMetadata.GrantsApplied {
		if !slices.Contains(desired, grant) {
			pendingRevokes = append(pendingRevokes, grant)
		}
	}
	return bindings.GrantApplyResult{
		GrantsApplied:  append(append([]types.BindingGrant{}, bindingMetadata.GrantsApplied...), granted...),
		Granted:        granted,
		PendingRevokes: pendingRevokes,
	}, nil
}

func (b *grantLifecycleServiceBinding) RevokeGrants(ctx context.Context, account map[string]string, _ types.BindingMetadata,
	revokes, regrants []types.BindingGrant) error {
	if b.revokeHook != nil && *b.revokeHook != nil {
		(*b.revokeHook)(ctx)
	}
	for _, grant := range revokes {
		*b.revokeCalls = append(*b.revokeCalls, grantCallMode(account["role"])+"|"+grant.String())
	}
	for _, grant := range regrants {
		*b.regrantCalls = append(*b.regrantCalls, grantCallMode(account["role"])+"|"+grant.String())
	}
	return nil
}

func (b *grantLifecycleServiceBinding) RunCommand(context.Context, types.BindingMetadata, string) (map[string]any, error) {
	return nil, nil
}

// registerGrantLifecycleBinding registers the fake under the given service type and
// creates a default service plus a base and derived binding pair for it.
func registerGrantLifecycleBinding(t *testing.T, server *Server, db *metadata.Metadata, ctx context.Context,
	serviceType string, grants []string, grantCalls, revokeCalls, regrantCalls *[]string, revokeHook *func(context.Context)) {
	t.Helper()
	previousBuilder, hadPreviousBuilder := bindings.ServiceBindings[serviceType]
	bindings.ServiceBindings[serviceType] = func() bindings.ServiceBinding {
		return &grantLifecycleServiceBinding{grantCalls: grantCalls, revokeCalls: revokeCalls, regrantCalls: regrantCalls, revokeHook: revokeHook}
	}
	t.Cleanup(func() {
		if hadPreviousBuilder {
			bindings.ServiceBindings[serviceType] = previousBuilder
		} else {
			delete(bindings.ServiceBindings, serviceType)
		}
	})

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	service := &types.Service{
		Id:          types.ID_PREFIX_SERVICE + serviceType,
		Name:        "primary",
		ServiceType: serviceType,
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
		Source: serviceType + "/primary",
		Config: map[string]string{},
	}, false); err != nil {
		t.Fatalf("create base binding: %v", err)
	}
	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path:   "/apps/derived",
		Source: "/apps/base",
		Grants: grants,
		Config: map[string]string{},
	}, false); err != nil {
		t.Fatalf("create derived binding: %v", err)
	}
}

func getBindingForTest(t *testing.T, db *metadata.Metadata, ctx context.Context, path string) *types.Binding {
	t.Helper()
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	binding, err := db.GetBinding(ctx, tx, path)
	if err != nil {
		t.Fatalf("get binding %s: %v", path, err)
	}
	return binding
}

func TestApplyRollbackCompensatesAppliedGrants(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	grantCalls := []string{}
	revokeCalls := []string{}
	regrantCalls := []string{}
	registerGrantLifecycleBinding(t, server, db, ctx, "grantroll", []string{"read:t1"}, &grantCalls, &revokeCalls, &regrantCalls, nil)

	grantCalls = nil
	revokeCalls = nil
	regrantCalls = nil
	applyPath := filepath.Join(t.TempDir(), "grants.ace")
	applyData := fmt.Sprintf(`binding("/apps/derived", "/apps/base", grants=["read:t1", "read:t2"])
app("/apps/bad", %q)
`, filepath.Join(t.TempDir(), "does-not-exist"))
	if err := os.WriteFile(applyPath, []byte(applyData), 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}

	_, _, err := server.Apply(ctx, types.Transaction{}, applyPath, "all", false, false, false,
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
	if err == nil {
		t.Fatal("apply with missing app source did not fail")
	}

	// The staging grant applied before the failure is revoked during rollback
	if !slices.Equal(grantCalls, []string{"stage|READ:t2"}) {
		t.Fatalf("grant calls = %v, want staging read:t2 only", grantCalls)
	}
	if !slices.Equal(revokeCalls, []string{"stage|READ:t2"}) {
		t.Fatalf("revoke calls = %v, want rollback compensation for read:t2", revokeCalls)
	}
	if !slices.Equal(regrantCalls, []string{"stage|READ:t1"}) {
		t.Fatalf("regrant calls = %v, want pre-operation grants restored", regrantCalls)
	}

	derived := getBindingForTest(t, db, ctx, "/apps/derived")
	if !slices.Equal(derived.StagedMetadata.Grants, []string{"read:t1"}) {
		t.Fatalf("staged grants = %v, want unchanged [read:t1]", derived.StagedMetadata.Grants)
	}
	wantApplied := []types.BindingGrant{{GrantType: types.GrantTypeRead, GrantTarget: "t1"}}
	if !slices.Equal(derived.StagedMetadata.GrantsApplied, wantApplied) {
		t.Fatalf("staged grants applied = %v, want unchanged %v", derived.StagedMetadata.GrantsApplied, wantApplied)
	}
}

func TestApplyDefersGrantRevokesUntilAfterCommit(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	grantCalls := []string{}
	revokeCalls := []string{}
	regrantCalls := []string{}
	var revokeHook func(context.Context)
	registerGrantLifecycleBinding(t, server, db, ctx, "grantdefer", []string{"read:t1"}, &grantCalls, &revokeCalls, &regrantCalls, &revokeHook)

	grantCalls = nil
	revokeCalls = nil
	applyPath := filepath.Join(t.TempDir(), "grants.ace")
	if err := os.WriteFile(applyPath, []byte(`binding("/apps/derived", "/apps/base", grants=["read:t2"])
`), 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}

	// The revokes must only run after the metadata transaction has committed: when
	// the first revoke executes, the committed binding row already has the new grants
	hookCalls := 0
	revokeHook = func(context.Context) {
		hookCalls++
		committed := getBindingForTest(t, db, ctx, "/apps/derived")
		if !slices.Equal(committed.StagedMetadata.Grants, []string{"read:t2"}) {
			t.Errorf("staged grants at revoke time = %v, want committed [read:t2]", committed.StagedMetadata.Grants)
		}
	}

	response, _, err := server.Apply(ctx, types.Transaction{}, applyPath, "all", false, false, true,
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !slices.Equal(response.UpdateBindingResults, []string{"/apps/derived"}) {
		t.Fatalf("update binding results = %v, want [/apps/derived]", response.UpdateBindingResults)
	}
	if !slices.Equal(response.PromoteBindingResults, []string{"/apps/derived"}) {
		t.Fatalf("promote binding results = %v, want [/apps/derived]", response.PromoteBindingResults)
	}

	if !slices.Equal(grantCalls, []string{"stage|READ:t2", "prod|READ:t2"}) {
		t.Fatalf("grant calls = %v, want staging and prod read:t2", grantCalls)
	}
	if !slices.Equal(revokeCalls, []string{"stage|READ:t1", "prod|READ:t1"}) {
		t.Fatalf("revoke calls = %v, want deferred staging and prod revokes of read:t1", revokeCalls)
	}
	if !slices.Equal(regrantCalls, []string{"stage|READ:t2", "prod|READ:t2"}) {
		t.Fatalf("regrant calls = %v, want remaining grants re-applied with the revokes", regrantCalls)
	}
	if hookCalls != 2 {
		t.Fatalf("revoke hook calls = %d, want 2", hookCalls)
	}

	// The finalized revokes are removed from the recorded applied grants
	derived := getBindingForTest(t, db, ctx, "/apps/derived")
	wantApplied := []types.BindingGrant{{GrantType: types.GrantTypeRead, GrantTarget: "t2"}}
	if !slices.Equal(derived.StagedMetadata.GrantsApplied, wantApplied) {
		t.Fatalf("staged grants applied = %v, want %v", derived.StagedMetadata.GrantsApplied, wantApplied)
	}
	if !slices.Equal(derived.Metadata.GrantsApplied, wantApplied) {
		t.Fatalf("prod grants applied = %v, want %v", derived.Metadata.GrantsApplied, wantApplied)
	}
	if !slices.Equal(derived.Metadata.Grants, []string{"read:t2"}) {
		t.Fatalf("prod grants = %v, want [read:t2]", derived.Metadata.Grants)
	}

	// Re-running the same apply is a no-op: no new grants, revokes or updates
	grantCalls = nil
	revokeCalls = nil
	regrantCalls = nil
	response, _, err = server.Apply(ctx, types.Transaction{}, applyPath, "all", false, false, true,
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if len(response.UpdateBindingResults) != 0 || len(response.PromoteBindingResults) != 0 {
		t.Fatalf("second apply results = %v %v, want no binding updates", response.UpdateBindingResults, response.PromoteBindingResults)
	}
	if len(grantCalls) != 0 || len(revokeCalls) != 0 || len(regrantCalls) != 0 {
		t.Fatalf("second apply grant calls = %v revoke calls = %v regrant calls = %v, want none", grantCalls, revokeCalls, regrantCalls)
	}
}

func TestUpdateBindingDefersRevokesUntilAfterCommit(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	grantCalls := []string{}
	revokeCalls := []string{}
	regrantCalls := []string{}
	registerGrantLifecycleBinding(t, server, db, ctx, "grantupd", []string{"read:t1", "read:t2"}, &grantCalls, &revokeCalls, &regrantCalls, nil)

	grantCalls = nil
	revokeCalls = nil
	updated, err := server.UpdateBinding(ctx, types.UpdateBindingRequest{
		Path:         "/apps/derived",
		DeleteGrants: []string{"read:t1"},
	}, false, true, false)
	if err != nil {
		t.Fatalf("update binding: %v", err)
	}
	if !slices.Equal(updated.StagedMetadata.Grants, []string{"read:t2"}) {
		t.Fatalf("staged grants = %v, want [read:t2]", updated.StagedMetadata.Grants)
	}

	if len(grantCalls) != 0 {
		t.Fatalf("grant calls = %v, want none for a delete-only update", grantCalls)
	}
	if !slices.Equal(revokeCalls, []string{"stage|READ:t1", "prod|READ:t1"}) {
		t.Fatalf("revoke calls = %v, want deferred staging and prod revokes", revokeCalls)
	}

	derived := getBindingForTest(t, db, ctx, "/apps/derived")
	wantApplied := []types.BindingGrant{{GrantType: types.GrantTypeRead, GrantTarget: "t2"}}
	if !slices.Equal(derived.StagedMetadata.GrantsApplied, wantApplied) {
		t.Fatalf("staged grants applied = %v, want %v", derived.StagedMetadata.GrantsApplied, wantApplied)
	}
	if !slices.Equal(derived.Metadata.GrantsApplied, wantApplied) {
		t.Fatalf("prod grants applied = %v, want %v", derived.Metadata.GrantsApplied, wantApplied)
	}
}

func TestCreateAppRollbackRemovesAutoBindingAccount(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	generateCalls := 0
	failAfterCreate := false
	deletedArtifacts := []bindings.Artifact{}
	closed := 0
	previousBuilder, hadPreviousBuilder := bindings.ServiceBindings["autoacct"]
	bindings.ServiceBindings["autoacct"] = func() bindings.ServiceBinding {
		return &applyAccountTrackingServiceBinding{
			generateCalls:    &generateCalls,
			failAfterCreate:  &failAfterCreate,
			deletedArtifacts: &deletedArtifacts,
			closed:           &closed,
		}
	}
	defer func() {
		if hadPreviousBuilder {
			bindings.ServiceBindings["autoacct"] = previousBuilder
		} else {
			delete(bindings.ServiceBindings, "autoacct")
		}
	}()

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	service := &types.Service{
		Id:          types.ID_PREFIX_SERVICE + "autoacct",
		Name:        "primary",
		ServiceType: "autoacct",
		IsDefault:   true,
		Config:      map[string]string{},
	}
	if err := db.CreateService(ctx, tx, service); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit service: %v", err)
	}

	// App create fails after the auto binding and its account were created; the
	// account artifacts must be deleted along with the transaction rollback
	appTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin app transaction: %v", err)
	}
	accounts := server.newBindingAccountManager(false)
	_, err = server.CreateAppTx(ctx, appTx, "/apps/auto-rollback", false, false, &types.CreateAppRequest{
		SourceUrl: filepath.Join(t.TempDir(), "does-not-exist"),
		Bindings:  []string{"autoacct"},
	}, nil, accounts)
	if err == nil {
		t.Fatal("create app with missing source did not fail")
	}
	if err := appTx.Rollback(); err != nil {
		t.Fatalf("rollback app transaction: %v", err)
	}
	accounts.rollbackAndClose(ctx)

	if generateCalls != 2 {
		t.Fatalf("generate calls = %d, want staging and prod account generation", generateCalls)
	}
	if len(deletedArtifacts) != 4 {
		t.Fatalf("deleted artifacts = %v, want the 4 auto binding artifacts removed on rollback", deletedArtifacts)
	}

	readTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer readTx.Rollback() //nolint:errcheck
	if _, err := db.GetBinding(ctx, readTx, autoBindingPathPrefix+"/"+string(types.AppId("."))); err == nil {
		t.Fatal("unexpected auto binding found")
	}
}

func TestRunSyncJobPersistsFailureStatus(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	server.staticConfig.System.MaxSyncFailureCount = 3

	applyPath := filepath.Join(t.TempDir(), "sync.ace")
	appSourceDir := filepath.Join(t.TempDir(), "app")
	if err := os.Mkdir(appSourceDir, 0700); err != nil {
		t.Fatalf("create app source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appSourceDir, "app.star"), []byte("app = ace.app(\"syncApp\")\n"), 0600); err != nil {
		t.Fatalf("write app.star: %v", err)
	}
	if err := os.WriteFile(applyPath, []byte(fmt.Sprintf("app(\"/apps/sync-status\", %q)\n", appSourceDir)), 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}

	response, err := server.CreateSyncEntry(ctx, applyPath, true, false, &types.SyncMetadata{})
	if err != nil {
		t.Fatalf("create sync entry: %v", err)
	}

	// Break the apply file so the next sync run fails
	if err := os.WriteFile(applyPath, []byte(fmt.Sprintf("app(\"/apps/sync-status\", %q)\napp(\"/apps/bad\", %q)\n",
		appSourceDir, filepath.Join(t.TempDir(), "does-not-exist"))), 0600); err != nil {
		t.Fatalf("rewrite apply file: %v", err)
	}

	readTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	entry, err := db.GetSyncEntry(ctx, readTx, response.Id)
	if err != nil {
		t.Fatalf("get sync entry: %v", err)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatalf("rollback read transaction: %v", err)
	}

	status, _, err := server.runSyncJob(ctx, types.Transaction{}, entry, false, true, nil)
	if err != nil {
		t.Fatalf("run sync job: %v", err)
	}
	if status.Error == "" {
		t.Fatal("sync job with bad app source did not report an error")
	}

	// The failure status must be persisted even though the sync changes were rolled back
	verifyTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin verify transaction: %v", err)
	}
	defer verifyTx.Rollback() //nolint:errcheck
	persisted, err := db.GetSyncEntry(ctx, verifyTx, response.Id)
	if err != nil {
		t.Fatalf("get sync entry after failure: %v", err)
	}
	if persisted.Status.FailureCount != 1 {
		t.Fatalf("failure count = %d, want 1", persisted.Status.FailureCount)
	}
	if persisted.Status.Error == "" {
		t.Fatal("persisted sync status has no error")
	}
	if persisted.Status.State != "Failing" {
		t.Fatalf("sync state = %q, want Failing", persisted.Status.State)
	}
	if persisted.Status.LastExecutionTime.IsZero() {
		t.Fatal("last execution time was not persisted")
	}
}

// updateBindingForTest commits a change to a binding row, simulating a concurrent
// operation modifying the binding outside the operation under test.
func updateBindingForTest(t *testing.T, db *metadata.Metadata, ctx context.Context, path string, mutate func(*types.Binding)) {
	t.Helper()
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin update transaction: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	binding, err := db.GetBinding(ctx, tx, path)
	if err != nil {
		t.Fatalf("get binding %s: %v", path, err)
	}
	mutate(binding)
	if err := db.UpdateBinding(ctx, tx, binding); err != nil {
		t.Fatalf("update binding %s: %v", path, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit binding update: %v", err)
	}
}

func TestFinalizeRevokesSkipsConcurrentlyReAddedGrants(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	grantCalls := []string{}
	revokeCalls := []string{}
	regrantCalls := []string{}
	var revokeHook func(context.Context)
	registerGrantLifecycleBinding(t, server, db, ctx, "grantrace", []string{"read:t1"}, &grantCalls, &revokeCalls, &regrantCalls, &revokeHook)

	grantCalls = nil
	revokeCalls = nil
	applyPath := filepath.Join(t.TempDir(), "grants.ace")
	if err := os.WriteFile(applyPath, []byte(`binding("/apps/derived", "/apps/base", grants=["read:t2"])
`), 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}

	// While the staging revoke executes (after the apply committed), a concurrent
	// update re-adds read:t1 to the prod desired grants; the prod revoke must be
	// skipped since the committed state owns that grant again
	hookCalls := 0
	revokeHook = func(hctx context.Context) {
		hookCalls++
		if hookCalls != 1 {
			return
		}
		updateBindingForTest(t, db, hctx, "/apps/derived", func(binding *types.Binding) {
			binding.Metadata.Grants = append(binding.Metadata.Grants, "read:t1")
		})
	}

	_, _, err := server.Apply(ctx, types.Transaction{}, applyPath, "all", false, false, true,
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	if !slices.Equal(revokeCalls, []string{"stage|READ:t1"}) {
		t.Fatalf("revoke calls = %v, want only the staging revoke", revokeCalls)
	}
	if hookCalls != 1 {
		t.Fatalf("revoke executions = %d, want 1 (prod revoke skipped)", hookCalls)
	}

	derived := getBindingForTest(t, db, ctx, "/apps/derived")
	wantStaged := []types.BindingGrant{{GrantType: types.GrantTypeRead, GrantTarget: "t2"}}
	if !slices.Equal(derived.StagedMetadata.GrantsApplied, wantStaged) {
		t.Fatalf("staged grants applied = %v, want %v", derived.StagedMetadata.GrantsApplied, wantStaged)
	}
	// The prod revoke was skipped and its grant stays recorded as applied for the
	// concurrently re-added desired grant
	wantKept := types.BindingGrant{GrantType: types.GrantTypeRead, GrantTarget: "t1"}
	if !slices.Contains(derived.Metadata.GrantsApplied, wantKept) {
		t.Fatalf("prod grants applied = %v, want read:t1 kept", derived.Metadata.GrantsApplied)
	}
}

func TestRollbackCompensationSkipsConcurrentlyCommittedGrants(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	grantCalls := []string{}
	revokeCalls := []string{}
	regrantCalls := []string{}
	var revokeHook func(context.Context)
	registerGrantLifecycleBinding(t, server, db, ctx, "grantcomp", []string{"read:t1"}, &grantCalls, &revokeCalls, &regrantCalls, &revokeHook)

	readTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	binding, err := db.GetBinding(ctx, readTx, "/apps/derived")
	if err != nil {
		t.Fatalf("get derived binding: %v", err)
	}
	derivedFrom, err := db.GetBinding(ctx, readTx, "/apps/base")
	if err != nil {
		t.Fatalf("get base binding: %v", err)
	}
	service, err := db.GetService(ctx, readTx, "grantcomp", "primary")
	if err != nil {
		t.Fatalf("get service: %v", err)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatalf("rollback read transaction: %v", err)
	}

	// Apply a new grant, as a failing operation would before its rollback
	grantCalls = nil
	revokeCalls = nil
	accounts := server.newBindingAccountManager(false)
	binding.StagedMetadata.Grants = []string{"read:t1", "read:t2"}
	if _, err := accounts.applyGrants(ctx, service, binding, derivedFrom, true, false); err != nil {
		t.Fatalf("apply grants: %v", err)
	}
	if !slices.Equal(grantCalls, []string{"stage|READ:t2"}) {
		t.Fatalf("grant calls = %v, want staging read:t2", grantCalls)
	}

	// A concurrent operation commits the same grant as applied before the rollback
	// runs; the compensation must not revoke it
	updateBindingForTest(t, db, ctx, "/apps/derived", func(b *types.Binding) {
		b.StagedMetadata.Grants = []string{"read:t1", "read:t2"}
		b.StagedMetadata.GrantsApplied = append(b.StagedMetadata.GrantsApplied, types.BindingGrant{GrantType: types.GrantTypeRead, GrantTarget: "t2"})
	})

	tctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	accounts.rollbackAndClose(tctx)
	if len(revokeCalls) != 0 {
		t.Fatalf("revoke calls = %v, want compensation skipped for the concurrently committed grant", revokeCalls)
	}

	// Without a concurrent commit the compensation revokes as usual, and the
	// rollback context deadline reaches the service call (the operation timeout
	// must not be stripped before the cluster rollback runs)
	updateBindingForTest(t, db, ctx, "/apps/derived", func(b *types.Binding) {
		b.StagedMetadata.Grants = []string{"read:t1"}
		b.StagedMetadata.GrantsApplied = []types.BindingGrant{{GrantType: types.GrantTypeRead, GrantTarget: "t1"}}
	})
	binding2 := getBindingForTest(t, db, ctx, "/apps/derived")
	binding2.StagedMetadata.Grants = []string{"read:t1", "read:t2"}
	grantCalls = nil
	accounts2 := server.newBindingAccountManager(false)
	if _, err := accounts2.applyGrants(ctx, service, binding2, derivedFrom, true, false); err != nil {
		t.Fatalf("apply grants again: %v", err)
	}
	deadlineSeen := false
	revokeHook = func(hctx context.Context) {
		_, deadlineSeen = hctx.Deadline()
	}
	accounts2.rollbackAndClose(tctx)
	if !slices.Equal(revokeCalls, []string{"stage|READ:t2"}) {
		t.Fatalf("revoke calls = %v, want compensation for read:t2", revokeCalls)
	}
	if !deadlineSeen {
		t.Fatal("rollback revoke did not receive the operation deadline")
	}
}

// newSyncRBACTestServer sets up the apply test server with an enabled RBAC
// config: "creator" holds sync:create plus app:apply on /apps/allowed* only
func newSyncRBACTestServer(t *testing.T) (*Server, *metadata.Metadata, context.Context) {
	t.Helper()
	server, db, ctx := newApplyTestServer(t)
	rbacConfig := &types.RBACConfig{
		Enabled: true,
		Groups:  map[string][]string{},
		Roles: map[string][]types.RBACPermission{
			"syncer": {types.PermissionSyncCreate, types.PermissionApply},
			// apply+approve but no promote: a staging-first builder publisher
			"publisher": {types.PermissionApply, types.PermissionApprove},
		},
		Grants: []types.RBACGrant{
			{Description: "creator grant", Users: []string{"creator"},
				Roles: []string{"syncer"}, Targets: []string{"/apps/allowed*"}},
			{Description: "publisher grant", Users: []string{"publisher"},
				Roles: []string{"publisher"}, Targets: []string{"/apps/allowed*"}},
		},
	}
	rbacManager, err := rbac.NewRBACHandler(server.Logger, rbacConfig, server.staticConfig)
	if err != nil {
		t.Fatalf("new rbac manager: %v", err)
	}
	server.rbacManager = rbacManager
	return server, db, ctx
}

// rbacEnforcedCtx simulates an RBAC enforced management API request context
func rbacEnforcedCtx(ctx context.Context, user string) context.Context {
	ctx = context.WithValue(ctx, types.RBAC_ENABLED, true)
	ctx = context.WithValue(ctx, types.USER_ID, user)
	return context.WithValue(ctx, types.GROUPS, []string{})
}

// writeSyncApplyFile writes an apply file declaring the given app paths, all
// using one valid app source dir, returning the apply file path
func writeSyncApplyFile(t *testing.T, applyPath string, appPaths ...string) {
	t.Helper()
	appSourceDir := filepath.Join(filepath.Dir(applyPath), "app")
	if _, err := os.Stat(appSourceDir); os.IsNotExist(err) {
		if err := os.Mkdir(appSourceDir, 0700); err != nil {
			t.Fatalf("create app source dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(appSourceDir, "app.star"), []byte("app = ace.app(\"syncApp\")\n"), 0600); err != nil {
			t.Fatalf("write app.star: %v", err)
		}
	}
	applyData := ""
	for _, appPath := range appPaths {
		applyData += fmt.Sprintf("app(%q, %q)\n", appPath, appSourceDir)
	}
	if err := os.WriteFile(applyPath, []byte(applyData), 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}
}

func getSyncEntryForTest(t *testing.T, db *metadata.Metadata, ctx context.Context, id string) *types.SyncEntry {
	t.Helper()
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	entry, err := db.GetSyncEntry(ctx, tx, id)
	if err != nil {
		t.Fatalf("get sync entry: %v", err)
	}
	return entry
}

func TestSyncRBACSnapshotEnforcement(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	server.staticConfig.System.MaxSyncFailureCount = 3

	applyPath := filepath.Join(t.TempDir(), "sync.ace")
	writeSyncApplyFile(t, applyPath, "/apps/allowed1")

	// Create the sync as the RBAC enforced limited user; the entry must persist
	// the creator's frozen authorization snapshot
	creatorCtx := rbacEnforcedCtx(ctx, "creator")
	response, err := server.CreateSyncEntry(creatorCtx, applyPath, true, false, &types.SyncMetadata{})
	if err != nil {
		t.Fatalf("create sync entry: %v", err)
	}
	entry := getSyncEntryForTest(t, db, ctx, response.Id)
	if entry.Metadata.RBAC == nil || entry.Metadata.RBAC.UserId != "creator" ||
		entry.Metadata.RBAC.Admin || len(entry.Metadata.RBAC.Grants) != 1 {
		t.Fatalf("unexpected persisted snapshot %+v", entry.Metadata.RBAC)
	}

	// Grow the apply file beyond the creator's target glob and run the job the
	// way the scheduler does: background context plus the frozen snapshot
	writeSyncApplyFile(t, applyPath, "/apps/allowed1", "/apps/denied")
	jobCtx := server.attachSyncRBAC(newBackgroundOperationContext(entry.UserID), entry)
	if !server.rbacManager.APIEnforced(jobCtx) {
		t.Fatal("expected background sync context to be RBAC enforced")
	}
	status, _, err := server.runSyncJob(jobCtx, types.Transaction{}, entry, false, true, nil)
	if err != nil {
		t.Fatalf("run sync job: %v", err)
	}
	for _, part := range []string{"creator", string(types.PermissionApply), "/apps/denied", "(sync " + entry.Id + ")"} {
		if !strings.Contains(status.Error, part) {
			t.Errorf("denial %q does not mention %q", status.Error, part)
		}
	}

	// The denial counts as a run failure and the out of glob app was not created
	persisted := getSyncEntryForTest(t, db, ctx, response.Id)
	if persisted.Status.FailureCount != 1 || persisted.Status.State != "Failing" {
		t.Fatalf("unexpected persisted status %+v", persisted.Status)
	}
	verifyTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin verify transaction: %v", err)
	}
	defer verifyTx.Rollback() //nolint:errcheck
	// Apps created from an apply file keep an empty domain (the default domain
	// applies at serving time), so look up with an empty domain. The allowed
	// app existing proves the path form is right, making the denied-app
	// not-found assertion meaningful
	if _, err := db.GetAppEntryTx(ctx, verifyTx, types.AppPathDomain{Path: "/apps/allowed1"}); err != nil {
		t.Fatalf("in-glob app should exist: %v", err)
	}
	if _, err := db.GetAppEntryTx(ctx, verifyTx, types.AppPathDomain{Path: "/apps/denied"}); err == nil {
		t.Fatal("out of glob app must not be created by the denied sync run")
	}

	// After the live config is widened, the frozen snapshot still denies
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Enabled: true,
		Roles:   map[string][]types.RBACPermission{"all": {"app:*", types.PermissionSyncCreate}},
		Grants: []types.RBACGrant{{Description: "wide", Users: []string{"creator"},
			Roles: []string{"all"}, Targets: []string{"all"}}},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	status, _, err = server.runSyncJob(server.attachSyncRBAC(newBackgroundOperationContext(entry.UserID), entry),
		types.Transaction{}, persisted, false, true, nil)
	if err != nil {
		t.Fatalf("run sync job after config widen: %v", err)
	}
	if !strings.Contains(status.Error, "/apps/denied") {
		t.Errorf("expected frozen snapshot to still deny, got %q", status.Error)
	}
}

func TestSyncRBACSnapshotUnenforcedCreate(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()

	applyPath := filepath.Join(t.TempDir(), "sync.ace")
	writeSyncApplyFile(t, applyPath, "/apps/anywhere")

	// A trusted create call (CLI over unix socket / admin over TCP, stamped by
	// apiHandler) is not enforced: no snapshot is stored even though RBAC is enabled
	response, err := server.CreateSyncEntry(system.WithTrustedOperation(ctx), applyPath, true, false, &types.SyncMetadata{})
	if err != nil {
		t.Fatalf("create sync entry: %v", err)
	}
	entry := getSyncEntryForTest(t, db, ctx, response.Id)
	if entry.Metadata.RBAC != nil {
		t.Fatalf("expected no snapshot for unenforced create, got %+v", entry.Metadata.RBAC)
	}

	// Scheduled style run stays unrestricted, even outside any grant target
	writeSyncApplyFile(t, applyPath, "/apps/anywhere", "/apps/elsewhere")
	jobCtx := server.attachSyncRBAC(newBackgroundOperationContext("scheduler"), entry)
	if server.rbacManager.APIEnforced(jobCtx) {
		t.Fatal("expected run without snapshot to stay unenforced")
	}
	status, _, err := server.runSyncJob(jobCtx, types.Transaction{}, entry, false, true, nil)
	if err != nil {
		t.Fatalf("run sync job: %v", err)
	}
	if status.Error != "" {
		t.Fatalf("unexpected run error %q", status.Error)
	}
}

func TestSyncRBACSnapshotAdminCreator(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()

	applyPath := filepath.Join(t.TempDir(), "sync.ace")
	writeSyncApplyFile(t, applyPath, "/apps/anywhere")

	adminCtx := rbacEnforcedCtx(ctx, types.ADMIN_USER)
	response, err := server.CreateSyncEntry(adminCtx, applyPath, true, false, &types.SyncMetadata{})
	if err != nil {
		t.Fatalf("create sync entry: %v", err)
	}
	entry := getSyncEntryForTest(t, db, ctx, response.Id)
	if entry.Metadata.RBAC == nil || !entry.Metadata.RBAC.Admin {
		t.Fatalf("expected admin snapshot, got %+v", entry.Metadata.RBAC)
	}

	// Admin snapshot allows everything on background runs
	writeSyncApplyFile(t, applyPath, "/apps/anywhere", "/apps/elsewhere")
	jobCtx := server.attachSyncRBAC(newBackgroundOperationContext(entry.UserID), entry)
	status, _, err := server.runSyncJob(jobCtx, types.Transaction{}, entry, false, true, nil)
	if err != nil {
		t.Fatalf("run sync job: %v", err)
	}
	if status.Error != "" {
		t.Fatalf("unexpected run error %q", status.Error)
	}
}

func TestSyncRBACDisabledKillSwitch(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()

	applyPath := filepath.Join(t.TempDir(), "sync.ace")
	writeSyncApplyFile(t, applyPath, "/apps/allowed1")

	response, err := server.CreateSyncEntry(rbacEnforcedCtx(ctx, "creator"), applyPath, true, false, &types.SyncMetadata{})
	if err != nil {
		t.Fatalf("create sync entry: %v", err)
	}
	entry := getSyncEntryForTest(t, db, ctx, response.Id)
	if entry.Metadata.RBAC == nil {
		t.Fatal("expected snapshot to be stored")
	}

	// Disabling RBAC disables snapshot enforcement too: the same entry now
	// runs unrestricted without being recreated
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{Enabled: false}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	writeSyncApplyFile(t, applyPath, "/apps/allowed1", "/apps/denied")
	jobCtx := server.attachSyncRBAC(newBackgroundOperationContext(entry.UserID), entry)
	if server.rbacManager.APIEnforced(jobCtx) {
		t.Fatal("expected disabled RBAC to disable snapshot enforcement")
	}
	status, _, err := server.runSyncJob(jobCtx, types.Transaction{}, entry, false, true, nil)
	if err != nil {
		t.Fatalf("run sync job: %v", err)
	}
	if status.Error != "" {
		t.Fatalf("unexpected run error %q", status.Error)
	}
}

// registerApplyTestBinding registers the applytest service binding type and a
// default service instance, for tests exercising bindings in apply files
func registerApplyTestBinding(t *testing.T, db *metadata.Metadata, ctx context.Context) {
	t.Helper()
	previousBuilder, hadPreviousBuilder := bindings.ServiceBindings["applytest"]
	bindings.ServiceBindings["applytest"] = func() bindings.ServiceBinding {
		return &applyTestServiceBinding{}
	}
	t.Cleanup(func() {
		if hadPreviousBuilder {
			bindings.ServiceBindings["applytest"] = previousBuilder
		} else {
			delete(bindings.ServiceBindings, "applytest")
		}
	})

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
}

// TestApplyBindingRBAC verifies that bindings declared in an apply file need
// the same authority as the direct binding APIs (binding:create for new
// bindings, binding:update for declared existing ones), even when the apply
// file matches no apps
func TestApplyBindingRBAC(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	registerApplyTestBinding(t, db, ctx)

	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Enabled: true,
		Roles: map[string][]types.RBACPermission{
			"apps-only": {types.PermissionApply},
			"no-bind":   {types.PermissionApply, types.PermissionBindingCreate, types.PermissionBindingUpdate},
			"binder": {types.PermissionApply, types.PermissionBindingCreate, types.PermissionBindingUpdate,
				types.PermissionServiceBind},
		},
		Grants: []types.RBACGrant{
			{Description: "apps only", Users: []string{"apponly"}, Roles: []string{"apps-only"}, Targets: []string{"all"}},
			{Description: "no bind", Users: []string{"nobind"}, Roles: []string{"no-bind"}, Targets: []string{"all"}},
			{Description: "binder", Users: []string{"binder"}, Roles: []string{"binder"}, Targets: []string{"all"}},
		},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}

	applyPath := filepath.Join(t.TempDir(), "bindings.ace")
	if err := os.WriteFile(applyPath, []byte("binding(\"/apps/bindonly\", \"applytest/primary\")\n"), 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}
	runApply := func(user string) error {
		_, _, err := server.Apply(rbacEnforcedCtx(ctx, user), types.Transaction{}, applyPath, "all",
			false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
		return err
	}

	// A bindings-only apply file matches no apps, so no app:apply check fires;
	// the binding preflight must still deny a user without binding:create
	err := runApply("apponly")
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionBindingCreate)) {
		t.Fatalf("expected binding:create denial for new binding, got %v", err)
	}

	// Creating a base binding provisions an account on the service, which
	// needs service:bind on it in addition to binding:create on the path
	err = runApply("nobind")
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionServiceBind)) {
		t.Fatalf("expected service:bind denial for new base binding, got %v", err)
	}

	if err := runApply("binder"); err != nil {
		t.Fatalf("binder create apply: %v", err)
	}

	// The binding now exists: re-applying the file needs binding:update
	err = runApply("apponly")
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionBindingUpdate)) {
		t.Fatalf("expected binding:update denial for existing binding, got %v", err)
	}
	if err := runApply("binder"); err != nil {
		t.Fatalf("binder update apply: %v", err)
	}

	// Trusted calls (CLI over unix socket) stay unrestricted
	if _, _, err := server.Apply(system.WithTrustedOperation(ctx), types.Transaction{}, applyPath, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("trusted apply: %v", err)
	}
}

// TestBuilderPublishPathRBAC verifies the builder publish target is enforced
// with the app permissions: app:create for a new path, app:update for a
// republish to an existing app
func TestBuilderPublishPathRBAC(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()

	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Enabled: true,
		Roles: map[string][]types.RBACPermission{
			"create-only": {types.PermissionCreate},
			"manager":     {types.PermissionAppManage},
		},
		Grants: []types.RBACGrant{
			{Description: "create only", Users: []string{"creator"}, Roles: []string{"create-only"}, Targets: []string{"/apps/allowed*"}},
			{Description: "manager", Users: []string{"manager"}, Roles: []string{"manager"}, Targets: []string{"/apps/allowed*"}},
		},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}

	// New path inside the grant target: app:create suffices
	if _, _, err := server.builderCheckPublishPath(rbacEnforcedCtx(ctx, "creator"), "/apps/allowed2"); err != nil {
		t.Fatalf("new path publish check: %v", err)
	}
	// Outside the target glob: denied
	if _, _, err := server.builderCheckPublishPath(rbacEnforcedCtx(ctx, "creator"), "/apps/denied"); err == nil {
		t.Fatal("expected denial outside the grant target")
	}

	// Create an app at the path (as a trusted CLI call), making a publish
	// there an update
	applyPath := filepath.Join(t.TempDir(), "app.ace")
	writeSyncApplyFile(t, applyPath, "/apps/allowed1")
	if _, _, err := server.Apply(system.WithTrustedOperation(ctx), types.Transaction{}, applyPath, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// The direct Apply call above does not go through CompleteTransaction,
	// which is what refreshes the apps cache on the real code paths
	server.apps.ResetAllAppCache()

	// Existing app: app:create alone is not enough, app:update is required
	if _, _, err := server.builderCheckPublishPath(rbacEnforcedCtx(ctx, "creator"), "/apps/allowed1"); err == nil ||
		!strings.Contains(err.Error(), string(types.PermissionUpdate)) {
		t.Fatalf("expected app:update denial for existing app, got %v", err)
	}
	if _, _, err := server.builderCheckPublishPath(rbacEnforcedCtx(ctx, "manager"), "/apps/allowed1"); err != nil {
		t.Fatalf("manager republish check: %v", err)
	}
}

// TestBuilderPublishLocalPreflight verifies a local publish checks every
// permission the apply will need BEFORE the shared apps file or the source
// directory is written: a post-copy denial would leave staged changes that a
// later privileged apply would deploy
func TestBuilderPublishLocalPreflight(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	home := t.TempDir()
	t.Setenv("OPENRUN_HOME", home)

	session := &types.BuilderSession{Id: "bld_ses_preflight0001", UserID: "creator", WorkspaceDir: t.TempDir()}
	gitCfg := types.BuilderGitConfig{AppsFile: "apps.star"}

	// A user without app:apply on the path is denied on the first check,
	// before any file is written
	err := server.builderPublishLocal(rbacEnforcedCtx(ctx, "nobody"), session, gitCfg,
		"allowed2", "/apps/allowed2", "app(\"/apps/allowed2\", \"src\")\n")
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionApply)) {
		t.Fatalf("expected app:apply denial, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, "app_src")); !os.IsNotExist(statErr) {
		t.Fatalf("publish root must not exist after denial, stat err %v", statErr)
	}

	// The harness "creator" grant holds app:apply but not app:approve: the
	// approving apply is denied by the preflight, before any file is written
	err = server.builderPublishLocal(rbacEnforcedCtx(ctx, "creator"), session, gitCfg,
		"allowed2", "/apps/allowed2", "app(\"/apps/allowed2\", \"src\")\n")
	if err == nil || !strings.Contains(err.Error(), string(types.PermissionApprove)) {
		t.Fatalf("expected app:approve denial, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, "app_src")); !os.IsNotExist(statErr) {
		t.Fatalf("publish root must not exist after denial, stat err %v", statErr)
	}

	// "publisher" holds app:apply and app:approve but not app:promote. The
	// publish is staging-first (no promote), so app:promote is NOT required:
	// the permission preflight passes and files are staged (promotion is a
	// separate console step)
	err = server.builderPublishLocal(rbacEnforcedCtx(ctx, "publisher"), session, gitCfg,
		"allowed2", "/apps/allowed2", "app(\"/apps/allowed2\", \"src\")\n")
	if err != nil && strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("staging-first publish must not need app:promote, got %v", err)
	}
	// The preflight passed: the publish root was created
	if _, statErr := os.Stat(filepath.Join(home, "app_src")); statErr != nil {
		t.Fatalf("publish root should exist after the permission preflight passed, stat err %v", statErr)
	}
}

// TestBuilderTurnDonePreviewOwner verifies the preview app created by the
// turn-done callback is owned by the session creator: the owner rule then
// covers preview access and session-delete cleanup (previously the background
// context left the owner empty, orphaning the preview app)
func TestBuilderTurnDonePreviewOwner(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	server.staticConfig.AppBuilder.PreviewPath = "/preview"
	server.builderManager = builder.NewManager(server.Logger, server.Config, db,
		func(input string) (string, error) { return input, nil })

	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "app.star"), []byte("app = ace.app(\"previewApp\")\n"), 0600); err != nil {
		t.Fatalf("write app.star: %v", err)
	}
	session := &types.BuilderSession{Id: "bld_ses_previewowner1", UserID: "creator",
		WorkspaceDir: workspace, Status: types.BuilderSessionReady}
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	if err := db.CreateBuilderSession(ctx, tx, session); err != nil {
		t.Fatalf("create builder session: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit session: %v", err)
	}

	// RBAC is enabled but the preview creation is authorized by builder:create
	// (system continuation of the checked builder calls), not app permissions
	server.builderTurnDone(session.Id)

	verifyTx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin verify transaction: %v", err)
	}
	defer verifyTx.Rollback() //nolint:errcheck
	entry, err := db.GetAppEntryTx(ctx, verifyTx, types.AppPathDomain{Path: "/preview/previewowner"})
	if err != nil {
		t.Fatalf("preview app not created: %v", err)
	}
	if entry.UserID != "creator" {
		t.Fatalf("preview app owner = %q, want creator", entry.UserID)
	}
	persisted, err := db.GetBuilderSession(ctx, verifyTx, session.Id)
	if err != nil || persisted.PreviewPath != "/preview/previewowner" {
		t.Fatalf("session preview path = %q err %v", persisted.PreviewPath, err)
	}
}

// TestBuilderEditableAppOwner verifies the owner rule applies to edit
// sessions: the creator of an app can start an edit session on it without an
// explicit grant, another user without grants cannot
func TestBuilderEditableAppOwner(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()

	// Create the app as an RBAC enforced user so it records the owner, then
	// drop every grant: only the owner rule can authorize after this
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Enabled: true,
		Roles:   map[string][]types.RBACPermission{"applier": {types.PermissionApply}},
		Grants: []types.RBACGrant{{Description: "applier", Users: []string{"owner-x"},
			Roles: []string{"applier"}, Targets: []string{"all"}}},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}
	applyPath := filepath.Join(t.TempDir(), "app.ace")
	writeSyncApplyFile(t, applyPath, "/apps/owned1")
	if _, _, err := server.Apply(rbacEnforcedCtx(ctx, "owner-x"), types.Transaction{}, applyPath, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	server.apps.ResetAllAppCache()
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{Enabled: true}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}

	entry, err := server.builderEditableApp(rbacEnforcedCtx(ctx, "owner-x"), "/apps/owned1")
	if err != nil {
		t.Fatalf("owner edit session check: %v", err)
	}
	if entry.UserID != "owner-x" {
		t.Fatalf("app owner = %q, want owner-x", entry.UserID)
	}

	if _, err := server.builderEditableApp(rbacEnforcedCtx(ctx, "stranger"), "/apps/owned1"); err == nil {
		t.Fatal("expected denial for non-owner without grants")
	}
}
