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
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		config: &types.ServerConfig{},
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
	server.config.System.MaxSyncFailureCount = 3

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
