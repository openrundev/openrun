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
	types.BindingMetadata, bool) ([]types.BindingGrant, error) {
	return nil, nil
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

	response, _, bindingAccounts, err := server.Apply(ctx, types.Transaction{}, applyPath, "/apps/**", false, false, false,
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
	if bindingAccounts != nil {
		defer bindingAccounts.rollbackAndClose(ctx)
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

	response, _, bindingAccounts, err := server.Apply(ctx, types.Transaction{}, applyPath, "all", false, false, false,
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
	if bindingAccounts != nil {
		defer bindingAccounts.rollbackAndClose(ctx)
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
