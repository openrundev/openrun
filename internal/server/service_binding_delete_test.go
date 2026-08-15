// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/types"
)

// registerDeleteTestService registers an artifact tracking service binding
// type and creates a default service instance for it. The returned pointer is
// the hook run on each artifact drop; it starts out nil and a test can set it to
// inspect the metadata state at drop time or to make a drop fail
func registerDeleteTestService(t *testing.T, db *metadata.Metadata, ctx context.Context, serviceType string, deleted *[]bindings.Artifact) *func(bindings.Artifact) error {
	t.Helper()
	generateCalls := 0
	failAfterCreate := false
	closed := 0
	var deleteHook func(bindings.Artifact) error
	previousBuilder, hadPreviousBuilder := bindings.GetServiceBinding(serviceType)
	bindings.SetServiceBinding(serviceType, func() bindings.ServiceBinding {
		return &applyAccountTrackingServiceBinding{
			generateCalls:    &generateCalls,
			failAfterCreate:  &failAfterCreate,
			deletedArtifacts: deleted,
			closed:           &closed,
			deleteHook:       &deleteHook,
		}
	})
	t.Cleanup(func() {
		if hadPreviousBuilder {
			bindings.SetServiceBinding(serviceType, previousBuilder)
		} else {
			bindings.SetServiceBinding(serviceType, nil)
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
	return &deleteHook
}

func getBindingRow(t *testing.T, db *metadata.Metadata, ctx context.Context, path string) (*types.Binding, error) {
	t.Helper()
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	return db.GetBinding(ctx, tx, path)
}

func TestDeleteBindingDropsBackendArtifacts(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	deletedArtifacts := []bindings.Artifact{}
	registerDeleteTestService(t, db, ctx, "deltest", &deletedArtifacts)

	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/apps/delbase", Source: "deltest",
	}, false); err != nil {
		t.Fatalf("create binding: %v", err)
	}

	// The artifacts created for the accounts are recorded in the binding metadata
	binding, err := getBindingRow(t, db, ctx, "/apps/delbase")
	if err != nil {
		t.Fatalf("get binding: %v", err)
	}
	wantProd := []types.BindingArtifact{
		{Type: "role", Name: binding.Id + "_role_prod"},
		{Type: "schema", Name: binding.Id + "_schema_prod"},
	}
	wantStage := []types.BindingArtifact{
		{Type: "role", Name: binding.Id + "_role_stage"},
		{Type: "schema", Name: binding.Id + "_schema_stage"},
	}
	if !slices.Equal(binding.Metadata.Artifacts, wantProd) {
		t.Fatalf("prod artifacts = %v, want %v", binding.Metadata.Artifacts, wantProd)
	}
	if !slices.Equal(binding.StagedMetadata.Artifacts, wantStage) {
		t.Fatalf("staged artifacts = %v, want %v", binding.StagedMetadata.Artifacts, wantStage)
	}

	// Dry run delete keeps the binding and drops nothing on the backend
	deletedArtifacts = nil
	if err := server.DeleteBinding(ctx, "/apps/delbase", true); err != nil {
		t.Fatalf("dry run delete binding: %v", err)
	}
	if _, err := getBindingRow(t, db, ctx, "/apps/delbase"); err != nil {
		t.Fatalf("binding deleted by dry run: %v", err)
	}
	if len(deletedArtifacts) != 0 {
		t.Fatalf("dry run deleted artifacts = %v, want none", deletedArtifacts)
	}

	// Deleting the binding removes the row and drops the recorded artifacts,
	// staged then prod, each in reverse creation order
	if err := server.DeleteBinding(ctx, "/apps/delbase", false); err != nil {
		t.Fatalf("delete binding: %v", err)
	}
	if _, err := getBindingRow(t, db, ctx, "/apps/delbase"); err == nil {
		t.Fatal("binding still exists after delete")
	}
	wantDeleted := []bindings.Artifact{
		{Type: bindings.ArtifactSchema, Name: binding.Id + "_schema_stage"},
		{Type: bindings.ArtifactRole, Name: binding.Id + "_role_stage"},
		{Type: bindings.ArtifactSchema, Name: binding.Id + "_schema_prod"},
		{Type: bindings.ArtifactRole, Name: binding.Id + "_role_prod"},
	}
	if !slices.Equal(deletedArtifacts, wantDeleted) {
		t.Fatalf("deleted artifacts = %v, want %v", deletedArtifacts, wantDeleted)
	}
}

// TestDeleteBindingDropsArtifactsAfterCommit checks that the backend objects are
// dropped only once the metadata delete has committed, so the metadata
// transaction is never held open across the calls to the backend service
func TestDeleteBindingDropsArtifactsAfterCommit(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	deletedArtifacts := []bindings.Artifact{}
	deleteHook := registerDeleteTestService(t, db, ctx, "delcommit", &deletedArtifacts)

	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/apps/delcommitted", Source: "delcommit",
	}, false); err != nil {
		t.Fatalf("create binding: %v", err)
	}

	rowsAtDropTime := 0
	*deleteHook = func(bindings.Artifact) error {
		if _, err := getBindingRow(t, db, ctx, "/apps/delcommitted"); err == nil {
			rowsAtDropTime++
		}
		return nil
	}
	if err := server.DeleteBinding(ctx, "/apps/delcommitted", false); err != nil {
		t.Fatalf("delete binding: %v", err)
	}
	if len(deletedArtifacts) != 4 {
		t.Fatalf("dropped %d artifacts, want 4", len(deletedArtifacts))
	}
	if rowsAtDropTime != 0 {
		t.Fatalf("binding row still present for %d of the artifact drops, want the drops to run after the commit", rowsAtDropTime)
	}
}

// TestDeleteBindingArtifactDropFailure checks the tradeoff of dropping after the
// commit: the binding stays deleted and the failure is reported, so the objects
// left on the service can be dropped manually
func TestDeleteBindingArtifactDropFailure(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	deletedArtifacts := []bindings.Artifact{}
	deleteHook := registerDeleteTestService(t, db, ctx, "delfail", &deletedArtifacts)

	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/apps/delfailing", Source: "delfail",
	}, false); err != nil {
		t.Fatalf("create binding: %v", err)
	}

	*deleteHook = func(artifact bindings.Artifact) error {
		if artifact.Type == bindings.ArtifactRole {
			return fmt.Errorf("simulated drop failure")
		}
		return nil
	}
	err := server.DeleteBinding(ctx, "/apps/delfailing", false)
	if err == nil || !strings.Contains(err.Error(), "simulated drop failure") ||
		!strings.Contains(err.Error(), "/apps/delfailing") {
		t.Fatalf("delete binding error = %v, want the drop failure reported for the binding", err)
	}
	if _, err := getBindingRow(t, db, ctx, "/apps/delfailing"); err == nil {
		t.Fatal("binding row kept after a failed artifact drop, want the metadata delete to stand")
	}
	// The staged and prod schemas are dropped before their roles, so both are
	// gone even though both role drops failed
	if len(deletedArtifacts) != 2 {
		t.Fatalf("dropped artifacts = %v, want the two schemas", deletedArtifacts)
	}
}

func TestDeleteBindingBlockedByDerivedBindings(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	deletedArtifacts := []bindings.Artifact{}
	registerDeleteTestService(t, db, ctx, "delderived", &deletedArtifacts)

	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/apps/base", Source: "delderived",
	}, false); err != nil {
		t.Fatalf("create base binding: %v", err)
	}
	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/apps/derived", Source: "/apps/base",
	}, false); err != nil {
		t.Fatalf("create derived binding: %v", err)
	}

	err := server.DeleteBinding(ctx, "/apps/base", false)
	if err == nil || !strings.Contains(err.Error(), "derived bindings (/apps/derived)") {
		t.Fatalf("delete base with derived binding error = %v, want derived bindings error", err)
	}
	if _, err := getBindingRow(t, db, ctx, "/apps/base"); err != nil {
		t.Fatalf("base binding removed by failed delete: %v", err)
	}

	// Deleting the derived binding first, then the base, succeeds
	if err := server.DeleteBinding(ctx, "/apps/derived", false); err != nil {
		t.Fatalf("delete derived binding: %v", err)
	}
	if err := server.DeleteBinding(ctx, "/apps/base", false); err != nil {
		t.Fatalf("delete base binding after derived: %v", err)
	}
	if len(deletedArtifacts) != 8 {
		t.Fatalf("deleted %d artifacts, want 8 (role+schema, staged+prod, for both bindings)", len(deletedArtifacts))
	}
}

func TestDeleteServiceBlockedByBindings(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	deletedArtifacts := []bindings.Artifact{}
	registerDeleteTestService(t, db, ctx, "delservice", &deletedArtifacts)

	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/apps/svcbound", Source: "delservice",
	}, false); err != nil {
		t.Fatalf("create binding: %v", err)
	}

	err := server.DeleteService(ctx, "primary", "delservice", false)
	if err == nil || !strings.Contains(err.Error(), "used by bindings (/apps/svcbound)") {
		t.Fatalf("delete service with binding error = %v, want used-by-bindings error", err)
	}
	services, err := server.ListServices(ctx, "delservice", "primary")
	if err != nil || len(services) != 1 {
		t.Fatalf("services after failed delete = %v (err %v), want the service kept", services, err)
	}

	if err := server.DeleteBinding(ctx, "/apps/svcbound", false); err != nil {
		t.Fatalf("delete binding: %v", err)
	}

	// With no bindings left the service delete succeeds and touches nothing on
	// the backend service
	deletedArtifacts = nil
	if err := server.DeleteService(ctx, "primary", "delservice", false); err != nil {
		t.Fatalf("delete service: %v", err)
	}
	services, err = server.ListServices(ctx, "delservice", "primary")
	if err != nil || len(services) != 0 {
		t.Fatalf("services after delete = %v (err %v), want none", services, err)
	}
	if len(deletedArtifacts) != 0 {
		t.Fatalf("service delete dropped artifacts %v, want no backend action", deletedArtifacts)
	}
}

func TestDeleteAppRemovesAutoBindings(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	deletedArtifacts := []bindings.Artifact{}
	deleteHook := registerDeleteTestService(t, db, ctx, "delautoapp", &deletedArtifacts)

	appSourceDir := writeExportTestAppSource(t)
	if _, err := server.CreateApp(ctx, "/apps/autodel", false, false, &types.CreateAppRequest{
		SourceUrl: appSourceDir,
		Bindings:  []string{"delautoapp"},
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}

	apps, err := server.FilterApps("/apps/autodel", false)
	if err != nil || len(apps) != 1 {
		t.Fatalf("filter apps = %v (err %v), want the created app", apps, err)
	}
	autoPath := autoBindingPathForAppID(apps[0].Id, "delautoapp")
	autoBinding, err := getBindingRow(t, db, ctx, autoPath)
	if err != nil {
		t.Fatalf("auto binding %s not found: %v", autoPath, err)
	}

	// A user binding on the same service is not owned by the app and survives
	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/apps/keepme", Source: "delautoapp",
	}, false); err != nil {
		t.Fatalf("create user binding: %v", err)
	}

	deletedArtifacts = nil
	// The auto binding's objects are dropped only after the app delete commits
	rowsAtDropTime := 0
	*deleteHook = func(bindings.Artifact) error {
		if _, err := getBindingRow(t, db, ctx, autoPath); err == nil {
			rowsAtDropTime++
		}
		return nil
	}
	if _, err := server.DeleteApps(ctx, "/apps/autodel", false); err != nil {
		t.Fatalf("delete app: %v", err)
	}
	if rowsAtDropTime != 0 {
		t.Fatalf("auto binding row still present for %d of the artifact drops, want the drops to run after the commit", rowsAtDropTime)
	}
	if _, err := getBindingRow(t, db, ctx, autoPath); err == nil {
		t.Fatal("auto binding still exists after app delete")
	}
	if _, err := getBindingRow(t, db, ctx, "/apps/keepme"); err != nil {
		t.Fatalf("user binding removed by app delete: %v", err)
	}
	wantDeleted := []bindings.Artifact{
		{Type: bindings.ArtifactSchema, Name: autoBinding.Id + "_schema_stage"},
		{Type: bindings.ArtifactRole, Name: autoBinding.Id + "_role_stage"},
		{Type: bindings.ArtifactSchema, Name: autoBinding.Id + "_schema_prod"},
		{Type: bindings.ArtifactRole, Name: autoBinding.Id + "_role_prod"},
	}
	if !slices.Equal(deletedArtifacts, wantDeleted) {
		t.Fatalf("deleted artifacts = %v, want %v", deletedArtifacts, wantDeleted)
	}
}

func TestAutoBindingCannotBeShared(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	deletedArtifacts := []bindings.Artifact{}
	registerDeleteTestService(t, db, ctx, "delautoshare", &deletedArtifacts)

	appSourceDir := writeExportTestAppSource(t)
	if _, err := server.CreateApp(ctx, "/apps/autoowner", false, false, &types.CreateAppRequest{
		SourceUrl: appSourceDir,
		Bindings:  []string{"delautoshare"},
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	apps, err := server.FilterApps("/apps/autoowner", false)
	if err != nil || len(apps) != 1 {
		t.Fatalf("filter apps = %v (err %v), want the created app", apps, err)
	}
	autoPath := autoBindingPathForAppID(apps[0].Id, "delautoshare")

	// A derived binding cannot use an auto binding as its base
	_, err = server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/apps/fromauto", Source: autoPath,
	}, false)
	if err == nil || !strings.Contains(err.Error(), "auto bindings are owned by their app") {
		t.Fatalf("derive from auto binding error = %v, want ownership error", err)
	}

	// Another app cannot attach the auto binding
	_, err = server.CreateApp(ctx, "/apps/otherapp", false, false, &types.CreateAppRequest{
		SourceUrl: appSourceDir,
		Bindings:  []string{autoPath},
	})
	if err == nil || !strings.Contains(err.Error(), "owned by another app") {
		t.Fatalf("attach foreign auto binding error = %v, want ownership error", err)
	}

	// The owning app deletes cleanly along with its auto binding
	if _, err := server.DeleteApps(ctx, "/apps/autoowner", false); err != nil {
		t.Fatalf("delete app: %v", err)
	}
	if _, err := getBindingRow(t, db, ctx, autoPath); err == nil {
		t.Fatal("auto binding still exists after app delete")
	}
}

// TestDeleteAppBackstopBlocksDerivedFromAutoBinding covers the app delete
// backstop for derived-from-auto bindings that predate the creation-time
// rejection: the row is inserted directly at the DB layer
func TestDeleteAppBackstopBlocksDerivedFromAutoBinding(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	deletedArtifacts := []bindings.Artifact{}
	registerDeleteTestService(t, db, ctx, "delautolegacy", &deletedArtifacts)

	appSourceDir := writeExportTestAppSource(t)
	if _, err := server.CreateApp(ctx, "/apps/legacyowner", false, false, &types.CreateAppRequest{
		SourceUrl: appSourceDir,
		Bindings:  []string{"delautolegacy"},
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	apps, err := server.FilterApps("/apps/legacyowner", false)
	if err != nil || len(apps) != 1 {
		t.Fatalf("filter apps = %v (err %v), want the created app", apps, err)
	}
	autoPath := autoBindingPathForAppID(apps[0].Id, "delautolegacy")

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	if err := db.CreateBinding(ctx, tx, &types.Binding{
		Id: types.ID_PREFIX_BINDING + "legacyderived", Path: "/apps/legacyderived",
		Source: autoPath, ServiceType: "delautolegacy", ServiceName: "primary", DerivedFrom: autoPath,
	}); err != nil {
		t.Fatalf("insert legacy derived binding: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit legacy derived binding: %v", err)
	}

	_, err = server.DeleteApps(ctx, "/apps/legacyowner", false)
	if err == nil || !strings.Contains(err.Error(), "derived bindings (/apps/legacyderived)") {
		t.Fatalf("delete app error = %v, want derived bindings error", err)
	}
	// The failed delete rolled everything back
	if apps, err := server.FilterApps("/apps/legacyowner", false); err != nil || len(apps) != 1 {
		t.Fatalf("apps after failed delete = %v (err %v), want the app kept", apps, err)
	}
	if _, err := getBindingRow(t, db, ctx, autoPath); err != nil {
		t.Fatalf("auto binding removed by failed app delete: %v", err)
	}

	// After deleting the derived binding the app delete goes through
	if err := server.DeleteBinding(ctx, "/apps/legacyderived", false); err != nil {
		t.Fatalf("delete derived binding: %v", err)
	}
	if _, err := server.DeleteApps(ctx, "/apps/legacyowner", false); err != nil {
		t.Fatalf("delete app after derived binding removed: %v", err)
	}
	if _, err := getBindingRow(t, db, ctx, autoPath); err == nil {
		t.Fatal("auto binding still exists after app delete")
	}
}

func TestDeleteStagingServiceBlockedByBindings(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	deletedArtifacts := []bindings.Artifact{}
	registerDeleteTestService(t, db, ctx, "delstaging", &deletedArtifacts)

	// "primary" (created by the helper) plus a "main" service that uses a
	// dedicated "stage" service for its staged accounts
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	if err := db.CreateService(ctx, tx, &types.Service{
		Id: types.ID_PREFIX_SERVICE + "delstagingstg", Name: "stage", ServiceType: "delstaging", Config: map[string]string{},
	}); err != nil {
		t.Fatalf("create staging service: %v", err)
	}
	if err := db.CreateService(ctx, tx, &types.Service{
		Id: types.ID_PREFIX_SERVICE + "delstagingmain", Name: "main", ServiceType: "delstaging", Staging: "stage", Config: map[string]string{},
	}); err != nil {
		t.Fatalf("create main service: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit services: %v", err)
	}

	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/apps/stagedbind", Source: "delstaging/main",
	}, false); err != nil {
		t.Fatalf("create binding: %v", err)
	}

	// The staging service hosts the binding's staged account, so it cannot be
	// deleted while the binding exists
	err = server.DeleteService(ctx, "stage", "delstaging", false)
	if err == nil || !strings.Contains(err.Error(), "staging service for delstaging/main which has bindings (/apps/stagedbind)") {
		t.Fatalf("delete staging service error = %v, want staging-in-use error", err)
	}

	if err := server.DeleteBinding(ctx, "/apps/stagedbind", false); err != nil {
		t.Fatalf("delete binding: %v", err)
	}
	if err := server.DeleteService(ctx, "stage", "delstaging", false); err != nil {
		t.Fatalf("delete staging service after binding removed: %v", err)
	}
	if err := server.DeleteService(ctx, "main", "delstaging", false); err != nil {
		t.Fatalf("delete main service: %v", err)
	}
}
