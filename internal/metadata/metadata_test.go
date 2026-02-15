// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func setupTestMetadata(t *testing.T) (*Metadata, func()) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "metadata.db")
	config := &types.ServerConfig{
		Metadata: types.MetadataConfig{
			DBConnection: "sqlite:" + dbPath,
			AutoUpgrade:  true,
		},
	}
	logger := types.NewLogger(&types.LogConfig{Level: "INFO"})

	m, err := NewMetadata(logger, config)
	if err != nil {
		t.Fatalf("failed to create metadata: %v", err)
	}

	return m, func() {
		_ = m.db.Close()
	}
}

func TestMetadata_InitializationAndNotifications(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()

	var version int
	err := m.db.QueryRow("select version from version").Scan(&version)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "db version", CURRENT_DB_VERSION, version)

	if m.GetCertStorage() == nil {
		t.Fatal("expected cert storage to be initialized")
	}

	err = m.VersionUpgrade(m.config)
	testutil.AssertNoError(t, err)

	err = m.NotifyAppUpdate([]types.AppPathDomain{{Path: "/a", Domain: "example.com"}})
	testutil.AssertNoError(t, err)

	err = m.NotifyConfigUpdate()
	testutil.AssertNoError(t, err)

	tx, err := m.BeginTransaction(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.CommitTransaction(tx))

	tx, err = m.BeginTransaction(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.RollbackTransaction(tx))
}

func TestMetadata_AppLifecycle(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	prod := &types.AppEntry{
		Id:        types.AppId(types.ID_PREFIX_APP_PROD + "1"),
		Path:      "/prod",
		Domain:    "example.com",
		SourceUrl: "https://example.com/repo.git",
		UserID:    "u1",
		Metadata: types.AppMetadata{
			Name: "Prod app",
			VersionMetadata: types.VersionMetadata{
				Version: 1,
			},
			AppConfig: map[string]string{"star_base": "\"/tmp/base\""},
		},
		Settings: types.AppSettings{
			AuthnType:   types.AppAuthnSystem,
			GitAuthName: "git-one",
		},
	}
	preview := &types.AppEntry{
		Id:        types.AppId(types.ID_PREFIX_APP_PREVIEW + "1"),
		Path:      "/preview",
		Domain:    "example.com",
		MainApp:   prod.Id,
		SourceUrl: "https://example.com/repo.git",
		UserID:    "u2",
		Metadata: types.AppMetadata{
			Name: "Preview app",
		},
	}

	tx, err := m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.CreateApp(ctx, tx, prod))
	testutil.AssertNoError(t, m.CreateApp(ctx, tx, preview))

	versionMetadata, err := json.Marshal(prod.Metadata)
	testutil.AssertNoError(t, err)
	_, err = tx.ExecContext(ctx,
		`insert into app_versions(appid, version, user_id, metadata, create_time) values(?, ?, ?, ?, datetime('now'))`,
		prod.Id, prod.Metadata.VersionMetadata.Version, prod.UserID, string(versionMetadata))
	testutil.AssertNoError(t, err)

	prod.SourceUrl = "https://example.com/repo2.git"
	testutil.AssertNoError(t, m.UpdateSourceUrl(ctx, tx, prod))

	prod.Metadata.Name = "Prod app updated"
	testutil.AssertNoError(t, m.UpdateAppMetadata(ctx, tx, prod))

	preview.Metadata.Name = "Preview app updated"
	testutil.AssertNoError(t, m.UpdateAppMetadata(ctx, tx, preview))

	prod.Settings.StageWriteAccess = true
	testutil.AssertNoError(t, m.UpdateAppSettings(ctx, tx, prod))
	testutil.AssertNoError(t, tx.Commit())

	gotProd, err := m.GetApp(types.CreateAppPathDomain(prod.Path, prod.Domain))
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "updated source", prod.SourceUrl, gotProd.SourceUrl)
	testutil.AssertEqualsString(t, "updated name", prod.Metadata.Name, gotProd.Metadata.Name)
	if gotProd.Metadata.SpecFiles == nil {
		t.Fatal("expected spec files map to be initialized")
	}

	paths, err := m.GetAppsForDomain(prod.Domain)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "apps for domain", 2, len(paths))

	withoutInternal, err := m.GetAllApps(false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "non-internal app count", 1, len(withoutInternal))
	testutil.AssertEqualsString(t, "star base stripped", "/tmp/base", withoutInternal[0].StarBase)

	withInternal, err := m.GetAllApps(true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "all app count", 2, len(withInternal))

	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	linkedApps, err := m.GetLinkedApps(ctx, tx, prod.Id)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "linked app count", 1, len(linkedApps))
	testutil.AssertNoError(t, tx.Rollback())

	var versionMetadataJSON string
	err = m.db.QueryRow(`select metadata from app_versions where appid = ? and version = ?`, prod.Id, 1).Scan(&versionMetadataJSON)
	testutil.AssertNoError(t, err)
	var versionEntry types.AppMetadata
	err = json.Unmarshal([]byte(versionMetadataJSON), &versionEntry)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "version metadata updated", prod.Metadata.Name, versionEntry.Name)

	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.DeleteApp(ctx, tx, prod.Id))
	testutil.AssertNoError(t, tx.Commit())

	_, err = m.GetApp(types.CreateAppPathDomain(prod.Path, prod.Domain))
	testutil.AssertErrorContains(t, err, "app not found")
}

func TestMetadata_SyncLifecycle(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	entry := &types.SyncEntry{
		Id:          "sync-1",
		Path:        "/prod",
		IsScheduled: true,
		UserID:      "u1",
		Metadata: types.SyncMetadata{
			GitBranch: "main",
			Promote:   true,
		},
		Status: types.SyncJobStatus{
			State:        "pending",
			FailureCount: 1,
		},
	}

	tx, err := m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.CreateSync(ctx, tx, entry))
	testutil.AssertNoError(t, tx.Commit())

	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	entries, err := m.GetSyncEntries(ctx, tx)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "sync entry count", 1, len(entries))
	testutil.AssertNoError(t, tx.Rollback())

	got, err := m.GetSyncEntry(ctx, types.Transaction{}, entry.Id)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "sync path", entry.Path, got.Path)
	testutil.AssertEqualsString(t, "sync status", "pending", got.Status.State)

	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	status := &types.SyncJobStatus{State: "success", CommitId: "abc123"}
	testutil.AssertNoError(t, m.UpdateSyncStatus(ctx, tx, entry.Id, status))
	testutil.AssertNoError(t, tx.Commit())

	got, err = m.GetSyncEntry(ctx, types.Transaction{}, entry.Id)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "updated sync status", "success", got.Status.State)

	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	err = m.DeleteSync(ctx, tx, "missing-sync")
	testutil.AssertErrorContains(t, err, "no sync entry found with id for delete")
	testutil.AssertNoError(t, tx.Rollback())

	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.DeleteSync(ctx, tx, entry.Id))
	testutil.AssertNoError(t, tx.Commit())

	_, err = m.GetSyncEntry(ctx, types.Transaction{}, entry.Id)
	testutil.AssertErrorContains(t, err, "sync entry not found")
}

func TestMetadata_ConfigAndKV(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	_, err := m.GetConfig()
	if !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("expected ErrConfigNotFound, got %v", err)
	}

	configV1 := &types.DynamicConfig{
		VersionId: "v1",
		RBAC: types.RBACConfig{
			Enabled: true,
		},
	}
	testutil.AssertNoError(t, m.InitConfig(ctx, "u1", configV1))

	err = m.InitConfig(ctx, "u1", configV1)
	if !errors.Is(err, ErrConfigAlreadyExists) {
		t.Fatalf("expected ErrConfigAlreadyExists, got %v", err)
	}

	configV2 := &types.DynamicConfig{
		VersionId: "v2",
		RBAC: types.RBACConfig{
			Enabled: false,
		},
	}
	err = m.UpdateConfig(ctx, "u2", "missing-version", configV2)
	testutil.AssertErrorContains(t, err, "no config entry found with version id for update")
	testutil.AssertNoError(t, m.UpdateConfig(ctx, "u2", "v1", configV2))

	gotConfig, err := m.GetConfig()
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "updated config version", "v2", gotConfig.VersionId)

	_, err = m.FetchKV(ctx, "missing-key")
	testutil.AssertErrorContains(t, err, "error fetching value")
	_, err = m.FetchKVBlob(ctx, "missing-key")
	testutil.AssertErrorContains(t, err, "error querying keystore")

	testutil.AssertNoError(t, m.StoreKV(ctx, "k1", map[string]any{"name": "openrun"}, nil))
	kv, err := m.FetchKV(ctx, "k1")
	testutil.AssertNoError(t, err)
	name, ok := kv["name"].(string)
	if !ok {
		t.Fatalf("expected string value for key name, got %#v", kv["name"])
	}
	testutil.AssertEqualsString(t, "kv value", "openrun", name)

	testutil.AssertNoError(t, m.UpdateKV(ctx, "k1", map[string]any{"name": "openrun-updated"}))
	kv, err = m.FetchKV(ctx, "k1")
	testutil.AssertNoError(t, err)
	name, ok = kv["name"].(string)
	if !ok {
		t.Fatalf("expected string value for key name, got %#v", kv["name"])
	}
	testutil.AssertEqualsString(t, "kv updated value", "openrun-updated", name)

	err = m.UpdateKVBlob(ctx, "missing-key", []byte("value"))
	testutil.AssertErrorContains(t, err, "no key entry found with key for update")

	testutil.AssertNoError(t, m.DeleteKV(ctx, "k1"))
	_, err = m.FetchKVBlob(ctx, "k1")
	testutil.AssertErrorContains(t, err, "error querying keystore")

	testutil.AssertNoError(t, m.StoreKVBlob(ctx, "bad-json", []byte("not-json"), nil))
	_, err = m.FetchKV(ctx, "bad-json")
	testutil.AssertErrorContains(t, err, "error unmarshalling value")

	_, err = m.db.ExecContext(ctx, `insert into keystore values (?, ?, datetime('now'), datetime('now', '-1 day'))`, "expired", []byte(`{"ok":true}`))
	testutil.AssertNoError(t, err)
	_, err = m.FetchKVBlob(ctx, "expired")
	testutil.AssertErrorContains(t, err, "error querying keystore")
}

func TestToNullTime(t *testing.T) {
	nullTime := toNullTime(nil)
	testutil.AssertEqualsBool(t, "nil time valid", false, nullTime.Valid)

	now := time.Now().Truncate(time.Second)
	nullTime = toNullTime(&now)
	testutil.AssertEqualsBool(t, "non nil time valid", true, nullTime.Valid)
	if !nullTime.Time.Equal(now) {
		t.Fatalf("expected %s got %s", now, nullTime.Time)
	}
}
