// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
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

func TestMetadata_MigrateLinkedAppPathsBackfillsInternalApps(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "metadata.db")
	db, err := sql.Open("sqlite", dbPath)
	testutil.AssertNoError(t, err)

	_, err = db.Exec(`create table version (version int, last_upgraded datetime)`)
	testutil.AssertNoError(t, err)
	_, err = db.Exec(`insert into version values (11, datetime('now'))`)
	testutil.AssertNoError(t, err)
	_, err = db.Exec(`create table apps(id text, path text, domain text, source_url text, is_dev bool, main_app text, user_id text, create_time datetime, update_time datetime, settings json, metadata json, UNIQUE(id), UNIQUE(path, domain))`)
	testutil.AssertNoError(t, err)
	// Real version 11 databases have the services and bindings tables (created
	// in the v11 migration); later migrations alter them
	_, err = db.Exec(`create table services (id text not null, name text, service_type text, is_default bool, staging text not null default '', ` +
		`config json, create_time datetime, update_time datetime, PRIMARY KEY(name, service_type), UNIQUE(id))`)
	testutil.AssertNoError(t, err)
	_, err = db.Exec(`create table bindings (id text not null, path text, source text, service_type text not null default '', ` +
		`service_name text not null default '', base_binding text not null default '', metadata json, staged_metadata json, ` +
		`create_time datetime, update_time datetime, PRIMARY KEY(path), UNIQUE(id))`)
	testutil.AssertNoError(t, err)
	_, err = db.Exec(`insert into apps(id, path, domain, source_url, is_dev, main_app, user_id, create_time, update_time, settings, metadata) values
		('app_prd_1', '/prod', '', 'https://example.com/repo.git', false, '', 'u1', datetime('now'), datetime('now'), '{}', '{}'),
		('app_prd_abc', '/abc', '', 'https://example.com/repo.git', false, '', 'u1', datetime('now'), datetime('now'), '{}', '{}'),
		('app_prd_domain_root', '', 'def', 'https://example.com/repo.git', false, '', 'u1', datetime('now'), datetime('now'), '{}', '{}'),
		('app_prd_domain_abc', '/abc', 'def', 'https://example.com/repo.git', false, '', 'u1', datetime('now'), datetime('now'), '{}', '{}'),
		('app_dev_1', '/dev', '', '/tmp/dev', true, '', 'u1', datetime('now'), datetime('now'), '{}', '{}'),
		('app_stg_1', '/prod_cl_stage', '', 'https://example.com/repo.git', false, 'app_prd_1', 'u1', datetime('now'), datetime('now'), '{}', '{}'),
		('app_pre_1', '/prod_cl_preview_abc123', '', 'https://example.com/repo.git', false, 'app_prd_1', 'u1', datetime('now'), datetime('now'), '{}', '{}'),
		('app_pre_2', '/legacy_preview', '', 'https://example.com/repo.git', false, 'app_prd_1', 'u1', datetime('now'), datetime('now'), '{}', '{}')`)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, db.Close())

	config := &types.ServerConfig{
		Metadata: types.MetadataConfig{
			DBConnection: "sqlite:" + dbPath,
			AutoUpgrade:  true,
		},
	}
	logger := types.NewLogger(&types.LogConfig{Level: "INFO"})
	m, err := NewMetadata(logger, config)
	testutil.AssertNoError(t, err)
	defer m.db.Close() //nolint:errcheck

	var prodLinkedPath, stageLinkedPath, previewLinkedPath string
	err = m.db.QueryRow(`select linked_app_path from apps where id = 'app_prd_1'`).Scan(&prodLinkedPath)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "prod linked path", "/prod"+types.STAGE_SUFFIX, prodLinkedPath)

	err = m.db.QueryRow(`select linked_app_path from apps where id = 'app_prd_abc'`).Scan(&prodLinkedPath)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "prod linked path without domain", "/abc"+types.STAGE_SUFFIX, prodLinkedPath)

	err = m.db.QueryRow(`select linked_app_path from apps where id = 'app_prd_domain_root'`).Scan(&prodLinkedPath)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "prod linked path with domain and empty path", "def:/"+types.STAGE_SUFFIX, prodLinkedPath)

	err = m.db.QueryRow(`select linked_app_path from apps where id = 'app_prd_domain_abc'`).Scan(&prodLinkedPath)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "prod linked path with domain", "def:/abc"+types.STAGE_SUFFIX, prodLinkedPath)

	err = m.db.QueryRow(`select linked_app_path from apps where id = 'app_stg_1'`).Scan(&stageLinkedPath)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "stage linked path", "/prod", stageLinkedPath)

	err = m.db.QueryRow(`select linked_app_path from apps where id = 'app_pre_1'`).Scan(&previewLinkedPath)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "preview linked path", "/prod", previewLinkedPath)

	prod, err := m.GetAppEntry(context.Background(), types.CreateAppPathDomain("/prod", ""))
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "prod linked path", "/prod"+types.STAGE_SUFFIX, prod.LinkedAppPath)

	dev, err := m.GetAppEntry(context.Background(), types.CreateAppPathDomain("/dev", ""))
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "dev linked path", "", dev.LinkedAppPath)

	tx, err := m.BeginTransaction(context.Background())
	testutil.AssertNoError(t, err)
	linkedApps, err := m.GetLinkedApps(context.Background(), tx, types.AppId("app_prd_1"))
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "linked app count", 3, len(linkedApps))
	testutil.AssertNoError(t, tx.Rollback())
}

func TestMetadata_AppLifecycle(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	prod := &types.AppEntry{
		Id:            types.AppId(types.ID_PREFIX_APP_PROD + "1"),
		Path:          "/prod",
		Domain:        "example.com",
		LinkedAppPath: "/prod" + types.STAGE_SUFFIX,
		SourceUrl:     "https://example.com/repo.git",
		UserID:        "u1",
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
		Id:            types.AppId(types.ID_PREFIX_APP_PREVIEW + "1"),
		Path:          "/preview",
		Domain:        "example.com",
		MainApp:       prod.Id,
		LinkedAppPath: prod.AppPathDomain().String(),
		SourceUrl:     "https://example.com/repo.git",
		UserID:        "u2",
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

	gotProd, err := m.GetAppEntry(ctx, types.CreateAppPathDomain(prod.Path, prod.Domain))
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "updated source", prod.SourceUrl, gotProd.SourceUrl)
	testutil.AssertEqualsString(t, "linked app path", prod.LinkedAppPath, gotProd.LinkedAppPath)
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
	testutil.AssertEqualsString(t, "linked app path", preview.LinkedAppPath, linkedApps[0].LinkedAppPath)
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

	_, err = m.GetAppEntry(ctx, types.CreateAppPathDomain(prod.Path, prod.Domain))
	testutil.AssertErrorContains(t, err, "app not found")
}

func TestFileStoreRejectsSymlinksInSource(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()

	ctx := context.Background()
	sourceDir := t.TempDir()
	externalDir := t.TempDir()
	externalFile := filepath.Join(externalDir, "secret.txt")
	if err := os.WriteFile(externalFile, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write external file: %v", err)
	}

	if err := os.WriteFile(filepath.Join(sourceDir, "app.star"), []byte("app = ace.app(\"test\")\n"), 0o600); err != nil {
		t.Fatalf("write app file: %v", err)
	}
	if err := os.Symlink(externalFile, filepath.Join(sourceDir, "leak.txt")); err != nil {
		t.Skipf("symlink unsupported in test environment: %v", err)
	}

	appEntry := &types.AppEntry{
		Id:        types.AppId(types.ID_PREFIX_APP_PROD + "symlinktest"),
		Path:      "/symlink",
		Domain:    "example.com",
		SourceUrl: sourceDir,
		UserID:    "u1",
		Metadata: types.AppMetadata{
			SpecFiles: &types.SpecFiles{},
		},
	}

	tx, err := m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.CreateApp(ctx, tx, appEntry))

	fileStore, err := NewFileStore(appEntry.Id, 0, m, tx)
	testutil.AssertNoError(t, err)

	err = fileStore.AddAppVersionDisk(ctx, tx, types.AppMetadata{
		VersionMetadata: types.VersionMetadata{
			Version: 1,
		},
	}, sourceDir)
	if err == nil {
		t.Fatal("expected symlinked source file to be rejected")
	}
	if !strings.Contains(err.Error(), "symlinks are not allowed") {
		t.Fatalf("unexpected error: %v", err)
	}

	testutil.AssertNoError(t, tx.Rollback())
}

func TestFileStoreSkipsSocketInSource(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()

	ctx := context.Background()
	sourceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, "app.star"), []byte("app = ace.app(\"test\")\n"), 0o600); err != nil {
		t.Fatalf("write app file: %v", err)
	}

	runDir := filepath.Join(sourceDir, "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatalf("create run dir: %v", err)
	}
	socketPath := filepath.Join(runDir, "openrun.sock")
	socket, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix sockets unsupported in test environment: %v", err)
	}
	defer socket.Close() //nolint:errcheck

	appEntry := &types.AppEntry{
		Id:        types.AppId(types.ID_PREFIX_APP_PROD + "sockettest"),
		Path:      "/socket",
		Domain:    "example.com",
		SourceUrl: sourceDir,
		UserID:    "u1",
		Metadata: types.AppMetadata{
			SpecFiles: &types.SpecFiles{},
		},
	}

	tx, err := m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.CreateApp(ctx, tx, appEntry))

	fileStore, err := NewFileStore(appEntry.Id, 0, m, tx)
	testutil.AssertNoError(t, err)

	err = fileStore.AddAppVersionDisk(ctx, tx, types.AppMetadata{
		VersionMetadata: types.VersionMetadata{
			Version: 1,
		},
	}, sourceDir)
	testutil.AssertNoError(t, err)

	var count int
	err = tx.QueryRowContext(ctx, `select count(*) from app_files where appid = ? and version = ? and name = ?`,
		appEntry.Id, 1, "run/openrun.sock").Scan(&count)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "socket app file count", 0, count)

	err = tx.QueryRowContext(ctx, `select count(*) from app_files where appid = ? and version = ? and name = ?`,
		appEntry.Id, 1, "app.star").Scan(&count)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "regular app file count", 1, count)

	testutil.AssertNoError(t, tx.Rollback())
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

func TestMetadata_ServiceBindingIdsPersisted(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	service := &types.Service{
		Id:          types.ID_PREFIX_SERVICE + "test",
		Name:        "svc1",
		ServiceType: "test",
		IsDefault:   true,
		Config:      map[string]string{"url": "postgres://localhost/db"},
	}
	binding := &types.Binding{
		Id:             types.ID_PREFIX_BINDING + "test",
		Path:           "/apps/b1",
		Source:         "test/svc1",
		ServiceType:    "test",
		ServiceName:    "svc1",
		StagedMetadata: types.BindingMetadata{Config: map[string]string{"role": "reader"}},
		Metadata:       types.BindingMetadata{Config: map[string]string{"role": "reader"}},
	}

	tx, err := m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.CreateService(ctx, tx, service))
	testutil.AssertNoError(t, m.CreateBinding(ctx, tx, binding))
	testutil.AssertNoError(t, tx.Commit())

	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	gotService, err := m.GetService(ctx, tx, service.ServiceType, service.Name)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "service id", service.Id, gotService.Id)
	gotBinding, err := m.GetBinding(ctx, tx, binding.Path)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "binding id", binding.Id, gotBinding.Id)
	testutil.AssertNoError(t, tx.Rollback())

	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	duplicateService := *service
	duplicateService.Name = "svc2"
	err = m.CreateService(ctx, tx, &duplicateService)
	testutil.AssertErrorContains(t, err, "error inserting service")
	testutil.AssertNoError(t, tx.Rollback())
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

	future := time.Now().Add(time.Hour)
	testutil.AssertNoError(t, m.UpsertKVBlob(ctx, "expired", []byte(`{"ok":true}`), &future))
	value, err := m.FetchKVBlob(ctx, "expired")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "upserted expired value", `{"ok":true}`, string(value))

	_, err = m.db.ExecContext(ctx, `insert into keystore values (?, ?, datetime('now'), datetime('now', '-1 day'))`, "expired-cleanup", []byte(`{"ok":true}`))
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.CleanupExpiredKV(ctx))
	_, err = m.db.ExecContext(ctx, `insert into keystore values (?, ?, datetime('now'), datetime('now', '-1 day'))`, "expired-cleanup", []byte(`{"ok":true}`))
	testutil.AssertNoError(t, err)
	_, err = m.FetchKVBlob(ctx, "expired-cleanup")
	testutil.AssertErrorContains(t, err, "error querying keystore")
}

func TestToNullTime(t *testing.T) {
	nullTime := toNullTime(nil)
	testutil.AssertEqualsBool(t, "nil time valid", false, nullTime.Valid)

	now := time.Now().Truncate(time.Second)
	nullTime = toNullTime(&now)
	testutil.AssertEqualsBool(t, "non nil time valid", true, nullTime.Valid)
	if !nullTime.Time.Equal(now.UTC()) {
		t.Fatalf("expected %s got %s", now.UTC(), nullTime.Time)
	}
}

func TestMetadata_ConfigHistoryDraftAndAtomicDelete(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	v1 := &types.DynamicConfig{VersionId: "history-v1", RBAC: types.RBACConfig{Enabled: true}}
	v2 := &types.DynamicConfig{VersionId: "history-v2", RBAC: types.RBACConfig{Enabled: false}}
	testutil.AssertNoError(t, m.InitConfig(ctx, "alice", v1))
	testutil.AssertNoError(t, m.UpdateConfig(ctx, "bob", v1.VersionId, v2))

	history, err := m.ListConfigHistory(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "history entries", 1, len(history))
	testutil.AssertEqualsString(t, "history version", v2.VersionId, history[0].VersionId)
	testutil.AssertEqualsString(t, "history user", "bob", history[0].UserId)

	snapshot, err := m.GetConfigVersion(ctx, v2.VersionId)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "snapshot version", v2.VersionId, snapshot.VersionId)
	_, err = m.GetConfigVersion(ctx, "missing")
	testutil.AssertErrorContains(t, err, "not found in history")

	if _, err := m.GetConfigDraft(ctx); !errors.Is(err, ErrNoConfigDraft) {
		t.Fatalf("missing draft error = %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	draft := &types.ConfigDraft{
		BaseVersion: v2.VersionId, DraftVersion: "draft-1", CreatedBy: "alice", UpdatedBy: "alice",
		CreateTime: now, UpdateTime: now, RBAC: types.RBACConfig{Enabled: true},
	}
	testutil.AssertNoError(t, m.SetConfigDraft(ctx, draft))
	gotDraft, err := m.GetConfigDraft(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "draft version", draft.DraftVersion, gotDraft.DraftVersion)
	draft.DraftVersion = "draft-2"
	draft.UpdatedBy = "bob"
	testutil.AssertNoError(t, m.SetConfigDraft(ctx, draft))
	gotDraft, err = m.GetConfigDraft(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "updated draft version", "draft-2", gotDraft.DraftVersion)
	testutil.AssertNoError(t, m.DeleteConfigDraft(ctx))
	if _, err := m.GetConfigDraft(ctx); !errors.Is(err, ErrNoConfigDraft) {
		t.Fatalf("deleted draft error = %v", err)
	}

	testutil.AssertNoError(t, m.StoreKVBlob(ctx, "single-use", []byte("value"), nil))
	deleted, err := m.DeleteKVIfPresent(ctx, "single-use")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "first delete", true, deleted)
	deleted, err = m.DeleteKVIfPresent(ctx, "single-use")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "second delete", false, deleted)
}

func TestMetadata_ServiceAndBindingLifecycle(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	primary := &types.Service{
		Id: types.ID_PREFIX_SERVICE + "primary", Name: "primary", ServiceType: "postgres",
		IsDefault: true, Staging: "staging", CreatedBy: "alice", Config: map[string]string{"host": "db"},
	}
	staging := &types.Service{
		Id: types.ID_PREFIX_SERVICE + "staging", Name: "staging", ServiceType: "postgres",
		CreatedBy: "alice", Config: map[string]string{"host": "stage-db"},
	}
	tx, err := m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.CreateService(ctx, tx, primary))
	testutil.AssertNoError(t, m.CreateService(ctx, tx, staging))
	testutil.AssertNoError(t, tx.Commit())

	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	exists, err := m.ServiceExists(ctx, tx, "postgres", "primary")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "service exists", true, exists)
	count, err := m.CountServices(ctx, tx, "postgres")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "service count", 2, count)
	defaultService, err := m.GetDefaultService(ctx, tx, "postgres")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "default service", "primary", defaultService.Name)
	services, err := m.ListServices(ctx, tx, "postgres", "")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "filtered services", 2, len(services))
	services, err = m.ListServices(ctx, tx, "postgres", "staging")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "name filtered services", 1, len(services))
	testutil.AssertNoError(t, tx.Rollback())

	primary.Config["host"] = "new-db"
	primary.Staging = ""
	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.UpdateService(ctx, tx, primary))
	testutil.AssertNoError(t, m.ClearServiceDefault(ctx, tx, "postgres", "staging"))
	testutil.AssertNoError(t, m.ClearServiceStaging(ctx, tx, "postgres", "staging"))
	testutil.AssertNoError(t, tx.Commit())

	missingService := &types.Service{Name: "missing", ServiceType: "postgres", Config: map[string]string{}}
	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	err = m.UpdateService(ctx, tx, missingService)
	testutil.AssertErrorContains(t, err, "no service found")
	testutil.AssertNoError(t, tx.Rollback())

	binding := &types.Binding{
		Id: types.ID_PREFIX_BINDING + "lifecycle", Path: "/bindings/main", Source: "postgres/primary",
		ServiceType: "postgres", ServiceName: "primary", CreatedBy: "alice",
		Metadata:       types.BindingMetadata{Config: map[string]string{"role": "reader"}},
		StagedMetadata: types.BindingMetadata{Config: map[string]string{"role": "stage-reader"}},
	}
	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.CreateBinding(ctx, tx, binding))
	testutil.AssertNoError(t, tx.Commit())

	binding.Source = "postgres/staging"
	binding.ServiceName = "staging"
	binding.DerivedFrom = "/bindings/base"
	binding.Metadata.Config["role"] = "writer"
	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.UpdateBinding(ctx, tx, binding))
	bindings, err := m.ListBindings(ctx, tx, binding.Source)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "source bindings", 1, len(bindings))
	testutil.AssertEqualsString(t, "updated binding source", binding.Source, bindings[0].Source)
	allBindings, err := m.ListBindings(ctx, tx, "")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "all bindings", 1, len(allBindings))
	testutil.AssertNoError(t, tx.Commit())

	missingBinding := *binding
	missingBinding.Path = "/bindings/missing"
	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	err = m.UpdateBinding(ctx, tx, &missingBinding)
	testutil.AssertErrorContains(t, err, "no binding found")
	err = m.DeleteBinding(ctx, tx, missingBinding.Path)
	testutil.AssertErrorContains(t, err, "no binding found")
	testutil.AssertNoError(t, tx.Rollback())

	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, m.DeleteBinding(ctx, tx, binding.Path))
	testutil.AssertNoError(t, m.DeleteService(ctx, tx, "primary", "postgres"))
	testutil.AssertNoError(t, m.DeleteService(ctx, tx, "staging", "postgres"))
	testutil.AssertNoError(t, tx.Commit())

	tx, err = m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	err = m.DeleteService(ctx, tx, "missing", "postgres")
	testutil.AssertErrorContains(t, err, "no service found")
	testutil.AssertNoError(t, tx.Rollback())
}
