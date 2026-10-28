// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// The config table is a singleton: the database rejects a second row, and
// InitConfig reports the race as ErrConfigAlreadyExists
func TestConfigTableSingleton(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	var count int
	testutil.AssertNoError(t, m.db.QueryRow(`select count(*) from config`).Scan(&count))
	testutil.AssertEqualsInt(t, "config rows", 1, count)

	_, err := m.db.ExecContext(ctx, `insert into config (version_id, user_id, update_time, config) values ('ver_dup', 'u', datetime('now'), '{}')`)
	if err == nil || !isUniqueViolation(err) {
		t.Fatalf("expected unique violation on second config row, got %v", err)
	}

	err = m.InitConfig(ctx, "u1", &types.DynamicConfig{VersionId: "ver_again"})
	if !errors.Is(err, ErrConfigAlreadyExists) {
		t.Fatalf("expected ErrConfigAlreadyExists, got %v", err)
	}
}

// Upgrading to version 34 keeps the newest config row when an earlier race
// left duplicates, then the index prevents further ones
func TestVersionUpgradeDedupesConfigRows(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	_, err := m.db.ExecContext(ctx, `drop index config_singleton`)
	testutil.AssertNoError(t, err)
	_, err = m.db.ExecContext(ctx, `update config set version_id = 'ver_old', update_time = datetime('now', '-1 hour')`)
	testutil.AssertNoError(t, err)
	_, err = m.db.ExecContext(ctx, `insert into config (version_id, user_id, update_time, config) values ('ver_new', 'u', datetime('now'), '{}')`)
	testutil.AssertNoError(t, err)
	_, err = m.db.ExecContext(ctx, `update version set version=33`)
	testutil.AssertNoError(t, err)

	testutil.AssertNoError(t, m.VersionUpgrade(m.config))

	var versionId string
	testutil.AssertNoError(t, m.db.QueryRow(`select version_id from config`).Scan(&versionId))
	testutil.AssertEqualsString(t, "surviving config row", "ver_new", versionId)
	var version int
	testutil.AssertNoError(t, m.db.QueryRow(`select version from version`).Scan(&version))
	testutil.AssertEqualsInt(t, "db version", CURRENT_DB_VERSION, version)
}

// Duplicates with the same update_time still collapse to exactly one row:
// the greater version_id wins, and fully identical rows are reduced too
func TestVersionUpgradeDedupesConfigRowTies(t *testing.T) {
	for name, rows := range map[string][]string{
		"tie on time":    {"ver_a", "ver_b"},
		"identical rows": {"ver_same", "ver_same", "ver_same"},
		"mixed":          {"ver_a", "ver_b", "ver_b"},
	} {
		t.Run(name, func(t *testing.T) {
			m, cleanup := setupTestMetadata(t)
			defer cleanup()
			ctx := context.Background()

			_, err := m.db.ExecContext(ctx, `drop index config_singleton`)
			testutil.AssertNoError(t, err)
			_, err = m.db.ExecContext(ctx, `delete from config`)
			testutil.AssertNoError(t, err)
			for _, id := range rows {
				_, err = m.db.ExecContext(ctx, `insert into config (version_id, user_id, update_time, config) values (?, 'u', '2026-01-01 00:00:00', '{"k":1}')`, id)
				testutil.AssertNoError(t, err)
			}
			_, err = m.db.ExecContext(ctx, `update version set version=33`)
			testutil.AssertNoError(t, err)

			testutil.AssertNoError(t, m.VersionUpgrade(m.config))

			var count int
			testutil.AssertNoError(t, m.db.QueryRow(`select count(*) from config`).Scan(&count))
			testutil.AssertEqualsInt(t, "config rows", 1, count)
			var versionId, configStr string
			var updateTime time.Time
			testutil.AssertNoError(t, m.db.QueryRow(`select version_id, update_time, config from config`).Scan(&versionId, &updateTime, &configStr))
			want := rows[len(rows)-1]
			testutil.AssertEqualsString(t, "surviving version_id", want, versionId)
			// The instant survives the re-insert (the text form may change, no
			// reader depends on it)
			if !updateTime.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
				t.Errorf("update_time not preserved: %v", updateTime)
			}
			testutil.AssertEqualsString(t, "config preserved", `{"k":1}`, configStr)
		})
	}
}

// A config write committed by another connection after the dedupe read its
// survivor makes the dedupe fail rather than overwrite the newer config
func TestDedupeConfigRowsDetectsConcurrentWriteSQLite(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	_, err := m.db.ExecContext(ctx, `drop index config_singleton`)
	testutil.AssertNoError(t, err)
	_, err = m.db.ExecContext(ctx, `insert into config (version_id, user_id, update_time, config) values ('ver_dup', 'u', datetime('now', '-1 hour'), '{}')`)
	testutil.AssertNoError(t, err)

	tx, err := m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	defer tx.Rollback() //nolint:errcheck
	// Establish the transaction's read snapshot, as the upgrade does
	var version int
	testutil.AssertNoError(t, tx.QueryRowContext(ctx, `select version from version`).Scan(&version))

	// Another connection commits a config update meanwhile
	_, err = m.db.ExecContext(ctx, `update config set config = '{"newer":true}' where version_id <> 'ver_dup'`)
	testutil.AssertNoError(t, err)

	err = m.dedupeConfigRows(ctx, tx)
	if err == nil {
		t.Fatal("expected the dedupe to fail after a concurrent config write")
	}
	t.Logf("dedupe failed as expected: %v", err)
}

// A version table which exists but cannot be read is an error, not a new
// database to initialize over
func TestVersionUpgradeUnreadableVersionTableFails(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	_, err := m.db.ExecContext(ctx, `alter table version rename column version to ver`)
	testutil.AssertNoError(t, err)
	err = m.VersionUpgrade(m.config)
	if err == nil {
		t.Fatal("expected VersionUpgrade to fail on an unreadable version table")
	}
}

func newPostgresMetadata(t *testing.T, connStr string) *Metadata {
	t.Helper()
	config := &types.ServerConfig{
		Metadata: types.MetadataConfig{DBConnection: connStr, AutoUpgrade: true},
	}
	m, err := NewMetadata(types.NewLogger(&types.LogConfig{Level: "INFO"}), config)
	if err != nil {
		t.Fatalf("NewMetadata: %v", err)
	}
	return m
}

// Nodes starting together against one empty PostgreSQL database all come up:
// one runs the upgrade under the advisory lock, the others find the schema
// current. The config table ends with its single row
func TestVersionUpgradeConcurrentPostgres(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, cleanup := startPostgres(t)
	defer cleanup()

	const nodes = 4
	var wg sync.WaitGroup
	errs := make([]error, nodes)
	for i := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			config := &types.ServerConfig{
				Metadata: types.MetadataConfig{DBConnection: connStr, AutoUpgrade: true},
			}
			m, err := NewMetadata(types.NewLogger(&types.LogConfig{Level: "INFO"}), config)
			if err != nil {
				errs[i] = err
				return
			}
			m.Close()
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("node %d: %v", i, err)
		}
	}

	m := newPostgresMetadata(t, connStr)
	defer m.Close()
	var version, count int
	testutil.AssertNoError(t, m.db.QueryRow(`select version from version`).Scan(&version))
	testutil.AssertEqualsInt(t, "db version", CURRENT_DB_VERSION, version)
	testutil.AssertNoError(t, m.db.QueryRow(`select count(*) from config`).Scan(&count))
	testutil.AssertEqualsInt(t, "config rows", 1, count)

	// The InitConfig race: the second insert is reported as already existing
	ctx := context.Background()
	err := m.InitConfig(ctx, "u1", &types.DynamicConfig{VersionId: "ver_again"})
	if !errors.Is(err, ErrConfigAlreadyExists) {
		t.Fatalf("expected ErrConfigAlreadyExists, got %v", err)
	}
}

// Existing tables in public are found through the search_path even when
// another schema precedes public: the installation is upgraded in place, no
// shadow tables are created in the preceding schema
func TestVersionUpgradeFollowsSearchPathPostgres(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, cleanup := startPostgres(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create the schema at the current version in public
	m := newPostgresMetadata(t, connStr)
	m.Close()

	db, err := sql.Open("pgx", connStr)
	testutil.AssertNoError(t, err)
	for _, stmt := range []string{
		`create schema first`,
		`alter database openrun_leader set search_path = first, public`,
	} {
		_, err := db.ExecContext(ctx, stmt)
		testutil.AssertNoError(t, err)
	}
	db.Close() //nolint:errcheck

	m = newPostgresMetadata(t, connStr)
	defer m.Close()
	var schema string
	testutil.AssertNoError(t, m.db.QueryRow(`select current_schema()`).Scan(&schema))
	testutil.AssertEqualsString(t, "current schema", "first", schema)
	var shadow int
	testutil.AssertNoError(t, m.db.QueryRow(`select count(*) from information_schema.tables where table_schema = 'first'`).Scan(&shadow))
	testutil.AssertEqualsInt(t, "tables created in the preceding schema", 0, shadow)
	var version int
	testutil.AssertNoError(t, m.db.QueryRow(`select version from public.version`).Scan(&version))
	testutil.AssertEqualsInt(t, "db version", CURRENT_DB_VERSION, version)
	exists, err := m.tableExists(ctx, m.db, "action_runs")
	testutil.AssertNoError(t, err)
	if !exists {
		t.Error("action_runs in public not resolved through the search_path")
	}
}

// The dedupe holds config writers off until its transaction commits, so a
// config update from a node of the previous version cannot be overwritten by
// the re-inserted survivor; readers are not blocked
func TestDedupeConfigRowsBlocksWritersPostgres(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, cleanup := startPostgres(t)
	defer cleanup()
	ctx := context.Background()

	m := newPostgresMetadata(t, connStr)
	defer m.Close()
	_, err := m.db.ExecContext(ctx, `drop index config_singleton`)
	testutil.AssertNoError(t, err)
	_, err = m.db.ExecContext(ctx, `insert into config (version_id, user_id, update_time, config) values ('ver_dup', 'u', now() - interval '1 hour', '{}')`)
	testutil.AssertNoError(t, err)

	tx, err := m.BeginTransaction(ctx)
	testutil.AssertNoError(t, err)
	defer tx.Rollback() //nolint:errcheck
	testutil.AssertNoError(t, m.dedupeConfigRows(ctx, tx))

	// A reader proceeds while the dedupe transaction is open
	var count int
	testutil.AssertNoError(t, m.db.QueryRowContext(ctx, `select count(*) from config`).Scan(&count))
	testutil.AssertEqualsInt(t, "rows seen by a reader", 2, count)

	// A writer waits for the commit
	done := make(chan error, 1)
	go func() {
		_, err := m.db.ExecContext(ctx, `update config set config = '{"newer":true}'`)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("config write went through while the dedupe held the lock: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	testutil.AssertNoError(t, tx.Commit())
	select {
	case err := <-done:
		testutil.AssertNoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("config write did not proceed after the commit")
	}

	var configStr string
	testutil.AssertNoError(t, m.db.QueryRowContext(ctx, `select config from config`).Scan(&configStr))
	testutil.AssertEqualsString(t, "the write after the dedupe is kept", `{"newer":true}`, configStr)
}

// A same-named table in another schema of the database does not make the
// idempotent migrations skip creating theirs
func TestVersionUpgradeIgnoresOtherSchemaPostgres(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, cleanup := startPostgres(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", connStr)
	testutil.AssertNoError(t, err)
	for _, stmt := range []string{
		`create schema other`,
		`create table other.action_runs (id text)`,
		`create table other.builtin_users (id text)`,
		`create table other.identities (id text, email text)`,
		`create table other.credentials (id text, options json)`,
	} {
		_, err := db.ExecContext(ctx, stmt)
		testutil.AssertNoError(t, err)
	}
	db.Close() //nolint:errcheck

	m := newPostgresMetadata(t, connStr)
	defer m.Close()
	for _, table := range []string{"action_runs", "builtin_users", "identities", "credentials"} {
		exists, err := m.tableExists(ctx, m.db, table)
		testutil.AssertNoError(t, err)
		if !exists {
			t.Errorf("table %s missing from current schema", table)
		}
	}
	exists, err := m.columnExists(ctx, m.db, "credentials", "options")
	testutil.AssertNoError(t, err)
	if !exists {
		t.Error("credentials.options missing")
	}
}
