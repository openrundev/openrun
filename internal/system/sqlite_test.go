// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
)

func stopSQLiteMaintenanceForTest(dbFilePath string) {
	key := sqliteMaintenanceKey(dbFilePath)
	sqliteMaintMu.Lock()
	state, ok := sqliteMaintFiles[key]
	if ok {
		delete(sqliteMaintFiles, key)
	}
	var cancel context.CancelFunc
	var db *sql.DB
	var done <-chan struct{}
	if ok {
		cancel = state.maintenanceCancel
		db = state.maintenanceDB
		done = state.maintenanceDone
	}
	sqliteMaintMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if db != nil {
		db.Close() //nolint:errcheck
	}
	if done != nil {
		<-done
	}
}

func TestAddSQLitePragmas(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		journalSizeLimit int64
		expected         string
	}{
		{
			name:             "plain path",
			input:            "/tmp/test.db",
			journalSizeLimit: sqliteJournalSizeLimit,
			expected:         "/tmp/test.db?_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=journal_size_limit(33554432)",
		},
		{
			name:             "existing query params",
			input:            "/tmp/test.db?_time_format=sqlite",
			journalSizeLimit: sqliteJournalSizeLimit,
			expected:         "/tmp/test.db?_time_format=sqlite&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=journal_size_limit(33554432)",
		},
		{
			name:             "user pragma not overridden",
			input:            "/tmp/test.db?_pragma=busy_timeout(500)",
			journalSizeLimit: sqliteJournalSizeLimit,
			expected:         "/tmp/test.db?_pragma=busy_timeout(500)&_pragma=synchronous(NORMAL)&_pragma=journal_size_limit(33554432)",
		},
		{
			name:             "journal size limit disabled",
			input:            "/tmp/test.db",
			journalSizeLimit: 0,
			expected:         "/tmp/test.db?_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AssertEqualsString(t, "connect string", tt.expected, AddSQLitePragmas(tt.input, tt.journalSizeLimit))
		})
	}
}

// TestSQLitePragmasPerConnection verifies that the pragmas are applied to every
// pooled connection, not just the first one
func TestSQLitePragmasPerConnection(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pragma_test.db")
	t.Cleanup(func() { stopSQLiteMaintenanceForTest(dbPath) })
	db, dbType, err := InitDBConnection(nil, "sqlite:"+dbPath, "test", DB_SQLITE, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	testutil.AssertEqualsString(t, "db type", string(DB_TYPE_SQLITE), string(dbType))

	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	testutil.AssertEqualsString(t, "journal mode", "wal", journalMode)

	// Force multiple concurrent connections by holding queries open in parallel
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := db.Conn(t.Context())
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close() //nolint:errcheck

			var timeout int
			if err := conn.QueryRowContext(t.Context(), "PRAGMA busy_timeout").Scan(&timeout); err != nil {
				errs <- err
				return
			}
			if timeout != 10000 {
				errs <- &testError{msg: "busy_timeout not applied to connection"}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestSQLiteMaintenanceRestoresZeroBusyTimeout(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "zero_timeout.db")
	t.Cleanup(func() { stopSQLiteMaintenanceForTest(dbPath) })
	db, _, err := InitDBConnection(nil, "sqlite:"+dbPath, "test", DB_SQLITE, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(t.Context(), "PRAGMA busy_timeout=0"); err != nil {
		t.Fatal(err)
	}
	prior, err := setSQLiteMaintenanceBusyTimeout(t.Context(), conn)
	if err != nil {
		t.Fatal(err)
	}
	if prior != 0 {
		t.Fatalf("prior busy timeout = %d, want 0", prior)
	}
	nop := zerolog.Nop()
	closeSQLiteMaintenanceConn(t.Context(), &types.Logger{Logger: &nop}, conn, "test", prior)

	conn, err = db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	var restored int
	if err := conn.QueryRowContext(t.Context(), "PRAGMA busy_timeout").Scan(&restored); err != nil {
		t.Fatal(err)
	}
	if restored != 0 {
		t.Fatalf("restored busy timeout = %d, want 0", restored)
	}
}

// TestSQLiteAutoVacuumMigration verifies that init migrates the database file
// to incremental auto-vacuum (one time, persisted) and applies
// journal_size_limit on the pooled connections
func TestSQLiteAutoVacuumMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vacuum_test.db")
	t.Cleanup(func() { stopSQLiteMaintenanceForTest(dbPath) })
	db, _, err := InitDBConnection(nil, "sqlite:"+dbPath, "test", DB_SQLITE, nil)
	if err != nil {
		t.Fatal(err)
	}

	var autoVacuum int
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&autoVacuum); err != nil {
		t.Fatal(err)
	}
	testutil.AssertEqualsInt(t, "auto_vacuum", 2, autoVacuum)

	var journalSizeLimit int64
	if err := db.QueryRow("PRAGMA journal_size_limit").Scan(&journalSizeLimit); err != nil {
		t.Fatal(err)
	}
	testutil.AssertEqualsInt(t, "journal_size_limit", sqliteJournalSizeLimit, int(journalSizeLimit))

	if _, err := db.Exec("create table t1 (id integer primary key)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: the persisted auto_vacuum setting survives and data is intact
	db, _, err = InitDBConnection(nil, "sqlite:"+dbPath, "test", DB_SQLITE, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&autoVacuum); err != nil {
		t.Fatal(err)
	}
	testutil.AssertEqualsInt(t, "auto_vacuum after reopen", 2, autoVacuum)
	var count int
	if err := db.QueryRow("select count(*) from t1").Scan(&count); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteMaintenanceSkipsVacuumUntilCheckpointCaughtUp(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "checkpoint_first.db")
	cfg := &types.MetadataConfig{
		SQLiteJournalSizeLimit:        sqliteJournalSizeLimit,
		SQLiteMaintenanceIntervalSecs: 0,
		SQLiteTruncateCheckpointEvery: 1,
		SQLiteVacuumPages:             10,
	}
	db, _, err := InitDBConnection(nil, "sqlite:"+dbPath, "test", DB_SQLITE, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck

	ctx := context.Background()
	writer, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close() //nolint:errcheck
	if _, err := writer.ExecContext(ctx, "PRAGMA wal_autocheckpoint=0"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "CREATE TABLE records (id INTEGER PRIMARY KEY, value BLOB)"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "INSERT INTO records VALUES (1, zeroblob(4096))"); err != nil {
		t.Fatal(err)
	}
	var busy, walFrames, checkpointed int
	if err := writer.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &walFrames, &checkpointed); err != nil {
		t.Fatal(err)
	}

	reader, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close() //nolint:errcheck
	readTx, err := reader.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var size int
	if err := readTx.QueryRowContext(ctx, "SELECT length(value) FROM records WHERE id=1").Scan(&size); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "UPDATE records SET value=zeroblob(8192) WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	maintConn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer maintConn.Close() //nolint:errcheck
	if _, err := maintConn.ExecContext(ctx, "PRAGMA busy_timeout=100"); err != nil {
		t.Fatal(err)
	}
	nop := zerolog.Nop()
	logger := &types.Logger{Logger: &nop}
	state := &sqliteMaintenanceState{}
	maint := sqliteMaintenanceSettings{vacuumPages: 10, truncateEvery: 1}

	runSQLiteMaintenancePass(ctx, logger, maintConn, "test", dbPath, maint, state, false)
	state.mu.RLock()
	first := state.status
	state.mu.RUnlock()
	if first.LastWALFrames <= first.LastCheckpointedFrames {
		t.Fatalf("expected checkpoint backlog, got wal=%d checkpointed=%d", first.LastWALFrames, first.LastCheckpointedFrames)
	}
	if first.LastCheckpointMode != "PASSIVE" || first.TruncateRuns != 0 {
		t.Fatalf("backlogged pass ran truncate: mode=%s truncate_runs=%d", first.LastCheckpointMode, first.TruncateRuns)
	}
	if first.VacuumRuns != 0 || first.VacuumSkippedRuns != 1 {
		t.Fatalf("backlogged pass vacuum counters: ran=%d skipped=%d", first.VacuumRuns, first.VacuumSkippedRuns)
	}

	// A continuously moving or pinned WAL may defer vacuum, but must not starve
	// it forever. The configured page batch bounds the extra WAL work.
	for range sqliteVacuumMaxDeferredPasses {
		runSQLiteMaintenancePass(ctx, logger, maintConn, "test", dbPath, maint, state, false)
	}
	state.mu.RLock()
	forced := state.status
	state.mu.RUnlock()
	if forced.VacuumRuns != 1 {
		t.Fatalf("vacuum remained starved after bounded deferrals: runs=%d skipped=%d",
			forced.VacuumRuns, forced.VacuumSkippedRuns)
	}

	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	runSQLiteMaintenancePass(ctx, logger, maintConn, "test", dbPath, maint, state, false)
	state.mu.RLock()
	second := state.status
	state.mu.RUnlock()
	if second.VacuumRuns != 2 {
		t.Fatalf("caught-up pass vacuum runs = %d, want 2", second.VacuumRuns)
	}
	if second.LastWALFrames != second.LastCheckpointedFrames {
		t.Fatalf("post-vacuum checkpoint backlog: wal=%d checkpointed=%d", second.LastWALFrames, second.LastCheckpointedFrames)
	}
	if second.LastCheckpointAt == "" {
		t.Fatal("last checkpoint time was not updated")
	}
}

func TestSQLiteDedicatedMaintenanceSurvivesApplicationPoolClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "handoff.db")
	t.Cleanup(func() { stopSQLiteMaintenanceForTest(dbPath) })
	openDB := func() *sql.DB {
		db, err := sql.Open("sqlite", AddSQLitePragmas(dbPath, sqliteJournalSizeLimit))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
			db.Close() //nolint:errcheck
			t.Fatal(err)
		}
		return db
	}
	nop := zerolog.Nop()
	logger := &types.Logger{Logger: &nop}
	maint := sqliteMaintenanceSettings{
		journalSizeLimit: sqliteJournalSizeLimit,
		interval:         10 * time.Millisecond,
		truncateEvery:    0,
		vacuumPages:      0,
	}

	db1 := openDB()
	dsn := AddSQLitePragmas(dbPath, sqliteJournalSizeLimit)
	initSQLiteSelfMaintenance(logger, db1, "owner", dbPath, maint, "sqlite", dsn)
	db2 := openDB()
	initSQLiteSelfMaintenance(logger, db2, "second_pool", dbPath, maint, "sqlite", dsn)
	if err := db1.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db2.Close(); err != nil {
		t.Fatal(err)
	}

	status, ok := GetSQLiteMaintenanceStatus(dbPath)
	if !ok {
		t.Fatal("maintenance status disappeared when application pools closed")
	}
	startRuns := status.CheckpointRuns
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status, ok = GetSQLiteMaintenanceStatus(dbPath)
		if !ok {
			t.Fatal("dedicated maintenance ownership disappeared")
		}
		if status.CheckpointRuns >= startRuns+2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if status.CheckpointRuns < startRuns+2 {
		t.Fatalf("dedicated maintenance stopped with application pools: runs=%d, started=%d", status.CheckpointRuns, startRuns)
	}
}

func TestSQLiteCheckpointErrorPreservesLastSuccessfulMeasurements(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	state := &sqliteMaintenanceState{status: types.SQLiteMetadataMetrics{
		CheckpointRuns:         7,
		TruncateRuns:           3,
		LastCheckpointMode:     "PASSIVE",
		LastCheckpointBusy:     1,
		LastWALFrames:          123,
		LastCheckpointedFrames: 45,
	}}

	if _, _, _, err := runSQLiteCheckpoint(t.Context(), db, "TRUNCATE", state); err == nil {
		t.Fatal("checkpoint on closed database unexpectedly succeeded")
	}
	state.mu.RLock()
	got := state.status
	state.mu.RUnlock()
	if got.CheckpointRuns != 7 || got.TruncateRuns != 3 || got.LastCheckpointMode != "PASSIVE" ||
		got.LastCheckpointBusy != 1 || got.LastWALFrames != 123 || got.LastCheckpointedFrames != 45 {
		t.Fatalf("failed checkpoint clobbered last successful measurements: %+v", got)
	}
	if got.CheckpointErrors != 1 || got.LastCheckpointError == "" {
		t.Fatalf("failed checkpoint was not recorded: %+v", got)
	}
}

func TestSQLiteStartupCheckpointUsesConnectionBusyTimeout(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "startup_checkpoint.db")
	db, err := sql.Open("sqlite", AddSQLitePragmas(dbPath, sqliteJournalSizeLimit))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO records VALUES (1, 'before')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}

	reader, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close() //nolint:errcheck
	readTx, err := reader.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var value string
	if err := readTx.QueryRowContext(t.Context(), "SELECT value FROM records WHERE id=1").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE records SET value='after' WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	cfg := &types.MetadataConfig{
		SQLiteJournalSizeLimit:        sqliteJournalSizeLimit,
		SQLiteMaintenanceIntervalSecs: 0,
		SQLiteTruncateCheckpointEvery: 0,
		SQLiteVacuumPages:             0,
	}
	type initResult struct {
		db  *sql.DB
		err error
	}
	result := make(chan initResult, 1)
	started := time.Now()
	go func() {
		opened, _, err := InitDBConnection(nil, "sqlite:"+dbPath, "startup", DB_SQLITE, cfg)
		result <- initResult{db: opened, err: err}
	}()

	// Longer than the 100ms background-maintenance timeout. Startup recovery
	// should keep waiting under the connection's normal 10 second policy.
	time.Sleep(250 * time.Millisecond)
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	opened := <-result
	if opened.err != nil {
		t.Fatal(opened.err)
	}
	defer opened.db.Close() //nolint:errcheck
	if elapsed := time.Since(started); elapsed < 200*time.Millisecond {
		t.Fatalf("startup checkpoint returned after %s; expected it to wait for the reader", elapsed)
	}
	status, ok := GetSQLiteMaintenanceStatus(dbPath)
	if !ok || status.LastCheckpointBusy != 0 {
		t.Fatalf("startup checkpoint did not recover WAL: status=%+v, present=%t", status, ok)
	}
}

func TestSQLitePeriodicTruncateUsesConnectionBusyTimeout(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "periodic_checkpoint.db")
	db, err := sql.Open("sqlite", AddSQLitePragmas(dbPath, sqliteJournalSizeLimit))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO records VALUES (1, 'before')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}

	reader, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close() //nolint:errcheck
	readTx, err := reader.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var value string
	if err := readTx.QueryRowContext(t.Context(), "SELECT value FROM records WHERE id=1").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE records SET value='after' WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	type checkpointResult struct {
		busy int
		err  error
	}
	result := make(chan checkpointResult, 1)
	state := &sqliteMaintenanceState{}
	started := time.Now()
	go func() {
		busy, _, _, err := runSQLiteCheckpoint(t.Context(), db, "TRUNCATE", state)
		result <- checkpointResult{busy: busy, err: err}
	}()

	select {
	case got := <-result:
		t.Fatalf("periodic truncate returned early under the 100ms maintenance timeout: %+v", got)
	case <-time.After(250 * time.Millisecond):
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	got := <-result
	if got.err != nil || got.busy != 0 {
		t.Fatalf("periodic truncate did not wait for reader: %+v", got)
	}
	if elapsed := time.Since(started); elapsed < 200*time.Millisecond {
		t.Fatalf("periodic truncate returned after %s; expected normal busy timeout", elapsed)
	}
	state.mu.RLock()
	status := state.status
	state.mu.RUnlock()
	if status.TruncateRuns != 1 || status.LastCheckpointMode != "TRUNCATE" {
		t.Fatalf("periodic truncate metrics not recorded: %+v", status)
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
