// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

func TestValidateLitestreamConfig(t *testing.T) {
	t.Parallel()

	if err := ValidateLitestreamConfig("a", types.LitestreamConfig{}); err == nil ||
		!strings.Contains(err.Error(), "bucket is required") {
		t.Fatalf("s3 without bucket error = %v", err)
	}
	if err := ValidateLitestreamConfig("a", types.LitestreamConfig{Type: "file"}); err == nil ||
		!strings.Contains(err.Error(), "path is required") {
		t.Fatalf("file without path error = %v", err)
	}
	if err := ValidateLitestreamConfig("a", types.LitestreamConfig{Type: "carrierpigeon"}); err == nil ||
		!strings.Contains(err.Error(), "unknown replica type") {
		t.Fatalf("unknown type error = %v", err)
	}
	if err := ValidateLitestreamConfig("a", types.LitestreamConfig{Bucket: "b", SyncInterval: "nope"}); err == nil ||
		!strings.Contains(err.Error(), "invalid sync_interval") {
		t.Fatalf("bad duration error = %v", err)
	}
	if err := ValidateLitestreamConfig("a", types.LitestreamConfig{Bucket: "b", Retention: "72h"}); err != nil {
		t.Fatalf("valid s3 config: %v", err)
	}
	if err := ValidateLitestreamConfig("a", types.LitestreamConfig{Type: "file", Path: "/tmp/x"}); err != nil {
		t.Fatalf("valid file config: %v", err)
	}
}

// TestLitestreamManagerReplicateAndRestore covers the metadata DR flow end to
// end with a local file replica: replicate a database, wipe it, and verify
// PrepareDB restores the data before the next open.
func TestLitestreamManagerReplicateAndRestore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "meta.db")
	t.Cleanup(func() { stopSQLiteMaintenanceForTest(dbPath) })
	replicaDir := filepath.Join(dir, "replica")
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	lsConfig := types.LitestreamConfig{Type: LitestreamReplicaTypeFile, Path: replicaDir, SyncInterval: "100ms"}

	mgr, err := NewLitestreamManager(logger, "", "test", lsConfig)
	if err != nil {
		t.Fatalf("NewLitestreamManager: %v", err)
	}
	// Fresh start: no replica exists yet
	if err := mgr.PrepareDB(ctx, "metadata", dbPath); err != nil {
		t.Fatalf("PrepareDB: %v", err)
	}
	if !isLitestreamManaged(dbPath) {
		t.Fatal("db file not marked litestream managed")
	}

	db, _, err := InitDBConnection(logger, "sqlite:"+dbPath, "litestream_test", DB_SQLITE, nil)
	if err != nil {
		t.Fatalf("InitDBConnection: %v", err)
	}
	if _, err := db.ExecContext(ctx, "create table t (x int)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.ExecContext(ctx, "insert into t values (42)"); err != nil {
		t.Fatalf("insert: %v", err)
	}

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for the replica to catch up before shutting down
	deadline := time.Now().Add(10 * time.Second)
	for {
		statuses := mgr.Status(ctx)
		if len(statuses) == 1 && statuses[0].InSync && statuses[0].Error == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("replica did not sync in time: %+v", statuses)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err := mgr.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	db.Close() //nolint:errcheck

	// Wipe the database (file, WAL, SHM) and restore from the replica
	for _, suffix := range []string{"", "-wal", "-shm"} {
		os.Remove(dbPath + suffix) //nolint:errcheck
	}

	mgr2, err := NewLitestreamManager(logger, "", "test", lsConfig)
	if err != nil {
		t.Fatalf("NewLitestreamManager restore: %v", err)
	}
	if err := mgr2.PrepareDB(ctx, "metadata", dbPath); err != nil {
		t.Fatalf("PrepareDB restore: %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("database not restored: %v", err)
	}

	db2, _, err := InitDBConnection(logger, "sqlite:"+dbPath, "litestream_test2", DB_SQLITE, nil)
	if err != nil {
		t.Fatalf("InitDBConnection after restore: %v", err)
	}
	defer db2.Close() //nolint:errcheck
	var x int
	if err := db2.QueryRowContext(ctx, "select x from t").Scan(&x); err != nil {
		t.Fatalf("query after restore: %v", err)
	}
	if x != 42 {
		t.Fatalf("restored value = %d, want 42", x)
	}
}
