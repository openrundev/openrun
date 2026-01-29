// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	_ "modernc.org/sqlite"
)

func setupTestCertStorage(t *testing.T) (*CertStorage, func()) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	// Force single connection for in-memory SQLite (each connection gets its own database)
	db.SetMaxOpenConns(1)

	m := &Metadata{
		db:     db,
		dbType: system.DB_TYPE_SQLITE,
	}

	cs, err := NewCertStorage(context.Background(), m.Logger, m)
	if err != nil {
		t.Fatalf("failed to create cert storage: %v", err)
	}

	cs.lockTimeout = 100 * time.Millisecond // Override the default lock timeout for testing

	ctx := context.Background()
	tx, err := m.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("failed to begin tx: %v", err)
	}
	if err := cs.createTables(ctx, tx); err != nil {
		t.Fatalf("failed to create tables: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	return cs, func() { db.Close() }
}

func TestCertStorage_StoreAndLoad(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Store
	err := cs.Store(ctx, "cert/test1", []byte("cert-data-1"))
	testutil.AssertNoError(t, err)

	// Load
	data, err := cs.Load(ctx, "cert/test1")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "data", "cert-data-1", string(data))

	// Load non-existent
	_, err = cs.Load(ctx, "cert/nonexistent")
	testutil.AssertErrorContains(t, err, "not found")
}

func TestCertStorage_StoreUpdate(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Store initial
	err := cs.Store(ctx, "cert/test1", []byte("initial"))
	testutil.AssertNoError(t, err)

	// Update
	err = cs.Store(ctx, "cert/test1", []byte("updated"))
	testutil.AssertNoError(t, err)

	// Verify update
	data, err := cs.Load(ctx, "cert/test1")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "data", "updated", string(data))
}

func TestCertStorage_Delete(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Store and delete
	cs.Store(ctx, "cert/test1", []byte("data"))
	err := cs.Delete(ctx, "cert/test1")
	testutil.AssertNoError(t, err)

	// Verify deleted
	_, err = cs.Load(ctx, "cert/test1")
	testutil.AssertErrorContains(t, err, "not found")

	// Delete non-existent (should not error)
	err = cs.Delete(ctx, "cert/nonexistent")
	testutil.AssertNoError(t, err)
}

func TestCertStorage_Exists(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Does not exist
	testutil.AssertEqualsBool(t, "exists before", false, cs.Exists(ctx, "cert/test1"))

	// Store
	cs.Store(ctx, "cert/test1", []byte("data"))

	// Exists
	testutil.AssertEqualsBool(t, "exists after", true, cs.Exists(ctx, "cert/test1"))
}

func TestCertStorage_List(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Store multiple
	cs.Store(ctx, "certs/domain1/cert", []byte("d1"))
	cs.Store(ctx, "certs/domain1/key", []byte("k1"))
	cs.Store(ctx, "certs/domain2/cert", []byte("d2"))
	cs.Store(ctx, "other/item", []byte("other"))

	// List with prefix
	ids, err := cs.List(ctx, "certs/domain1", false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "count", 2, len(ids))

	// List all certs
	ids, err = cs.List(ctx, "certs/", false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "count", 3, len(ids))

	// Recursive not supported
	_, err = cs.List(ctx, "certs/", true)
	testutil.AssertErrorContains(t, err, "recursive not supported")
}

func TestCertStorage_Stat(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	before := time.Now().Add(-time.Second)
	cs.Store(ctx, "cert/test1", []byte("test-data"))
	after := time.Now().Add(time.Second)

	info, err := cs.Stat(ctx, "cert/test1")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "key", "cert/test1", info.Key)
	testutil.AssertEqualsInt(t, "size", 9, int(info.Size))
	testutil.AssertEqualsBool(t, "terminal", true, info.IsTerminal)

	if info.Modified.Before(before) || info.Modified.After(after) {
		t.Errorf("modified time %v not in expected range [%v, %v]", info.Modified, before, after)
	}

	// Stat non-existent
	_, err = cs.Stat(ctx, "cert/nonexistent")
	if err == nil {
		t.Error("expected error for non-existent stat")
	}
}

func TestCertStorage_LockUnlock(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Lock
	err := cs.Lock(ctx, "lock/test1")
	testutil.AssertNoError(t, err)

	// Lock again should fail (already locked)
	err = cs.Lock(ctx, "lock/test1")
	testutil.AssertErrorContains(t, err, "is locked")

	// Unlock
	err = cs.Unlock(ctx, "lock/test1")
	testutil.AssertNoError(t, err)

	// Lock again should succeed
	err = cs.Lock(ctx, "lock/test1")
	testutil.AssertNoError(t, err)
}

func TestCertStorage_LockExpiry(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Lock with short timeout (100ms set in setup)
	err := cs.Lock(ctx, "lock/expiry")
	testutil.AssertNoError(t, err)

	// Wait for lock to expire
	time.Sleep(150 * time.Millisecond)

	// Lock again should succeed (expired)
	err = cs.Lock(ctx, "lock/expiry")
	testutil.AssertNoError(t, err)
}

func TestCertStorage_UnlockNonExistent(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Unlock non-existent (should not error)
	err := cs.Unlock(ctx, "lock/nonexistent")
	testutil.AssertNoError(t, err)
}

func TestCertStorage_CertMagicInterface(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()

	// Verify CertStorage implements certmagic.Storage by using it
	ctx := context.Background()
	_ = cs.Exists(ctx, "test")
}
