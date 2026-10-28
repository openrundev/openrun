// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
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
		Logger: testutil.TestLogger(),
		db:     db,
		dbType: system.DB_TYPE_SQLITE,
	}

	cs, err := NewCertStorage(context.Background(), m.Logger, m)
	if err != nil {
		t.Fatalf("failed to create cert storage: %v", err)
	}

	// Short lock timings for testing: a lock left unrefreshed expires after
	// 100ms, a held lock is refreshed every 20ms
	cs.lockLease = 100 * time.Millisecond
	cs.lockRefresh = 20 * time.Millisecond
	cs.lockPoll = 10 * time.Millisecond

	ctx := context.Background()
	tx, err := m.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("failed to begin tx: %v", err)
	}
	if err := cs.createTables(ctx, tx); err != nil {
		t.Fatalf("failed to create tables: %v", err)
	}
	if err := cs.addLockOwnerColumn(ctx, tx); err != nil {
		t.Fatalf("failed to add owner column: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	return cs, func() { db.Close() } //nolint:errcheck
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
	cs.Store(ctx, "cert/test1", []byte("data")) //nolint:errcheck
	err := cs.Delete(ctx, "cert/test1")
	testutil.AssertNoError(t, err)

	// Verify deleted
	_, err = cs.Load(ctx, "cert/test1")
	if err != fs.ErrNotExist {
		t.Errorf("expected fs.ErrNotExist, got: %v", err)
	}

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
	cs.Store(ctx, "cert/test1", []byte("data")) //nolint:errcheck

	// Exists
	testutil.AssertEqualsBool(t, "exists after", true, cs.Exists(ctx, "cert/test1"))
}

func TestCertStorage_List(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Store multiple
	cs.Store(ctx, "certs/domain1/cert", []byte("d1")) //nolint:errcheck
	cs.Store(ctx, "certs/domain1/key", []byte("k1"))  //nolint:errcheck
	cs.Store(ctx, "certs/domain2/cert", []byte("d2")) //nolint:errcheck
	cs.Store(ctx, "other/item", []byte("other"))      //nolint:errcheck

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
	cs.Store(ctx, "cert/test1", []byte("test-data")) //nolint:errcheck
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

// lockRow returns the owner and expiry of a lock row, or ok=false if absent.
func lockRow(t *testing.T, cs *CertStorage, id string) (owner string, expires int64, ok bool) {
	t.Helper()
	err := cs.metadata.db.QueryRow(`select owner, expires from cert_locks where id = ?`, id).Scan(&owner, &expires)
	if err == sql.ErrNoRows {
		return "", 0, false
	}
	testutil.AssertNoError(t, err)
	return owner, expires, true
}

func TestCertStorage_LockUnlock(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Lock
	err := cs.Lock(ctx, "lock/test1")
	testutil.AssertNoError(t, err)
	owner, _, ok := lockRow(t, cs, "lock/test1")
	testutil.AssertEqualsBool(t, "lock row", true, ok)
	if owner == "" {
		t.Fatal("expected lock row to have an owner")
	}

	// Unlock removes the row
	err = cs.Unlock(ctx, "lock/test1")
	testutil.AssertNoError(t, err)
	_, _, ok = lockRow(t, cs, "lock/test1")
	testutil.AssertEqualsBool(t, "lock row after unlock", false, ok)

	// Lock again should succeed with a new owner token
	err = cs.Lock(ctx, "lock/test1")
	testutil.AssertNoError(t, err)
	owner2, _, _ := lockRow(t, cs, "lock/test1")
	if owner2 == owner {
		t.Fatal("expected a new owner token on re-acquire")
	}
	testutil.AssertNoError(t, cs.Unlock(ctx, "lock/test1"))

	// Unlock of a lock not held is an error
	err = cs.Unlock(ctx, "lock/test1")
	testutil.AssertErrorContains(t, err, "not held by this process")
}

// Lock blocks while another holder has the lock and honors ctx cancellation
func TestCertStorage_LockBlocksUntilCancelled(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Another holder (simulated as a second storage over the same db, so the
	// lock is not in this storage's held set) takes the lock
	other, err := NewCertStorage(ctx, cs.Logger, cs.metadata)
	testutil.AssertNoError(t, err)
	other.lockLease, other.lockRefresh, other.lockPoll = cs.lockLease, cs.lockRefresh, cs.lockPoll
	testutil.AssertNoError(t, other.Lock(ctx, "lock/test1"))
	defer other.Unlock(ctx, "lock/test1") //nolint:errcheck

	// The lock is refreshed by the holder, so waiting past the lease must not
	// get it; the wait ends with the context deadline
	waitCtx, cancel := context.WithTimeout(ctx, 3*cs.lockLease)
	defer cancel()
	start := time.Now()
	err = cs.Lock(waitCtx, "lock/test1")
	if err == nil {
		t.Fatal("expected lock wait to fail")
	}
	// The deadline can hit during the lock query or during the poll wait;
	// either way the context error is reported
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed < 3*cs.lockLease {
		t.Fatalf("lock returned after %v, expected to block until the deadline", elapsed)
	}
}

// Lock waits for a held lock to be released, then acquires it
func TestCertStorage_LockWaitsForRelease(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	other, err := NewCertStorage(ctx, cs.Logger, cs.metadata)
	testutil.AssertNoError(t, err)
	other.lockLease, other.lockRefresh, other.lockPoll = cs.lockLease, cs.lockRefresh, cs.lockPoll
	testutil.AssertNoError(t, other.Lock(ctx, "lock/test1"))

	released := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(released)
		other.Unlock(ctx, "lock/test1") //nolint:errcheck
	}()

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	testutil.AssertNoError(t, cs.Lock(waitCtx, "lock/test1"))
	select {
	case <-released:
	default:
		t.Fatal("lock acquired before the holder released it")
	}
	testutil.AssertNoError(t, cs.Unlock(ctx, "lock/test1"))
}

// A held lock is kept alive by the refresh goroutine beyond the lease
// duration, so a slow operation does not lose its lock
func TestCertStorage_LockRefreshedWhileHeld(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	testutil.AssertNoError(t, cs.Lock(ctx, "lock/held"))
	owner, expires, _ := lockRow(t, cs, "lock/held")

	// Wait well past the lease; the row's expiry must have moved forward
	time.Sleep(3 * cs.lockLease)
	owner2, expires2, ok := lockRow(t, cs, "lock/held")
	testutil.AssertEqualsBool(t, "lock row", true, ok)
	testutil.AssertEqualsString(t, "owner unchanged", owner, owner2)
	if expires2 <= expires {
		t.Fatalf("expected lock expiry to be refreshed, before %d after %d", expires, expires2)
	}

	// Another holder cannot take it over
	other, err := NewCertStorage(ctx, cs.Logger, cs.metadata)
	testutil.AssertNoError(t, err)
	acquired, err := other.tryLock(ctx, "lock/held", "other-owner")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "takeover of refreshed lock", false, acquired)

	testutil.AssertNoError(t, cs.Unlock(ctx, "lock/held"))
}

// A lock whose holder died (no refresh) is taken over after the lease
// expires, and the old holder's Unlock does not remove the new holder's lock
func TestCertStorage_LockExpiry(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	// Simulate a dead holder: a lock row with an owner that is not refreshed
	_, err := cs.metadata.db.ExecContext(ctx, `insert into cert_locks (id, expires, owner) values (?, ?, ?)`,
		"lock/expiry", time.Now().Add(cs.lockLease).UnixNano(), "dead-owner")
	testutil.AssertNoError(t, err)

	// Not yet expired: an attempt does not get it
	acquired, err := cs.tryLock(ctx, "lock/expiry", "new-owner")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "acquire before expiry", false, acquired)

	// Lock waits for the expiry and takes over
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	testutil.AssertNoError(t, cs.Lock(waitCtx, "lock/expiry"))
	owner, _, _ := lockRow(t, cs, "lock/expiry")
	if owner == "dead-owner" {
		t.Fatal("expected lock to be taken over with a new owner")
	}

	// The old holder's release (owner checked) leaves the new lock in place
	res, err := cs.metadata.db.ExecContext(ctx, `delete from cert_locks where id = ? and owner = ?`, "lock/expiry", "dead-owner")
	testutil.AssertNoError(t, err)
	n, _ := res.RowsAffected()
	testutil.AssertEqualsInt(t, "rows deleted by old owner", 0, int(n))
	_, _, ok := lockRow(t, cs, "lock/expiry")
	testutil.AssertEqualsBool(t, "lock row after old owner release", true, ok)

	testutil.AssertNoError(t, cs.Unlock(ctx, "lock/expiry"))
}

// A holder whose lock was taken over (its refreshes stalled past the lease)
// cannot extend it, and its Unlock leaves the successor's lock in place
func TestCertStorage_LockTakenOver(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	testutil.AssertNoError(t, cs.Lock(ctx, "lock/stolen"))

	// Force the row to look expired and let a successor take it over
	_, err := cs.metadata.db.ExecContext(ctx, `update cert_locks set expires = ?, owner = ? where id = ?`,
		time.Now().Add(cs.lockLease).UnixNano(), "successor", "lock/stolen")
	testutil.AssertNoError(t, err)

	err = cs.RenewLockLease(ctx, "lock/stolen", time.Minute)
	testutil.AssertErrorContains(t, err, "taken over")

	// Unlock succeeds (nothing left to release for this holder) but does not
	// delete the successor's row
	testutil.AssertNoError(t, cs.Unlock(ctx, "lock/stolen"))
	owner, _, ok := lockRow(t, cs, "lock/stolen")
	testutil.AssertEqualsBool(t, "successor lock row", true, ok)
	testutil.AssertEqualsString(t, "successor owner", "successor", owner)
}

// TryLock takes a free lock and reports false without waiting on a held one
func TestCertStorage_TryLock(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	acquired, err := cs.TryLock(ctx, "lock/try")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "try lock free", true, acquired)
	owner, _, ok := lockRow(t, cs, "lock/try")
	testutil.AssertEqualsBool(t, "lock row", true, ok)

	// Held elsewhere: returns at once without the lock
	other, err := NewCertStorage(ctx, cs.Logger, cs.metadata)
	testutil.AssertNoError(t, err)
	start := time.Now()
	acquired, err = other.TryLock(ctx, "lock/try")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "try lock held", false, acquired)
	if elapsed := time.Since(start); elapsed > cs.lockLease {
		t.Fatalf("TryLock waited %v, expected an immediate return", elapsed)
	}
	owner2, _, _ := lockRow(t, cs, "lock/try")
	testutil.AssertEqualsString(t, "owner unchanged", owner, owner2)

	// A TryLock acquisition is refreshed and released like a Lock one
	time.Sleep(2 * cs.lockLease)
	_, _, ok = lockRow(t, cs, "lock/try")
	testutil.AssertEqualsBool(t, "lock row after lease", true, ok)
	testutil.AssertNoError(t, cs.Unlock(ctx, "lock/try"))
	_, _, ok = lockRow(t, cs, "lock/try")
	testutil.AssertEqualsBool(t, "lock row after unlock", false, ok)

	// Free again
	acquired, err = other.TryLock(ctx, "lock/try")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "try lock after release", true, acquired)
	testutil.AssertNoError(t, other.Unlock(ctx, "lock/try"))
}

// Close stops refreshing held locks; the rows then expire on their own
func TestCertStorage_CloseStopsRefresh(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	testutil.AssertNoError(t, cs.Lock(ctx, "lock/closing"))
	cs.Close()
	_, expires, ok := lockRow(t, cs, "lock/closing")
	testutil.AssertEqualsBool(t, "lock row after close", true, ok)

	// No refresh after Close: the expiry stays where it was and passes
	time.Sleep(2 * cs.lockLease)
	_, expires2, _ := lockRow(t, cs, "lock/closing")
	testutil.AssertEqualsInt(t, "expiry unchanged", int(expires), int(expires2))
	if time.Now().UnixNano() < expires2 {
		t.Fatal("expected lock to have expired after close")
	}

	// A lock taken after Close is not refreshed either, and Unlock still works
	testutil.AssertNoError(t, cs.Lock(ctx, "lock/after-close"))
	testutil.AssertNoError(t, cs.Unlock(ctx, "lock/after-close"))
	testutil.AssertNoError(t, cs.Unlock(ctx, "lock/closing"))
}

func TestCertStorage_RenewLockLease(t *testing.T) {
	cs, cleanup := setupTestCertStorage(t)
	defer cleanup()
	ctx := context.Background()

	err := cs.RenewLockLease(ctx, "lock/renew", time.Minute)
	testutil.AssertErrorContains(t, err, "not held by this process")

	testutil.AssertNoError(t, cs.Lock(ctx, "lock/renew"))
	_, before, _ := lockRow(t, cs, "lock/renew")
	time.Sleep(5 * time.Millisecond)
	testutil.AssertNoError(t, cs.RenewLockLease(ctx, "lock/renew", time.Minute))
	_, after, _ := lockRow(t, cs, "lock/renew")
	if after <= before {
		t.Fatalf("expected renewed expiry to move forward, before %d after %d", before, after)
	}
	testutil.AssertNoError(t, cs.Unlock(ctx, "lock/renew"))
}
