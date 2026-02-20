// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func skipIfNoPostgres(t *testing.T) {
	t.Helper()
	if os.Getenv("ENABLE_POSTGRES_TESTCONTAINER") == "" {
		t.Skip("set ENABLE_POSTGRES_TESTCONTAINER=1 to run postgres testcontainer leader election tests")
	}
}

func startPostgres(t *testing.T) (connStr string, cleanup func()) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	container, err := tcpostgres.Run(ctx,
		"postgres:17-alpine",
		tcpostgres.WithDatabase("openrun_leader"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
	)
	if err != nil {
		t.Fatalf("failed to start postgres testcontainer: %v", err)
	}

	connStr, err = container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		container.Terminate(context.Background()) //nolint:errcheck
		t.Fatalf("failed to build postgres connection string: %v", err)
	}

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer readyCancel()
	if err := waitForPostgresReady(readyCtx, connStr); err != nil {
		container.Terminate(context.Background()) //nolint:errcheck
		t.Fatalf("postgres testcontainer did not become ready: %v", err)
	}

	return connStr, func() {
		container.Terminate(context.Background()) //nolint:errcheck
	}
}

func waitForPostgresReady(ctx context.Context, connStr string) error {
	var lastErr error
	for {
		db, err := sql.Open("pgx", connStr)
		if err == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err = db.PingContext(pingCtx)
			cancel()
			db.Close() //nolint:errcheck
			if err == nil {
				return nil
			}
		}
		lastErr = err

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("last error: %w", lastErr)
			}
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// newLeaderElectionForTest creates a LeaderElection backed by the given postgres connStr.
// It creates the schema (version table + leader_election table) and returns a cleanup function.
func newLeaderElectionForTest(t *testing.T, connStr, nodeId, hostname string, leaseSecs, heartbeatSecs int) (*LeaderElection, func()) {
	t.Helper()

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}

	logger := testutil.TestLogger()
	m := &Metadata{
		Logger: logger,
		db:     db,
		dbType: system.DB_TYPE_POSTGRES,
	}

	config := &types.ServerConfig{}
	config.System.LeaderElectionLeaseSecs = leaseSecs
	config.System.LeaderElectionHeartbeatIntervalSecs = heartbeatSecs

	le := NewLeaderElection(logger, m, config, nodeId, hostname)

	return le, func() { db.Close() } //nolint:errcheck
}

// ensureLeaderTable creates the leader_election table once for the test database.
func ensureLeaderTable(t *testing.T, connStr string) {
	t.Helper()
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close() //nolint:errcheck

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS leader_election (id smallint PRIMARY KEY CHECK (id = 1), ` +
		`leader_id text, leader_hostname text, last_heartbeat_at timestamptz, last_leadership_change_at timestamptz)`)
	if err != nil {
		t.Fatalf("failed to create leader_election table: %v", err)
	}
	_, err = db.Exec(`INSERT INTO leader_election (id) VALUES (1) ON CONFLICT (id) DO NOTHING`)
	if err != nil {
		t.Fatalf("failed to seed leader_election row: %v", err)
	}
}

// resetLeaderRow clears the leader row so each test starts fresh.
func resetLeaderRow(t *testing.T, connStr string) {
	t.Helper()
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close() //nolint:errcheck

	_, err = db.Exec(`UPDATE leader_election SET leader_id = NULL, leader_hostname = NULL, last_heartbeat_at = NULL, last_leadership_change_at = NULL WHERE id = 1`)
	if err != nil {
		t.Fatalf("failed to reset leader row: %v", err)
	}
}

func TestLeaderElection_SqliteAlwaysLeader(t *testing.T) {
	logger := testutil.TestLogger()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close() //nolint:errcheck

	m := &Metadata{Logger: logger, db: db, dbType: system.DB_TYPE_SQLITE}
	config := &types.ServerConfig{}
	le := NewLeaderElection(logger, m, config, "node-1", "host-1")

	testutil.AssertEqualsBool(t, "sqlite is always leader", true, le.IsLeader())
}

func TestLeaderElection_AcquireLeadership(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, pgCleanup := startPostgres(t)
	defer pgCleanup()
	ensureLeaderTable(t, connStr)
	resetLeaderRow(t, connStr)

	le, cleanup := newLeaderElectionForTest(t, connStr, "node-A", "host-A", 30, 5)
	defer cleanup()

	testutil.AssertEqualsBool(t, "not leader before acquire", false, le.IsLeader())

	st, acquired, err := le.tryAcquire(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "acquired", true, acquired)
	testutil.AssertEqualsString(t, "leader id", "node-A", st.LeaderID)
	testutil.AssertEqualsString(t, "hostname", "host-A", st.Hostname)
}

func TestLeaderElection_HeartbeatRenewsLease(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, pgCleanup := startPostgres(t)
	defer pgCleanup()
	ensureLeaderTable(t, connStr)
	resetLeaderRow(t, connStr)

	le, cleanup := newLeaderElectionForTest(t, connStr, "node-A", "host-A", 30, 5)
	defer cleanup()

	_, acquired, err := le.tryAcquire(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "acquired", true, acquired)

	ts, ok, err := le.heartbeat(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "heartbeat ok", true, ok)
	if ts.IsZero() {
		t.Fatal("expected non-zero heartbeat timestamp")
	}
}

func TestLeaderElection_HeartbeatFailsForNonLeader(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, pgCleanup := startPostgres(t)
	defer pgCleanup()
	ensureLeaderTable(t, connStr)
	resetLeaderRow(t, connStr)

	leA, cleanupA := newLeaderElectionForTest(t, connStr, "node-A", "host-A", 30, 5)
	defer cleanupA()
	leB, cleanupB := newLeaderElectionForTest(t, connStr, "node-B", "host-B", 30, 5)
	defer cleanupB()

	_, acquired, err := leA.tryAcquire(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "A acquired", true, acquired)

	// B's heartbeat should fail — it's not the leader
	_, ok, err := leB.heartbeat(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "B heartbeat should fail", false, ok)
}

func TestLeaderElection_SecondNodeCannotAcquireWhileLeaseActive(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, pgCleanup := startPostgres(t)
	defer pgCleanup()
	ensureLeaderTable(t, connStr)
	resetLeaderRow(t, connStr)

	leA, cleanupA := newLeaderElectionForTest(t, connStr, "node-A", "host-A", 30, 5)
	defer cleanupA()
	leB, cleanupB := newLeaderElectionForTest(t, connStr, "node-B", "host-B", 30, 5)
	defer cleanupB()

	_, acquired, err := leA.tryAcquire(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "A acquired", true, acquired)

	// B should not be able to acquire while A's lease is active
	_, acquired, err = leB.tryAcquire(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "B should not acquire", false, acquired)
}

func TestLeaderElection_LeaseExpiryAllowsTakeover(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, pgCleanup := startPostgres(t)
	defer pgCleanup()
	ensureLeaderTable(t, connStr)
	resetLeaderRow(t, connStr)

	// Use a 1-second lease so the test doesn't take long
	leA, cleanupA := newLeaderElectionForTest(t, connStr, "node-A", "host-A", 1, 5)
	defer cleanupA()
	leB, cleanupB := newLeaderElectionForTest(t, connStr, "node-B", "host-B", 1, 5)
	defer cleanupB()

	_, acquired, err := leA.tryAcquire(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "A acquired", true, acquired)

	// B cannot acquire yet
	_, acquired, err = leB.tryAcquire(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "B blocked", false, acquired)

	// Wait for A's lease to expire
	time.Sleep(1500 * time.Millisecond)

	// Now B should be able to acquire
	st, acquired, err := leB.tryAcquire(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "B acquired after expiry", true, acquired)
	testutil.AssertEqualsString(t, "new leader", "node-B", st.LeaderID)

	// A's heartbeat should now fail
	_, ok, err := leA.heartbeat(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "A heartbeat after takeover", false, ok)
}

func TestLeaderElection_SameNodeReacquires(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, pgCleanup := startPostgres(t)
	defer pgCleanup()
	ensureLeaderTable(t, connStr)
	resetLeaderRow(t, connStr)

	le, cleanup := newLeaderElectionForTest(t, connStr, "node-A", "host-A", 1, 5)
	defer cleanup()

	_, acquired, err := le.tryAcquire(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "first acquire", true, acquired)

	// Wait for lease to expire
	time.Sleep(1500 * time.Millisecond)

	// Same node should be able to reacquire
	st, acquired, err := le.tryAcquire(context.Background())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "reacquire", true, acquired)
	testutil.AssertEqualsString(t, "still same leader", "node-A", st.LeaderID)
}

func TestLeaderElection_CreateTablesIdempotent(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, pgCleanup := startPostgres(t)
	defer pgCleanup()

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close() //nolint:errcheck

	logger := testutil.TestLogger()
	m := &Metadata{Logger: logger, db: db, dbType: system.DB_TYPE_POSTGRES}
	config := &types.ServerConfig{}
	le := NewLeaderElection(logger, m, config, "node-A", "host-A")

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, le.CreateTables(ctx, types.Transaction{Tx: tx}))
	testutil.AssertNoError(t, tx.Commit())

	// Call again — should be idempotent
	tx, err = db.BeginTx(ctx, nil)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, le.CreateTables(ctx, types.Transaction{Tx: tx}))
	testutil.AssertNoError(t, tx.Commit())
}

func TestLeaderElection_CreateTablesSkippedForSqlite(t *testing.T) {
	logger := testutil.TestLogger()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close() //nolint:errcheck

	m := &Metadata{Logger: logger, db: db, dbType: system.DB_TYPE_SQLITE}
	config := &types.ServerConfig{}
	le := NewLeaderElection(logger, m, config, "node-A", "host-A")

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, le.CreateTables(ctx, types.Transaction{Tx: tx}))
	testutil.AssertNoError(t, tx.Commit())
}

func TestLeaderElection_StartLoopAndStop(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, pgCleanup := startPostgres(t)
	defer pgCleanup()
	ensureLeaderTable(t, connStr)
	resetLeaderRow(t, connStr)

	le, cleanup := newLeaderElectionForTest(t, connStr, "node-A", "host-A", 30, 1)
	defer cleanup()

	testutil.AssertEqualsBool(t, "not leader before start", false, le.IsLeader())

	le.StartLoop(context.Background())

	// Give the goroutine time to run the initial tryAcquire
	time.Sleep(500 * time.Millisecond)
	testutil.AssertEqualsBool(t, "leader after start", true, le.IsLeader())

	le.Stop()
	// Verify stop doesn't panic on double-call
	le.Stop()
}

func TestLeaderElection_StartLoopNoopForSqlite(t *testing.T) {
	logger := testutil.TestLogger()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close() //nolint:errcheck

	m := &Metadata{Logger: logger, db: db, dbType: system.DB_TYPE_SQLITE}
	config := &types.ServerConfig{}
	le := NewLeaderElection(logger, m, config, "node-A", "host-A")

	// StartLoop should return immediately for sqlite without setting cancel
	le.StartLoop(context.Background())
	if le.cancel != nil {
		t.Fatal("expected cancel to be nil for sqlite")
	}

	// Stop should be safe even though StartLoop was a no-op
	le.Stop()
}

func TestLeaderElection_LoopDetectsLostLeadership(t *testing.T) {
	skipIfNoPostgres(t)
	connStr, pgCleanup := startPostgres(t)
	defer pgCleanup()
	ensureLeaderTable(t, connStr)
	resetLeaderRow(t, connStr)

	// Node A: 1-second heartbeat, 2-second lease
	leA, cleanupA := newLeaderElectionForTest(t, connStr, "node-A", "host-A", 2, 1)
	defer cleanupA()

	leA.StartLoop(context.Background())
	defer leA.Stop()

	time.Sleep(500 * time.Millisecond)
	testutil.AssertEqualsBool(t, "A is leader", true, leA.IsLeader())

	// Simulate another node stealing leadership by directly updating the DB
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close() //nolint:errcheck

	_, err = db.Exec(`UPDATE leader_election SET leader_id = 'node-X', last_heartbeat_at = clock_timestamp() WHERE id = 1`)
	testutil.AssertNoError(t, err)

	// Wait for A's next heartbeat tick to detect the loss
	time.Sleep(2 * time.Second)
	testutil.AssertEqualsBool(t, "A lost leadership", false, leA.IsLeader())
}
