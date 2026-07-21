// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

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

// TestSQLiteAutoVacuumMigration verifies that init migrates the database file
// to incremental auto-vacuum (one time, persisted) and applies
// journal_size_limit on the pooled connections
func TestSQLiteAutoVacuumMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vacuum_test.db")
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

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
