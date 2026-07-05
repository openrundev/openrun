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
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain path",
			input:    "/tmp/test.db",
			expected: "/tmp/test.db?_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)",
		},
		{
			name:     "existing query params",
			input:    "/tmp/test.db?_time_format=sqlite",
			expected: "/tmp/test.db?_time_format=sqlite&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)",
		},
		{
			name:     "user pragma not overridden",
			input:    "/tmp/test.db?_pragma=busy_timeout(500)",
			expected: "/tmp/test.db?_pragma=busy_timeout(500)&_pragma=synchronous(NORMAL)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AssertEqualsString(t, "connect string", tt.expected, AddSQLitePragmas(tt.input))
		})
	}
}

// TestSQLitePragmasPerConnection verifies that the pragmas are applied to every
// pooled connection, not just the first one
func TestSQLitePragmasPerConnection(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pragma_test.db")
	db, dbType, err := InitDBConnection("sqlite:"+dbPath, "test", DB_SQLITE)
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

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
