// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/system"
)

func TestCloseFileStoreStopsAndResetsSingleton(t *testing.T) {
	// Keep this global singleton isolated if another test failed after opening
	// it, and ensure this test never leaves its cleanup worker behind.
	if err := CloseFileStore(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = CloseFileStore() })

	connectString := "sqlite:" + filepath.Join(t.TempDir(), "files.db")
	if err := InitFileStore(connectString); err != nil {
		t.Fatal(err)
	}
	mu.RLock()
	openedDB := fsDB
	mu.RUnlock()
	if openedDB == nil {
		t.Fatal("file store database was not initialized")
	}

	if err := CloseFileStore(); err != nil {
		t.Fatal(err)
	}
	mu.RLock()
	defer mu.RUnlock()
	if fsDB != nil || fsCancel != nil || fsDone != nil {
		t.Fatal("file store singleton retained resources after close")
	}
	if err := openedDB.Ping(); err == nil {
		t.Fatal("file store database pool remained usable after close")
	}
}

// A prepared query that waits for cancellation, with a separate escape hatch
// so a regression cannot strand the test's database and cleanup goroutines.
type cleanupQueryDriver struct {
	started chan struct{}
	release chan struct{}
}

func (d *cleanupQueryDriver) Connect(context.Context) (driver.Conn, error) {
	return &cleanupQueryConn{d: d}, nil
}
func (d *cleanupQueryDriver) Driver() driver.Driver { return d }
func (d *cleanupQueryDriver) Open(string) (driver.Conn, error) {
	return d.Connect(context.Background())
}

type cleanupQueryConn struct{ d *cleanupQueryDriver }

func (c *cleanupQueryConn) Prepare(string) (driver.Stmt, error) {
	return &cleanupQueryStmt{d: c.d}, nil
}
func (*cleanupQueryConn) Close() error              { return nil }
func (*cleanupQueryConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected transaction") }

type cleanupQueryStmt struct{ d *cleanupQueryDriver }

func (*cleanupQueryStmt) Close() error  { return nil }
func (*cleanupQueryStmt) NumInput() int { return -1 }
func (*cleanupQueryStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("unexpected exec")
}
func (s *cleanupQueryStmt) Query([]driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), nil)
}
func (s *cleanupQueryStmt) QueryContext(ctx context.Context, _ []driver.NamedValue) (driver.Rows, error) {
	close(s.d.started)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.d.release:
		return nil, errors.New("query released by test")
	}
}

func TestCloseFileStoreCancelsActiveCleanup(t *testing.T) {
	if err := CloseFileStore(); err != nil {
		t.Fatal(err)
	}
	d := &cleanupQueryDriver{started: make(chan struct{}), release: make(chan struct{})}
	db := sql.OpenDB(d)
	ctx, cancel := context.WithCancel(context.Background())
	mu.Lock()
	fsDB, fsDBType, fsCancel, fsDone = db, system.DB_TYPE_SQLITE, cancel, make(chan struct{})
	done := fsDone
	mu.Unlock()
	go func() {
		defer close(done)
		backgroundCleanup(ctx, time.NewTicker(time.Hour))
	}()
	defer func() {
		close(d.release)
		_ = CloseFileStore()
	}()
	select {
	case <-d.started:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup query did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- CloseFileStore() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("file store shutdown did not cancel its active query")
	}
	if db.Stats().InUse != 0 {
		t.Fatal("cleanup retained a database connection")
	}
}
