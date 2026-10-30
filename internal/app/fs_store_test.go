// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
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

func TestRemoveServedFileRefusesSymlinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "outside", "keep.txt")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A path component which became a symlink after registration: the stored
	// path no longer names the file that was checked
	linkDir := filepath.Join(root, "served")
	if err := os.Symlink(filepath.Join(root, "outside"), linkDir); err != nil {
		t.Fatal(err)
	}
	if err := removeServedFile(filepath.Join(linkDir, "keep.txt")); err == nil {
		t.Fatal("expected deletion through a directory symlink to be refused")
	}
	// A file symlink is refused as well
	fileLink := filepath.Join(root, "link.txt")
	if err := os.Symlink(target, fileLink); err != nil {
		t.Fatal(err)
	}
	if err := removeServedFile(fileLink); err == nil {
		t.Fatal("expected deletion of a symlink to be refused")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("target must be untouched: %v", err)
	}

	// A regular file at its resolved path is deleted; a missing file reports
	// not exist so the cleanup can drop the row
	if err := removeServedFile(target); err != nil {
		t.Fatal(err)
	}
	if err := removeServedFile(target); !os.IsNotExist(err) {
		t.Fatalf("expected not exist error, got %v", err)
	}
}

func TestFileCleanupRetiresRefusedRowsAndContinues(t *testing.T) {
	if err := CloseFileStore(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = CloseFileStore() })
	if err := InitFileStore("sqlite:" + filepath.Join(t.TempDir(), "files.db")); err != nil {
		t.Fatal(err)
	}

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(root, "outside", "keep.txt")
	if err := os.MkdirAll(filepath.Dir(kept), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kept, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside"), filepath.Join(root, "served")); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(root, "regular.txt")
	if err := os.WriteFile(regular, []byte("gone"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	expired := time.Now().UTC().Add(-time.Hour)
	// The refused row sorts first so a cleanup which stops at it leaves the
	// regular file behind
	rows := []*types.UserFile{
		{Id: "usr_file_1", AppId: "app1", FilePath: "file://" + filepath.Join(root, "served", "keep.txt"), FileName: "keep.txt"},
		{Id: "usr_file_2", AppId: "app2", FilePath: "file://" + regular, FileName: "regular.txt"},
		{Id: "usr_file_3", AppId: "app2", FilePath: "file://" + filepath.Join(root, "missing.txt"), FileName: "missing.txt"},
		{Id: "usr_file_4", AppId: "app2", FilePath: "file://" + filepath.Join(root, "future.txt"), FileName: "future.txt"},
	}
	for _, row := range rows {
		row.CreateTime = expired
		row.ExpireAt = expired
		row.Metadata = map[string]any{}
		if row.Id == "usr_file_4" {
			row.ExpireAt = time.Now().UTC().Add(time.Hour)
		}
		if err := AddUserFile(ctx, row); err != nil {
			t.Fatal(err)
		}
	}

	if err := fileCleanup(ctx); err != nil {
		t.Fatalf("cleanup must not fail on a refused row: %v", err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("file behind the symlink must be untouched: %v", err)
	}
	if _, err := os.Stat(regular); !os.IsNotExist(err) {
		t.Fatalf("expired regular file must be deleted: %v", err)
	}
	for _, id := range []string{"usr_file_1", "usr_file_2", "usr_file_3"} {
		if _, err := GetUserFile(ctx, id); err == nil {
			t.Fatalf("expired row %s must be retired", id)
		}
	}
	if _, err := GetUserFile(ctx, "usr_file_4"); err != nil {
		t.Fatalf("unexpired row must remain: %v", err)
	}
}
