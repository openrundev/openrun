// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

var (
	mu       sync.RWMutex
	fsDB     *sql.DB
	fsDBType system.DBType
	fsCancel context.CancelFunc
	fsDone   chan struct{}
)

func InitFileStore(connectString string) error {
	mu.RLock()
	if fsDB != nil {
		mu.RUnlock()
		return nil
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()
	if fsDB != nil {
		// Another caller initialized the store while this one waited on the lock
		return nil
	}

	db, dbType, err := system.InitDBConnection(nil, connectString, "fs_store", system.DB_SQLITE_POSTGRES, nil)
	if err != nil {
		return err
	}

	if err := initFileStoreSchema(db, dbType); err != nil {
		db.Close() //nolint:errcheck
		return err
	}
	fsDB, fsDBType = db, dbType

	// The file store is shared by all apps, so its context is server-scoped
	// rather than request-scoped. CloseFileStore cancels it during shutdown.
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	cleanupTicker := time.NewTicker(5 * time.Minute)
	fsCancel = cleanupCancel
	fsDone = make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		backgroundCleanup(cleanupCtx, cleanupTicker)
	}(fsDone)

	return nil
}

// CloseFileStore stops the shared cleanup goroutine, closes its database
// pool and resets the singleton so another in-process server can initialize
// it again. Server shutdown calls this after requests and apps have drained.
func CloseFileStore() error {
	mu.Lock()
	defer mu.Unlock()
	db, cancel, done := fsDB, fsCancel, fsDone
	if cancel != nil {
		cancel()
	}

	if done != nil {
		<-done
	}
	// fsDB stays non-nil until the cleanup loop exits, preventing a new
	// initializer from replacing the globals while that loop still uses them.
	if fsDB == db {
		fsDB = nil
		fsDBType = ""
		fsCancel = nil
		fsDone = nil
	}
	if db != nil {
		return db.Close()
	}
	return nil
}

func initFileStoreSchema(db *sql.DB, dbType system.DBType) error {
	if _, err := db.Exec(`create table IF NOT EXISTS user_files (id text, appid text, file_path text, file_name text, ` +
		`mime_type text, create_time ` + system.MapDataType(dbType, "datetime") + `, expire_at ` + system.MapDataType(dbType,
		"datetime") + `, created_by text, single_access bool, visibility text, metadata json, PRIMARY KEY(id))`); err != nil {
		return err
	}

	// File cleanup first lists and then deletes expired rows every five minutes.
	// IF NOT EXISTS upgrades file-store databases created by older releases.
	if _, err := db.Exec(`create index IF NOT EXISTS idx_user_files_expire_at on user_files(expire_at)`); err != nil {
		return err
	}

	return nil
}

func fileCleanup(ctx context.Context) error {
	expired, err := listExpiredFile(ctx)
	if err != nil {
		return fmt.Errorf("error cleaning up expired files %w", err)
	}

	for _, file := range expired {
		if strings.HasPrefix(file.FilePath, "file://") {
			err := os.Remove(strings.TrimPrefix(file.FilePath, "file://"))
			if err != nil && !os.IsNotExist(err) {
				// A file already deleted from disk should not block the row cleanup
				return fmt.Errorf("error deleting file %s: %w", file.FilePath, err)
			}
		}
	}
	err = deleteExpiredFiles(ctx)
	if err != nil {
		return fmt.Errorf("error deleting expired files %w", err)
	}
	return nil
}

func backgroundCleanup(ctx context.Context, cleanupTicker *time.Ticker) {
	defer cleanupTicker.Stop()
	// Errors are logged and cleanup is retried on the next tick
	if err := fileCleanup(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error cleaning up expired files %s", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-cleanupTicker.C:
		}
		if err := fileCleanup(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "error cleaning up expired files %s", err)
		}
	}
}

func AddUserFile(ctx context.Context, file *types.UserFile) error {
	return addUserFile(ctx, file)
}

func addUserFile(ctx context.Context, file *types.UserFile) error {
	metadataJson, err := json.Marshal(file.Metadata)
	if err != nil {
		return fmt.Errorf("error marshalling metadata: %w", err)
	}

	_, err = fsDB.ExecContext(ctx, system.RebindQuery(fsDBType, `INSERT into user_files(id, appid, file_name, file_path, mime_type,`+
		`create_time, expire_at, created_by, single_access, visibility, metadata) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		file.Id, file.AppId, file.FileName, file.FilePath, file.MimeType, file.CreateTime, file.ExpireAt, file.CreatedBy, file.SingleAccess, file.Visibility, string(metadataJson))
	if err != nil {
		return fmt.Errorf("error inserting user file: %w", err)
	}
	return nil
}

func GetUserFile(ctx context.Context, id string) (*types.UserFile, error) {
	stmt, err := fsDB.PrepareContext(ctx, system.RebindQuery(fsDBType,
		`select id, appid, file_name, file_path, mime_type, create_time, expire_at, created_by, single_access, visibility, metadata from user_files where id = ?`))
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close() //nolint:errcheck
	row := stmt.QueryRow(id)
	var file types.UserFile
	var metadata sql.NullString
	err = row.Scan(&file.Id, &file.AppId, &file.FileName, &file.FilePath, &file.MimeType, &file.CreateTime, &file.ExpireAt,
		&file.CreatedBy, &file.SingleAccess, &file.Visibility, &metadata)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("file not found")
		}
		return nil, fmt.Errorf("error querying file: %w", err)
	}

	if metadata.Valid && metadata.String != "" {
		err = json.Unmarshal([]byte(metadata.String), &file.Metadata)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling metadata: %w", err)
		}
	}

	return &file, nil
}

func DeleteUserFile(ctx context.Context, id string) error {
	stmt, err := fsDB.PrepareContext(ctx, system.RebindQuery(fsDBType, `delete from user_files where id = ?`))
	if err != nil {
		return fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close() //nolint:errcheck
	_, err = stmt.Exec(id)
	if err != nil {
		return fmt.Errorf("error deleting file: %w", err)
	}
	return nil
}

type expiredFile struct {
	Id       string
	FilePath string
}

func listExpiredFile(ctx context.Context) ([]expiredFile, error) {
	stmt, err := fsDB.PrepareContext(ctx, system.RebindQuery(fsDBType, `select id, file_path from user_files where expire_at < ?`))
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %w", err)
	}

	defer stmt.Close() //nolint:errcheck

	rows, err := stmt.Query(time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("error querying files: %w", err)
	}

	defer rows.Close() //nolint:errcheck

	var expiredFiles []expiredFile
	for rows.Next() {
		var id, file_path string
		err = rows.Scan(&id, &file_path)
		if err != nil {
			return nil, fmt.Errorf("error scanning id: %w", err)
		}
		expiredFiles = append(expiredFiles, expiredFile{
			Id:       id,
			FilePath: file_path,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating expired files: %w", err)
	}
	return expiredFiles, nil
}

func deleteExpiredFiles(ctx context.Context) error {
	stmt, err := fsDB.PrepareContext(ctx, system.RebindQuery(fsDBType, `delete from user_files where expire_at < ?`))
	if err != nil {
		return fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close() //nolint:errcheck

	_, err = stmt.Exec(time.Now().UTC())
	if err != nil {
		return fmt.Errorf("error deleting files: %w", err)
	}

	return nil
}
