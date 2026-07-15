// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/segmentio/ksuid"
	"go.starlark.net/starlark"
)

var (
	mu       sync.RWMutex
	fsDB     *sql.DB
	fsDBType system.DBType
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

	db, dbType, err := system.InitDBConnection(connectString, "fs_store", system.DB_SQLITE_POSTGRES)
	if err != nil {
		return err
	}

	if _, err := db.Exec(`create table IF NOT EXISTS user_files (id text, appid text, file_path text, file_name text, ` +
		`mime_type text, create_time ` + system.MapDataType(dbType, "datetime") + `, expire_at ` + system.MapDataType(dbType,
		"datetime") + `, created_by text, single_access bool, visibility text, metadata json, PRIMARY KEY(id))`); err != nil {
		db.Close() //nolint:errcheck
		return err
	}
	fsDB, fsDBType = db, dbType

	// The file store is a process-lifetime singleton, so the cleanup loop runs
	// with a background context; a request-scoped context would cancel the
	// cleanup queries once the request that initialized the store completes
	cleanupTicker := time.NewTicker(5 * time.Minute)
	go backgroundCleanup(context.Background(), cleanupTicker)

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
	// Errors are logged and cleanup is retried on the next tick
	if err := fileCleanup(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error cleaning up expired files %s", err)
	}

	for range cleanupTicker.C {
		if err := fileCleanup(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "error cleaning up expired files %s", err)
		}
	}
}

func (f *fsPlugin) ServeTmpFile(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pathVal, fileName starlark.String
	visibility := starlark.String(UserAccess)
	mimeType := starlark.String("application/octet-stream")
	expiryMinutes := starlark.MakeInt(60)
	singleAccess := starlark.Bool(true)

	if err := starlark.UnpackArgs("serve_tmp_file", args, kwargs, "path", &pathVal, "name?", &fileName, "visibility?", &visibility,
		"mime_type?", &mimeType, "expiry_minutes?", &expiryMinutes, "single_access", &singleAccess); err != nil {
		return nil, err
	}

	pathStr, err := filepath.Abs(string(pathVal))
	if err != nil {
		return nil, err
	}

	ok, err := f.checkAccess(pathStr)
	if err != nil {
		return nil, fmt.Errorf("error during access check for %s: %w", pathStr, err)
	}
	if !ok {
		return nil, fmt.Errorf("file access denied for %s", pathStr)
	}

	connectString, err := system.GetConnectString(f.pluginContext)
	if err != nil {
		return nil, err
	}

	err = InitFileStore(connectString)
	if err != nil {
		return nil, err
	}

	var expiryMinutesInt int
	if err = starlark.AsInt(expiryMinutes, &expiryMinutesInt); err != nil {
		return nil, fmt.Errorf("expiry_minutes must be an integer")
	}

	createTime := time.Now()
	expireAt := createTime.Add(time.Duration(expiryMinutesInt) * time.Minute)
	if expiryMinutesInt <= 0 {
		expireAt = time.Unix(0, int64(^uint64(0)>>1))
	}

	id, err := ksuid.NewRandom()
	if err != nil {
		return nil, err
	}

	fileNameStr := string(fileName)
	if fileNameStr == "" {
		fileNameStr = filepath.Base(pathStr)
	}

	userFile := &types.UserFile{
		Id:           "usr_file_" + id.String(),
		AppId:        string(f.pluginContext.AppId),
		FilePath:     "file://" + pathStr,
		FileName:     fileNameStr,
		MimeType:     string(mimeType),
		CreateTime:   createTime,
		ExpireAt:     expireAt,
		CreatedBy:    system.GetRequestUserId(thread),
		SingleAccess: bool(singleAccess),
		Visibility:   string(visibility),
		Metadata:     make(map[string]any),
	}

	err = AddUserFile(GetContext(thread), userFile)
	if err != nil {
		return nil, err
	}

	appPath := f.pluginContext.AppPath
	if appPath == "/" {
		appPath = ""
	}
	downloadUrl := fmt.Sprintf("%s%s/file/%s", appPath, types.APP_INTERNAL_URL_PREFIX, userFile.Id)

	ret := map[string]string{
		"id":   userFile.Id,
		"url":  downloadUrl,
		"name": userFile.FileName,
	}
	return NewResponse(ret), nil
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

	rows, err := stmt.Query(time.Now())
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

	_, err = stmt.Exec(time.Now())
	if err != nil {
		return fmt.Errorf("error deleting files: %w", err)
	}

	return nil
}
