// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

const CURRENT_FILE_CACHE_VERSION = 1

// TODO : add file cleanup logic

type FileCache struct {
	db *sql.DB
	*types.Logger
}

func InitFileCache(logger *types.Logger, config *types.ServerConfig) (*FileCache, error) {
	db, _, err := system.InitDBConnection(config.Metadata.FileCacheConnection, "filecache", system.DB_SQLITE)
	if err != nil {
		return nil, fmt.Errorf("error initializing db: %w", err)
	}

	fc := FileCache{
		db:     db,
		Logger: logger,
	}

	err = fc.VersionUpgrade(config)
	if err != nil {
		return nil, err
	}
	return &fc, nil
}

func (f *FileCache) VersionUpgrade(config *types.ServerConfig) error {
	version := 0
	row := f.db.QueryRow("SELECT version, last_upgraded FROM version")
	var dt time.Time
	row.Scan(&version, &dt) //nolint:errcheck // ignore error if no version is found

	if version < CURRENT_DB_VERSION && !config.Metadata.AutoUpgrade {
		return fmt.Errorf("DB autoupgrade is disabled, exiting. Server %d, DB %d", CURRENT_DB_VERSION, version)
	}

	if !config.Metadata.IgnoreHigherVersion && version > CURRENT_DB_VERSION {
		return fmt.Errorf("DB version is newer than server version, upgrade OpenRun server version. Server %d, DB %d", CURRENT_DB_VERSION, version)
	}

	if version == CURRENT_DB_VERSION {
		f.Info().Msg("DB version is current")
		return nil
	}

	ctx := context.Background()
	tx, err := f.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if version < 1 {
		f.Info().Msg("No version, initializing file cache")
		if _, err := tx.ExecContext(ctx, `create table version (version int, last_upgraded datetime)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `insert into version values (1, datetime('now'))`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `create table files (sha text, compression_type text, content blob, create_time datetime, last_accessed datetime, PRIMARY KEY(sha))`); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (f *FileCache) GetCachedFile(ctx context.Context, sha string) ([]byte, string, error) {
	stmt, err := f.db.PrepareContext(ctx, `select compression_type, content from files where sha = ?`)
	if err != nil {
		return nil, "", fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close() //nolint:errcheck

	row := stmt.QueryRow(sha)
	var compressionType string
	var content []byte
	if err := row.Scan(&compressionType, &content); err != nil {
		return nil, "", err
	}

	return content, compressionType, nil
}

func (f *FileCache) AddCache(ctx context.Context, sha string, compressionType string, content []byte) error {
	stmt, err := f.db.PrepareContext(ctx, `insert or replace into files (sha, compression_type, content) values (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close() //nolint:errcheck

	_, err = stmt.ExecContext(ctx, sha, compressionType, content)
	return err
}
