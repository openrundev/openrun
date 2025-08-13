// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func (s *SqlStore) initStore(ctx context.Context) error {
	if s.pluginContext.StoreInfo == nil {
		return fmt.Errorf("store info not found")
	}
	connectString, err := system.GetConnectString(s.pluginContext)
	if err != nil {
		return err
	}
	s.db, _, err = system.InitDBConnection(connectString, "store", system.DB_SQLITE)
	if err != nil {
		return err
	}
	s.isSqlite = true

	s.prefix = "db_" + string(s.pluginContext.AppId)[len(types.ID_PREFIX_APP_PROD):]

	autoKey := "INTEGER PRIMARY KEY AUTOINCREMENT"
	if !s.isSqlite {
		autoKey = "SERIAL PRIMARY KEY"
	}

	for _, storeType := range s.pluginContext.StoreInfo.Types {
		table, err := s.genTableName(storeType.Name)
		if err != nil {
			return err
		}

		createStmt := "CREATE TABLE IF NOT EXISTS " + table + " (_id " + autoKey + ", _version INTEGER, _created_by TEXT, _updated_by TEXT, _created_at INTEGER, _updated_at INTEGER, _json JSON)"
		_, err = s.db.ExecContext(ctx, createStmt)
		if err != nil {
			return fmt.Errorf("error creating table %s: %w", table, err)
		}
		s.Info().Msgf("Created table %s", table)

		unquotedTable := strings.Trim(table, "'")
		if storeType.Indexes != nil {
			for _, index := range storeType.Indexes {

				indexStmt, err := createIndexStmt(unquotedTable, index)
				if err != nil {
					return err
				}

				_, err = s.db.ExecContext(ctx, indexStmt)
				s.Trace().Msgf("indexStmt: %s", indexStmt)
				if err != nil {
					return fmt.Errorf("error creating index on %s: %w", unquotedTable, err)
				}
			}
		}
	}

	if err := s.createSchemaInfo(ctx); err != nil {
		return err
	}

	return nil
}

func (s *SqlStore) createSchemaInfo(ctx context.Context) error {
	autoKey := "INTEGER PRIMARY KEY AUTOINCREMENT"
	if !s.isSqlite {
		autoKey = "SERIAL PRIMARY KEY"
	}

	schemaTable := fmt.Sprintf("'%s_cl_schema'", s.prefix)
	createStmt := "CREATE TABLE IF NOT EXISTS " + schemaTable + " (version " + autoKey + ", created_by TEXT, updated_by TEXT, created_at INTEGER, updated_at INTEGER, main_app TEXT, schema_data BLOB, schema_etag TEXT)"
	_, err := s.db.Exec(createStmt)
	if err != nil {
		return fmt.Errorf("error creating table %s: %w", schemaTable, err)
	}

	statusQuery := "select schema_etag from " + schemaTable + " order by version desc limit 1"

	var schemaEtag string
	err = s.db.QueryRowContext(ctx, statusQuery).Scan(&schemaEtag)
	if err != nil {
		if err != sql.ErrNoRows {
			return fmt.Errorf("error querying table %s: %w", schemaTable, err)
		}
	}

	hash := sha256.Sum256(s.pluginContext.StoreInfo.Bytes)
	hashHex := hex.EncodeToString(hash[:])
	if schemaEtag == hashHex {
		// Schema is up to date. This means there is an existing entry and that has a has same as the current schema
		s.Debug().Msgf("Schema up to date, not inserting new entry")
		return nil
	}

	// Either no existing schema entry or hash mismatch. Insert new entry
	currentTime := time.Now().UnixMilli()
	userId := "admin"
	insertStmt := "insert into " + schemaTable + " (created_by, updated_by, created_at, updated_at, main_app, schema_data, schema_etag) values (?, ?, ?, ?, ?, ?, ?)"

	_, err = s.db.ExecContext(ctx, insertStmt, userId, userId, currentTime, currentTime, s.pluginContext.AppId, s.pluginContext.StoreInfo.Bytes, hashHex)
	if err != nil {
		return fmt.Errorf("error inserting into table %s: %w", schemaTable, err)
	}

	return nil
}

func createIndexStmt(unquotedTableName string, index starlark_type.Index) (string, error) {
	mappedColumns, err := genSortString(index.Fields, sqliteFieldMapper)
	if err != nil {
		return "", fmt.Errorf("error generating index columns for table %s: %w", unquotedTableName, err)
	}
	unmappedColumns, err := genSortString(index.Fields, nil)
	if err != nil {
		return "", fmt.Errorf("error generating index columns for table %s: %w", unquotedTableName, err)
	}
	indexName := fmt.Sprintf("index_%s_%s", unquotedTableName, strings.ReplaceAll(unmappedColumns, ", ", "_"))
	indexName = strings.ReplaceAll(indexName, " ", "_")

	unique := " "
	if index.Unique {
		unique = " UNIQUE "
	}

	indexStmt := fmt.Sprintf("CREATE%sINDEX IF NOT EXISTS '%s' ON '%s' (%s)", unique, indexName, unquotedTableName, mappedColumns)
	return indexStmt, nil
}
