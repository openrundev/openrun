// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

const (
	SELECT_MAX_LIMIT     = 100_000
	SELECT_DEFAULT_LIMIT = 10_000
	SORT_ASCENDING       = "asc"
	SORT_DESCENDING      = "desc"
)

type SqlStore struct {
	*types.Logger
	sync.Mutex
	isInitialized bool
	pluginContext *types.PluginContext
	db            *sql.DB
	prefix        string
	isSqlite      bool // false means postgres, no other options
}

var _ Store = (*SqlStore)(nil)

func NewSqlStore(pluginContext *types.PluginContext) (*SqlStore, error) {
	return &SqlStore{
		Logger:        pluginContext.Logger,
		pluginContext: pluginContext,
	}, nil
}

func (s *SqlStore) dbType() system.DBType {
	if s.isSqlite {
		return system.DB_TYPE_SQLITE
	}
	return system.DB_TYPE_POSTGRES
}

func (s *SqlStore) rebindQuery(query string) string {
	return system.RebindQuery(s.dbType(), query)
}

func (s *SqlStore) queryMapper() fieldMapper {
	if s.isSqlite {
		return sqliteFieldMapper
	}
	return postgresFieldMapper
}

func (s *SqlStore) queryOptions() queryOptions {
	if s.isSqlite {
		return queryOptions{}
	}
	return queryOptions{stringifyMappedParams: true}
}

func (s *SqlStore) quoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

func (s *SqlStore) genRawTableName(table string) (string, error) {
	err := validateTableName(table)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s_%s", s.prefix, table), nil
}

func validateTableName(name string) error {
	// TODO: validate table name
	return nil
}

func genSortString(sortFields []string, mapper fieldMapper) (string, error) {
	var buf bytes.Buffer
	var err error

	for i, field := range sortFields {
		if i > 0 {
			buf.WriteString(", ")
		}

		lower := strings.ToLower(field)
		if strings.HasSuffix(lower, ":"+SORT_DESCENDING) {
			field = strings.TrimSpace(field[:len(field)-len(":"+SORT_DESCENDING)])

			mapped := field
			if mapper != nil {
				mapped, err = mapper(field)
				if err != nil {
					return "", err
				}
			}
			buf.WriteString(mapped)
			buf.WriteString(" DESC")

		} else {
			if strings.HasSuffix(lower, ":"+SORT_ASCENDING) { // :ASC is optional
				field = strings.TrimSpace(field[:len(field)-len(":"+SORT_ASCENDING)])
			}

			mapped := field
			if mapper != nil {
				mapped, err = mapper(field)
				if err != nil {
					return "", err
				}
			}

			buf.WriteString(mapped)
			buf.WriteString(" ASC")
		}
	}
	return buf.String(), nil
}

func (s *SqlStore) genTableName(table string) (string, error) {
	rawName, err := s.genRawTableName(table)
	if err != nil {
		return "", err
	}
	return s.quoteIdentifier(rawName), nil
}

func (s *SqlStore) initialize(ctx context.Context) error {
	s.Lock()
	defer s.Unlock()

	if s.isInitialized {
		// Already initialized
		return nil
	}

	if err := s.initStore(ctx); err != nil {
		return err
	}
	s.isInitialized = true
	return nil
}

func (s *SqlStore) Begin(ctx context.Context) (*sql.Tx, error) {
	if err := s.initialize(ctx); err != nil {
		return nil, err
	}
	return s.db.BeginTx(ctx, nil)
}

func (s *SqlStore) Commit(ctx context.Context, tx *sql.Tx) error {
	if err := s.initialize(ctx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SqlStore) Rollback(ctx context.Context, tx *sql.Tx) error {
	if err := s.initialize(ctx); err != nil {
		return err
	}
	return tx.Rollback()
}

// Insert a new entry in the store
func (s *SqlStore) Insert(ctx context.Context, tx *sql.Tx, table string, entry *Entry) (EntryId, error) {
	if err := s.initialize(ctx); err != nil {
		return -1, err
	}

	entry.CreatedAt = time.Now()
	entry.UpdatedAt = entry.CreatedAt
	entry.CreatedBy = "admin" // TODO update userid

	var err error
	table, err = s.genTableName(table)
	if err != nil {
		return -1, err
	}

	dataJson, err := json.Marshal(entry.Data)
	if err != nil {
		return -1, fmt.Errorf("error marshalling data for table %s: %w", table, err)
	}

	createStmt := "INSERT INTO " + table + " (_version, _created_by, _updated_by, _created_at, _updated_at, _json) VALUES (?, ?, ?, ?, ?, ?)"
	createStmt = s.rebindQuery(createStmt)
	args := []any{entry.Version, entry.CreatedBy, entry.UpdatedBy, entry.CreatedAt.UnixMilli(), entry.UpdatedAt.UnixMilli(), dataJson}

	if !s.isSqlite {
		insertStmt := createStmt + " RETURNING _id"
		var insertId int64
		if tx != nil {
			err = tx.QueryRowContext(ctx, insertStmt, args...).Scan(&insertId)
		} else {
			err = s.db.QueryRowContext(ctx, insertStmt, args...).Scan(&insertId)
		}
		if err != nil {
			return -1, err
		}
		return EntryId(insertId), nil
	}

	var result sql.Result
	if tx != nil {
		result, err = tx.ExecContext(ctx, createStmt, args...)
	} else {
		result, err = s.db.ExecContext(ctx, createStmt, args...)

	}
	if err != nil {
		return -1, err
	}

	insertId, err := result.LastInsertId()
	if err != nil {
		return -1, err
	}
	return EntryId(insertId), nil
}

// SelectById returns a single item from the store
func (s *SqlStore) SelectById(ctx context.Context, tx *sql.Tx, table string, id EntryId) (*Entry, error) {
	if err := s.initialize(ctx); err != nil {
		return nil, err
	}

	var err error
	table, err = s.genTableName(table)
	if err != nil {
		return nil, err
	}

	query := s.rebindQuery("SELECT _id, _version, _created_by, _updated_by, _created_at, _updated_at, _json FROM " + table + " WHERE _id = ?")
	var row *sql.Row
	if tx != nil {
		row = tx.QueryRowContext(ctx, query, id)
	} else {
		row = s.db.QueryRowContext(ctx, query, id)
	}

	entry := &Entry{}
	var dataStr string
	var createdAt, updatedAt int64
	err = row.Scan(&entry.Id, &entry.Version, &entry.CreatedBy, &entry.UpdatedBy, &createdAt, &updatedAt, &dataStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("entry %d not found in table %s", id, table)
		}
		return nil, err
	}

	if dataStr != "" {
		if err := json.Unmarshal([]byte(dataStr), &entry.Data); err != nil {
			return nil, err
		}
	}

	entry.CreatedAt = time.UnixMilli(createdAt)
	entry.UpdatedAt = time.UnixMilli(updatedAt)
	return entry, nil
}

// SelectOne returns a single item from the store
func (s *SqlStore) SelectOne(ctx context.Context, tx *sql.Tx, table string, filter map[string]any) (*Entry, error) {
	if err := s.initialize(ctx); err != nil {
		return nil, err
	}

	var err error
	table, err = s.genTableName(table)
	if err != nil {
		return nil, err
	}

	filterStr, params, err := parseQueryWithOptions(filter, s.queryMapper(), s.queryOptions())
	if err != nil {
		return nil, err
	}

	whereStr := ""
	if filterStr != "" {
		whereStr = " WHERE " + filterStr
	}

	query := s.rebindQuery("SELECT _id, _version, _created_by, _updated_by, _created_at, _updated_at, _json FROM " + table + whereStr)

	var row *sql.Row
	if tx != nil {
		row = tx.QueryRowContext(ctx, query, params...)
	} else {
		row = s.db.QueryRowContext(ctx, query, params...)
	}

	entry := &Entry{}
	var dataStr string
	var createdAt, updatedAt int64
	err = row.Scan(&entry.Id, &entry.Version, &entry.CreatedBy, &entry.UpdatedBy, &createdAt, &updatedAt, &dataStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("entry %s not found in table %s", whereStr, table)
		}
		return nil, err
	}

	if dataStr != "" {
		if err := json.Unmarshal([]byte(dataStr), &entry.Data); err != nil {
			return nil, err
		}
	}

	entry.CreatedAt = time.UnixMilli(createdAt)
	entry.UpdatedAt = time.UnixMilli(updatedAt)
	return entry, nil

}

// Select returns the entries matching the filter
func (s *SqlStore) Select(ctx context.Context, tx *sql.Tx, thread *starlark.Thread, table string, filter map[string]any, sort []string, offset, limit int64) (starlark.Iterable, error) {
	if err := s.initialize(ctx); err != nil {
		return nil, err
	}

	var err error
	table, err = s.genTableName(table)
	if err != nil {
		return nil, err
	}

	if limit > SELECT_MAX_LIMIT {
		return nil, fmt.Errorf("select limit %d exceeds max limit %d", limit, SELECT_MAX_LIMIT)
	}
	if limit <= 0 {
		limit = SELECT_DEFAULT_LIMIT
	}
	if offset < 0 {
		return nil, fmt.Errorf("select offset %d is invalid", offset)
	}

	limitOffsetStr := fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)

	var sortStr string
	if len(sort) > 0 {
		sortStr, err = genSortString(sort, s.queryMapper())
		if err != nil {
			return nil, err
		}
	}
	if sortStr != "" {
		sortStr = " ORDER BY " + sortStr
	}

	filterStr, params, err := parseQueryWithOptions(filter, s.queryMapper(), s.queryOptions())
	if err != nil {
		return nil, err
	}

	whereStr := ""
	if filterStr != "" {
		whereStr = " WHERE " + filterStr
	}

	query := s.rebindQuery("SELECT _id, _version, _created_by, _updated_by, _created_at, _updated_at, _json FROM " + table + whereStr + sortStr + limitOffsetStr)
	s.Trace().Msgf("query: %s, params: %#v", query, params)

	var rows *sql.Rows
	if tx != nil {
		rows, err = tx.QueryContext(ctx, query, params...)
	} else {
		rows, err = s.db.QueryContext(ctx, query, params...)
	}

	app.DeferCleanup(thread, fmt.Sprintf("rows_cursor_%s_%p", table, rows), rows.Close, true)

	if err != nil {
		return nil, err
	}

	return NewStoreEntryIterabe(thread, s.Logger, table, rows), nil
}

// Count returns the number of entries matching the filter
func (s *SqlStore) Count(ctx context.Context, tx *sql.Tx, table string, filter map[string]any) (int64, error) {
	if err := s.initialize(ctx); err != nil {
		return -1, err
	}

	var err error
	table, err = s.genTableName(table)
	if err != nil {
		return -1, err
	}

	filterStr, params, err := parseQueryWithOptions(filter, s.queryMapper(), s.queryOptions())
	if err != nil {
		return -1, err
	}

	whereStr := ""
	if filterStr != "" {
		whereStr = " WHERE " + filterStr
	}

	query := s.rebindQuery("SELECT count(_id) FROM " + table + whereStr)
	s.Trace().Msgf("query: %s, params: %#v", query, params)

	var row *sql.Row
	if tx != nil {
		row = tx.QueryRowContext(ctx, query, params...)
	} else {
		row = s.db.QueryRowContext(ctx, query, params...)
	}

	var count int64
	err = row.Scan(&count)
	if err != nil {
		return -1, err
	}

	return count, nil
}

// Update an existing entry in the store
func (s *SqlStore) Update(ctx context.Context, tx *sql.Tx, table string, entry *Entry) (int64, error) {
	if err := s.initialize(ctx); err != nil {
		return 0, err
	}

	var err error
	if table, err = s.genTableName(table); err != nil {
		return 0, err
	}

	origUpdateAt := entry.UpdatedAt
	entry.UpdatedAt = time.Now()
	entry.UpdatedBy = "admin" // TODO update userid

	dataJson, err := json.Marshal(entry.Data)
	if err != nil {
		return 0, fmt.Errorf("error marshalling data for table %s: %w", table, err)
	}

	updateStmt := "UPDATE " + table + " set _version = ?, _updated_by = ?, _updated_at = ?, _json = ? where _id = ? and _updated_at = ?"
	updateStmt = s.rebindQuery(updateStmt)
	s.Trace().Msgf("query: %s, id: %d updated_at %d", updateStmt, entry.Id, origUpdateAt.UnixMilli())

	var result sql.Result
	if tx != nil {
		result, err = tx.ExecContext(ctx, updateStmt, entry.Version, entry.UpdatedBy, entry.UpdatedAt.UnixMilli(), dataJson, entry.Id, origUpdateAt.UnixMilli())
	} else {
		result, err = s.db.ExecContext(ctx, updateStmt, entry.Version, entry.UpdatedBy, entry.UpdatedAt.UnixMilli(), dataJson, entry.Id, origUpdateAt.UnixMilli())
	}
	if err != nil {
		return 0, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if rows == 0 {
		return 0, fmt.Errorf("entry %d not found or concurrently updated in table %s", entry.Id, table)
	}

	return rows, nil
}

// DeleteById an entry from the store by id
func (s *SqlStore) DeleteById(ctx context.Context, tx *sql.Tx, table string, id EntryId) (int64, error) {
	if err := s.initialize(ctx); err != nil {
		return 0, err
	}

	var err error
	if table, err = s.genTableName(table); err != nil {
		return 0, err
	}

	deleteStmt := s.rebindQuery("DELETE from " + table + " where _id = ?")

	var result sql.Result
	if tx != nil {
		result, err = tx.ExecContext(ctx, deleteStmt, id)
	} else {
		result, err = s.db.ExecContext(ctx, deleteStmt, id)
	}
	if err != nil {
		return 0, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	if rows == 0 {
		return 0, fmt.Errorf("entry %d not found in table %s", id, table)
	}

	return rows, nil
}

// Delete entries from the store matching the filter
func (s *SqlStore) Delete(ctx context.Context, tx *sql.Tx, table string, filter map[string]any) (int64, error) {
	if err := s.initialize(ctx); err != nil {
		return 0, err
	}

	var err error
	if table, err = s.genTableName(table); err != nil {
		return 0, err
	}

	filterStr, params, err := parseQueryWithOptions(filter, s.queryMapper(), s.queryOptions())
	if err != nil {
		return 0, err
	}

	whereStr := ""
	if filterStr != "" {
		whereStr = " WHERE " + filterStr
	}

	deleteStmt := s.rebindQuery("DELETE FROM " + table + whereStr)

	var result sql.Result
	if tx != nil {
		result, err = tx.ExecContext(ctx, deleteStmt, params...)
	} else {
		result, err = s.db.ExecContext(ctx, deleteStmt, params...)
	}
	if err != nil {
		return 0, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return rows, nil
}
