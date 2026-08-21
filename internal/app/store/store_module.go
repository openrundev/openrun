// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// The store plugin module, implemented against the plugin SDK (pkg/plugin).
// The same implementation serves both builds: compiled into the OpenRun
// binary as "store.in" (registered below as a local provider), and as the
// out-of-process provider executable in ./storeprovider (loadable as
// "store.ex", or "store.in" in a binary without the compiled-in module).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/types"
	plugin "github.com/openrundev/openrun/pkg/plugin"
)

const TRANSACTION_KEY = "transaction"

func init() {
	app.RegisterLocalProvider("store", ProviderConfig("builtin"), app.LocalProviderOptions{})
}

// ProviderConfig returns the store plugin's provider config, shared by the
// compiled-in registration above and the storeprovider executable.
func ProviderConfig(version string) *plugin.ServeConfig {
	return &plugin.ServeConfig{
		ProviderVersion: version,
		Modules: map[string]plugin.ModuleDef{
			"store": {
				Builder: NewStoreModule,
				Functions: []plugin.FuncDef{
					{Name: "begin", Type: plugin.READ, Method: "Begin"},
					{Name: "commit", Type: plugin.WRITE, Method: "Commit"},
					{Name: "rollback", Type: plugin.READ, Method: "Rollback"},
					{Name: "select_by_id", Type: plugin.READ, Method: "SelectById"},
					{Name: "select", Type: plugin.READ, Method: "Select"},
					{Name: "select_one", Type: plugin.READ, Method: "SelectOne"},
					{Name: "count", Type: plugin.READ, Method: "Count"},
					{Name: "insert", Type: plugin.WRITE, Method: "Insert"},
					{Name: "update", Type: plugin.WRITE, Method: "Update"},
					{Name: "delete_by_id", Type: plugin.WRITE, Method: "DeleteById"},
					{Name: "delete", Type: plugin.WRITE, Method: "Delete"},
				},
			},
		},
	}
}

type storeModule struct {
	sqlStore *SqlStore
}

func NewStoreModule() plugin.Module {
	return &storeModule{}
}

func (m *storeModule) InitModule(ctx context.Context, init plugin.ModuleInit) error {
	var storeInfo *starlark_type.StoreInfo
	if len(init.AppSchema) > 0 {
		var err error
		storeInfo, err = apptype.ReadStoreInfo(apptype.SCHEMA_FILE_NAME, init.AppSchema)
		if err != nil {
			return fmt.Errorf("error reading app schema: %w", err)
		}
	}

	pluginContext := &types.PluginContext{
		Logger:    &types.Logger{Logger: init.Logger.Logger},
		AppId:     types.AppId(init.AppId),
		StoreInfo: storeInfo,
		Config:    types.PluginSettings(init.Settings),
		AppPath:   init.AppPath,
	}

	var err error
	m.sqlStore, err = NewSqlStore(pluginContext)
	return err
}

func (m *storeModule) Close(ctx context.Context) error {
	return nil
}

func fetchTransaction(call *plugin.Call) *sql.Tx {
	tx, _ := call.Session.Get(TRANSACTION_KEY).(*sql.Tx)
	return tx
}

func (m *storeModule) Begin(ctx context.Context, call *plugin.Call) (any, error) {
	// The transaction outlives this call: database/sql rolls a transaction
	// back when its context is cancelled, and the per-call gRPC context is
	// cancelled as soon as the begin call returns, so the transaction must
	// run on the session context (alive until request end)
	tx, err := m.sqlStore.Begin(call.Session.Context())
	if err != nil {
		return nil, err
	}
	call.Session.Set(TRANSACTION_KEY, tx)
	// An uncommitted transaction rolls back at session end (request end)
	// without failing the request.
	call.Session.Defer(fmt.Sprintf("transaction_%p", tx), false, func(ctx context.Context) error {
		return tx.Rollback()
	})
	return true, nil
}

func (m *storeModule) Commit(ctx context.Context, call *plugin.Call) (any, error) {
	tx := fetchTransaction(call)
	if tx == nil {
		return nil, errors.New("no transaction to commit")
	}
	call.Session.ClearDefer(fmt.Sprintf("transaction_%p", tx))
	if err := m.sqlStore.Commit(ctx, tx); err != nil {
		return nil, err
	}
	return true, nil
}

func (m *storeModule) Rollback(ctx context.Context, call *plugin.Call) (any, error) {
	tx := fetchTransaction(call)
	if tx == nil {
		return nil, errors.New("no transaction to rollback")
	}
	call.Session.ClearDefer(fmt.Sprintf("transaction_%p", tx))
	if err := m.sqlStore.Rollback(ctx, tx); err != nil {
		return nil, err
	}
	return true, nil
}

func (m *storeModule) Insert(ctx context.Context, call *plugin.Call) (any, error) {
	var table string
	var entryStruct *plugin.Struct
	if err := plugin.UnpackArgs("insert", call, "table", &table, "entry", &entryStruct); err != nil {
		return nil, err
	}

	entry, err := entryFromStruct(entryStruct)
	if err != nil {
		return nil, err
	}

	id, err := m.sqlStore.Insert(ctx, fetchTransaction(call), table, entry)
	if err != nil {
		return nil, err
	}
	return int64(id), nil
}

func (m *storeModule) SelectById(ctx context.Context, call *plugin.Call) (any, error) {
	var table string
	var id int64
	if err := plugin.UnpackArgs("select_by_id", call, "table", &table, "id", &id); err != nil {
		return nil, err
	}
	if id < 0 {
		return nil, fmt.Errorf("invalid id value")
	}

	entry, err := m.sqlStore.SelectById(ctx, fetchTransaction(call), table, EntryId(id))
	if err != nil {
		return nil, err
	}
	return structFromEntry(table, entry), nil
}

func (m *storeModule) Update(ctx context.Context, call *plugin.Call) (any, error) {
	var table string
	var entryStruct *plugin.Struct
	if err := plugin.UnpackArgs("update", call, "table", &table, "entry", &entryStruct); err != nil {
		return nil, err
	}

	entry, err := entryFromStruct(entryStruct)
	if err != nil {
		return nil, err
	}

	rows, err := m.sqlStore.Update(ctx, fetchTransaction(call), table, entry)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (m *storeModule) DeleteById(ctx context.Context, call *plugin.Call) (any, error) {
	var table string
	var id int64
	if err := plugin.UnpackArgs("delete_by_id", call, "table", &table, "id", &id); err != nil {
		return nil, err
	}
	if id < 0 {
		return nil, fmt.Errorf("invalid id value")
	}

	rows, err := m.sqlStore.DeleteById(ctx, fetchTransaction(call), table, EntryId(id))
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (m *storeModule) SelectOne(ctx context.Context, call *plugin.Call) (any, error) {
	var table string
	var filter map[string]any
	if err := plugin.UnpackArgs("select_one", call, "table", &table, "filter", &filter); err != nil {
		return nil, err
	}
	entry, err := m.sqlStore.SelectOne(ctx, fetchTransaction(call), table, normalizeFilter(filter))
	if err != nil {
		return nil, err
	}
	return structFromEntry(table, entry), nil
}

func (m *storeModule) Count(ctx context.Context, call *plugin.Call) (any, error) {
	var table string
	var filter map[string]any
	if err := plugin.UnpackArgs("count", call, "table", &table, "filter", &filter); err != nil {
		return nil, err
	}
	count, err := m.sqlStore.Count(ctx, fetchTransaction(call), table, normalizeFilter(filter))
	if err != nil {
		return nil, err
	}
	return count, nil
}

func (m *storeModule) Delete(ctx context.Context, call *plugin.Call) (any, error) {
	var table string
	var filter map[string]any
	if err := plugin.UnpackArgs("delete", call, "table", &table, "filter", &filter); err != nil {
		return nil, err
	}
	rows, err := m.sqlStore.Delete(ctx, fetchTransaction(call), table, normalizeFilter(filter))
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (m *storeModule) Select(ctx context.Context, call *plugin.Call) (any, error) {
	var table string
	var filter map[string]any
	var sort []string
	var offset, limit int64
	if err := plugin.UnpackArgs("select", call, "table", &table, "filter", &filter,
		"sort?", &sort, "offset?", &offset, "limit?", &limit); err != nil {
		return nil, err
	}
	if limit < 0 {
		return nil, fmt.Errorf("invalid limit value")
	}
	if offset < 0 {
		return nil, fmt.Errorf("invalid offset value")
	}

	// The rows cursor outlives this call (it is drained by later CursorNext
	// calls), so the query must run on the session context: the per-call gRPC
	// context is cancelled when this call returns, which would close the rows
	iterator, err := m.sqlStore.SelectEntries(call.Session.Context(), fetchTransaction(call), table, normalizeFilter(filter), sort, offset, limit)
	if err != nil {
		return nil, err
	}

	return &plugin.Cursor{
		TypeName: iterator.Table(),
		LeakKey:  iterator.LeakKey(),
		Next: func(ctx context.Context, max int) ([]any, bool, error) {
			items := make([]any, 0, max)
			for len(items) < max {
				entry, ok, err := iterator.Next()
				if err != nil {
					return nil, false, err
				}
				if !ok {
					return items, true, nil
				}
				items = append(items, structFromEntry(iterator.Table(), entry))
			}
			return items, false, nil
		},
		Close: func(ctx context.Context) error {
			return iterator.Close()
		},
	}, nil
}

// entryFromStruct converts a typed entry argument into a store Entry: the
// reserved _-fields map to Entry columns and everything else goes into the
// JSON document.
func entryFromStruct(s *plugin.Struct) (*Entry, error) {
	entry := &Entry{Data: Document{}}
	for name, value := range s.Fields {
		switch name {
		case ID_FIELD:
			id, err := intField(name, value)
			if err != nil {
				return nil, err
			}
			entry.Id = EntryId(id)
		case VERSION_FIELD:
			version, err := intField(name, value)
			if err != nil {
				return nil, err
			}
			entry.Version = version
		case CREATED_BY_FIELD:
			createdBy, err := stringField(name, value)
			if err != nil {
				return nil, err
			}
			entry.CreatedBy = UserId(createdBy)
		case UPDATED_BY_FIELD:
			updatedBy, err := stringField(name, value)
			if err != nil {
				return nil, err
			}
			entry.UpdatedBy = UserId(updatedBy)
		case CREATED_AT_FIELD:
			createdAt, err := intField(name, value)
			if err != nil {
				return nil, err
			}
			entry.CreatedAt = time.UnixMilli(createdAt)
		case UPDATED_AT_FIELD:
			updatedAt, err := intField(name, value)
			if err != nil {
				return nil, err
			}
			entry.UpdatedAt = time.UnixMilli(updatedAt)
		default:
			entry.Data[name] = normalizeValue(value)
		}
	}
	return entry, nil
}

func intField(name string, value any) (int64, error) {
	switch v := value.(type) {
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("error reading %s: expected int, got %T", name, value)
	}
}

func stringField(name string, value any) (string, error) {
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("error reading %s: expected string, got %T", name, value)
	}
	return s, nil
}

// normalizeFilter converts a plugin-decoded filter into the value shapes the
// query parser expects: ints are Go ints, and homogeneous lists specialize to
// []string, []int, or []map[string]any (e.g. for $or/$and conditions).
func normalizeFilter(filter map[string]any) map[string]any {
	if filter == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(filter))
	for k, v := range filter {
		out[k] = normalizeFilterValue(v)
	}
	return out
}

func normalizeFilterValue(value any) any {
	switch v := value.(type) {
	case int64:
		return int(v)
	case map[string]any:
		return normalizeFilter(v)
	case plugin.Tuple:
		return specializeList(normalizeSliceFilter(v))
	case plugin.Set:
		return specializeList(normalizeSliceFilter(v))
	case []any:
		return specializeList(normalizeSliceFilter(v))
	default:
		return value
	}
}

func normalizeSliceFilter(items []any) []any {
	out := make([]any, len(items))
	for i, item := range items {
		out[i] = normalizeFilterValue(item)
	}
	return out
}

// specializeList mirrors the homogeneous-list specialization of the builtin
// plugin's starlark unmarshalling.
func specializeList(items []any) any {
	allInt, allString, allMap := true, true, true
	for _, item := range items {
		switch item.(type) {
		case int:
			allString, allMap = false, false
		case string:
			allInt, allMap = false, false
		case map[string]any:
			allInt, allString = false, false
		default:
			return items
		}
	}
	switch {
	case len(items) == 0:
		return items
	case allInt:
		out := make([]int, len(items))
		for i, item := range items {
			out[i] = item.(int)
		}
		return out
	case allString:
		out := make([]string, len(items))
		for i, item := range items {
			out[i] = item.(string)
		}
		return out
	case allMap:
		out := make([]map[string]any, len(items))
		for i, item := range items {
			out[i] = item.(map[string]any)
		}
		return out
	}
	return items
}

// normalizeValue converts SDK value shapes into plain JSON-compatible values
// for the entry document.
func normalizeValue(value any) any {
	switch v := value.(type) {
	case plugin.Tuple:
		return normalizeSlice(v)
	case plugin.Set:
		return normalizeSlice(v)
	case []any:
		return normalizeSlice(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = normalizeValue(item)
		}
		return out
	case *plugin.Struct:
		out := make(map[string]any, len(v.Fields))
		for k, item := range v.Fields {
			out[k] = normalizeValue(item)
		}
		return out
	default:
		return value
	}
}

func normalizeSlice(items []any) []any {
	out := make([]any, len(items))
	for i, item := range items {
		out[i] = normalizeValue(item)
	}
	return out
}

// structFromEntry converts a store Entry into a typed struct containing the
// reserved fields followed by the document fields.
func structFromEntry(name string, entry *Entry) *plugin.Struct {
	fields := map[string]any{
		ID_FIELD:         int64(entry.Id),
		VERSION_FIELD:    entry.Version,
		CREATED_BY_FIELD: string(entry.CreatedBy),
		UPDATED_BY_FIELD: string(entry.UpdatedBy),
		CREATED_AT_FIELD: entry.CreatedAt.UnixMilli(),
		UPDATED_AT_FIELD: entry.UpdatedAt.UnixMilli(),
	}
	for k, v := range entry.Data {
		fields[k] = v
	}
	return &plugin.Struct{TypeName: name, Fields: fields}
}
