// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

const (
	TRANSACTION_KEY = "transaction"
)

func init() {
	h := &storePlugin{}
	pluginFuncs := []plugin.PluginFunc{
		app.CreatePluginApi(h.Begin, app.READ),
		app.CreatePluginApi(h.Commit, app.WRITE),
		app.CreatePluginApi(h.Rollback, app.READ),

		app.CreatePluginApiName(h.SelectById, app.READ, "select_by_id"),
		app.CreatePluginApi(h.Select, app.READ),
		app.CreatePluginApiName(h.SelectOne, app.READ, "select_one"),
		app.CreatePluginApi(h.Count, app.READ),
		app.CreatePluginApi(h.Insert, app.WRITE),
		app.CreatePluginApi(h.Update, app.WRITE),
		app.CreatePluginApiName(h.DeleteById, app.WRITE, "delete_by_id"),
		app.CreatePluginApi(h.Delete, app.WRITE),
	}
	app.RegisterPlugin("store", NewStorePlugin, pluginFuncs)
}

type storePlugin struct {
	sqlStore *SqlStore
}

func NewStorePlugin(pluginContext *types.PluginContext) (any, error) {
	sqlStore, err := NewSqlStore(pluginContext)

	return &storePlugin{
		sqlStore: sqlStore,
	}, err
}

func fetchTransation(thread *starlark.Thread) *sql.Tx {
	tx := app.FetchPluginState(thread, TRANSACTION_KEY)
	if tx == nil {
		return nil
	}
	return tx.(*sql.Tx)
}

func (s *storePlugin) Begin(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	ctx := app.GetContext(thread)
	tx, err := s.sqlStore.Begin(ctx)
	if err != nil {
		return nil, err
	}
	app.SavePluginState(thread, TRANSACTION_KEY, tx)
	app.DeferCleanup(thread, fmt.Sprintf("transaction_%p", tx), tx.Rollback, false)
	return app.NewResponse(true), nil
}

func (s *storePlugin) Commit(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	ctx := app.GetContext(thread)
	tx := fetchTransation(thread)

	if tx == nil {
		return nil, errors.New("no transaction to commit")
	}

	app.ClearCleanup(thread, fmt.Sprintf("transaction_%p", tx))
	err := s.sqlStore.Commit(ctx, tx)
	if err != nil {
		return nil, err
	}
	return app.NewResponse(true), nil
}

func (s *storePlugin) Rollback(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	ctx := app.GetContext(thread)
	tx := fetchTransation(thread)

	if tx == nil {
		return nil, errors.New("no transaction to rollback")
	}

	app.ClearCleanup(thread, fmt.Sprintf("transaction_%p", tx))
	err := s.sqlStore.Rollback(ctx, tx)
	if err != nil {
		return nil, err
	}
	return app.NewResponse(true), nil
}

func (s *storePlugin) Insert(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var table string
	var entry Entry

	if err := starlark.UnpackArgs("insert", args, kwargs, "table", &table, "entry", &entry); err != nil {
		return nil, err
	}

	id, err := s.sqlStore.Insert(app.GetContext(thread), fetchTransation(thread), table, &entry)
	if err != nil {
		return nil, err
	}
	return app.NewResponse(int64(id)), nil
}

func (s *storePlugin) SelectById(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var table string
	var id starlark.Int

	if err := starlark.UnpackArgs("select_by_id", args, kwargs, "table", &table, "id", &id); err != nil {
		return nil, err
	}

	var idVal int64
	var ok bool
	if idVal, ok = id.Int64(); !ok || idVal < 0 {
		return nil, fmt.Errorf("invalid id value")
	}

	entry, err := s.sqlStore.SelectById(app.GetContext(thread), fetchTransation(thread), table, EntryId(idVal))
	if err != nil {
		return nil, err
	}

	returnType, err := CreateType(table, entry)
	if err != nil {
		return nil, err
	}
	return app.NewResponse(returnType), nil
}

func (s *storePlugin) Update(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var table string
	var entry Entry

	if err := starlark.UnpackArgs("update", args, kwargs, "table", &table, "entry", &entry); err != nil {
		return nil, err
	}

	success, err := s.sqlStore.Update(app.GetContext(thread), fetchTransation(thread), table, &entry)
	if err != nil {
		return nil, err
	}
	return app.NewResponse(success), nil
}

func (s *storePlugin) DeleteById(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var table string
	var id starlark.Int

	if err := starlark.UnpackArgs("delete_by_id", args, kwargs, "table", &table, "id", &id); err != nil {
		return nil, err
	}

	var idVal int64
	var ok bool
	if idVal, ok = id.Int64(); !ok || idVal < 0 {
		return nil, fmt.Errorf("invalid id value")
	}

	rows, err := s.sqlStore.DeleteById(app.GetContext(thread), fetchTransation(thread), table, EntryId(idVal))
	if err != nil {
		return nil, err
	}
	return app.NewResponse(rows), nil
}

func (s *storePlugin) SelectOne(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var table string
	var filter *starlark.Dict

	if err := starlark.UnpackArgs("select", args, kwargs, "table", &table, "filter", &filter); err != nil {
		return nil, err
	}

	if filter == nil {
		filter = starlark.NewDict(0)
	}

	filterUnmarshalled, err := starlark_type.UnmarshalStarlark(filter)
	if err != nil {
		return nil, err
	}

	filterMap, ok := filterUnmarshalled.(map[string]any)
	if !ok {
		return nil, errors.New("invalid filter")
	}

	entry, err := s.sqlStore.SelectOne(app.GetContext(thread), fetchTransation(thread), table, filterMap)
	if err != nil {
		return nil, err
	}

	returnType, err := CreateType(table, entry)
	if err != nil {
		return nil, err
	}

	return app.NewResponse(returnType), nil
}

type filterData struct {
	data map[string]any
}

func (e *filterData) Unpack(value starlark.Value) error {
	v, err := starlark_type.UnmarshalStarlark(value)
	if err != nil {
		return err
	}

	if data, ok := v.(map[string]any); ok {
		e.data = data
		return nil
	} else {
		return fmt.Errorf("invalid filter, expected map[string]any, got %T", v)
	}
}

func (s *storePlugin) Select(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var table string
	var limit, offset starlark.Int
	filter := filterData{data: make(map[string]any)}
	var sort *starlark.List

	if err := starlark.UnpackArgs("select", args, kwargs, "table", &table, "filter", &filter, "sort?", &sort, "offset?", &offset, "limit?", &limit); err != nil {
		return nil, err
	}

	var limitVal, offsetVal int64
	var ok bool
	if limitVal, ok = limit.Int64(); !ok || limitVal < 0 {
		return nil, fmt.Errorf("invalid limit value")
	}
	if offsetVal, ok = offset.Int64(); !ok || offsetVal < 0 {
		return nil, fmt.Errorf("invalid offset value")
	}

	if sort == nil {
		sort = starlark.NewList([]starlark.Value{})
	}

	sortList, err := apptype.GetStringList(sort)
	if err != nil {
		return nil, err
	}

	iterator, err := s.sqlStore.Select(app.GetContext(thread), fetchTransation(thread), thread, table, filter.data, sortList, offsetVal, limitVal)
	if err != nil {
		return nil, err
	}
	return app.NewResponse(iterator), nil
}

func (s *storePlugin) Count(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var table string
	var filter *starlark.Dict

	if err := starlark.UnpackArgs("select", args, kwargs, "table", &table, "filter", &filter); err != nil {
		return nil, err
	}

	if filter == nil {
		filter = starlark.NewDict(0)
	}

	filterUnmarshalled, err := starlark_type.UnmarshalStarlark(filter)
	if err != nil {
		return nil, err
	}

	filterMap, ok := filterUnmarshalled.(map[string]any)
	if !ok {
		return nil, errors.New("invalid filter")
	}

	count, err := s.sqlStore.Count(app.GetContext(thread), fetchTransation(thread), table, filterMap)
	if err != nil {
		return nil, err
	}
	return app.NewResponse(count), nil
}

func (s *storePlugin) Delete(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var table string
	var filter *starlark.Dict

	if err := starlark.UnpackArgs("delete", args, kwargs, "table", &table, "filter", &filter); err != nil {
		return nil, err
	}

	if filter == nil {
		filter = starlark.NewDict(0)
	}

	filterUnmarshalled, err := starlark_type.UnmarshalStarlark(filter)
	if err != nil {
		return nil, err
	}

	filterMap, ok := filterUnmarshalled.(map[string]any)
	if !ok {
		return nil, errors.New("invalid filter")
	}

	rows, err := s.sqlStore.Delete(app.GetContext(thread), fetchTransation(thread), table, filterMap)
	if err != nil {
		return nil, err
	}
	return app.NewResponse(rows), nil
}
