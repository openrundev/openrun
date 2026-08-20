// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

type StoreEntryIterable struct {
	thread *starlark.Thread
	*types.Logger
	modulePath string // module the cursor cleanup entry is registered under
	table      string
	iterator   *EntryIterator
}

func NewStoreEntryIterabe(thread *starlark.Thread, logger *types.Logger, modulePath, table string, iterator *EntryIterator) *StoreEntryIterable {
	return &StoreEntryIterable{
		thread:     thread,
		Logger:     logger,
		modulePath: modulePath,
		table:      table,
		iterator:   iterator,
	}
}

var _ starlark.Iterable = (*StoreEntryIterable)(nil)

func (s *StoreEntryIterable) Iterate() starlark.Iterator {
	return NewStoreEntryIterator(s.thread, s.Logger, s.modulePath, s.table, s.iterator)
}

func (s *StoreEntryIterable) String() string {
	return s.Type()
}

func (s *StoreEntryIterable) Type() string {
	return s.table + " iterator"
}

func (s *StoreEntryIterable) Freeze() {
	// Not supported
}

func (s *StoreEntryIterable) Truth() starlark.Bool {
	return true
}

func (s *StoreEntryIterable) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: %s", s.Type())
}

type StoreEntryIterator struct {
	thread *starlark.Thread
	*types.Logger
	modulePath string
	table      string
	iterator   *EntryIterator
}

var _ starlark.Iterator = (*StoreEntryIterator)(nil)

func NewStoreEntryIterator(thread *starlark.Thread, logger *types.Logger, modulePath, table string, iterator *EntryIterator) *StoreEntryIterator {
	return &StoreEntryIterator{
		thread:     thread,
		Logger:     logger,
		modulePath: modulePath,
		table:      table,
		iterator:   iterator,
	}
}

func (i *StoreEntryIterator) Next(value *starlark.Value) bool {
	entry, ok, err := i.iterator.Next()
	if err != nil {
		// starlark.Iterator.Next cannot return an error; the handler's panic
		// recovery turns it into a request failure
		panic(err)
	}
	if !ok {
		return false
	}

	returnType, err := CreateType(i.table, entry)
	if err != nil {
		panic(err)
	}

	*value = returnType
	return true
}

func (i *StoreEntryIterator) Done() {
	// Clear the deferred cleanup function, since Close is called here. The
	// entry is cleared under its registering module: Done can run while
	// another plugin is the current module
	app.ClearCleanupModule(i.thread, i.modulePath, i.iterator.LeakKey())
	closeErr := i.iterator.Close()
	if closeErr != nil {
		i.Error().Err(fmt.Errorf("error closing rows: %w", closeErr))
	}
}
