// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/app/starlark_type"
)

func TestGenTableName(t *testing.T) {
	s := &SqlStore{
		prefix: "prefix",
	}

	table := "table"
	expected := `"prefix_table"`

	result, err := s.genTableName(table)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

func TestValidateTableName(t *testing.T) {
	validNames := []string{
		"table",
		"Table1",
		"_table",
		"a_b_c_123",
	}
	for _, name := range validNames {
		t.Run("valid_"+name, func(t *testing.T) {
			if err := validateTableName(name); err != nil {
				t.Fatalf("expected %q to be valid, got %v", name, err)
			}
		})
	}

	invalidNames := []struct {
		name        string
		errContains string
	}{
		{name: "", errContains: "cannot be empty"},
		{name: "1table", errContains: "must start"},
		{name: "table-name", errContains: "can only contain"},
		{name: "table.name", errContains: "can only contain"},
		{name: "table name", errContains: "can only contain"},
		{name: "table\"name", errContains: "can only contain"},
		{name: "table;name", errContains: "can only contain"},
		{name: "table\nname", errContains: "can only contain"},
		{name: "tábla", errContains: "can only contain"},
		{name: "cl_schema", errContains: "reserved"},
		{name: "CL_SCHEMA", errContains: "reserved"},
		{name: strings.Repeat("a", MAX_TABLE_NAME_LEN+1), errContains: "exceeds max length"},
	}
	for _, tt := range invalidNames {
		t.Run("invalid_"+tt.errContains, func(t *testing.T) {
			err := validateTableName(tt.name)
			if err == nil {
				t.Fatalf("expected %q to be invalid", tt.name)
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got %v", tt.errContains, err)
			}
		})
	}
}

func TestGenSortString(t *testing.T) {
	sort := []string{"field1:asc", "field2:DEsc", "_id"}
	expected := "_json ->> 'field1' ASC, _json ->> 'field2' DESC, _id ASC"

	result, err := genSortString(sort, sqliteFieldMapper)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}

	result, err = genSortString(sort, nil) // no field name mapping
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result != "field1 ASC, field2 DESC, _id ASC" {
		t.Errorf("Expected %s, but got %s", expected, result)
	}

	result, err = genSortString(sort, postgresSortFieldMapper)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	expectedPostgres := "(_json::jsonb -> 'field1') ASC, (_json::jsonb -> 'field2') DESC, _id ASC"
	if result != expectedPostgres {
		t.Errorf("Expected %s, but got %s", expectedPostgres, result)
	}
}

// test for createIndexStmt
func TestCreateIndexStmt(t *testing.T) {
	table := "prefix_table"
	quoteIdentifier := func(identifier string) string {
		return `"` + identifier + `"`
	}
	index := starlark_type.Index{
		Fields: []string{"field:asc", "_id:desc"},
		Unique: false,
	}

	result, err := createIndexStmt(table, index, sqliteFieldMapper, quoteIdentifier)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expected := `CREATE INDEX IF NOT EXISTS "index_prefix_table_field_ASC__id_DESC" ON "prefix_table" (_json ->> 'field' ASC, _id DESC)`
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}

	index = starlark_type.Index{
		Fields: []string{"map.key", "_id:desc"},
		Unique: true,
	}
	result, err = createIndexStmt(table, index, sqliteFieldMapper, quoteIdentifier)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expected = `CREATE UNIQUE INDEX IF NOT EXISTS "index_prefix_table_map.key_ASC__id_DESC" ON "prefix_table" (_json ->> 'map.key' ASC, _id DESC)`
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}
