// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"testing"

	"go.starlark.net/starlark"
)

// appRecord mirrors a typical plugin result row (e.g. one entry from
// list_apps): a mix of strings, ints, bools and a nested list/map.
func appRecordMap(i int) map[string]any {
	return map[string]any{
		"id":       "app_prd_00000000000000000000",
		"name":     "my application",
		"path":     "/apps/example",
		"version":  i,
		"active":   true,
		"star_url": "github.com/example/repo",
		"tags":     []any{"web", "prod", "team-a"},
		"meta": map[string]any{
			"spec":   "proxy",
			"branch": "main",
		},
	}
}

// buildStarlarkDict marshals a Go value into a starlark value the way a plugin
// result crosses into starlark, so the unmarshal benchmark starts from a real
// starlark tree.
func buildStarlarkDict(tb testing.TB, v any) starlark.Value {
	tb.Helper()
	sv, err := MarshalStarlark(v)
	if err != nil {
		tb.Fatalf("marshal: %v", err)
	}
	return sv
}

// BenchmarkUnmarshalStarlarkDict measures the starlark->Go direction (data in),
// the path taken for every handler dict return value and plugin dict argument.
func BenchmarkUnmarshalStarlarkDict(b *testing.B) {
	dict := buildStarlarkDict(b, appRecordMap(3))

	b.ReportAllocs()
	for b.Loop() {
		if _, err := UnmarshalStarlark(dict); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUnmarshalStarlarkList measures a list of records (e.g. list_apps
// returning many rows) crossing back to Go.
func BenchmarkUnmarshalStarlarkList(b *testing.B) {
	elems := make([]starlark.Value, 50)
	for i := range elems {
		elems[i] = buildStarlarkDict(b, appRecordMap(i))
	}
	list := starlark.NewList(elems)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := UnmarshalStarlark(list); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConvertToStarlark measures the Go->starlark direction (data out) as
// plugins use it: build a starlark value from a Go map result.
func BenchmarkConvertToStarlark(b *testing.B) {
	rec := appRecordMap(3)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := ConvertToStarlark(rec); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMarshalStarlarkDict measures the direct marshal (no json round-trip)
// for comparison with ConvertToStarlark.
func BenchmarkMarshalStarlarkDict(b *testing.B) {
	rec := appRecordMap(3)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := MarshalStarlark(rec); err != nil {
			b.Fatal(err)
		}
	}
}
