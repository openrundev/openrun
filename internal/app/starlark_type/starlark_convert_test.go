// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"testing"
	"time"

	"go.starlark.net/starlark"
)

// convertViaJSON is the original ConvertToStarlark implementation: the
// json.Marshal -> Unmarshal -> MarshalStarlark round-trip. The fast path in
// ConvertToStarlark must produce output identical to this for every input it
// accepts.
func convertViaJSON(p any) (starlark.Value, error) {
	mapVal, err := ConvertToMap(p)
	if err != nil {
		return nil, err
	}
	return MarshalStarlark(mapVal)
}

// starlarkEqual compares two starlark values structurally. Dict key order is not
// significant (both the json round-trip and the fast path iterate Go maps in
// random order), so dicts are compared by key set and per-key values.
func starlarkEqual(t *testing.T, a, b starlark.Value) bool {
	t.Helper()
	switch av := a.(type) {
	case *starlark.Dict:
		bv, ok := b.(*starlark.Dict)
		if !ok || av.Len() != bv.Len() {
			return false
		}
		for _, item := range av.Items() {
			bval, found, err := bv.Get(item[0])
			if err != nil || !found {
				return false
			}
			if !starlarkEqual(t, item[1], bval) {
				return false
			}
		}
		return true
	case *starlark.List:
		bv, ok := b.(*starlark.List)
		if !ok || av.Len() != bv.Len() {
			return false
		}
		for i := 0; i < av.Len(); i++ {
			if !starlarkEqual(t, av.Index(i), bv.Index(i)) {
				return false
			}
		}
		return true
	default:
		// Scalars: compare type and repr
		return a.Type() == b.Type() && a.String() == b.String()
	}
}

// TestConvertToStarlarkEquivalence asserts the fast path and the json round-trip
// yield identical starlark output across json-primitive inputs and the edge
// cases (integers-as-floats, nil collections, empty collections, nested).
func TestConvertToStarlarkEquivalence(t *testing.T) {
	cases := []struct {
		name string
		in   any
	}{
		{"empty_map", map[string]any{}},
		{"flat", map[string]any{"a": "x", "b": 1, "c": true, "d": nil}},
		{"numbers", map[string]any{"i": 42, "i64": int64(9007199254740992), "f": 3.5, "u": uint(7)}},
		{"nested_map", map[string]any{"outer": map[string]any{"inner": 2, "k": "v"}}},
		{"list_any", map[string]any{"tags": []any{"a", 1, true, nil}}},
		{"nested_list_map", map[string]any{"rows": []any{map[string]any{"n": 1}, map[string]any{"n": 2}}}},
		{"map_string_string", map[string]any{"m": map[string]string{"k": "v"}}},
		{"list_string", map[string]any{"s": []string{"a", "b"}}},
		{"list_map", map[string]any{"r": []map[string]any{{"x": 1}, {"y": 2}}}},
		{"nil_slice", map[string]any{"s": []any(nil)}},
		{"nil_map", map[string]any{"m": map[string]any(nil)}},
		{"empty_slice", map[string]any{"s": []any{}}},
		{"special_chars", map[string]any{"s": "<a href=\"x\">& \t\n"}},
		{"unicode", map[string]any{"s": "héllo ✓ 😀"}},
		{"html_chars", map[string]any{"lt": "1 < 2 && 3 > 2"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fast, err := ConvertToStarlark(tc.in)
			if err != nil {
				t.Fatalf("fast path error: %v", err)
			}
			ref, err := convertViaJSON(tc.in)
			if err != nil {
				t.Fatalf("json path error: %v", err)
			}
			if !starlarkEqual(t, fast, ref) {
				t.Fatalf("mismatch:\n fast=%s\n  ref=%s", fast.String(), ref.String())
			}
		})
	}
}

// TestConvertToStarlarkFallback verifies that inputs the fast path cannot handle
// (a struct field, a time.Time value) still convert via the json path and match
// the reference output exactly.
func TestConvertToStarlarkFallback(t *testing.T) {
	type inner struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	cases := []struct {
		name string
		in   any
	}{
		{"struct", inner{Name: "x", Count: 3}},
		{"struct_in_map", map[string]any{"obj": inner{Name: "y", Count: 4}}},
		{"time_value", map[string]any{"ts": time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fast, err := ConvertToStarlark(tc.in)
			if err != nil {
				t.Fatalf("ConvertToStarlark error: %v", err)
			}
			ref, err := convertViaJSON(tc.in)
			if err != nil {
				t.Fatalf("json path error: %v", err)
			}
			if !starlarkEqual(t, fast, ref) {
				t.Fatalf("mismatch:\n fast=%s\n  ref=%s", fast.String(), ref.String())
			}
		})
	}
}

// TestConvertToStarlarkNumbersAreFloats pins the compatibility guarantee that
// integers in a map become starlark floats (json decodes numbers as float64),
// so existing consumers that receive float64 after a round-trip keep working.
func TestConvertToStarlarkNumbersAreFloats(t *testing.T) {
	v, err := ConvertToStarlark(map[string]any{"count": 42})
	if err != nil {
		t.Fatal(err)
	}
	dict := v.(*starlark.Dict)
	got, _, _ := dict.Get(starlark.String("count"))
	if _, ok := got.(starlark.Float); !ok {
		t.Fatalf("expected starlark.Float, got %s (%s)", got.Type(), got.String())
	}
}
