// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"math/big"
	"reflect"
	"testing"
	"time"

	sdk "github.com/openrundev/openrun/pkg/plugin"
	startime "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// starCorpus builds starlark values covering every type the bridge accepts.
func starCorpus(t testing.TB) map[string]starlark.Value {
	t.Helper()
	dict := starlark.NewDict(2)
	if err := dict.SetKey(starlark.String("a"), starlark.MakeInt(1)); err != nil {
		t.Fatal(err)
	}
	if err := dict.SetKey(starlark.String("b"), starlark.String("two")); err != nil {
		t.Fatal(err)
	}

	mixedDict := starlark.NewDict(2)
	if err := mixedDict.SetKey(starlark.MakeInt(1), starlark.String("one")); err != nil {
		t.Fatal(err)
	}
	if err := mixedDict.SetKey(starlark.String("k"), starlark.MakeInt(2)); err != nil {
		t.Fatal(err)
	}

	set := starlark.NewSet(2)
	if err := set.Insert(starlark.String("x")); err != nil {
		t.Fatal(err)
	}
	if err := set.Insert(starlark.MakeInt(7)); err != nil {
		t.Fatal(err)
	}

	nested := starlark.NewDict(1)
	inner := starlark.NewList([]starlark.Value{starlark.MakeInt(1), dict})
	if err := nested.SetKey(starlark.String("items"), inner); err != nil {
		t.Fatal(err)
	}

	bigVal, _ := new(big.Int).SetString("123456789012345678901234567890", 10)

	return map[string]starlark.Value{
		"none":       starlark.None,
		"true":       starlark.Bool(true),
		"int":        starlark.MakeInt(42),
		"negint":     starlark.MakeInt(-42),
		"bigint":     starlark.MakeBigInt(bigVal),
		"negbigint":  starlark.MakeBigInt(new(big.Int).Neg(bigVal)),
		"float":      starlark.Float(3.25),
		"string":     starlark.String("hello"),
		"bytes":      starlark.Bytes("\x00\x01binary"),
		"time":       startime.Time(time.Date(2026, 8, 19, 10, 30, 0, 123456789, time.UTC)),
		"list":       starlark.NewList([]starlark.Value{starlark.MakeInt(1), starlark.String("a"), starlark.Float(2.5)}),
		"empty_list": starlark.NewList(nil),
		"tuple":      starlark.Tuple{starlark.MakeInt(1), starlark.String("a")},
		"set":        set,
		"dict":       dict,
		"mixed_dict": mixedDict,
		"nested":     nested,
		"struct": starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
			"name": starlark.String("first"),
			"val":  starlark.MakeInt(10),
		}),
	}
}

// TestStarToGoMatchesWire verifies the direct bridge's starlark->Go
// conversion is exactly equivalent to the wire path (ToWire followed by
// DecodeValue), which external providers use.
func TestStarToGoMatchesWire(t *testing.T) {
	for name, v := range starCorpus(t) {
		t.Run(name, func(t *testing.T) {
			direct, err := ToPlugin(v, 0)
			if err != nil {
				t.Fatalf("direct: %v", err)
			}
			wire, err := ToWire(v, 0)
			if err != nil {
				t.Fatalf("wire encode: %v", err)
			}
			viaWire, err := sdk.DecodeValue(wire)
			if err != nil {
				t.Fatalf("wire decode: %v", err)
			}
			if !reflect.DeepEqual(direct, viaWire) {
				t.Fatalf("mismatch:\n direct:  %#v\n viaWire: %#v", direct, viaWire)
			}
		})
	}
}

// goCorpus builds SDK Go values covering every return shape EncodeValue
// accepts (except cursors and thunks, which are handled at dispatch level).
func goCorpus() map[string]any {
	bigVal, _ := new(big.Int).SetString("987654321098765432109876543210", 10)
	return map[string]any{
		"nil":       nil,
		"bool":      true,
		"int":       int(7),
		"int64":     int64(-9),
		"uint64big": uint64(1) << 63,
		"bigint":    bigVal,
		"float32":   float32(1.5),
		"float64":   float64(2.75),
		"string":    "hello",
		"bytes":     []byte{0, 1, 2},
		"time":      time.Date(2026, 8, 19, 10, 30, 0, 123456789, time.UTC),
		"tuple":     sdk.Tuple{int64(1), "a"},
		"set":       sdk.Set{"x", int64(7)},
		"dict": &sdk.Dict{Entries: []sdk.DictEntry{
			{Key: int64(1), Value: "one"},
			{Key: "k", Value: int64(2)},
		}},
		"struct": &sdk.Struct{TypeName: "mytype", Fields: map[string]any{
			"name": "first", "val": int64(10),
		}},
		"slice_any":    []any{int64(1), "a", 2.5},
		"slice_string": []string{"a", "b"},
		"slice_int":    []int{1, 2},
		"slice_int64":  []int64{3, 4},
		"slice_maps":   []map[string]any{{"a": int64(1)}},
		"map":          map[string]any{"only": int64(5)},
		"map_ss":       map[string]string{"only": "v"},
		"nested": map[string]any{
			"rows": []map[string]any{{"n": "x", "v": int64(1)}},
		},
		"nil_bigint":   (*big.Int)(nil),
		"nil_dict":     (*sdk.Dict)(nil),
		"nil_struct":   (*sdk.Struct)(nil),
		"nil_thunk":    (*sdk.Thunk)(nil),
		"nil_funcref":  (*sdk.FuncRef)(nil),
		"nil_download": (*sdk.Download)(nil),
		"nil_cursor":   (*sdk.Cursor)(nil),
	}
}

// TestGoToStarMatchesWire verifies the direct bridge's Go->starlark
// conversion is exactly equivalent to the wire path (EncodeValue followed by
// FromWire). Equality is checked by round-tripping both results through
// the already-validated starlark->Go direction and comparing types.
func TestGoToStarMatchesWire(t *testing.T) {
	for name, v := range goCorpus() {
		t.Run(name, func(t *testing.T) {
			direct, err := FromPlugin(v, 0, nil)
			if err != nil {
				t.Fatalf("direct: %v", err)
			}
			wire, err := sdk.EncodeValue(v)
			if err != nil {
				t.Fatalf("wire encode: %v", err)
			}
			viaWire, err := FromWire(wire, nil, nil, 0)
			if err != nil {
				t.Fatalf("wire decode: %v", err)
			}
			if direct.Type() != viaWire.Type() {
				t.Fatalf("type mismatch: direct %s, viaWire %s", direct.Type(), viaWire.Type())
			}
			directGo, err := ToPlugin(direct, 0)
			if err != nil {
				t.Fatalf("direct roundtrip: %v", err)
			}
			wireGo, err := ToPlugin(viaWire, 0)
			if err != nil {
				t.Fatalf("wire roundtrip: %v", err)
			}
			if !reflect.DeepEqual(directGo, wireGo) {
				t.Fatalf("mismatch:\n direct:  %#v\n viaWire: %#v", directGo, wireGo)
			}
		})
	}
}

// TestThunkMaterialization verifies both bridge and wire paths materialize a
// Thunk as a callable returning its value, and an error thunk as a callable
// that fails.
func TestThunkMaterialization(t *testing.T) {
	thread := &starlark.Thread{Name: "test"}
	thunk := &sdk.Thunk{Name: "body", Value: "the body"}

	for _, tc := range []struct {
		name        string
		materialize func() (starlark.Value, error)
	}{
		{"direct", func() (starlark.Value, error) { return FromPlugin(thunk, 0, nil) }},
		{"wire", func() (starlark.Value, error) {
			enc, err := sdk.EncodeValue(thunk)
			if err != nil {
				return nil, err
			}
			return FromWire(enc, nil, nil, 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := tc.materialize()
			if err != nil {
				t.Fatal(err)
			}
			fn, ok := v.(starlark.Callable)
			if !ok {
				t.Fatalf("expected callable, got %s", v.Type())
			}
			result, err := starlark.Call(thread, fn, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if result != starlark.String("the body") {
				t.Fatalf("unexpected thunk result: %v", result)
			}
		})
	}

	errThunk := &sdk.Thunk{Name: "json", Error: "invalid json"}
	v, err := FromPlugin(errThunk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := starlark.Call(thread, v.(starlark.Callable), nil, nil); err == nil || err.Error() != "invalid json" {
		t.Fatalf("expected thunk error, got %v", err)
	}
}
