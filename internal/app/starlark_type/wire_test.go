// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"math/big"
	"testing"
	"time"

	startime "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
)

func starRoundTrip(t *testing.T, v starlark.Value) starlark.Value {
	t.Helper()
	enc, err := ToWire(v, 0)
	if err != nil {
		t.Fatalf("encode %s: %v", v, err)
	}
	dec, err := FromWire(enc, nil, nil, 0)
	if err != nil {
		t.Fatalf("decode %s: %v", v, err)
	}
	return dec
}

func assertStarEqual(t *testing.T, got, want starlark.Value) {
	t.Helper()
	eq, err := starlark.EqualDepth(got, want, 20)
	if err != nil {
		t.Fatalf("comparing %s and %s: %v", got, want, err)
	}
	if !eq {
		t.Errorf("got %s (%s), want %s (%s)", got, got.Type(), want, want.Type())
	}
}

func TestStarValueRoundTrip(t *testing.T) {
	dict := starlark.NewDict(2)
	_ = dict.SetKey(starlark.String("b"), starlark.MakeInt(2))
	_ = dict.SetKey(starlark.String("a"), starlark.MakeInt(1))

	set := starlark.NewSet(2)
	_ = set.Insert(starlark.MakeInt(1))
	_ = set.Insert(starlark.String("x"))

	values := []starlark.Value{
		starlark.None,
		starlark.True,
		starlark.MakeInt(42),
		starlark.MakeInt64(-1 << 62),
		starlark.Float(3.25),
		starlark.String("hello"),
		starlark.Bytes([]byte{0, 1, 2}),
		starlark.NewList([]starlark.Value{starlark.MakeInt(1), starlark.String("a")}),
		starlark.Tuple{starlark.MakeInt(1), starlark.None},
		set,
		dict,
	}
	for _, v := range values {
		got := starRoundTrip(t, v)
		assertStarEqual(t, got, v)
		if got.Type() != v.Type() {
			t.Errorf("type changed: got %s, want %s", got.Type(), v.Type())
		}
	}
}

func TestStarValueBigInt(t *testing.T) {
	big1, _ := new(big.Int).SetString("-987654321098765432109876543210", 10)
	v := starlark.MakeBigInt(big1)
	got := starRoundTrip(t, v)
	assertStarEqual(t, got, v)
}

func TestStarValueIntFloatDistinct(t *testing.T) {
	gotInt := starRoundTrip(t, starlark.MakeInt(100))
	if _, ok := gotInt.(starlark.Int); !ok {
		t.Errorf("int became %s", gotInt.Type())
	}
	gotFloat := starRoundTrip(t, starlark.Float(100))
	if _, ok := gotFloat.(starlark.Float); !ok {
		t.Errorf("float became %s", gotFloat.Type())
	}
}

func TestStarValueDictOrder(t *testing.T) {
	dict := starlark.NewDict(3)
	for _, k := range []string{"zebra", "apple", "mango"} {
		_ = dict.SetKey(starlark.String(k), starlark.MakeInt(1))
	}
	got := starRoundTrip(t, dict).(*starlark.Dict)
	gotKeys := got.Keys()
	wantKeys := dict.Keys()
	for i := range wantKeys {
		if gotKeys[i] != wantKeys[i] {
			t.Fatalf("dict order changed: got %v, want %v", gotKeys, wantKeys)
		}
	}
}

func TestStarValueTime(t *testing.T) {
	now := time.Now().UTC()
	got := starRoundTrip(t, startime.Time(now))
	gotTime, ok := got.(startime.Time)
	if !ok {
		t.Fatalf("expected time, got %s", got.Type())
	}
	if !time.Time(gotTime).Equal(now) {
		t.Errorf("got %s, want %s", time.Time(gotTime), now)
	}
}

func TestStarValueTypedStruct(t *testing.T) {
	typed := NewStarlarkType("test1", map[string]starlark.Value{
		"_id":     starlark.MakeInt(7),
		"aint":    starlark.MakeInt(10),
		"astring": starlark.String("abc"),
		"adict":   starlark.NewDict(0),
	})
	got := starRoundTrip(t, typed)
	gotTyped, ok := got.(*StarlarkType)
	if !ok {
		t.Fatalf("expected StarlarkType, got %s", got.Type())
	}
	if gotTyped.Type() != "test1" {
		t.Errorf("type name: got %s, want test1", gotTyped.Type())
	}
	for _, attr := range []string{"_id", "aint", "astring", "adict"} {
		wantVal, _ := typed.Attr(attr)
		gotVal, err := gotTyped.Attr(attr)
		if err != nil {
			t.Fatalf("attr %s: %v", attr, err)
		}
		assertStarEqual(t, gotVal, wantVal)
	}
	// StarlarkType round trips as mutable: SetField must work
	if err := gotTyped.SetField("aint", starlark.MakeInt(100)); err != nil {
		t.Errorf("SetField failed: %v", err)
	}
}

func TestStarValueCycleDetection(t *testing.T) {
	list := starlark.NewList([]starlark.Value{})
	_ = list.Append(list) // cyclic
	if _, err := ToWire(list, 0); err == nil {
		t.Error("expected error for cyclic list")
	}
}

func TestStarValueUnsupported(t *testing.T) {
	fn := starlark.NewBuiltin("f", func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.None, nil
	})
	if _, err := ToWire(fn, 0); err == nil {
		t.Error("expected error for builtin function")
	}
}
