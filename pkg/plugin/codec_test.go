// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"math/big"
	"reflect"
	"testing"
	"time"
)

func roundTrip(t *testing.T, v any) any {
	t.Helper()
	enc, err := EncodeValue(v)
	if err != nil {
		t.Fatalf("encode %#v: %v", v, err)
	}
	dec, err := DecodeValue(enc)
	if err != nil {
		t.Fatalf("decode %#v: %v", v, err)
	}
	return dec
}

func TestCodecRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want any
	}{
		{"nil", nil, nil},
		{"true", true, true},
		{"int", int64(42), int64(42)},
		{"int negative", int64(-7), int64(-7)},
		{"int from int", 7, int64(7)},
		{"float", 3.5, 3.5},
		{"float stays float", 100.0, 100.0},
		{"string", "hello", "hello"},
		{"bytes", []byte{1, 2, 3}, []byte{1, 2, 3}},
		{"list", []any{int64(1), "a", true}, []any{int64(1), "a", true}},
		{"string slice", []string{"a", "b"}, []any{"a", "b"}},
		{"tuple", Tuple{int64(1), "x"}, Tuple{int64(1), "x"}},
		{"set", Set{int64(1), int64(2)}, Set{int64(1), int64(2)}},
		{"map", map[string]any{"a": int64(1), "b": []any{"x"}},
			map[string]any{"a": int64(1), "b": []any{"x"}}},
		{"nested", map[string]any{"outer": map[string]any{"inner": []any{int64(1), 2.5}}},
			map[string]any{"outer": map[string]any{"inner": []any{int64(1), 2.5}}}},
		{"struct", &Struct{TypeName: "test1", Fields: map[string]any{"aint": int64(10), "astring": "abc"}},
			&Struct{TypeName: "test1", Fields: map[string]any{"aint": int64(10), "astring": "abc"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := roundTrip(t, tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("round trip: got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestCodecBigInt(t *testing.T) {
	big1, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	got := roundTrip(t, big1)
	gotBig, ok := got.(*big.Int)
	if !ok {
		t.Fatalf("expected *big.Int, got %T", got)
	}
	if gotBig.Cmp(big1) != 0 {
		t.Errorf("got %s, want %s", gotBig, big1)
	}

	neg := new(big.Int).Neg(big1)
	got = roundTrip(t, neg)
	if got.(*big.Int).Cmp(neg) != 0 {
		t.Errorf("got %s, want %s", got, neg)
	}

	// int64-representable big ints normalize to int64
	small := big.NewInt(1234)
	if got := roundTrip(t, small); got != int64(1234) {
		t.Errorf("small big.Int: got %#v, want int64", got)
	}
}

func TestCodecTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	got := roundTrip(t, now)
	gotTime, ok := got.(time.Time)
	if !ok {
		t.Fatalf("expected time.Time, got %T", got)
	}
	if !gotTime.Equal(now) {
		t.Errorf("got %s, want %s", gotTime, now)
	}
}

func TestCodecIntFloatDistinct(t *testing.T) {
	// int64 and float64 must not be conflated on the wire
	if got := roundTrip(t, int64(100)); got != int64(100) {
		t.Errorf("int: got %#v", got)
	}
	if got := roundTrip(t, float64(100)); got != float64(100) {
		t.Errorf("float: got %#v", got)
	}
}

func TestCodecDictOrder(t *testing.T) {
	d := &Dict{Entries: []DictEntry{
		{Key: int64(3), Value: "c"},
		{Key: int64(1), Value: "a"},
		{Key: int64(2), Value: "b"},
	}}
	got := roundTrip(t, d)
	gotDict, ok := got.(*Dict)
	if !ok {
		t.Fatalf("expected *Dict, got %T", got)
	}
	if !reflect.DeepEqual(gotDict.Entries, d.Entries) {
		t.Errorf("got %#v, want %#v", gotDict.Entries, d.Entries)
	}
}

func TestCodecCycleDetection(t *testing.T) {
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	if _, err := EncodeValue(cyclic); err == nil {
		t.Error("expected error for cyclic value")
	}
}

func TestCodecUnsupported(t *testing.T) {
	if _, err := EncodeValue(make(chan int)); err == nil {
		t.Error("expected error for chan")
	}
	if _, err := EncodeValue(&Cursor{}); err == nil {
		t.Error("expected error for nested cursor")
	}
}

func TestUnpackArgs(t *testing.T) {
	call := &Call{
		Args:   []any{"mytable"},
		Kwargs: []Kwarg{{Name: "filter", Value: map[string]any{"a": int64(1)}}},
	}
	var table string
	var filter map[string]any
	var sort []string
	if err := UnpackArgs("select", call, "table", &table, "filter", &filter, "sort?", &sort); err != nil {
		t.Fatal(err)
	}
	if table != "mytable" || filter["a"] != int64(1) || sort != nil {
		t.Errorf("got table=%q filter=%#v sort=%#v", table, filter, sort)
	}

	// missing required arg
	if err := UnpackArgs("select", &Call{}, "table", &table); err == nil {
		t.Error("expected missing argument error")
	}

	// duplicate assignment
	dup := &Call{Args: []any{"t1"}, Kwargs: []Kwarg{{Name: "table", Value: "t2"}}}
	if err := UnpackArgs("select", dup, "table", &table); err == nil {
		t.Error("expected duplicate parameter error")
	}

	// unexpected kwarg
	unk := &Call{Kwargs: []Kwarg{{Name: "bogus", Value: "x"}}}
	if err := UnpackArgs("select", unk, "table?", &table); err == nil {
		t.Error("expected unexpected keyword error")
	}
}
