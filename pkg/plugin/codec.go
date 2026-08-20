// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"fmt"
	"math"
	"math/big"
	"time"

	pb "github.com/openrundev/openrun/pkg/plugin/proto"
)

// MaxValueDepth bounds StarValue nesting. Starlark collections are mutable
// and can be made cyclic; the encoder fails cleanly instead of recursing
// forever.
const MaxValueDepth = 100

// EncodeValue converts a Go value into its wire representation. It accepts
// the value shapes plugin functions return: nil, bool, all int/uint widths,
// *big.Int, float32/64, string, []byte, time.Time, Tuple, Set, *Dict/Dict,
// *Struct/Struct, []any (and common typed slices), and map[string]any (and
// common typed maps). Cursors are not encoded here; the provider serve loop
// registers them and encodes a cursor handle.
func EncodeValue(v any) (*pb.StarValue, error) {
	return encodeValue(v, 0)
}

func encodeValue(v any, depth int) (*pb.StarValue, error) {
	if depth > MaxValueDepth {
		return nil, fmt.Errorf("value nesting exceeds max depth %d (cyclic value?)", MaxValueDepth)
	}
	depth++

	switch x := v.(type) {
	case nil:
		return &pb.StarValue{Kind: &pb.StarValue_None{None: true}}, nil
	case bool:
		return &pb.StarValue{Kind: &pb.StarValue_Bool{Bool: x}}, nil
	case int:
		return encodeInt64(int64(x)), nil
	case int8:
		return encodeInt64(int64(x)), nil
	case int16:
		return encodeInt64(int64(x)), nil
	case int32:
		return encodeInt64(int64(x)), nil
	case int64:
		return encodeInt64(x), nil
	case uint:
		return encodeUint64(uint64(x)), nil
	case uint8:
		return encodeUint64(uint64(x)), nil
	case uint16:
		return encodeUint64(uint64(x)), nil
	case uint32:
		return encodeUint64(uint64(x)), nil
	case uint64:
		return encodeUint64(x), nil
	case *big.Int:
		if x.IsInt64() {
			return encodeInt64(x.Int64()), nil
		}
		return &pb.StarValue{Kind: &pb.StarValue_Bigint{Bigint: &pb.BigInt{
			Negative: x.Sign() < 0,
			Abs:      x.Bytes(),
		}}}, nil
	case float32:
		return &pb.StarValue{Kind: &pb.StarValue_Float{Float: float64(x)}}, nil
	case float64:
		return &pb.StarValue{Kind: &pb.StarValue_Float{Float: x}}, nil
	case string:
		return &pb.StarValue{Kind: &pb.StarValue_Str{Str: x}}, nil
	case []byte:
		return &pb.StarValue{Kind: &pb.StarValue_Bytes{Bytes: x}}, nil
	case time.Time:
		return &pb.StarValue{Kind: &pb.StarValue_TimeUnixNanos{TimeUnixNanos: x.UnixNano()}}, nil
	case Tuple:
		list, err := encodeSlice(x, depth)
		if err != nil {
			return nil, err
		}
		return &pb.StarValue{Kind: &pb.StarValue_Tuple{Tuple: list}}, nil
	case Set:
		list, err := encodeSlice(x, depth)
		if err != nil {
			return nil, err
		}
		return &pb.StarValue{Kind: &pb.StarValue_Set{Set: list}}, nil
	case Dict:
		return encodeDictEntries(x.Entries, depth)
	case *Dict:
		return encodeDictEntries(x.Entries, depth)
	case Struct:
		return encodeStruct(&x, depth)
	case *Struct:
		return encodeStruct(x, depth)
	case []any:
		list, err := encodeSlice(x, depth)
		if err != nil {
			return nil, err
		}
		return &pb.StarValue{Kind: &pb.StarValue_List{List: list}}, nil
	case []string:
		values := make([]*pb.StarValue, len(x))
		for i, s := range x {
			values[i] = &pb.StarValue{Kind: &pb.StarValue_Str{Str: s}}
		}
		return &pb.StarValue{Kind: &pb.StarValue_List{List: &pb.ValueList{Values: values}}}, nil
	case []int:
		values := make([]*pb.StarValue, len(x))
		for i, n := range x {
			values[i] = encodeInt64(int64(n))
		}
		return &pb.StarValue{Kind: &pb.StarValue_List{List: &pb.ValueList{Values: values}}}, nil
	case []int64:
		values := make([]*pb.StarValue, len(x))
		for i, n := range x {
			values[i] = encodeInt64(n)
		}
		return &pb.StarValue{Kind: &pb.StarValue_List{List: &pb.ValueList{Values: values}}}, nil
	case []map[string]any:
		anySlice := make([]any, len(x))
		for i, m := range x {
			anySlice[i] = m
		}
		list, err := encodeSlice(anySlice, depth)
		if err != nil {
			return nil, err
		}
		return &pb.StarValue{Kind: &pb.StarValue_List{List: list}}, nil
	case map[string]any:
		return encodeStringMap(x, depth)
	case map[string]string:
		anyMap := make(map[string]any, len(x))
		for k, val := range x {
			anyMap[k] = val
		}
		return encodeStringMap(anyMap, depth)
	case map[any]any:
		entries := make([]*pb.StarEntry, 0, len(x))
		for k, val := range x {
			ke, err := encodeValue(k, depth)
			if err != nil {
				return nil, err
			}
			ve, err := encodeValue(val, depth)
			if err != nil {
				return nil, err
			}
			entries = append(entries, &pb.StarEntry{Key: ke, Value: ve})
		}
		return &pb.StarValue{Kind: &pb.StarValue_Dict{Dict: &pb.StarDict{Entries: entries}}}, nil
	case Thunk:
		return encodeThunk(&x, depth)
	case *Thunk:
		return encodeThunk(x, depth)
	case FuncRef:
		return encodeFuncRef(&x, depth)
	case *FuncRef:
		return encodeFuncRef(x, depth)
	case *Cursor:
		return nil, fmt.Errorf("a Cursor can only be the top-level return value of a plugin function")
	default:
		return nil, fmt.Errorf("cannot encode value of type %T for plugin transport", v)
	}
}

func encodeFuncRef(x *FuncRef, depth int) (*pb.StarValue, error) {
	args := make([]*pb.StarValue, len(x.Args))
	for i, arg := range x.Args {
		enc, err := encodeValue(arg, depth)
		if err != nil {
			return nil, err
		}
		args[i] = enc
	}
	return &pb.StarValue{Kind: &pb.StarValue_Funcref{Funcref: &pb.FuncRef{
		Function: x.Function,
		Args:     args,
	}}}, nil
}

func encodeThunk(x *Thunk, depth int) (*pb.StarValue, error) {
	thunk := &pb.Thunk{Name: x.Name, Error: x.Error}
	if x.Error == "" {
		value, err := encodeValue(x.Value, depth)
		if err != nil {
			return nil, err
		}
		thunk.Value = value
	}
	return &pb.StarValue{Kind: &pb.StarValue_Thunk{Thunk: thunk}}, nil
}

func encodeInt64(x int64) *pb.StarValue {
	return &pb.StarValue{Kind: &pb.StarValue_Int{Int: x}}
}

func encodeUint64(x uint64) *pb.StarValue {
	if x <= math.MaxInt64 {
		return encodeInt64(int64(x))
	}
	return &pb.StarValue{Kind: &pb.StarValue_Bigint{Bigint: &pb.BigInt{
		Abs: new(big.Int).SetUint64(x).Bytes(),
	}}}
}

func encodeSlice(x []any, depth int) (*pb.ValueList, error) {
	values := make([]*pb.StarValue, len(x))
	for i, item := range x {
		enc, err := encodeValue(item, depth)
		if err != nil {
			return nil, err
		}
		values[i] = enc
	}
	return &pb.ValueList{Values: values}, nil
}

func encodeStringMap(x map[string]any, depth int) (*pb.StarValue, error) {
	entries := make([]*pb.StarEntry, 0, len(x))
	for k, val := range x {
		ve, err := encodeValue(val, depth)
		if err != nil {
			return nil, err
		}
		entries = append(entries, &pb.StarEntry{
			Key:   &pb.StarValue{Kind: &pb.StarValue_Str{Str: k}},
			Value: ve,
		})
	}
	return &pb.StarValue{Kind: &pb.StarValue_Dict{Dict: &pb.StarDict{Entries: entries}}}, nil
}

func encodeStruct(x *Struct, depth int) (*pb.StarValue, error) {
	fields := make([]*pb.StarEntry, 0, len(x.Fields))
	for k, val := range x.Fields {
		ve, err := encodeValue(val, depth)
		if err != nil {
			return nil, err
		}
		fields = append(fields, &pb.StarEntry{
			Key:   &pb.StarValue{Kind: &pb.StarValue_Str{Str: k}},
			Value: ve,
		})
	}
	return &pb.StarValue{Kind: &pb.StarValue_Struct{Struct: &pb.TypedStruct{
		TypeName: x.TypeName,
		Fields:   &pb.StarDict{Entries: fields},
	}}}, nil
}

// DecodeValue converts a wire value into its Go representation: nil, bool,
// int64, *big.Int, float64, string, []byte, []any, Tuple, Set,
// map[string]any (string-keyed dicts) or *Dict, *Struct, and time.Time.
func DecodeValue(v *pb.StarValue) (any, error) {
	return decodeValue(v, 0)
}

func decodeValue(v *pb.StarValue, depth int) (any, error) {
	if depth > MaxValueDepth {
		return nil, fmt.Errorf("value nesting exceeds max depth %d", MaxValueDepth)
	}
	depth++

	if v == nil {
		return nil, nil
	}
	switch kind := v.Kind.(type) {
	case *pb.StarValue_None:
		return nil, nil
	case *pb.StarValue_Bool:
		return kind.Bool, nil
	case *pb.StarValue_Int:
		return kind.Int, nil
	case *pb.StarValue_Bigint:
		b := new(big.Int).SetBytes(kind.Bigint.GetAbs())
		if kind.Bigint.GetNegative() {
			b.Neg(b)
		}
		return b, nil
	case *pb.StarValue_Float:
		return kind.Float, nil
	case *pb.StarValue_Str:
		return kind.Str, nil
	case *pb.StarValue_Bytes:
		return kind.Bytes, nil
	case *pb.StarValue_TimeUnixNanos:
		return time.Unix(0, kind.TimeUnixNanos).UTC(), nil
	case *pb.StarValue_List:
		return decodeSlice(kind.List, depth)
	case *pb.StarValue_Tuple:
		items, err := decodeSlice(kind.Tuple, depth)
		if err != nil {
			return nil, err
		}
		return Tuple(items), nil
	case *pb.StarValue_Set:
		items, err := decodeSlice(kind.Set, depth)
		if err != nil {
			return nil, err
		}
		return Set(items), nil
	case *pb.StarValue_Dict:
		return decodeDict(kind.Dict, depth)
	case *pb.StarValue_Struct:
		fields := make(map[string]any, len(kind.Struct.GetFields().GetEntries()))
		for _, entry := range kind.Struct.GetFields().GetEntries() {
			key, ok := entry.GetKey().GetKind().(*pb.StarValue_Str)
			if !ok {
				return nil, fmt.Errorf("struct field key must be a string")
			}
			val, err := decodeValue(entry.GetValue(), depth)
			if err != nil {
				return nil, err
			}
			fields[key.Str] = val
		}
		return &Struct{TypeName: kind.Struct.GetTypeName(), Fields: fields}, nil
	case *pb.StarValue_Thunk:
		thunk := &Thunk{Name: kind.Thunk.GetName(), Error: kind.Thunk.GetError()}
		if thunk.Error == "" {
			value, err := decodeValue(kind.Thunk.GetValue(), depth)
			if err != nil {
				return nil, err
			}
			thunk.Value = value
		}
		return thunk, nil
	case *pb.StarValue_Funcref:
		ref := &FuncRef{Function: kind.Funcref.GetFunction()}
		for i, arg := range kind.Funcref.GetArgs() {
			dec, err := decodeValue(arg, depth)
			if err != nil {
				return nil, fmt.Errorf("funcref arg %d: %w", i, err)
			}
			ref.Args = append(ref.Args, dec)
		}
		return ref, nil
	case *pb.StarValue_Cursor:
		return nil, fmt.Errorf("cursors cannot be decoded as plugin arguments")
	default:
		return nil, fmt.Errorf("unknown wire value kind %T", v.Kind)
	}
}

func decodeSlice(list *pb.ValueList, depth int) ([]any, error) {
	values := list.GetValues()
	items := make([]any, len(values))
	for i, item := range values {
		dec, err := decodeValue(item, depth)
		if err != nil {
			return nil, err
		}
		items[i] = dec
	}
	return items, nil
}

// decodeDict returns map[string]any when every key is a string (the common
// case), preserving nothing about order; otherwise it returns *Dict with the
// wire entry order intact.
func decodeDict(dict *pb.StarDict, depth int) (any, error) {
	entries := dict.GetEntries()
	stringKeys := true
	for _, entry := range entries {
		if _, ok := entry.GetKey().GetKind().(*pb.StarValue_Str); !ok {
			stringKeys = false
			break
		}
	}

	if stringKeys {
		m := make(map[string]any, len(entries))
		for _, entry := range entries {
			val, err := decodeValue(entry.GetValue(), depth)
			if err != nil {
				return nil, err
			}
			m[entry.GetKey().GetKind().(*pb.StarValue_Str).Str] = val
		}
		return m, nil
	}

	d := &Dict{Entries: make([]DictEntry, 0, len(entries))}
	for _, entry := range entries {
		key, err := decodeValue(entry.GetKey(), depth)
		if err != nil {
			return nil, err
		}
		val, err := decodeValue(entry.GetValue(), depth)
		if err != nil {
			return nil, err
		}
		d.Entries = append(d.Entries, DictEntry{Key: key, Value: val})
	}
	return d, nil
}

func encodeDictEntries(entries []DictEntry, depth int) (*pb.StarValue, error) {
	wireEntries := make([]*pb.StarEntry, 0, len(entries))
	for _, entry := range entries {
		ke, err := encodeValue(entry.Key, depth)
		if err != nil {
			return nil, err
		}
		ve, err := encodeValue(entry.Value, depth)
		if err != nil {
			return nil, err
		}
		wireEntries = append(wireEntries, &pb.StarEntry{Key: ke, Value: ve})
	}
	return &pb.StarValue{Kind: &pb.StarValue_Dict{Dict: &pb.StarDict{Entries: wireEntries}}}, nil
}

// EncodeValueMap encodes a settings-style map.
func EncodeValueMap(m map[string]any) (map[string]*pb.StarValue, error) {
	if m == nil {
		return nil, nil
	}
	out := make(map[string]*pb.StarValue, len(m))
	for k, v := range m {
		enc, err := EncodeValue(v)
		if err != nil {
			return nil, fmt.Errorf("encoding %q: %w", k, err)
		}
		out[k] = enc
	}
	return out, nil
}

// DecodeValueMap decodes a settings-style map.
func DecodeValueMap(m map[string]*pb.StarValue) (map[string]any, error) {
	if m == nil {
		return nil, nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		dec, err := DecodeValue(v)
		if err != nil {
			return nil, fmt.Errorf("decoding %q: %w", k, err)
		}
		out[k] = dec
	}
	return out, nil
}
