// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"fmt"
	"math/big"
	"time"

	sdk "github.com/openrundev/openrun/pkg/plugin"
	pb "github.com/openrundev/openrun/pkg/plugin/proto"
	startime "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// ToWire converts a starlark value into its wire representation for a
// plugin provider call, in a single pass with no intermediate Go value tree.
// Fidelity notes: int64-representable ints use the int fast path and larger
// ints go as big ints; int and float stay distinct; tuple/set/bytes are
// preserved; dict entries keep insertion order; StarlarkType values become
// typed structs.
func ToWire(v starlark.Value, depth int) (*pb.StarValue, error) {
	if depth > sdk.MaxValueDepth {
		return nil, fmt.Errorf("value nesting exceeds max depth %d (cyclic value?)", sdk.MaxValueDepth)
	}
	depth++

	switch x := v.(type) {
	case nil, starlark.NoneType:
		return &pb.StarValue{Kind: &pb.StarValue_None{None: true}}, nil
	case starlark.Bool:
		return &pb.StarValue{Kind: &pb.StarValue_Bool{Bool: bool(x)}}, nil
	case starlark.Int:
		if i, ok := x.Int64(); ok {
			return &pb.StarValue{Kind: &pb.StarValue_Int{Int: i}}, nil
		}
		b := x.BigInt()
		return &pb.StarValue{Kind: &pb.StarValue_Bigint{Bigint: &pb.BigInt{
			Negative: b.Sign() < 0,
			Abs:      b.Bytes(),
		}}}, nil
	case starlark.Float:
		return &pb.StarValue{Kind: &pb.StarValue_Float{Float: float64(x)}}, nil
	case starlark.String:
		return &pb.StarValue{Kind: &pb.StarValue_Str{Str: string(x)}}, nil
	case starlark.Bytes:
		return &pb.StarValue{Kind: &pb.StarValue_Bytes{Bytes: []byte(x)}}, nil
	case startime.Time:
		return &pb.StarValue{Kind: &pb.StarValue_TimeUnixNanos{TimeUnixNanos: time.Time(x).UnixNano()}}, nil
	case *starlark.List:
		list, err := iterableToWire(x.Elements(), x.Len(), depth)
		if err != nil {
			return nil, err
		}
		return &pb.StarValue{Kind: &pb.StarValue_List{List: list}}, nil
	case starlark.Tuple:
		list, err := iterableToWire(x.Elements(), x.Len(), depth)
		if err != nil {
			return nil, err
		}
		return &pb.StarValue{Kind: &pb.StarValue_Tuple{Tuple: list}}, nil
	case *starlark.Set:
		list, err := iterableToWire(x.Elements(), x.Len(), depth)
		if err != nil {
			return nil, err
		}
		return &pb.StarValue{Kind: &pb.StarValue_Set{Set: list}}, nil
	case *starlark.Dict:
		entries := make([]*pb.StarEntry, 0, x.Len())
		for key, value := range x.Entries() {
			ke, err := ToWire(key, depth)
			if err != nil {
				return nil, err
			}
			ve, err := ToWire(value, depth)
			if err != nil {
				return nil, err
			}
			entries = append(entries, &pb.StarEntry{Key: ke, Value: ve})
		}
		return &pb.StarValue{Kind: &pb.StarValue_Dict{Dict: &pb.StarDict{Entries: entries}}}, nil
	case *StarlarkType:
		return typedStructToWire(x.Type(), x.AttrNames(), x.Attr, depth)
	case *starlarkstruct.Struct:
		return typedStructToWire("", x.AttrNames(), x.Attr, depth)
	default:
		return nil, fmt.Errorf("cannot pass value of type %s to an external plugin", v.Type())
	}
}

func iterableToWire(seq func(yield func(starlark.Value) bool), n, depth int) (*pb.ValueList, error) {
	values := make([]*pb.StarValue, 0, n)
	var seqErr error
	seq(func(item starlark.Value) bool {
		enc, err := ToWire(item, depth)
		if err != nil {
			seqErr = err
			return false
		}
		values = append(values, enc)
		return true
	})
	if seqErr != nil {
		return nil, seqErr
	}
	return &pb.ValueList{Values: values}, nil
}

func typedStructToWire(typeName string, attrNames []string, attr func(string) (starlark.Value, error), depth int) (*pb.StarValue, error) {
	fields := make([]*pb.StarEntry, 0, len(attrNames))
	for _, name := range attrNames {
		value, err := attr(name)
		if err != nil {
			return nil, err
		}
		ve, err := ToWire(value, depth)
		if err != nil {
			return nil, err
		}
		fields = append(fields, &pb.StarEntry{
			Key:   &pb.StarValue{Kind: &pb.StarValue_Str{Str: name}},
			Value: ve,
		})
	}
	return &pb.StarValue{Kind: &pb.StarValue_Struct{Struct: &pb.TypedStruct{
		TypeName: typeName,
		Fields:   &pb.StarDict{Entries: fields},
	}}}, nil
}

// CursorValueFunc materializes a wire cursor handle into a starlark value;
// supplied by the remote call path, which knows the session and provider.
type CursorValueFunc func(cursor *pb.Cursor) (starlark.Value, error)

// WireFuncRefFunc materializes a wire func ref into a starlark callable that
// dispatches the referenced plugin function; supplied by the remote call
// path. A nil WireFuncRefFunc rejects func refs (e.g. in constants).
type WireFuncRefFunc func(ref *pb.FuncRef) (starlark.Value, error)

// FromWire converts a wire value into a starlark value. Typed structs
// become StarlarkType values (attribute access, mutable fields), matching
// what in-process plugins return. Cursors are materialized via cursorFn; a nil
// cursorFn rejects cursors (e.g. in constants).
func FromWire(v *pb.StarValue, cursorFn CursorValueFunc, funcRefFn WireFuncRefFunc, depth int) (starlark.Value, error) {
	if depth > sdk.MaxValueDepth {
		return nil, fmt.Errorf("value nesting exceeds max depth %d", sdk.MaxValueDepth)
	}
	depth++

	if v == nil {
		return starlark.None, nil
	}
	switch kind := v.Kind.(type) {
	case *pb.StarValue_None:
		return starlark.None, nil
	case *pb.StarValue_Bool:
		return starlark.Bool(kind.Bool), nil
	case *pb.StarValue_Int:
		return starlark.MakeInt64(kind.Int), nil
	case *pb.StarValue_Bigint:
		b := new(big.Int).SetBytes(kind.Bigint.GetAbs())
		if kind.Bigint.GetNegative() {
			b.Neg(b)
		}
		return starlark.MakeBigInt(b), nil
	case *pb.StarValue_Float:
		return starlark.Float(kind.Float), nil
	case *pb.StarValue_Str:
		return starlark.String(kind.Str), nil
	case *pb.StarValue_Bytes:
		return starlark.Bytes(kind.Bytes), nil
	case *pb.StarValue_TimeUnixNanos:
		return startime.Time(time.Unix(0, kind.TimeUnixNanos).UTC()), nil
	case *pb.StarValue_List:
		items, err := wireListToStar(kind.List, cursorFn, funcRefFn, depth)
		if err != nil {
			return nil, err
		}
		return starlark.NewList(items), nil
	case *pb.StarValue_Tuple:
		items, err := wireListToStar(kind.Tuple, cursorFn, funcRefFn, depth)
		if err != nil {
			return nil, err
		}
		return starlark.Tuple(items), nil
	case *pb.StarValue_Set:
		items, err := wireListToStar(kind.Set, cursorFn, funcRefFn, depth)
		if err != nil {
			return nil, err
		}
		set := starlark.NewSet(len(items))
		for _, item := range items {
			if err := set.Insert(item); err != nil {
				return nil, err
			}
		}
		return set, nil
	case *pb.StarValue_Dict:
		entries := kind.Dict.GetEntries()
		dict := starlark.NewDict(len(entries))
		for _, entry := range entries {
			key, err := FromWire(entry.GetKey(), cursorFn, funcRefFn, depth)
			if err != nil {
				return nil, err
			}
			value, err := FromWire(entry.GetValue(), cursorFn, funcRefFn, depth)
			if err != nil {
				return nil, err
			}
			if err := dict.SetKey(key, value); err != nil {
				return nil, err
			}
		}
		return dict, nil
	case *pb.StarValue_Struct:
		fields := kind.Struct.GetFields().GetEntries()
		data := make(map[string]starlark.Value, len(fields))
		for _, entry := range fields {
			key, ok := entry.GetKey().GetKind().(*pb.StarValue_Str)
			if !ok {
				return nil, fmt.Errorf("struct field key must be a string")
			}
			value, err := FromWire(entry.GetValue(), cursorFn, funcRefFn, depth)
			if err != nil {
				return nil, err
			}
			data[key.Str] = value
		}
		return NewStarlarkType(kind.Struct.GetTypeName(), data), nil
	case *pb.StarValue_Thunk:
		if kind.Thunk.GetError() != "" {
			errMsg := kind.Thunk.GetError()
			return starlark.NewBuiltin(kind.Thunk.GetName(), func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				return nil, fmt.Errorf("%s", errMsg)
			}), nil
		}
		value, err := FromWire(kind.Thunk.GetValue(), cursorFn, funcRefFn, depth)
		if err != nil {
			return nil, err
		}
		return starlark.NewBuiltin(kind.Thunk.GetName(), func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(fn.Name(), args, kwargs); err != nil {
				return nil, err
			}
			return value, nil
		}), nil
	case *pb.StarValue_Funcref:
		if funcRefFn == nil {
			return nil, fmt.Errorf("func ref values are not valid here")
		}
		return funcRefFn(kind.Funcref)
	case *pb.StarValue_Cursor:
		if cursorFn == nil {
			return nil, fmt.Errorf("cursor values are not valid here")
		}
		return cursorFn(kind.Cursor)
	default:
		return nil, fmt.Errorf("unknown wire value kind %T", v.Kind)
	}
}

func wireListToStar(list *pb.ValueList, cursorFn CursorValueFunc, funcRefFn WireFuncRefFunc, depth int) ([]starlark.Value, error) {
	values := list.GetValues()
	items := make([]starlark.Value, len(values))
	for i, item := range values {
		dec, err := FromWire(item, cursorFn, funcRefFn, depth)
		if err != nil {
			return nil, err
		}
		items[i] = dec
	}
	return items, nil
}
