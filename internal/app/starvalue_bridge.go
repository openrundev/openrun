// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/openrundev/openrun/internal/app/starlark_type"
	sdk "github.com/openrundev/openrun/pkg/plugin"
	startime "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// The direct bridge converts values between Starlark and the plugin SDK's
// plain Go representation in a single pass, for plugin modules running
// in-process. It is defined to be exactly equivalent to the wire path used
// for external providers (starToWire→DecodeValue in, EncodeValue→wireToStar
// out), so a plugin observes identical values whether it runs internal or
// external; the equivalence is enforced by differential tests in
// starvalue_bridge_test.go. The wire path allocates an intermediate protobuf
// tree per value, which the bridge avoids (see starvalue_bench_test.go).

// starToGoValue converts a starlark value into the SDK's Go representation:
// nil, bool, int64 (or *big.Int), float64, string, []byte, time.Time, []any,
// sdk.Tuple, sdk.Set, map[string]any (string-keyed dicts) or *sdk.Dict, and
// *sdk.Struct for typed records.
func starToGoValue(v starlark.Value, depth int) (any, error) {
	if depth > maxStarValueDepth {
		return nil, fmt.Errorf("value nesting exceeds max depth %d (cyclic value?)", maxStarValueDepth)
	}
	depth++

	switch x := v.(type) {
	case nil, starlark.NoneType:
		return nil, nil
	case starlark.Bool:
		return bool(x), nil
	case starlark.Int:
		if i, ok := x.Int64(); ok {
			return i, nil
		}
		return new(big.Int).Set(x.BigInt()), nil
	case starlark.Float:
		return float64(x), nil
	case starlark.String:
		return string(x), nil
	case starlark.Bytes:
		return []byte(x), nil
	case startime.Time:
		return time.Unix(0, time.Time(x).UnixNano()).UTC(), nil
	case *starlark.List:
		return iterableToGo(x.Elements(), x.Len(), depth)
	case starlark.Tuple:
		items, err := iterableToGo(x.Elements(), x.Len(), depth)
		if err != nil {
			return nil, err
		}
		return sdk.Tuple(items), nil
	case *starlark.Set:
		items, err := iterableToGo(x.Elements(), x.Len(), depth)
		if err != nil {
			return nil, err
		}
		return sdk.Set(items), nil
	case *starlark.Dict:
		// Match decodeDict: map[string]any when every key is a string (the
		// common case), *sdk.Dict with entry order preserved otherwise
		stringKeys := true
		for key := range x.Entries() {
			if _, ok := key.(starlark.String); !ok {
				stringKeys = false
				break
			}
		}
		if stringKeys {
			m := make(map[string]any, x.Len())
			for key, value := range x.Entries() {
				dec, err := starToGoValue(value, depth)
				if err != nil {
					return nil, err
				}
				m[string(key.(starlark.String))] = dec
			}
			return m, nil
		}
		d := &sdk.Dict{Entries: make([]sdk.DictEntry, 0, x.Len())}
		for key, value := range x.Entries() {
			kd, err := starToGoValue(key, depth)
			if err != nil {
				return nil, err
			}
			vd, err := starToGoValue(value, depth)
			if err != nil {
				return nil, err
			}
			d.Entries = append(d.Entries, sdk.DictEntry{Key: kd, Value: vd})
		}
		return d, nil
	case *starlark_type.StarlarkType:
		return typedStructToGo(x.Type(), x.AttrNames(), x.Attr, depth)
	case *starlarkstruct.Struct:
		return typedStructToGo("", x.AttrNames(), x.Attr, depth)
	default:
		return nil, fmt.Errorf("cannot pass value of type %s to a plugin", v.Type())
	}
}

func iterableToGo(seq func(yield func(starlark.Value) bool), n, depth int) ([]any, error) {
	items := make([]any, 0, n)
	var seqErr error
	seq(func(item starlark.Value) bool {
		dec, err := starToGoValue(item, depth)
		if err != nil {
			seqErr = err
			return false
		}
		items = append(items, dec)
		return true
	})
	if seqErr != nil {
		return nil, seqErr
	}
	return items, nil
}

func typedStructToGo(typeName string, attrNames []string, attr func(string) (starlark.Value, error), depth int) (*sdk.Struct, error) {
	fields := make(map[string]any, len(attrNames))
	for _, name := range attrNames {
		value, err := attr(name)
		if err != nil {
			return nil, err
		}
		dec, err := starToGoValue(value, depth)
		if err != nil {
			return nil, err
		}
		fields[name] = dec
	}
	return &sdk.Struct{TypeName: typeName, Fields: fields}, nil
}

// funcRefValueFunc materializes an sdk.FuncRef into a starlark callable that
// dispatches the referenced plugin function; supplied by the call dispatch,
// which knows the module, account, and session. A nil funcRefFn rejects func
// refs (e.g. in constants).
type funcRefValueFunc func(ref *sdk.FuncRef) (starlark.Value, error)

// goValueToStar converts an SDK Go value into a starlark value: the reverse
// of starToGoValue, accepting every value shape EncodeValue accepts (all
// int/uint widths, typed slices and maps, sdk.Thunk, sdk.FuncRef, ...).
// Typed structs become StarlarkType values, matching what plugin calls
// return to apps. Cursors are not handled here: a *sdk.Cursor can only be a
// top-level return value and is wrapped by the call dispatch, not by the
// value bridge.
func goValueToStar(v any, depth int, funcRefFn funcRefValueFunc) (starlark.Value, error) {
	if depth > maxStarValueDepth {
		return nil, fmt.Errorf("value nesting exceeds max depth %d (cyclic value?)", maxStarValueDepth)
	}
	depth++

	switch x := v.(type) {
	case nil:
		return starlark.None, nil
	case bool:
		return starlark.Bool(x), nil
	case int:
		return starlark.MakeInt64(int64(x)), nil
	case int8:
		return starlark.MakeInt64(int64(x)), nil
	case int16:
		return starlark.MakeInt64(int64(x)), nil
	case int32:
		return starlark.MakeInt64(int64(x)), nil
	case int64:
		return starlark.MakeInt64(x), nil
	case uint:
		return goUintToStar(uint64(x)), nil
	case uint8:
		return goUintToStar(uint64(x)), nil
	case uint16:
		return goUintToStar(uint64(x)), nil
	case uint32:
		return goUintToStar(uint64(x)), nil
	case uint64:
		return goUintToStar(x), nil
	case *big.Int:
		if x.IsInt64() {
			return starlark.MakeInt64(x.Int64()), nil
		}
		return starlark.MakeBigInt(x), nil
	case float32:
		return starlark.Float(float64(x)), nil
	case float64:
		return starlark.Float(x), nil
	case string:
		return starlark.String(x), nil
	case []byte:
		return starlark.Bytes(x), nil
	case time.Time:
		return startime.Time(time.Unix(0, x.UnixNano()).UTC()), nil
	case sdk.Tuple:
		items, err := goSliceToStar(x, depth, funcRefFn)
		if err != nil {
			return nil, err
		}
		return starlark.Tuple(items), nil
	case sdk.Set:
		items, err := goSliceToStar(x, depth, funcRefFn)
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
	case sdk.Dict:
		return goDictEntriesToStar(x.Entries, depth, funcRefFn)
	case *sdk.Dict:
		return goDictEntriesToStar(x.Entries, depth, funcRefFn)
	case sdk.Struct:
		return goStructToStar(&x, depth, funcRefFn)
	case *sdk.Struct:
		return goStructToStar(x, depth, funcRefFn)
	case sdk.Thunk:
		return goThunkToStar(&x, depth, funcRefFn)
	case *sdk.Thunk:
		return goThunkToStar(x, depth, funcRefFn)
	case *sdk.Download:
		// A download's content is produced at response-write time, in the
		// host process: in-process modules only (EncodeValue rejects it for
		// external transport)
		return starlark_type.NewDownloadStream(x.Name, x.Producer), nil
	case sdk.FuncRef:
		if funcRefFn == nil {
			return nil, fmt.Errorf("func ref values are not valid here")
		}
		return funcRefFn(&x)
	case *sdk.FuncRef:
		if funcRefFn == nil {
			return nil, fmt.Errorf("func ref values are not valid here")
		}
		return funcRefFn(x)
	case []any:
		items, err := goSliceToStar(x, depth, funcRefFn)
		if err != nil {
			return nil, err
		}
		return starlark.NewList(items), nil
	case []string:
		items := make([]starlark.Value, len(x))
		for i, s := range x {
			items[i] = starlark.String(s)
		}
		return starlark.NewList(items), nil
	case []int:
		items := make([]starlark.Value, len(x))
		for i, n := range x {
			items[i] = starlark.MakeInt64(int64(n))
		}
		return starlark.NewList(items), nil
	case []int64:
		items := make([]starlark.Value, len(x))
		for i, n := range x {
			items[i] = starlark.MakeInt64(n)
		}
		return starlark.NewList(items), nil
	case []map[string]any:
		items := make([]starlark.Value, len(x))
		for i, m := range x {
			sv, err := goValueToStar(m, depth, funcRefFn)
			if err != nil {
				return nil, err
			}
			items[i] = sv
		}
		return starlark.NewList(items), nil
	case map[string]any:
		dict := starlark.NewDict(len(x))
		for k, val := range x {
			sv, err := goValueToStar(val, depth, funcRefFn)
			if err != nil {
				return nil, err
			}
			if err := dict.SetKey(starlark.String(k), sv); err != nil {
				return nil, err
			}
		}
		return dict, nil
	case map[string]string:
		dict := starlark.NewDict(len(x))
		for k, val := range x {
			if err := dict.SetKey(starlark.String(k), starlark.String(val)); err != nil {
				return nil, err
			}
		}
		return dict, nil
	case map[any]any:
		dict := starlark.NewDict(len(x))
		for k, val := range x {
			ks, err := goValueToStar(k, depth, funcRefFn)
			if err != nil {
				return nil, err
			}
			vs, err := goValueToStar(val, depth, funcRefFn)
			if err != nil {
				return nil, err
			}
			if err := dict.SetKey(ks, vs); err != nil {
				return nil, err
			}
		}
		return dict, nil
	case *sdk.Cursor:
		return nil, fmt.Errorf("a Cursor can only be the top-level return value of a plugin function")
	default:
		return nil, fmt.Errorf("cannot return value of type %T from a plugin", v)
	}
}

func goUintToStar(x uint64) starlark.Value {
	if x <= math.MaxInt64 {
		return starlark.MakeInt64(int64(x))
	}
	return starlark.MakeBigInt(new(big.Int).SetUint64(x))
}

func goSliceToStar(items []any, depth int, funcRefFn funcRefValueFunc) ([]starlark.Value, error) {
	out := make([]starlark.Value, len(items))
	for i, item := range items {
		sv, err := goValueToStar(item, depth, funcRefFn)
		if err != nil {
			return nil, err
		}
		out[i] = sv
	}
	return out, nil
}

func goDictEntriesToStar(entries []sdk.DictEntry, depth int, funcRefFn funcRefValueFunc) (starlark.Value, error) {
	dict := starlark.NewDict(len(entries))
	for _, entry := range entries {
		ks, err := goValueToStar(entry.Key, depth, funcRefFn)
		if err != nil {
			return nil, err
		}
		vs, err := goValueToStar(entry.Value, depth, funcRefFn)
		if err != nil {
			return nil, err
		}
		if err := dict.SetKey(ks, vs); err != nil {
			return nil, err
		}
	}
	return dict, nil
}

func goStructToStar(x *sdk.Struct, depth int, funcRefFn funcRefValueFunc) (starlark.Value, error) {
	data := make(map[string]starlark.Value, len(x.Fields))
	for name, value := range x.Fields {
		sv, err := goValueToStar(value, depth, funcRefFn)
		if err != nil {
			return nil, err
		}
		data[name] = sv
	}
	return starlark_type.NewStarlarkType(x.TypeName, data), nil
}

// goThunkToStar materializes an sdk.Thunk as a zero-argument callable: the
// thunk's value is converted eagerly (it must be transportable), and calling
// the builtin returns it (or the thunk's error). This is how a plugin returns
// a record with callable members, e.g. the http plugin's response.body() and
// response.json().
func goThunkToStar(x *sdk.Thunk, depth int, funcRefFn funcRefValueFunc) (starlark.Value, error) {
	if x.Error != "" {
		errMsg := x.Error
		name := x.Name
		return starlark.NewBuiltin(name, func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return nil, fmt.Errorf("%s", errMsg)
		}), nil
	}
	value, err := goValueToStar(x.Value, depth, funcRefFn)
	if err != nil {
		return nil, err
	}
	return starlark.NewBuiltin(x.Name, func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs); err != nil {
			return nil, err
		}
		return value, nil
	}), nil
}
