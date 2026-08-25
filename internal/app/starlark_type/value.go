// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"time"

	sdk "github.com/openrundev/openrun/pkg/plugin"
	startime "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

type valueMode uint8

const (
	applicationValue valueMode = iota
	pluginValue
)

// FuncRefValueFunc materializes an SDK function reference as a Starlark
// callable. It is supplied by plugin dispatch, which owns the module and
// session needed to invoke the reference.
type FuncRefValueFunc func(ref *sdk.FuncRef) (starlark.Value, error)

// ToGo converts a Starlark value to application-friendly Go data for JSON,
// templates, configuration, and schema values. It intentionally retains the
// established application contract: integers are int, homogeneous lists are
// specialized (for example []string), and typed values become plain maps.
func ToGo(v starlark.Value) (any, error) {
	return starlarkToGo(v, 0, applicationValue)
}

// ToPlugin converts a Starlark value to the plugin SDK representation while
// preserving Starlark-specific types such as tuples, sets, ordered dicts,
// large integers, and typed structs.
func ToPlugin(v starlark.Value, depth int) (any, error) {
	return starlarkToGo(v, depth, pluginValue)
}

func starlarkToGo(v starlark.Value, depth int, mode valueMode) (any, error) {
	if depth > sdk.MaxValueDepth {
		return nil, fmt.Errorf("value nesting exceeds max depth %d (cyclic value?)", sdk.MaxValueDepth)
	}
	depth++

	switch x := v.(type) {
	case nil, starlark.NoneType:
		return nil, nil
	case starlark.Bool:
		return bool(x), nil
	case starlark.Int:
		if mode == pluginValue {
			if i, ok := x.Int64(); ok {
				return i, nil
			}
			return new(big.Int).Set(x.BigInt()), nil
		}
		var i int
		if err := starlark.AsInt(x, &i); err != nil {
			return nil, err
		}
		return i, nil
	case starlark.Float:
		return float64(x), nil
	case starlark.String:
		return string(x), nil
	case starlark.Bytes:
		return []byte(x), nil
	case startime.Time:
		if mode == pluginValue {
			return time.Unix(0, time.Time(x).UnixNano()).UTC(), nil
		}
		return time.Time(x), nil
	case *starlark.List:
		items, err := iterableToGo(x.Elements(), x.Len(), depth, mode)
		if err != nil {
			return nil, err
		}
		if mode == applicationValue {
			return specializeApplicationList(items), nil
		}
		return items, nil
	case starlark.Tuple:
		items, err := iterableToGo(x.Elements(), x.Len(), depth, mode)
		if err != nil {
			return nil, err
		}
		if mode == pluginValue {
			return sdk.Tuple(items), nil
		}
		return items, nil
	case *starlark.Set:
		items, err := iterableToGo(x.Elements(), x.Len(), depth, mode)
		if err != nil {
			return nil, err
		}
		if mode == pluginValue {
			return sdk.Set(items), nil
		}
		return items, nil
	case *starlark.Dict:
		return starlarkDictToGo(x, depth, mode)
	case *StarlarkType:
		return attrsToGo(x.Type(), x.AttrNames(), x.Attr, depth, mode)
	case *starlarkstruct.Struct:
		if mode == applicationValue {
			return nil, fmt.Errorf("unrecognized starlark type: %s", x.Type())
		}
		return attrsToGo("", x.AttrNames(), x.Attr, depth, mode)
	default:
		if mode == applicationValue {
			if valuer, ok := v.(GoValuer); ok {
				return valuer.ToGoValue()
			}
			return nil, fmt.Errorf("unrecognized starlark type: %s", v.Type())
		}
		if valuer, ok := v.(PluginValuer); ok {
			// A plugin call result passed to another plugin call (e.g. a
			// container.sidecar() entry in container.config(sidecars=))
			return valuer.ToPluginValue(depth)
		}
		return nil, fmt.Errorf("cannot pass value of type %s to a plugin", v.Type())
	}
}

func iterableToGo(seq func(yield func(starlark.Value) bool), n, depth int, mode valueMode) ([]any, error) {
	items := make([]any, 0, n)
	var seqErr error
	seq(func(item starlark.Value) bool {
		decoded, err := starlarkToGo(item, depth, mode)
		if err != nil {
			seqErr = err
			return false
		}
		items = append(items, decoded)
		return true
	})
	if seqErr != nil {
		return nil, seqErr
	}
	return items, nil
}

func starlarkDictToGo(dict *starlark.Dict, depth int, mode valueMode) (any, error) {
	m := make(map[string]any, dict.Len())
	for key, value := range dict.Entries() {
		ks, ok := key.(starlark.String)
		if !ok {
			return starlarkDictEntriesToGo(dict, depth, mode)
		}
		decoded, err := starlarkToGo(value, depth, mode)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling starlark value: %w", err)
		}
		m[string(ks)] = decoded
	}
	return m, nil
}

func starlarkDictEntriesToGo(dict *starlark.Dict, depth int, mode valueMode) (any, error) {
	if mode == pluginValue {
		d := &sdk.Dict{Entries: make([]sdk.DictEntry, 0, dict.Len())}
		for key, value := range dict.Entries() {
			decodedKey, err := starlarkToGo(key, depth, mode)
			if err != nil {
				return nil, err
			}
			decodedValue, err := starlarkToGo(value, depth, mode)
			if err != nil {
				return nil, err
			}
			d.Entries = append(d.Entries, sdk.DictEntry{Key: decodedKey, Value: decodedValue})
		}
		return d, nil
	}

	m := make(map[any]any, dict.Len())
	for key, value := range dict.Entries() {
		decodedKey, err := starlarkToGo(key, depth, mode)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling starlark key: %w", err)
		}
		if decodedKey != nil && !reflect.TypeOf(decodedKey).Comparable() {
			return nil, fmt.Errorf("starlark key %s has no comparable Go representation", key)
		}
		decodedValue, err := starlarkToGo(value, depth, mode)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling starlark value: %w", err)
		}
		m[decodedKey] = decodedValue
	}
	return m, nil
}

func attrsToGo(typeName string, attrNames []string, attr func(string) (starlark.Value, error), depth int, mode valueMode) (any, error) {
	fields := make(map[string]any, len(attrNames))
	for _, name := range attrNames {
		value, err := attr(name)
		if err != nil {
			return nil, err
		}
		decoded, err := starlarkToGo(value, depth, mode)
		if err != nil {
			return nil, err
		}
		fields[name] = decoded
	}
	if mode == pluginValue {
		return &sdk.Struct{TypeName: typeName, Fields: fields}, nil
	}
	return fields, nil
}

func specializeApplicationList(items []any) any {
	allInt := true
	allString := true
	allStringMap := true
	allMap := true
	for _, item := range items {
		switch item.(type) {
		case int:
			allString, allStringMap, allMap = false, false, false
		case string:
			allInt, allStringMap, allMap = false, false, false
		case map[string]any:
			allInt, allString, allMap = false, false, false
		case map[any]any:
			allInt, allString, allStringMap = false, false, false
		default:
			return items
		}
	}

	switch {
	case allString:
		out := make([]string, len(items))
		for i, item := range items {
			out[i] = item.(string)
		}
		return out
	case allInt:
		out := make([]int, len(items))
		for i, item := range items {
			out[i] = item.(int)
		}
		return out
	case allStringMap:
		out := make([]map[string]any, len(items))
		for i, item := range items {
			out[i] = item.(map[string]any)
		}
		return out
	case allMap:
		out := make([]map[any]any, len(items))
		for i, item := range items {
			out[i] = item.(map[any]any)
		}
		return out
	default:
		return items
	}
}

// FromGo converts application Go data to Starlark. In addition to the plugin
// value set it accepts the named map types used by HTTP requests.
func FromGo(v any) (starlark.Value, error) {
	return goToStarlark(v, 0, nil, applicationValue)
}

// FromPlugin converts a plugin SDK return value to Starlark.
func FromPlugin(v any, depth int, funcRefFn FuncRefValueFunc) (starlark.Value, error) {
	return goToStarlark(v, depth, funcRefFn, pluginValue)
}

func goToStarlark(v any, depth int, funcRefFn FuncRefValueFunc, mode valueMode) (starlark.Value, error) {
	if depth > sdk.MaxValueDepth {
		return nil, fmt.Errorf("value nesting exceeds max depth %d (cyclic value?)", sdk.MaxValueDepth)
	}
	depth++

	switch x := v.(type) {
	case nil:
		return starlark.None, nil
	case starlark.Value:
		if mode == applicationValue {
			return x, nil
		}
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
		return uintToStarlark(uint64(x)), nil
	case uint8:
		return uintToStarlark(uint64(x)), nil
	case uint16:
		return uintToStarlark(uint64(x)), nil
	case uint32:
		return uintToStarlark(uint64(x)), nil
	case uint64:
		return uintToStarlark(x), nil
	case *big.Int:
		if x == nil {
			return starlark.None, nil
		}
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
		if mode == pluginValue {
			return startime.Time(time.Unix(0, x.UnixNano()).UTC()), nil
		}
		return startime.Time(x), nil
	case sdk.Tuple:
		items, err := goSliceToStarlark(x, depth, funcRefFn, mode)
		if err != nil {
			return nil, err
		}
		return starlark.Tuple(items), nil
	case sdk.Set:
		items, err := goSliceToStarlark(x, depth, funcRefFn, mode)
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
		return goDictToStarlark(x.Entries, depth, funcRefFn, mode)
	case *sdk.Dict:
		if x == nil {
			return starlark.None, nil
		}
		return goDictToStarlark(x.Entries, depth, funcRefFn, mode)
	case sdk.Struct:
		return goStructToStarlark(&x, depth, funcRefFn, mode)
	case *sdk.Struct:
		if x == nil {
			return starlark.None, nil
		}
		return goStructToStarlark(x, depth, funcRefFn, mode)
	case sdk.Thunk:
		return goThunkToStarlark(&x, depth, funcRefFn, mode)
	case *sdk.Thunk:
		if x == nil {
			return starlark.None, nil
		}
		return goThunkToStarlark(x, depth, funcRefFn, mode)
	case *sdk.Download:
		if x == nil {
			return starlark.None, nil
		}
		return NewDownloadStream(x.Name, x.Producer), nil
	case sdk.FuncRef:
		if mode != pluginValue || funcRefFn == nil {
			return nil, fmt.Errorf("func ref values are not valid here")
		}
		return funcRefFn(&x)
	case *sdk.FuncRef:
		if x == nil {
			return starlark.None, nil
		}
		if mode != pluginValue || funcRefFn == nil {
			return nil, fmt.Errorf("func ref values are not valid here")
		}
		return funcRefFn(x)
	case []any:
		items, err := goSliceToStarlark(x, depth, funcRefFn, mode)
		if err != nil {
			return nil, err
		}
		return starlark.NewList(items), nil
	case []string:
		items := make([]starlark.Value, len(x))
		for i, item := range x {
			items[i] = starlark.String(item)
		}
		return starlark.NewList(items), nil
	case []int:
		items := make([]starlark.Value, len(x))
		for i, item := range x {
			items[i] = starlark.MakeInt(item)
		}
		return starlark.NewList(items), nil
	case []int64:
		items := make([]starlark.Value, len(x))
		for i, item := range x {
			items[i] = starlark.MakeInt64(item)
		}
		return starlark.NewList(items), nil
	case []map[string]any:
		items := make([]starlark.Value, len(x))
		for i, item := range x {
			converted, err := goToStarlark(item, depth, funcRefFn, mode)
			if err != nil {
				return nil, err
			}
			items[i] = converted
		}
		return starlark.NewList(items), nil
	case []map[string]string:
		items := make([]starlark.Value, len(x))
		for i, item := range x {
			converted, err := goToStarlark(item, depth, funcRefFn, mode)
			if err != nil {
				return nil, err
			}
			items[i] = converted
		}
		return starlark.NewList(items), nil
	case map[string]any:
		return goStringMapToStarlark(x, depth, funcRefFn, mode)
	case map[string]string:
		dict := starlark.NewDict(len(x))
		for key, value := range x {
			if err := dict.SetKey(starlark.String(key), starlark.String(value)); err != nil {
				return nil, err
			}
		}
		return dict, nil
	case http.Header:
		return goStringSlicesToStarlark(map[string][]string(x), depth, funcRefFn, mode)
	case url.Values:
		return goStringSlicesToStarlark(map[string][]string(x), depth, funcRefFn, mode)
	case map[any]any:
		dict := starlark.NewDict(len(x))
		for key, value := range x {
			convertedKey, err := goToStarlark(key, depth, funcRefFn, mode)
			if err != nil {
				return nil, err
			}
			convertedValue, err := goToStarlark(value, depth, funcRefFn, mode)
			if err != nil {
				return nil, err
			}
			if err := dict.SetKey(convertedKey, convertedValue); err != nil {
				return nil, err
			}
		}
		return dict, nil
	case *sdk.Cursor:
		if x == nil {
			return starlark.None, nil
		}
		return nil, fmt.Errorf("a Cursor can only be the top-level return value of a plugin function")
	}

	if mode == pluginValue {
		return nil, fmt.Errorf("cannot return value of type %T from a plugin", v)
	}
	return nil, fmt.Errorf("unrecognized type: %#v %T", v, v)
}

func uintToStarlark(x uint64) starlark.Value {
	if x <= math.MaxInt64 {
		return starlark.MakeInt64(int64(x))
	}
	return starlark.MakeBigInt(new(big.Int).SetUint64(x))
}

func goSliceToStarlark(items []any, depth int, funcRefFn FuncRefValueFunc, mode valueMode) ([]starlark.Value, error) {
	out := make([]starlark.Value, len(items))
	for i, item := range items {
		converted, err := goToStarlark(item, depth, funcRefFn, mode)
		if err != nil {
			return nil, err
		}
		out[i] = converted
	}
	return out, nil
}

func goStringMapToStarlark(values map[string]any, depth int, funcRefFn FuncRefValueFunc, mode valueMode) (starlark.Value, error) {
	dict := starlark.NewDict(len(values))
	for key, value := range values {
		converted, err := goToStarlark(value, depth, funcRefFn, mode)
		if err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String(key), converted); err != nil {
			return nil, err
		}
	}
	return dict, nil
}

func goStringSlicesToStarlark(values map[string][]string, depth int, funcRefFn FuncRefValueFunc, mode valueMode) (starlark.Value, error) {
	dict := starlark.NewDict(len(values))
	for key, value := range values {
		converted, err := goToStarlark(value, depth, funcRefFn, mode)
		if err != nil {
			return nil, err
		}
		if err := dict.SetKey(starlark.String(key), converted); err != nil {
			return nil, err
		}
	}
	return dict, nil
}

func goDictToStarlark(entries []sdk.DictEntry, depth int, funcRefFn FuncRefValueFunc, mode valueMode) (starlark.Value, error) {
	dict := starlark.NewDict(len(entries))
	for _, entry := range entries {
		key, err := goToStarlark(entry.Key, depth, funcRefFn, mode)
		if err != nil {
			return nil, err
		}
		value, err := goToStarlark(entry.Value, depth, funcRefFn, mode)
		if err != nil {
			return nil, err
		}
		if err := dict.SetKey(key, value); err != nil {
			return nil, err
		}
	}
	return dict, nil
}

func goStructToStarlark(value *sdk.Struct, depth int, funcRefFn FuncRefValueFunc, mode valueMode) (starlark.Value, error) {
	data := make(map[string]starlark.Value, len(value.Fields))
	for name, field := range value.Fields {
		converted, err := goToStarlark(field, depth, funcRefFn, mode)
		if err != nil {
			return nil, err
		}
		data[name] = converted
	}
	return NewStarlarkType(value.TypeName, data), nil
}

func goThunkToStarlark(value *sdk.Thunk, depth int, funcRefFn FuncRefValueFunc, mode valueMode) (starlark.Value, error) {
	if value.Error != "" {
		errorMessage := value.Error
		return starlark.NewBuiltin(value.Name, func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return nil, fmt.Errorf("%s", errorMessage)
		}), nil
	}
	converted, err := goToStarlark(value.Value, depth, funcRefFn, mode)
	if err != nil {
		return nil, err
	}
	return starlark.NewBuiltin(value.Name, func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs); err != nil {
			return nil, err
		}
		return converted, nil
	}), nil
}

// GoValuer converts a custom Starlark value to its application Go
// representation.
type GoValuer interface {
	ToGoValue() (any, error)
}

// PluginValuer converts a custom Starlark value to its plugin SDK
// representation, for values passed from one plugin call into another.
type PluginValuer interface {
	ToPluginValue(depth int) (any, error)
}
