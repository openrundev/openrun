// Based on https://github.com/qri-io/starlib/blob/master/util/util.go
// Copyright (c) 2018 QRI, Inc. The MIT License (MIT)

package starlark_type

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	startime "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// UnquoteStarlark unquotes a starlark string value
func UnquoteStarlark(x starlark.Value) (string, error) {
	return strconv.Unquote(x.String())
}

// IsEmptyStarlarkString checks is a starlark string is empty ("" for a go string)
// starlark.String.String performs repr-style quotation, which is necessary
// for the starlark.Value contract but a frequent source of errors in API
// clients. This helper method makes sure it'll work properly
func IsEmptyStarlarkString(s starlark.String) bool {
	return s.String() == `""`
}

// UnmarshalStarlark decodes a starlark.Value into it's golang counterpart
func UnmarshalStarlark(x starlark.Value) (val interface{}, err error) {
	switch v := x.(type) {
	case starlark.NoneType:
		val = nil
	case starlark.Bool:
		val = v.Truth() == starlark.True
	case starlark.Int:
		var tmp int
		err = starlark.AsInt(x, &tmp)
		val = tmp
	case starlark.Float:
		if f, ok := starlark.AsFloat(x); !ok {
			err = fmt.Errorf("couldn't parse float")
		} else {
			val = f
		}
	case starlark.String:
		val = v.GoString()
	case startime.Time:
		val = time.Time(v)
	case *starlark.Dict:
		// Fast path: string keys (the common case) produce map[string]any.
		// Iterate the keys and look up each value with Get instead of calling
		// Items(), which allocates a two-element Tuple slice per entry. Get
		// during iteration is safe (it does not mutate the table). A non-string
		// key drops to the map[any]any fallback below.
		n := v.Len()
		rs := make(map[string]interface{}, n)
		iter := v.Iterate()
		var key starlark.Value
		stringKeys := true
		for iter.Next(&key) {
			ks, ok := key.(starlark.String)
			if !ok {
				stringKeys = false
				break
			}
			dictVal, _, _ := v.Get(key)
			var pval interface{}
			pval, err = UnmarshalStarlark(dictVal)
			if err != nil {
				iter.Done()
				err = fmt.Errorf("unmarshaling starlark value: %w", err)
				return
			}
			rs[string(ks)] = pval
		}
		iter.Done()

		if stringKeys {
			val = rs // map[string]interface{}
		} else {
			// Rare: at least one non-string key. Rebuild from Items() into a
			// map[any]any (the partial rs above is discarded)
			ri := make(map[interface{}]interface{}, n)
			for _, item := range v.Items() {
				var kval, pval interface{}
				kval, err = UnmarshalStarlark(item[0])
				if err != nil {
					err = fmt.Errorf("unmarshaling starlark key: %w", err)
					return
				}
				pval, err = UnmarshalStarlark(item[1])
				if err != nil {
					err = fmt.Errorf("unmarshaling starlark value: %w", err)
					return
				}
				ri[kval] = pval
			}
			val = ri // map[interface{}]interface{}
		}
	case *starlark.List:
		var (
			i       int
			listVal starlark.Value
			iter    = v.Iterate()
			value   = make([]interface{}, v.Len())
		)

		defer iter.Done()
		for iter.Next(&listVal) {
			value[i], err = UnmarshalStarlark(listVal)
			if err != nil {
				return
			}
			i++
		}

		allInt := true
		allString := true
		allMapStringString := true
		allMapStringAny := true
		allMap := true
		for _, entry := range value {
			switch entry.(type) {
			case int:
				allString = false
				allMapStringString = false
				allMapStringAny = false
				allMap = false
			case string:
				allInt = false
				allMapStringString = false
				allMapStringAny = false
				allMap = false
			case map[string]string:
				allInt = false
				allString = false
				allMapStringAny = false
				allMap = false
			case map[string]any:
				allInt = false
				allString = false
				allMapStringString = false
				allMap = false
			case map[any]any:
				allInt = false
				allString = false
				allMapStringString = false
				allMapStringAny = false
			default:
				allInt = false
				allString = false
				allMapStringString = false
				allMapStringAny = false
				allMap = false
			}

			if !allInt && !allString && !allMapStringString && !allMapStringAny && !allMap {
				break
			}
		}

		if allString {
			ret := make([]string, len(value))
			for i, v := range value {
				ret[i] = v.(string)
			}
			val = ret
		} else if allInt {
			ret := make([]int, len(value))
			for i, v := range value {
				ret[i] = v.(int)
			}
			val = ret
		} else if allMapStringString {
			ret := make([]map[string]string, len(value))
			for i, v := range value {
				ret[i] = v.(map[string]string)
			}
			val = ret
		} else if allMapStringAny {
			ret := make([]map[string]any, len(value))
			for i, v := range value {
				ret[i] = v.(map[string]any)
			}
			val = ret
		} else if allMap {
			ret := make([]map[any]any, len(value))
			for i, v := range value {
				ret[i] = v.(map[any]any)
			}
			val = ret
		} else {
			val = value
		}
	case starlark.Tuple:
		var (
			i        int
			tupleVal starlark.Value
			iter     = v.Iterate()
			value    = make([]interface{}, v.Len())
		)

		defer iter.Done()
		for iter.Next(&tupleVal) {
			value[i], err = UnmarshalStarlark(tupleVal)
			if err != nil {
				return
			}
			i++
		}
		val = value
	case *starlark.Set:
		fmt.Println("errnotdone: SET")
		err = fmt.Errorf("sets aren't yet supported")
	case *starlarkstruct.Struct:
		if _var, ok := v.Constructor().(Unmarshaler); ok {
			err = _var.UnmarshalStarlark(x)
			if err != nil {
				err = fmt.Errorf("failed marshal %q to Starlark object : %w", v.Constructor().Type(), err)
				return
			}
			val = _var
		} else {
			err = fmt.Errorf("constructor object from *starlarkstruct.Struct does not support Unmarshaler: %s", v.Constructor().Type())
		}
	default:
		if _var, ok := v.(TypeUnmarshaler); ok {
			var ret any
			ret, err = _var.UnmarshalStarlarkType()
			if err != nil {
				err = fmt.Errorf("failed marshal %q to Starlark object : %w", v.Type(), err)
				return
			}
			val = ret
		} else {
			err = fmt.Errorf("unrecognized starlark type: %s", x.Type())
		}

	}
	return
}

// MarshalStarlark turns go values into starlark types
func MarshalStarlark(data interface{}) (v starlark.Value, err error) {
	switch x := data.(type) {
	case nil:
		v = starlark.None
	case bool:
		v = starlark.Bool(x)
	case string:
		v = starlark.String(x)
	case int:
		v = starlark.MakeInt(x)
	case int8:
		v = starlark.MakeInt(int(x))
	case int16:
		v = starlark.MakeInt(int(x))
	case int32:
		v = starlark.MakeInt(int(x))
	case int64:
		v = starlark.MakeInt64(x)
	case uint:
		v = starlark.MakeUint(x)
	case uint8:
		v = starlark.MakeUint(uint(x))
	case uint16:
		v = starlark.MakeUint(uint(x))
	case uint32:
		v = starlark.MakeUint(uint(x))
	case uint64:
		v = starlark.MakeUint64(x)
	case float32:
		v = starlark.Float(float64(x))
	case float64:
		v = starlark.Float(x)
	case time.Time:
		v = startime.Time(x)
	case []interface{}:
		var elems = make([]starlark.Value, len(x))
		for i, val := range x {
			elems[i], err = MarshalStarlark(val)
			if err != nil {
				return
			}
		}
		v = starlark.NewList(elems)
	case []string:
		var elems = make([]starlark.Value, len(x))
		for i, val := range x {
			elems[i] = starlark.String(val)
		}
		v = starlark.NewList(elems)
	case map[interface{}]interface{}:
		dict := &starlark.Dict{}
		var elem starlark.Value
		for ki, val := range x {
			var key starlark.Value
			key, err = MarshalStarlark(ki)
			if err != nil {
				return
			}

			elem, err = MarshalStarlark(val)
			if err != nil {
				return
			}
			if err = dict.SetKey(key, elem); err != nil {
				return
			}
		}
		v = dict
	case []map[string]any:
		var elems = make([]starlark.Value, len(x))
		for i, val := range x {
			elems[i], err = MarshalStarlark(val)
			if err != nil {
				return
			}
		}
		v = starlark.NewList(elems)
	case []map[string]string:
		var elems = make([]starlark.Value, len(x))
		for i, val := range x {
			elems[i], err = MarshalStarlark(val)
			if err != nil {
				return
			}
		}
		v = starlark.NewList(elems)
	case map[string]any:
		dict := &starlark.Dict{}
		var elem starlark.Value
		for key, val := range x {
			elem, err = MarshalStarlark(val)
			if err != nil {
				return
			}
			if err = dict.SetKey(starlark.String(key), elem); err != nil {
				return
			}
		}
		v = dict
	case http.Header:
		dict := &starlark.Dict{}
		var elem starlark.Value
		for key, val := range x {
			elem, err = MarshalStarlark(val)
			if err != nil {
				return
			}
			if err = dict.SetKey(starlark.String(key), elem); err != nil {
				return
			}
		}
		v = dict
	case map[string]string:
		dict := &starlark.Dict{}
		var elem starlark.Value
		for key, val := range x {
			elem = starlark.String(val)
			if err = dict.SetKey(starlark.String(key), elem); err != nil {
				return
			}
		}
		v = dict
	case url.Values:
		dict := &starlark.Dict{}
		var elem starlark.Value
		for key, val := range x {
			elem, err = MarshalStarlark(val)
			if err != nil {
				return
			}

			if err = dict.SetKey(starlark.String(key), elem); err != nil {
				return
			}
		}
		v = dict
	case Marshaler:
		v, err = x.MarshalStarlark()
	default:
		return starlark.None, fmt.Errorf("unrecognized type: %#v %t", x, x)
	}
	return
}

// Unmarshaler is the interface use to unmarshal starlark custom types.
type Unmarshaler interface {
	// UnmarshalStarlark unmarshal a starlark object to custom type.
	UnmarshalStarlark(starlark.Value) error
}

// Marshaler is the interface use to marshal starlark custom types.
type Marshaler interface {
	// MarshalStarlark marshal a custom type to starlark object.
	MarshalStarlark() (starlark.Value, error)
}

// Unmarshaler is the interface use to unmarshal starlark custom types.
type TypeUnmarshaler interface {
	// UnmarshalStarlark unmarshals a starlark object to go object
	UnmarshalStarlarkType() (any, error)
}
