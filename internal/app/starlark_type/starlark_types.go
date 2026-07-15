// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"encoding/json"
	"fmt"
	"math"

	"go.starlark.net/starlark"
)

// StarlarkType represents a Starlark type created from the schema type definition.
type StarlarkType struct {
	name string
	data map[string]starlark.Value
	keys []string
}

var _ starlark.Value = (*StarlarkType)(nil)

func NewStarlarkType(name string, data map[string]starlark.Value) *StarlarkType {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}

	return &StarlarkType{
		name: name,
		data: data,
		keys: keys,
	}
}

func (s *StarlarkType) Attr(attr string) (starlark.Value, error) {
	val, ok := s.data[attr]
	if !ok {
		return starlark.None, fmt.Errorf("type %s has no attribute '%s'", s.name, attr)
	}
	return val, nil
}

func (s *StarlarkType) AttrNames() []string {
	return s.keys
}

func (s *StarlarkType) SetField(name string, val starlark.Value) error {
	if _, ok := s.data[name]; !ok {
		return starlark.NoSuchAttrError(fmt.Sprintf("type %s has no attribute '%s'", s.name, name))
	}

	s.data[name] = val
	return nil
}

func (s *StarlarkType) String() string {
	return fmt.Sprintf("type %s", s.name)
}

func (s *StarlarkType) Type() string {
	return s.name
}

func (s *StarlarkType) Freeze() {
	// Not supported
}

func (s *StarlarkType) Truth() starlark.Bool {
	return true
}

func (s *StarlarkType) Hash() (uint32, error) {
	values := make([]starlark.Value, 0, len(s.data))
	for _, v := range s.data {
		values = append(values, v)
	}

	return starlark.Tuple(values).Hash()
}

func (s *StarlarkType) UnmarshalStarlarkType() (any, error) {
	ret := make(map[string]any)
	for k, v := range s.data {
		var err error
		ret[k], err = UnmarshalStarlark(v)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

// ConvertToMap converts a struct to a map[string]any
func ConvertToMap(p any) (map[string]any, error) {
	jsonBytes, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func ConvertToStarlark(p any) (starlark.Value, error) {
	// Fast path: inputs already composed of json-primitive Go types (the common
	// case - plugins build map[string]any results) convert directly, skipping
	// the json.Marshal + json.Unmarshal round-trip and its intermediate
	// map[string]any tree. jsonCompatMarshal reproduces the round-trip's output
	// exactly (all numbers become starlark floats, nil maps/slices become None)
	// and returns ok=false for anything json would normalize differently
	// (time.Time, []byte, structs, ...), which falls back to the json path.
	if v, ok := jsonCompatMarshal(p); ok {
		return v, nil
	}

	mapVal, err := ConvertToMap(p)
	if err != nil {
		return nil, err
	}

	return MarshalStarlark(mapVal)
}

// jsonCompatMarshal converts go values that are already in json-primitive form
// directly into starlark, matching the result of the
// json.Marshal->Unmarshal->MarshalStarlark round-trip used by ConvertToStarlark.
// The key compatibility points: every number becomes a starlark float (json
// decodes numbers as float64), nil maps and slices become None (they marshal to
// json null), and non-finite floats are rejected (json.Marshal errors on them).
// It returns ok=false for any type json would treat differently or reject, so
// the caller falls back to the exact json path.
func jsonCompatMarshal(p any) (starlark.Value, bool) {
	switch x := p.(type) {
	case nil:
		return starlark.None, true
	case bool:
		return starlark.Bool(x), true
	case string:
		return starlark.String(x), true
	case int:
		return starlark.Float(float64(x)), true
	case int8:
		return starlark.Float(float64(x)), true
	case int16:
		return starlark.Float(float64(x)), true
	case int32:
		return starlark.Float(float64(x)), true
	case int64:
		return starlark.Float(float64(x)), true
	case uint:
		return starlark.Float(float64(x)), true
	case uint8:
		return starlark.Float(float64(x)), true
	case uint16:
		return starlark.Float(float64(x)), true
	case uint32:
		return starlark.Float(float64(x)), true
	case uint64:
		return starlark.Float(float64(x)), true
	case float32:
		f := float64(x)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, false
		}
		return starlark.Float(f), true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, false
		}
		return starlark.Float(x), true
	case map[string]any:
		if x == nil {
			return starlark.None, true
		}
		dict := starlark.NewDict(len(x))
		for k, val := range x {
			sv, ok := jsonCompatMarshal(val)
			if !ok {
				return nil, false
			}
			if err := dict.SetKey(starlark.String(k), sv); err != nil {
				return nil, false
			}
		}
		return dict, true
	case []any:
		if x == nil {
			return starlark.None, true
		}
		elems := make([]starlark.Value, len(x))
		for i, val := range x {
			sv, ok := jsonCompatMarshal(val)
			if !ok {
				return nil, false
			}
			elems[i] = sv
		}
		return starlark.NewList(elems), true
	case map[string]string:
		if x == nil {
			return starlark.None, true
		}
		dict := starlark.NewDict(len(x))
		for k, val := range x {
			if err := dict.SetKey(starlark.String(k), starlark.String(val)); err != nil {
				return nil, false
			}
		}
		return dict, true
	case []string:
		if x == nil {
			return starlark.None, true
		}
		elems := make([]starlark.Value, len(x))
		for i, s := range x {
			elems[i] = starlark.String(s)
		}
		return starlark.NewList(elems), true
	case []map[string]any:
		if x == nil {
			return starlark.None, true
		}
		elems := make([]starlark.Value, len(x))
		for i, m := range x {
			sv, ok := jsonCompatMarshal(m)
			if !ok {
				return nil, false
			}
			elems[i] = sv
		}
		return starlark.NewList(elems), true
	case []map[string]string:
		if x == nil {
			return starlark.None, true
		}
		elems := make([]starlark.Value, len(x))
		for i, m := range x {
			sv, ok := jsonCompatMarshal(m)
			if !ok {
				return nil, false
			}
			elems[i] = sv
		}
		return starlark.NewList(elems), true
	default:
		return nil, false
	}
}
