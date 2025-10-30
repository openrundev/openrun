// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"encoding/json"
	"fmt"

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
	mapVal, err := ConvertToMap(p)
	if err != nil {
		return nil, err
	}

	return MarshalStarlark(mapVal)
}
