// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"fmt"

	"go.starlark.net/starlark"
)

// StarlarkType represents a Starlark type created from the schema type definition.
type StarlarkType struct {
	name string
	data map[string]starlark.Value
	keys []string
	// sealed makes the value read only, see Seal
	sealed bool
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
	if s.sealed {
		return fmt.Errorf("cannot set attribute '%s' of type %s: the value is read only", name, s.name)
	}
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

// Seal makes the value and everything it holds read only. Used for plugin
// results which the platform acts on after the plugin call's permission
// check (proxy and container config): the app must not be able to change
// them once checked
func (s *StarlarkType) Seal() {
	if s.sealed {
		return
	}
	s.sealed = true
	for _, v := range s.data {
		SealValue(v)
	}
}

// SealValue makes a value read only, at any depth: StarlarkType values are
// sealed, the standard collections are frozen
func SealValue(v starlark.Value) {
	switch val := v.(type) {
	case nil:
	case *StarlarkType:
		val.Seal()
	case *starlark.List:
		for i := range val.Len() {
			SealValue(val.Index(i))
		}
		val.Freeze()
	case starlark.Tuple:
		for _, elem := range val {
			SealValue(elem)
		}
	case *starlark.Dict:
		for _, item := range val.Items() {
			SealValue(item[1])
		}
		val.Freeze()
	default:
		v.Freeze()
	}
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
