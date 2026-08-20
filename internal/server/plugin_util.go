// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
)

// structValue converts a Go value (structs, slices of structs, maps, ...)
// into plugin-transportable form: structs become map[string]any keyed by
// json tag names (falling back to the Go field name), recursively. Unlike a
// json round trip there is no serialization and full type fidelity is kept:
// ints stay ints, time.Time values stay timestamps (starlark time.time),
// []byte stays bytes. Fields tagged `json:"-"` are skipped; omitempty has no
// effect (zero-valued fields are always present).
//
// Conversion is reflection-based with a cached per-type field plan, ~8x
// faster than the json round trip it replaced (see plugin_util_bench_test.go).
func structValue(v any) (any, error) {
	return reflectToValue(reflect.ValueOf(v), 0)
}

// maxStructValueDepth bounds recursion: Go values can be cyclic (a struct
// holding a pointer back to itself), so conversion fails cleanly instead of
// recursing forever.
const maxStructValueDepth = 100

var timeType = reflect.TypeOf(time.Time{})

func reflectToValue(rv reflect.Value, depth int) (any, error) {
	if depth > maxStructValueDepth {
		return nil, fmt.Errorf("value nesting exceeds max depth %d (cyclic value?)", maxStructValueDepth)
	}
	depth++

	switch rv.Kind() {
	case reflect.Invalid:
		return nil, nil
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil, nil
		}
		return reflectToValue(rv.Elem(), depth)
	case reflect.Bool:
		return rv.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint(), nil
	case reflect.Float32, reflect.Float64:
		return rv.Float(), nil
	case reflect.String:
		return rv.String(), nil
	case reflect.Slice:
		if rv.IsNil() {
			return nil, nil
		}
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			// []byte (and named byte-slice types) stay bytes
			out := make([]byte, rv.Len())
			reflect.Copy(reflect.ValueOf(out), rv)
			return out, nil
		}
		return reflectSliceToValue(rv, depth)
	case reflect.Array:
		return reflectSliceToValue(rv, depth)
	case reflect.Map:
		if rv.IsNil() {
			return nil, nil
		}
		if rv.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("cannot convert map with %s keys for plugin transport", rv.Type().Key())
		}
		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			value, err := reflectToValue(iter.Value(), depth)
			if err != nil {
				return nil, err
			}
			out[iter.Key().String()] = value
		}
		return out, nil
	case reflect.Struct:
		if rv.Type() == timeType {
			return rv.Interface().(time.Time), nil
		}
		plan := planForType(rv.Type())
		out := make(map[string]any, len(plan))
		for _, f := range plan {
			fv, err := rv.FieldByIndexErr(f.index)
			if err != nil {
				// A nil embedded pointer on the promoted field's path: the
				// promoted fields are absent, matching encoding/json
				continue
			}
			value, err := reflectToValue(fv, depth)
			if err != nil {
				return nil, err
			}
			out[f.name] = value
		}
		return out, nil
	default:
		return nil, fmt.Errorf("cannot convert value of kind %s for plugin transport", rv.Kind())
	}
}

func reflectSliceToValue(rv reflect.Value, depth int) ([]any, error) {
	out := make([]any, rv.Len())
	for i := range out {
		value, err := reflectToValue(rv.Index(i), depth)
		if err != nil {
			return nil, err
		}
		out[i] = value
	}
	return out, nil
}

// structFieldPlan is one exported field of a struct type: its output name
// (json tag name, or the Go field name) and its index path (promoted fields
// of embedded structs have multi-element paths).
type structFieldPlan struct {
	name  string
	index []int
}

var structPlans sync.Map // reflect.Type -> []structFieldPlan

func planForType(t reflect.Type) []structFieldPlan {
	if cached, ok := structPlans.Load(t); ok {
		return cached.([]structFieldPlan)
	}

	fields := reflect.VisibleFields(t)
	plan := make([]structFieldPlan, 0, len(fields))
	for _, sf := range fields {
		if sf.Anonymous || !sf.IsExported() {
			// Embedded structs contribute their promoted fields, not an
			// entry of their own, matching encoding/json
			continue
		}
		name := sf.Name
		if tag, ok := sf.Tag.Lookup("json"); ok {
			tagName, _, _ := strings.Cut(tag, ",")
			if tagName == "-" {
				continue
			}
			if tagName != "" {
				name = tagName
			}
		}
		plan = append(plan, structFieldPlan{name: name, index: sf.Index})
	}

	structPlans.Store(t, plan)
	return plan
}
