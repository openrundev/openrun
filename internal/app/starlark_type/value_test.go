// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	sdk "github.com/openrundev/openrun/pkg/plugin"
	"go.starlark.net/starlark"
)

func mustSetKey(t *testing.T, dict *starlark.Dict, key, value starlark.Value) {
	t.Helper()
	if err := dict.SetKey(key, value); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationValueShapes(t *testing.T) {
	dict := starlark.NewDict(3)
	mustSetKey(t, dict, starlark.String("count"), starlark.MakeInt(7))
	mustSetKey(t, dict, starlark.String("names"), starlark.NewList([]starlark.Value{
		starlark.String("a"), starlark.String("b"),
	}))
	mustSetKey(t, dict, starlark.String("tuple"), starlark.Tuple{
		starlark.MakeInt(1), starlark.MakeInt(2),
	})

	got, err := ToGo(dict)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"count": 7,
		"names": []string{"a", "b"},
		"tuple": []any{1, 2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestApplicationTypedValueBecomesMap(t *testing.T) {
	value := NewStarlarkType("entry", map[string]starlark.Value{
		"name": starlark.String("first"),
		"id":   starlark.MakeInt(1),
	})
	got, err := ToGo(value)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"name": "first", "id": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestApplicationNonComparableDictKeyReturnsError(t *testing.T) {
	dict := starlark.NewDict(1)
	mustSetKey(t, dict, starlark.Tuple{starlark.MakeInt(1)}, starlark.String("value"))
	if _, err := ToGo(dict); err == nil {
		t.Fatal("expected tuple-key conversion error")
	}
}

func TestApplicationFromGoNamedMaps(t *testing.T) {
	tests := []struct {
		value any
		want  any
	}{
		{http.Header{"X-Test": []string{"one", "two"}}, map[string]any{"X-Test": []string{"one", "two"}}},
		{url.Values{"query": []string{"a", "b"}}, map[string]any{"query": []string{"a", "b"}}},
		{[]map[string]string{{"key": "value"}}, []map[string]any{{"key": "value"}}},
	}
	for _, test := range tests {
		converted, err := FromGo(test.value)
		if err != nil {
			t.Fatalf("FromGo(%T): %v", test.value, err)
		}
		got, err := ToGo(converted)
		if err != nil {
			t.Fatalf("ToGo(%T): %v", test.value, err)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf("round trip %T: got %#v, want %#v", test.value, got, test.want)
		}
	}
}

func TestPluginAndApplicationContractsDiffer(t *testing.T) {
	list := starlark.NewList([]starlark.Value{starlark.String("a"), starlark.String("b")})
	application, err := ToGo(list)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := ToPlugin(list, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := application.([]string); !ok {
		t.Fatalf("application list type = %T, want []string", application)
	}
	if _, ok := plugin.([]any); !ok {
		t.Fatalf("plugin list type = %T, want []any", plugin)
	}

	tuple := starlark.Tuple{starlark.MakeInt(1)}
	plugin, err = ToPlugin(tuple, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plugin.(sdk.Tuple); !ok {
		t.Fatalf("plugin tuple type = %T, want plugin.Tuple", plugin)
	}
}
