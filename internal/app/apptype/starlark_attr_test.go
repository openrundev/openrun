// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package apptype

import (
	"reflect"
	"testing"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func TestGetDictStringAttr(t *testing.T) {
	dict := starlark.NewDict(2)
	if err := dict.SetKey(starlark.String("first"), starlark.String("one")); err != nil {
		t.Fatal(err)
	}
	if err := dict.SetKey(starlark.String("second"), starlark.String("two")); err != nil {
		t.Fatal(err)
	}
	value := starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{"values": dict})

	got, err := GetDictStringAttr(value, "values", false)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"first": "one", "second": "two"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestGetDictStringAttrRejectsNonStringValue(t *testing.T) {
	dict := starlark.NewDict(1)
	if err := dict.SetKey(starlark.String("count"), starlark.MakeInt(1)); err != nil {
		t.Fatal(err)
	}
	value := starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{"values": dict})

	if _, err := GetDictStringAttr(value, "values", false); err == nil {
		t.Fatal("expected non-string value error")
	}
}
