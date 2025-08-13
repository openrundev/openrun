// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package apptype

import (
	"testing"

	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/testutil"
)

func TestValidateStoreInfo(t *testing.T) {
	storeInfo := &starlark_type.StoreInfo{
		Types: []starlark_type.StoreType{
			{
				Name: "Type1",
				Fields: []starlark_type.StoreField{
					{
						Name:    "Field1",
						Type:    starlark_type.STRING,
						Default: "default",
					},
					{
						Name:    "Field2",
						Type:    starlark_type.INT,
						Default: 1,
					},
				},
				Indexes: []starlark_type.Index{
					{
						Fields: []string{"Field1"},
						Unique: true,
					},
				},
			},
			{
				Name: "Type2",
				Fields: []starlark_type.StoreField{
					{
						Name:    "Field1",
						Type:    starlark_type.STRING,
						Default: "default",
					},
					{
						Name:    "Field2",
						Type:    starlark_type.INT,
						Default: 1,
					},
				},
				Indexes: []starlark_type.Index{
					{
						Fields: []string{"Field1:asc", "Field2:DESC"},
						Unique: true,
					},
				},
			},
		},
	}

	err := validateStoreInfo(storeInfo)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	storeInfo.Types = append(storeInfo.Types, starlark_type.StoreType{
		Name: "Type1",
		Fields: []starlark_type.StoreField{
			{
				Name:    "Field1",
				Type:    starlark_type.STRING,
				Default: "default",
			},
			{
				Name:    "Field1",
				Type:    starlark_type.INT,
				Default: 1,
			},
		},
	})

	err = validateStoreInfo(storeInfo)
	if err == nil {
		t.Fatal("Expected error")
	} else {
		testutil.AssertEqualsString(t, "error message", "type Type1 already defined", err.Error())
	}

	storeInfo.Types[2].Name = "Type3"
	err = validateStoreInfo(storeInfo)
	if err == nil {
		t.Fatal("Expected error")
	} else {
		testutil.AssertEqualsString(t, "error message", "field Field1 already defined in type Type3", err.Error())
	}

	storeInfo.Types[2].Fields[1].Name = "Field2"
	storeInfo.Types[2].Indexes = []starlark_type.Index{
		{
			Fields: []string{"Invalid"},
			Unique: true,
		},
	}

	err = validateStoreInfo(storeInfo)
	if err == nil {
		t.Fatal("Expected error")
	} else {
		testutil.AssertEqualsString(t, "error message", "index field Invalid not defined in type Type3", err.Error())
	}

	storeInfo.Types[2].Indexes[0].Fields[0] = "Field1:Invalid"
	err = validateStoreInfo(storeInfo)
	if err == nil {
		t.Fatal("Expected error")
	} else {
		testutil.AssertEqualsString(t, "error message", "invalid index field Field1:Invalid in type Type3", err.Error())
	}

	storeInfo.Types[2].Indexes[0].Fields[0] = "Field1:asc:bad"
	err = validateStoreInfo(storeInfo)
	if err == nil {
		t.Fatal("Expected error")
	} else {
		testutil.AssertEqualsString(t, "error message", "invalid index field Field1:asc:bad in type Type3", err.Error())
	}
}
