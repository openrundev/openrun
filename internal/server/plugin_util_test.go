// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"reflect"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

type utilEmbedded struct {
	Inner  string
	hidden string //nolint:unused // exercises unexported field skipping
}

type utilNested struct {
	N int `json:"n"`
}

type utilSample struct {
	utilEmbedded
	Name      string
	Id        types.AppId // named string type must arrive as a plain string
	Count     int         `json:"count"`
	Ratio     float64     `json:"ratio,omitempty"` // omitempty is ignored: zero values stay present
	Active    bool
	Skipped   string `json:"-"`
	When      time.Time
	Data      []byte
	Tags      []string
	Rows      []utilNested
	Meta      map[string]any
	Child     *utilNested
	NilChild  *utilNested
	NilSlice  []string
	unexpored int //nolint:unused
}

func TestStructValue(t *testing.T) {
	when := time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC)
	sample := utilSample{
		utilEmbedded: utilEmbedded{Inner: "promoted"},
		Name:         "app one",
		Id:           "app_prd_123",
		Count:        42,
		Active:       true,
		Skipped:      "never seen",
		When:         when,
		Data:         []byte{1, 2},
		Tags:         []string{"a", "b"},
		Rows:         []utilNested{{N: 1}, {N: 2}},
		Meta:         map[string]any{"k": utilNested{N: 3}},
		Child:        &utilNested{N: 4},
	}

	got, err := structValue(sample)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]any{
		"Inner":    "promoted", // embedded struct fields are promoted
		"Name":     "app one",
		"Id":       "app_prd_123", // named string type normalized to string
		"count":    int64(42),     // json tag name; int stays an integer
		"ratio":    float64(0),    // omitempty ignored: zero value present
		"Active":   true,
		"When":     when, // time.Time passes through (starlark time.time)
		"Data":     []byte{1, 2},
		"Tags":     []any{"a", "b"},
		"Rows":     []any{map[string]any{"n": int64(1)}, map[string]any{"n": int64(2)}},
		"Meta":     map[string]any{"k": map[string]any{"n": int64(3)}},
		"Child":    map[string]any{"n": int64(4)},
		"NilChild": nil,
		"NilSlice": nil,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("structValue mismatch:\n got:  %#v\n want: %#v", got, want)
	}

	// The result must be plugin-transportable (same rules for the in-process
	// bridge and the wire codec)
	if _, err := sdk.EncodeValue(got); err != nil {
		t.Fatalf("structValue output is not transportable: %v", err)
	}
}

func TestStructValueScalarsAndPointers(t *testing.T) {
	if got, err := structValue(nil); err != nil || got != nil {
		t.Fatalf("nil: %v, %v", got, err)
	}
	if got, err := structValue("plain"); err != nil || got != "plain" {
		t.Fatalf("string: %v, %v", got, err)
	}
	if got, err := structValue(uint16(7)); err != nil || got != uint64(7) {
		t.Fatalf("uint: %v, %v", got, err)
	}
	nested := &utilNested{N: 9}
	got, err := structValue(&nested) // pointer to pointer
	if err != nil || !reflect.DeepEqual(got, map[string]any{"n": int64(9)}) {
		t.Fatalf("double pointer: %v, %v", got, err)
	}
}

func TestStructValueErrors(t *testing.T) {
	if _, err := structValue(map[int]string{1: "a"}); err == nil {
		t.Fatal("expected error for non-string map keys")
	}
	if _, err := structValue(func() {}); err == nil {
		t.Fatal("expected error for unsupported kind")
	}

	type cyclic struct {
		Self *cyclic
	}
	c := &cyclic{}
	c.Self = c
	if _, err := structValue(c); err == nil {
		t.Fatal("expected depth error for cyclic value")
	}
}

// A nil embedded struct pointer drops its promoted fields instead of
// panicking, matching encoding/json/v2.
func TestStructValueNilEmbeddedPointer(t *testing.T) {
	type embedded struct{ Promoted string }
	type outer struct {
		*embedded
		Own string
	}
	got, err := structValue(outer{Own: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{"Own": "x"}) {
		t.Fatalf("nil embedded pointer: %#v", got)
	}
}
