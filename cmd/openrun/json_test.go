// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json/v2"
	"testing"
)

func TestCLIJSONIsDeterministic(t *testing.T) {
	var out bytes.Buffer
	enc := newJSONEncoder(&out, false)
	if err := json.MarshalEncode(enc, map[string]int{"b": 2, "a": 1}, deterministicJSON); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "{\"a\":1,\"b\":2}\n"; got != want {
		t.Fatalf("JSON output = %q, want %q", got, want)
	}
}
