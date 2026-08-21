// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
)

var (
	deterministicJSON = json.Deterministic(true)
	prettyJSON        = jsontext.WithIndent("  ")
)

func newJSONEncoder(w io.Writer, pretty bool) *jsontext.Encoder {
	if pretty {
		return jsontext.NewEncoder(w, prettyJSON)
	}
	return jsontext.NewEncoder(w)
}
