// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// Copied from https://github.com/qri-io/starlib/blob/master/http/http_test.go
func TestSetBody(t *testing.T) {
	fd := map[string]string{
		"foo": "bar baz",
	}

	cases := []struct {
		rawBody      starlark.String
		formData     map[string]string
		formEncoding starlark.String
		jsonData     starlark.Value
		body         string
		err          string
	}{
		{starlark.String("hallo"), nil, starlark.String(""), nil, "hallo", ""},
		{starlark.String(""), fd, starlark.String(""), nil, "foo=bar+baz", ""},
		// TODO - this should check multipart form data is being set
		{starlark.String(""), fd, starlark.String("multipart/form-data"), nil, "", ""},
		{starlark.String(""), nil, starlark.String(""), starlark.Tuple{starlark.Bool(true), starlark.MakeInt(1), starlark.String("der")}, "[true,1,\"der\"]", ""},
	}

	for i, c := range cases {
		var formData *starlark.Dict
		if c.formData != nil {
			formData = starlark.NewDict(len(c.formData))
			for k, v := range c.formData {
				if err := formData.SetKey(starlark.String(k), starlark.String(v)); err != nil {
					t.Fatal(err)
				}
			}
		}

		req := httptest.NewRequest("get", "https://example.com", nil)
		err := setBody(req, c.rawBody, formData, c.formEncoding, c.jsonData)
		if !(err == nil && c.err == "" || (err != nil && err.Error() == c.err)) { //nolint:staticcheck
			t.Errorf("case %d error mismatch. expected: %s, got: %s", i, c.err, err)
			continue
		}

		if strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/form-data;") {
			if err := req.ParseMultipartForm(0); err != nil {
				t.Fatal(err)
			}

			for k, v := range c.formData {
				fv := req.FormValue(k)
				if fv != v {
					t.Errorf("case %d error mismatch. expected %s=%s, got: %s", i, k, v, fv)
				}
			}
		} else {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}

			if string(body) != c.body {
				t.Errorf("case %d body mismatch. expected: %s, got: %s", i, c.body, string(body))
			}
		}
	}
}
