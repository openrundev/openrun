// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestStreamResponse(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"index.go.html": `
		<div>
{{.}}
</div>
`,
		"app.star": `
load("exec.in", "exec")

app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return exec.run("sh", ["-c", 'echo "aa"; sleep 5; echo "bb"'], stream=True)
`}
	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"exec.in"}, []types.Permission{{Plugin: "exec.in", Method: "run"}}, nil)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	request := httptest.NewRequest("GET", "/test", nil)
	// exec is a system plugin: an authenticated caller is required
	request = request.WithContext(context.WithValue(request.Context(), types.USER_ID, "testuser"))
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "text/html; charset=utf-8", response.Header().Get("Content-Type"))
	testutil.AssertStringContains(t, response.Body.String(), "aa")
}

func TestStreamResponseError(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
load("exec.in", "exec")

app = ace.app("testApp", custom_layout=True, routes = [ace.api("/")])

def handler(req):
	return exec.run("ls", ["-l", "/tmp"], stream=True).value
`}
	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"exec.in"}, []types.Permission{{Plugin: "exec.in", Method: "run"}}, nil)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	request := httptest.NewRequest("GET", "/test", nil)
	// exec is a system plugin: an authenticated caller is required
	request = request.WithContext(context.WithValue(request.Context(), types.USER_ID, "testuser"))
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "stream value cannot be accessed in Starlark")
}

func TestResponseTypes(t *testing.T) {
	for _, tc := range []struct {
		name, routes, handler        string
		path, template, mode         string
		status                       int
		contentType, body, loadError string
	}{
		{name: "root API with template", mode: "root", path: "/", routes: `ace.api("/")`, handler: `{"a": "aval", "b": 1}`,
			template: `Template. {{block "testtmpl" .}}ABC {{.Data.key}} {{end}}`},
		{name: "API without template", routes: `ace.api("/")`, handler: `{"a": "aval", "b": 1}`},
		{name: "API fragment", path: "/test/frag", routes: `ace.html("/", fragments=[ace.api("frag")])`, handler: `{"a": "aval", "b": 1}`},
		{name: "explicit JSON response", routes: `ace.html("/")`, handler: `ace.response({"a": "aval", "b": 1}, type="json")`},
		{name: "text overrides JSON", mode: "prod", routes: `ace.api("/", type=ace.JSON)`, handler: `ace.response(100, type=ace.TEXT)`, contentType: "text/plain", body: "100"},
		{name: "response inherits API type", routes: `ace.api("/")`, handler: `ace.response({"a": "aval", "b": 1})`},
		{name: "response inherits fragment type", path: "/test/frag", routes: `ace.html("/", fragments=[ace.api("frag")])`, handler: `ace.response({"a": "aval", "b": 1})`},
		{name: "HTML fragment needs block", path: "/test/frag", routes: `ace.html("/", fragments=[ace.fragment("frag")])`, handler: `ace.response({"a": "aval", "b": 1})`,
			status: http.StatusInternalServerError, body: "Error handling response: block not defined in response and type is not json/text\n"},
		{name: "invalid API type", path: "/test/frag", routes: `ace.html("/", fragments=[ace.api("frag", type="abc")])`, handler: `ace.response({"a": "aval", "b": 1})`, loadError: "invalid API type specified : ABC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ""
			if tc.mode == "root" {
				layout = ", custom_layout=True"
			}
			files := map[string]string{"app.star": fmt.Sprintf("app = ace.app(\"testApp\"%s, routes=[%s])\n\ndef handler(req):\n    return %s", layout, tc.routes, tc.handler)}
			if tc.template != "" {
				files["index.go.html"] = tc.template
			}
			create := CreateDevModeTestApp
			if tc.mode == "root" {
				create = CreateTestAppRoot
			}
			if tc.mode == "prod" {
				create = CreateTestApp
			}
			a, _, err := create(testutil.TestLogger(), files)
			if tc.loadError != "" {
				testutil.AssertErrorContains(t, err, tc.loadError)
				return
			}
			if err != nil {
				// A failed create leaves no app to serve from
				t.Fatalf("create app: %s", err)
			}
			response := httptest.NewRecorder()
			path, status := tc.path, tc.status
			if path == "" {
				path = "/test"
			}
			if status == 0 {
				status = http.StatusOK
			}
			a.ServeHTTP(response, httptest.NewRequest("GET", path, nil))
			testutil.AssertEqualsInt(t, "code", status, response.Code)
			if tc.body == "" {
				testutil.AssertEqualsString(t, "type", "application/json", response.Header().Get("Content-Type"))
				var ret map[string]any
				testutil.AssertNoError(t, json.UnmarshalRead(response.Body, &ret))
				testutil.AssertEqualsString(t, "a", "aval", ret["a"].(string))
				testutil.AssertEqualsInt(t, "b", 1, int(ret["b"].(float64)))
			} else {
				if tc.contentType != "" {
					testutil.AssertStringContains(t, response.Header().Get("Content-Type"), tc.contentType)
				}
				testutil.AssertEqualsString(t, "body", tc.body, response.Body.String())
			}
		})
	}
}
