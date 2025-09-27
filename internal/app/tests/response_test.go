// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestRTypeBasic(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.api("/")])

def handler(req):
	return {"a": "aval", "b": 1}`,
		"index.go.html": `Template. {{block "testtmpl" .}}ABC {{.Data.key}} {{end}}`,
	}
	a, _, err := CreateTestAppRoot(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "application/json", response.Header().Get("Content-Type"))
	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck
	testutil.AssertEqualsString(t, "a", ret["a"].(string), "aval")
	testutil.AssertEqualsInt(t, "b", int(ret["b"].(float64)), 1)
}

func TestRTypeNoTemplate(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.api("/")])

def handler(req):
	return {"a": "aval", "b": 1}`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "application/json", response.Header().Get("Content-Type"))
	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck
	testutil.AssertEqualsString(t, "a", ret["a"].(string), "aval")
	testutil.AssertEqualsInt(t, "b", int(ret["b"].(float64)), 1)
}

func TestRTypeFragment(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/", fragments=[ace.api("frag")])])

def handler(req):
	return {"a": "aval", "b": 1}`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/frag", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "application/json", response.Header().Get("Content-Type"))
	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck
	testutil.AssertEqualsString(t, "a", ret["a"].(string), "aval")
	testutil.AssertEqualsInt(t, "b", int(ret["b"].(float64)), 1)
}

func TestRTypeResponse(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/")])

def handler(req):
	return ace.response({"a": "aval", "b": 1}, type="json")`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "application/json", response.Header().Get("Content-Type"))
	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck
	testutil.AssertEqualsString(t, "a", ret["a"].(string), "aval")
	testutil.AssertEqualsInt(t, "b", int(ret["b"].(float64)), 1)
}

func TestRTypeText(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.api("/", type=ace.JSON)])

def handler(req):
	return ace.response(100, type=ace.TEXT)`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Header().Get("Content-Type"), "text/plain")
	testutil.AssertEqualsString(t, "body", "100", response.Body.String())

}

func TestRTypeResponseInherit(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.api("/")])

def handler(req):
	return ace.response({"a": "aval", "b": 1})`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "application/json", response.Header().Get("Content-Type"))
	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck
	testutil.AssertEqualsString(t, "a", ret["a"].(string), "aval")
	testutil.AssertEqualsInt(t, "b", int(ret["b"].(float64)), 1)
}

func TestRTypeFragmentInherit(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/", fragments=[ace.api("frag")])])

def handler(req):
	return ace.response({"a": "aval", "b": 1})`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/frag", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "application/json", response.Header().Get("Content-Type"))
	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck
	testutil.AssertEqualsString(t, "a", ret["a"].(string), "aval")
	testutil.AssertEqualsInt(t, "b", int(ret["b"].(float64)), 1)
}

func TestRTypeResponseInvalid(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/", fragments=[ace.fragment("frag")])])

def handler(req):
	return ace.response({"a": "aval", "b": 1})`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/frag", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertEqualsString(t, "error", "Error handling response: block not defined in response and type is not json/text\n", response.Body.String())
}

func TestRTypeInvalidType(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/", fragments=[ace.api("frag", type="abc")])])

def handler(req):
	return ace.response({"a": "aval", "b": 1})`,
	}
	_, _, err := CreateDevModeTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "invalid API type specified : ABC")
}

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
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "stream value cannot be accessed in Starlark")
}
