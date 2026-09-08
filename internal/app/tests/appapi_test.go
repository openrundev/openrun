// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func assertJSONMatch(t *testing.T, name, expected, actual string) {
	t.Helper()

	var expectedVal, actualVal any
	if err := json.Unmarshal([]byte(expected), &expectedVal); err != nil {
		t.Fatalf("%s: error parsing expected JSON %q: %s", name, expected, err)
	}
	if err := json.Unmarshal([]byte(actual), &actualVal); err != nil {
		t.Fatalf("%s: error parsing actual JSON %q: %s", name, actual, err)
	}

	if !reflect.DeepEqual(expectedVal, actualVal) {
		t.Errorf("%s: expected JSON %s, got %s", name, expected, strings.TrimSpace(actual))
	}
}

func createJSONRequest(t *testing.T, reqPath, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest("POST", reqPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func apiTester(t *testing.T, rootPath bool, actionPath string) {
	t.Helper()
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a", "b"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "` + actionPath + `", handler, description="test desc")])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}

	var err error
	appPath := "/test"
	if rootPath {
		appPath = "/"
	}
	a, _, err := CreateTestAppInt(logger, appPath, "", fileData, false, nil, nil, nil, "app_prd_testapp", types.AppSettings{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	apiBase := "/test/api"
	execPath := "/test/api/actions"
	validatePath := "/test/api/validate"
	uiPath := "/test"
	if rootPath {
		apiBase = "/api"
		execPath = "/api/actions"
		validatePath = "/api/validate"
		uiPath = ""
	}
	if actionPath != "/" {
		execPath += actionPath
		validatePath += actionPath
		uiPath += actionPath
	}
	if uiPath == "" {
		uiPath = "/"
	}

	// App level API descriptor
	request := httptest.NewRequest("GET", apiBase, nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "content type", "application/json", response.Header().Get("Content-Type"))
	assertJSONMatch(t, "describe", `{
		"app": "testApp",
		"actions": [{
			"name": "testAction",
			"description": "test desc",
			"path": "`+execPath+`",
			"validate_path": "`+validatePath+`",
			"ui_path": "`+uiPath+`",
			"suggest": false,
			"authorized": true
		}]
	}`, response.Body.String())

	// Action schema
	request = httptest.NewRequest("GET", execPath, nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "schema", `{
		"name": "testAction",
		"description": "test desc",
		"params": [{
			"name": "param1",
			"type": "STRING",
			"description": "param1 description",
			"default": "myvalue",
			"required": true
		}],
		"suggest": false
	}`, response.Body.String())

	// Run the action with a JSON body
	request = createJSONRequest(t, execPath, `{"param1": "abc"}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "content type", "application/json", response.Header().Get("Content-Type"))
	assertJSONMatch(t, "run", `{"status": "done", "report": "TEXT", "values": ["a", "b"]}`, response.Body.String())

	// Run the action with an empty body
	request = httptest.NewRequest("POST", execPath, nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "run empty", `{"status": "done", "report": "TEXT", "values": ["a", "b"]}`, response.Body.String())
}

func TestAPIRootAppRootAction(t *testing.T) {
	apiTester(t, true, "/")
}

func TestAPIRootApp(t *testing.T) {
	apiTester(t, true, "/abc")
}

func TestAPINonRootAppRootAction(t *testing.T) {
	apiTester(t, false, "/")
}

func TestAPINonRootApp(t *testing.T) {
	apiTester(t, false, "/abc")
}

func apiParamApp(t *testing.T) http.Handler {
	t.Helper()
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"c1": args.param1, "c2": args.param2, "c3": args.param3}], report=ace.TABLE)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")
param("param2", description="param2 description", type=BOOLEAN, default=True)
param("param3", description="param3 description", type=INT, default=10)`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	return a
}

func TestAPIParamPost(t *testing.T) {
	a := apiParamApp(t)

	// JSON body with typed values
	request := createJSONRequest(t, "/test/api/actions", `{"param1": "abc", "param2": false, "param3": 20}`)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "typed values", `{"status": "done", "report": "TABLE",
		"values": [{"c1": "abc", "c2": false, "c3": 20}]}`, response.Body.String())

	// Empty JSON body, all params get their default values. Note that the
	// boolean param keeps its default value true, unlike the form UI where
	// a missing checkbox value means false
	request = createJSONRequest(t, "/test/api/actions", `{}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "defaults", `{"status": "done", "report": "TABLE",
		"values": [{"c1": "myvalue", "c2": true, "c3": 10}]}`, response.Body.String())

	// null values also use the defaults
	request = createJSONRequest(t, "/test/api/actions", `{"param1": null, "param3": null}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "null values", `{"status": "done", "report": "TABLE",
		"values": [{"c1": "myvalue", "c2": true, "c3": 10}]}`, response.Body.String())

	// Large integers keep their precision, they are not decoded through a float
	request = createJSONRequest(t, "/test/api/actions", `{"param3": 9007199254740993}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "large int", `{"status": "done", "report": "TABLE",
		"values": [{"c1": "myvalue", "c2": true, "c3": 9007199254740993}]}`, response.Body.String())

	// String values are coerced to the param type, same as form submissions
	request = createJSONRequest(t, "/test/api/actions", `{"param2": "false", "param3": "30"}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "string coercion", `{"status": "done", "report": "TABLE",
		"values": [{"c1": "myvalue", "c2": false, "c3": 30}]}`, response.Body.String())

	// Form encoded body works on the API endpoint, with form semantics for
	// the missing boolean param (set to false)
	values := url.Values{
		"param1": {"formval"},
		"param3": {"40"},
	}
	request = httptest.NewRequest("POST", "/test/api/actions", strings.NewReader(values.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "form encoded", `{"status": "done", "report": "TABLE",
		"values": [{"c1": "formval", "c2": false, "c3": 40}]}`, response.Body.String())
}

func TestAPIParamTypeErrors(t *testing.T) {
	a := apiParamApp(t)

	tests := []struct {
		name string
		body string
		err  string
	}{
		{"string param number", `{"param1": 123}`, "param param1 must be a string"},
		{"int param float", `{"param3": 1.5}`, "param param3 must be an integer"},
		{"int param exponent", `{"param3": 1e3}`, "param param3 must be an integer"},
		{"int param out of range", `{"param3": 1e100}`, "param param3 must be an integer"},
		{"int param overflow", `{"param3": 99999999999999999999}`, "param param3 must be an integer"},
		{"int param bad string", `{"param3": "abc"}`, "param param3 is not an int"},
		{"bool param number", `{"param2": 1}`, "param param2 must be a boolean"},
		{"unknown param", `{"paramX": 1}`, "unknown param paramX"},
		{"invalid json", `{"param1": `, "unexpected EOF"},
	}

	for _, tc := range tests {
		request := createJSONRequest(t, "/test/api/actions", tc.body)
		response := httptest.NewRecorder()
		a.ServeHTTP(response, request)
		testutil.AssertEqualsInt(t, tc.name+" code", http.StatusBadRequest, response.Code)
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("%s: error parsing response %q: %s", tc.name, response.Body.String(), err)
		}
		if !strings.Contains(errResp.Error, tc.err) {
			t.Errorf("%s: expected error containing %q, got %q", tc.name, tc.err, errResp.Error)
		}
	}
}

func TestAPIListDictParams(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"l": args.lparam, "d": args.dparam}], report=ace.JSON)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("lparam", description="list param", type=LIST, default=["x"])
param("dparam", description="dict param", type=DICT, default={"k": "v"})`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := createJSONRequest(t, "/test/api/actions", `{"lparam": ["a", "b"], "dparam": {"n": "m"}}`)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "list dict", `{"status": "done", "report": "JSON",
		"values": [{"l": ["a", "b"], "d": {"n": "m"}}]}`, response.Body.String())

	// String values are parsed as JSON for LIST/DICT params
	request = createJSONRequest(t, "/test/api/actions", `{"lparam": "[\"c\"]", "dparam": "{\"p\": \"q\"}"}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "string coerced", `{"status": "done", "report": "JSON",
		"values": [{"l": ["c"], "d": {"p": "q"}}]}`, response.Body.String())

	request = createJSONRequest(t, "/test/api/actions", `{"lparam": {"a": 1}}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusBadRequest, response.Code)
	assertJSONMatch(t, "bad list", `{"error": "param lparam must be a list"}`, response.Body.String())

	request = createJSONRequest(t, "/test/api/actions", `{"dparam": ["a"]}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusBadRequest, response.Code)
	assertJSONMatch(t, "bad dict", `{"error": "param dparam must be a dict"}`, response.Body.String())
}

func TestAPIParamErrors(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="failed", values=["a"], param_errors={"param1": "param1error", "paramX": "ignored"})

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// Param errors are reported with 422, errors for unknown params are
	// dropped and values are not included
	request := createJSONRequest(t, "/test/api/actions", `{}`)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusUnprocessableEntity, response.Code)
	assertJSONMatch(t, "param errors", `{"status": "failed", "param_errors": {"param1": "param1error"}}`, response.Body.String())
}

func TestAPIReportTypes(t *testing.T) {
	reportTester := func(name, result, expected string) {
		logger := testutil.TestLogger()
		fileData := map[string]string{
			"app.star": `
def handler(dry_run, args):
	return ` + result + `

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
			"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
		}
		a, _, err := CreateTestApp(logger, fileData)
		if err != nil {
			t.Fatalf("%s: Error %s", name, err)
		}

		request := createJSONRequest(t, "/test/api/actions", `{}`)
		response := httptest.NewRecorder()
		a.ServeHTTP(response, request)
		testutil.AssertEqualsInt(t, name+" code", 200, response.Code)
		assertJSONMatch(t, name, expected, response.Body.String())
	}

	// AUTO with list of strings resolves to TEXT
	reportTester("auto text", `ace.result(status="done", values=["a", "b"])`,
		`{"status": "done", "report": "TEXT", "values": ["a", "b"]}`)

	// AUTO with simple types resolves to TABLE
	reportTester("auto table", `ace.result(status="done", values=[{"a": 1, "b": "abc"}])`,
		`{"status": "done", "report": "TABLE", "values": [{"a": 1, "b": "abc"}]}`)

	// AUTO with complex types resolves to JSON
	reportTester("auto json", `ace.result(status="done", values=[{"a": {"c": 1}, "b": "abc"}])`,
		`{"status": "done", "report": "JSON", "values": [{"a": {"c": 1}, "b": "abc"}]}`)

	// Explicit report type is retained
	reportTester("explicit table", `ace.result(status="done", values=[{"a": {"c": 1}}], report=ace.TABLE)`,
		`{"status": "done", "report": "TABLE", "values": [{"a": {"c": 1}}]}`)

	// Custom report template name is returned as is, with the raw values
	reportTester("custom report", `ace.result(status="done", values=["a"], report="custom")`,
		`{"status": "done", "report": "custom", "values": ["a"]}`)

	// No values
	reportTester("no values", `ace.result(status="done")`,
		`{"status": "done", "report": "TEXT", "values": []}`)

	// Handler returning a plain string, the string is used as the status
	reportTester("string return", `"statusonly"`,
		`{"status": "statusonly", "report": "TEXT", "values": []}`)
}

func TestAPISuggest(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a"], report=ace.TEXT)

def suggest_handler(args):
	if args.param1 == "none":
		return "No suggestions"
	return {"param1": ["a", "b", "c"], "param2": True, "unknown": "x"}

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler, suggest=suggest_handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")
param("param2", description="param2 description", type=BOOLEAN, default=False)`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// Suggest values, entries which are not params are dropped
	request := createJSONRequest(t, "/test/api/suggest", `{}`)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "suggest", `{"status": "Suggesting values",
		"params": {"param1": ["a", "b", "c"], "param2": true}}`, response.Body.String())

	// Suggest handler returning a string, no suggestions
	request = createJSONRequest(t, "/test/api/suggest", `{"param1": "none"}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "suggest string", `{"status": "No suggestions"}`, response.Body.String())

	// Descriptor reports suggest availability
	request = httptest.NewRequest("GET", "/test/api", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), `"suggest":true`)
}

func TestAPISuggestNotSupported(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := createJSONRequest(t, "/test/api/suggest", `{}`)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusNotImplemented, response.Code)
	assertJSONMatch(t, "no suggest", `{"error": "suggest not supported for this action"}`, response.Body.String())
}

func TestAPIValidate(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	if args.param1 == "bad":
		return ace.result(status="failed", param_errors={"param1": "bad value"})
	if dry_run:
		return "Looks good"
	return ace.result(status="done", values=["a"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler, show_validate=True)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// Validate success, no values/report in the response
	request := createJSONRequest(t, "/test/api/validate", `{"param1": "good"}`)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "validate ok", `{"status": "Looks good"}`, response.Body.String())

	// Validate failure
	request = createJSONRequest(t, "/test/api/validate", `{"param1": "bad"}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusUnprocessableEntity, response.Code)
	assertJSONMatch(t, "validate failed", `{"status": "failed", "param_errors": {"param1": "bad value"}}`, response.Body.String())

	// Actual run
	request = createJSONRequest(t, "/test/api/actions", `{"param1": "good"}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "run", `{"status": "done", "report": "TEXT", "values": ["a"]}`, response.Body.String())
}

func TestAPIHandlerError(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	10/args.param3
	return ace.result(status="done", values=["a"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param3", description="param3 description", type=INT, default=10)`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := createJSONRequest(t, "/test/api/actions", `{"param3": 0}`)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusInternalServerError, response.Code)
	assertJSONMatch(t, "handler error", `{"error": "floating-point division by zero"}`, response.Body.String())
}

func TestAPIMultipleActions(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler1(dry_run, args):
	return ace.result(status="one", values=["a"], report=ace.TEXT)

def handler2(dry_run, args):
	return ace.result(status="two", values=["b"], report=ace.TEXT)

def suggest_handler(args):
	return {"param1": ["a"]}

app = ace.app("testApp",
	actions=[ace.action("test1Action", "/test1", handler1, suggest=suggest_handler),
	         ace.action("test2Action", "/test2", handler2)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/api", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "describe", `{
		"app": "testApp",
		"actions": [
			{"name": "test1Action", "path": "/test/api/actions/test1", "validate_path": "/test/api/validate/test1", "suggest_path": "/test/api/suggest/test1", "ui_path": "/test/test1", "suggest": true, "authorized": true},
			{"name": "test2Action", "path": "/test/api/actions/test2", "validate_path": "/test/api/validate/test2", "ui_path": "/test/test2", "suggest": false, "authorized": true}
		]
	}`, response.Body.String())

	request = createJSONRequest(t, "/test/api/actions/test1", `{}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "run test1", `{"status": "one", "report": "TEXT", "values": ["a"]}`, response.Body.String())

	request = createJSONRequest(t, "/test/api/actions/test2", `{}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "run test2", `{"status": "two", "report": "TEXT", "values": ["b"]}`, response.Body.String())

	// Unknown action path
	request = createJSONRequest(t, "/test/api/actions/unknown", `{}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusNotFound, response.Code)
}

func TestAPIOptionsAndHiddenParams(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status=args.param2, values=["a"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler, hidden=["param2"])])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="a")
param("options-param1", description="param1 options", type=LIST, default=["a", "b", "c"])
param("param2", description="param2 description", type=STRING, default="hiddenvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// Schema folds the options param into the param options, hidden params
	// are excluded
	request := httptest.NewRequest("GET", "/test/api/actions", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "schema", `{
		"name": "testAction",
		"description": "",
		"params": [{
			"name": "param1",
			"type": "STRING",
			"description": "param1 description",
			"default": "a",
			"required": true,
			"options": ["a", "b", "c"]
		}],
		"suggest": false
	}`, response.Body.String())

	// Hidden params cannot be set through the API
	request = createJSONRequest(t, "/test/api/actions", `{"param2": "override"}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusBadRequest, response.Code)
	assertJSONMatch(t, "hidden param", `{"error": "unknown param param2"}`, response.Body.String())

	// Options params cannot be set through the API
	request = createJSONRequest(t, "/test/api/actions", `{"options-param1": ["x"]}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusBadRequest, response.Code)
	assertJSONMatch(t, "options param", `{"error": "unknown param options-param1"}`, response.Body.String())

	// The hidden param keeps its app level value for the handler
	request = createJSONRequest(t, "/test/api/actions", `{"param1": "b"}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "hidden default", `{"status": "hiddenvalue", "report": "TEXT", "values": ["a"]}`, response.Body.String())
}

func TestAPIFileUpload(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="got " + args.upload.split("/")[-1], values=["ok"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])
		`,
		"params.star": `param("upload", description="upload", type=STRING, display_type=FILE, default="")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// Multipart file upload works on the API endpoint
	request := createMultipartUploadRequest(t, "/test/api/actions", "upload", "report.txt", 64)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "file upload", `{"status": "got report.txt", "report": "TEXT", "values": ["ok"]}`, response.Body.String())

	// File params cannot be set through JSON, the value would be a server
	// side file path
	request = createJSONRequest(t, "/test/api/actions", `{"upload": "/etc/passwd"}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusBadRequest, response.Code)
	assertJSONMatch(t, "file through json", `{"error": "param upload is a file upload param, submit using multipart/form-data"}`, response.Body.String())

	// Schema notes the display type
	request = httptest.NewRequest("GET", "/test/api/actions", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), `"display_type":"file"`)
}

func TestAPIUploadRequestBodyLimit(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["ok"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])
		`,
		"params.star": `param("upload", description="upload", type=STRING, display_type=FILE, default="")`,
	}

	a, _, err := CreateTestAppConfig(logger, fileData, types.AppConfig{
		Action: types.ActionConfig{
			MaxRequestBodyBytes: 128,
		},
	})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := createMultipartUploadRequest(t, "/test/api/actions", "upload", "report.txt", 512)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusRequestEntityTooLarge, response.Code)
	assertJSONMatch(t, "body limit", `{"error": "request body too large: limit is 128 bytes"}`, response.Body.String())

	// JSON body over the limit
	request = createJSONRequest(t, "/test/api/actions", `{"upload": "`+strings.Repeat("a", 512)+`"}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusRequestEntityTooLarge, response.Code)
	assertJSONMatch(t, "json body limit", `{"error": "request body too large: limit is 128 bytes"}`, response.Body.String())
}

func TestAPIPermitChecks(t *testing.T) {
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("test1Action", "/test1", handler, permit=["perm1"]),
	         ace.action("test2Action", "/test2", handler, permit=["perm2"])])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}

	logger := testutil.TestLogger()
	a, _, err := CreateTestAppAuthorizer(logger, fileData, nil, nil, nil, &testRBAC{perms: []string{"perm1"}})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// Descriptor reports the authorized status per action
	request := httptest.NewRequest("GET", "/test/api", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "describe", `{
		"app": "testApp",
		"actions": [
			{"name": "test1Action", "path": "/test/api/actions/test1", "validate_path": "/test/api/validate/test1", "ui_path": "/test/test1", "suggest": false, "authorized": true},
			{"name": "test2Action", "path": "/test/api/actions/test2", "validate_path": "/test/api/validate/test2", "ui_path": "/test/test2", "suggest": false, "authorized": false}
		]
	}`, response.Body.String())

	// Authorized action works
	request = createJSONRequest(t, "/test/api/actions/test1", `{}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "authorized run", `{"status": "done", "report": "TEXT", "values": ["a"]}`, response.Body.String())

	// Unauthorized action is blocked, for both run and schema
	request = createJSONRequest(t, "/test/api/actions/test2", `{}`)
	request = request.WithContext(context.WithValue(request.Context(), types.USER_ID, "user@example.com"))
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusForbidden, response.Code)
	assertJSONMatch(t, "unauthorized run", `{"error": "Forbidden : user@example.com does not have access to action test2Action"}`, response.Body.String())

	request = httptest.NewRequest("GET", "/test/api/actions/test2", nil)
	request = request.WithContext(context.WithValue(request.Context(), types.USER_ID, "user@example.com"))
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusForbidden, response.Code)
	assertJSONMatch(t, "unauthorized schema", `{"error": "Forbidden : user@example.com does not have access to action test2Action"}`, response.Body.String())
}

func TestAPIReservedPath(t *testing.T) {
	logger := testutil.TestLogger()

	appStar := func(actionPath string) string {
		return `
def handler(dry_run, args):
	return ace.result(status="done", values=["a"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "` + actionPath + `", handler)])
		`
	}
	paramsStar := `param("param1", description="param1 description", type=STRING, default="myvalue")`

	_, _, err := CreateTestApp(logger, map[string]string{
		"app.star":    appStar("/api"),
		"params.star": paramsStar,
	})
	testutil.AssertErrorContains(t, err, "action path /api is not allowed, /api is reserved for the actions API")

	_, _, err = CreateTestApp(logger, map[string]string{
		"app.star":    appStar("/api/foo"),
		"params.star": paramsStar,
	})
	testutil.AssertErrorContains(t, err, "action path /api/foo is not allowed, /api is reserved for the actions API")

	// Path without the leading slash is also checked
	_, _, err = CreateTestApp(logger, map[string]string{
		"app.star":    appStar("api"),
		"params.star": paramsStar,
	})
	testutil.AssertErrorContains(t, err, "action path /api is not allowed, /api is reserved for the actions API")

	// Paths which only share the prefix are fine
	a, _, err := CreateTestApp(logger, map[string]string{
		"app.star":    appStar("/apifoo"),
		"params.star": paramsStar,
	})
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	request := createJSONRequest(t, "/test/api/actions/apifoo", `{}`)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
}

func TestAPINoActions(t *testing.T) {
	logger := testutil.TestLogger()
	a, _, err := CreateTestApp(logger, map[string]string{
		"app.star":      `app = ace.app("testApp", routes = [ace.html("/")])`,
		"index.go.html": `{{.}}`,
	})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// The API is mounted only for apps with actions
	request := httptest.NewRequest("GET", "/test/api", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusNotFound, response.Code)
}

func TestAPIOpenAPISpec(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a"], report=ace.TEXT)

def suggest_handler(args):
	return {}

app = ace.app("testApp",
	actions=[ace.action("test1Action", "/test1", handler, suggest=suggest_handler, description="first action"),
	         ace.action("test2Action", "/test2", handler, hidden=["param3"])])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="a")
param("options-param1", description="param1 options", type=LIST, default=["a", "b", "c"])
param("param2", description="param2 description", type=BOOLEAN, default=True)
param("param3", description="param3 description", type=INT, default=10)
param("param4", description="param4 description", type=LIST, default=["x"])
param("param5", description="param5 description", type=STRING, default="p", display_type=COMBO)
param("options-param5", description="param5 options", type=LIST, default=["p", "q"])`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/api/openapi.json", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	body := response.Body.String()

	var spec map[string]any
	if err := json.Unmarshal([]byte(body), &spec); err != nil {
		t.Fatalf("Error parsing OpenAPI spec: %s", err)
	}

	testutil.AssertEqualsString(t, "openapi version", "3.0.3", spec["openapi"].(string))
	info := spec["info"].(map[string]any)
	testutil.AssertEqualsString(t, "title", "testApp", info["title"].(string))

	paths := spec["paths"].(map[string]any)
	expectedPaths := []string{
		"/test/api/actions/test1",
		"/test/api/suggest/test1",
		"/test/api/validate/test1",
		"/test/api/actions/test2",
		"/test/api/validate/test2",
	}
	for _, p := range expectedPaths {
		if paths[p] == nil {
			t.Errorf("expected path %s in OpenAPI spec, got paths %v", p, paths)
		}
	}
	if paths["/test/api/suggest/test2"] != nil {
		t.Errorf("suggest path should not be present for test2Action")
	}

	// Check the request body schema for test1
	test1 := paths["/test/api/actions/test1"].(map[string]any)
	post := test1["post"].(map[string]any)
	testutil.AssertEqualsString(t, "operationId", "run_test1", post["operationId"].(string))
	testutil.AssertEqualsString(t, "summary", "test1Action", post["summary"].(string))
	testutil.AssertEqualsString(t, "description", "first action", post["description"].(string))

	schema := post["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	properties := schema["properties"].(map[string]any)

	param1 := properties["param1"].(map[string]any)
	testutil.AssertEqualsString(t, "param1 type", "string", param1["type"].(string))
	if !reflect.DeepEqual(param1["enum"], []any{"a", "b", "c"}) {
		t.Errorf("expected param1 enum [a b c], got %v", param1["enum"])
	}

	param2 := properties["param2"].(map[string]any)
	testutil.AssertEqualsString(t, "param2 type", "boolean", param2["type"].(string))
	if param2["default"] != true {
		t.Errorf("expected param2 default true, got %v", param2["default"])
	}

	param3 := properties["param3"].(map[string]any)
	testutil.AssertEqualsString(t, "param3 type", "integer", param3["type"].(string))

	if properties["options-param1"] != nil {
		t.Errorf("options param should not be in the schema")
	}

	// OpenAPI 3.0 requires items for array schemas
	param4 := properties["param4"].(map[string]any)
	testutil.AssertEqualsString(t, "param4 type", "array", param4["type"].(string))
	if param4["items"] == nil {
		t.Errorf("expected items for list param4, got %v", param4)
	}

	// COMBO params allow free text, the options are not an enum. The schema
	// object supports a single example in OpenAPI 3.0
	param5 := properties["param5"].(map[string]any)
	if param5["enum"] != nil || param5["examples"] != nil {
		t.Errorf("combo param5 should not have enum or examples, got %v", param5)
	}
	testutil.AssertEqualsString(t, "param5 example", "p", param5["example"].(string))
	if !reflect.DeepEqual(param5["x-options"], []any{"p", "q"}) {
		t.Errorf("expected param5 x-options [p q], got %v", param5["x-options"])
	}

	// param3 is hidden for test2Action
	test2 := paths["/test/api/actions/test2"].(map[string]any)
	post2 := test2["post"].(map[string]any)
	schema2 := post2["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	properties2 := schema2["properties"].(map[string]any)
	if properties2["param3"] != nil {
		t.Errorf("hidden param3 should not be in the test2 schema")
	}
	if properties2["param1"] == nil {
		t.Errorf("param1 should be in the test2 schema")
	}

	// Components schemas are defined
	components := spec["components"].(map[string]any)["schemas"].(map[string]any)
	if components["ActionResult"] == nil || components["Error"] == nil {
		t.Errorf("expected ActionResult and Error schemas, got %v", components)
	}
}

func TestAPIOpenAPIOperationIds(t *testing.T) {
	// Different action paths can sanitize to the same operationId name
	// (/ and /root, /a/b and /a_b). The ids must be unique across the spec
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("a1", "/", handler),
	         ace.action("a2", "/root", handler),
	         ace.action("a3", "/a/b", handler),
	         ace.action("a4", "/a_b", handler),
	         ace.action("a5", "/a_b_2", handler),
	         ace.action("a6", "/a/b/2", handler),
	         ace.action("a7", "/plain", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/api/openapi.json", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	var spec map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &spec); err != nil {
		t.Fatalf("Error parsing OpenAPI spec: %s", err)
	}

	ids := map[string]string{} // operationId -> path
	paths := spec["paths"].(map[string]any)
	for p, item := range paths {
		for method, opAny := range item.(map[string]any) {
			op := opAny.(map[string]any)
			id, _ := op["operationId"].(string)
			if id == "" {
				t.Errorf("missing operationId for %s %s", method, p)
				continue
			}
			if prev, ok := ids[id]; ok {
				t.Errorf("duplicate operationId %s for %s and %s", id, prev, p)
			}
			ids[id] = p
		}
	}
	// 7 actions, each with schema/run/validate operations
	testutil.AssertEqualsInt(t, "operation count", 21, len(ids))

	// Non colliding names are kept readable, collisions get a suffix
	// which does not clash with another action's name
	expected := map[string]string{
		"run_root":    "/test/api/actions",
		"run_root_2":  "/test/api/actions/root",
		"run_a_b":     "/test/api/actions/a/b",
		"run_a_b_3":   "/test/api/actions/a_b", // a_b_2 is taken by the /a_b_2 action
		"run_a_b_2":   "/test/api/actions/a_b_2",
		"run_a_b_2_2": "/test/api/actions/a/b/2", // sanitizes to a_b_2, taken by the /a_b_2 action
		"run_plain":   "/test/api/actions/plain",
	}
	for id, p := range expected {
		testutil.AssertEqualsString(t, id, p, ids[id])
	}
}

func TestAPIOpenAPISpecPermitChecks(t *testing.T) {
	// The OpenAPI spec discloses the param definitions and defaults, so only
	// the actions the user is authorized for are included
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("test1Action", "/test1", handler, permit=["perm1"]),
	         ace.action("test2Action", "/test2", handler, permit=["perm2"]),
	         ace.action("test3Action", "/test3", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}

	logger := testutil.TestLogger()
	a, _, err := CreateTestAppAuthorizer(logger, fileData, nil, nil, nil, &testRBAC{perms: []string{"perm1"}})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/api/openapi.json", nil)
	request = request.WithContext(context.WithValue(request.Context(), types.USER_ID, "user@example.com"))
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	var spec map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &spec); err != nil {
		t.Fatalf("Error parsing OpenAPI spec: %s", err)
	}
	paths := spec["paths"].(map[string]any)
	for _, p := range []string{"/test/api/actions/test1", "/test/api/validate/test1", "/test/api/actions/test3", "/test/api/validate/test3"} {
		if paths[p] == nil {
			t.Errorf("expected path %s in OpenAPI spec, got paths %v", p, paths)
		}
	}
	for _, p := range []string{"/test/api/actions/test2", "/test/api/validate/test2", "/test/api/suggest/test2"} {
		if paths[p] != nil {
			t.Errorf("unauthorized path %s should not be in OpenAPI spec", p)
		}
	}
	if len(paths) != 4 {
		t.Errorf("expected 4 paths, got %d: %v", len(paths), paths)
	}
}

func TestAPIHelperPathCollision(t *testing.T) {
	// Actions at / and /validate (or /suggest) must not collide with the
	// validate/suggest endpoints of the root action
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def root_handler(dry_run, args):
	return ace.result(status="root dry_run=%s" % dry_run, values=[], report=ace.TEXT)

def root_suggest(args):
	return {"param1": "from root suggest"}

def validate_handler(dry_run, args):
	return ace.result(status="validate action dry_run=%s" % dry_run, values=[], report=ace.TEXT)

def suggest_handler(dry_run, args):
	return ace.result(status="suggest action dry_run=%s" % dry_run, values=[], report=ace.TEXT)

def nested_handler(dry_run, args):
	return ace.result(status="nested dry_run=%s" % dry_run, values=[], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("rootAction", "/", root_handler, suggest=root_suggest),
	         ace.action("validateAction", "/validate", validate_handler),
	         ace.action("suggestAction", "/suggest", suggest_handler),
	         ace.action("nestedAction", "/validate/nested", nested_handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	tests := []struct {
		name   string
		path   string
		status string
	}{
		{"root run", "/test/api/actions", "root dry_run=False"},
		{"root validate", "/test/api/validate", "root dry_run=True"},
		{"root suggest", "/test/api/suggest", "Suggesting values"},
		{"validate action run", "/test/api/actions/validate", "validate action dry_run=False"},
		{"validate action validate", "/test/api/validate/validate", "validate action dry_run=True"},
		{"suggest action run", "/test/api/actions/suggest", "suggest action dry_run=False"},
		{"suggest action validate", "/test/api/validate/suggest", "suggest action dry_run=True"},
		{"nested action run", "/test/api/actions/validate/nested", "nested dry_run=False"},
		{"nested action validate", "/test/api/validate/validate/nested", "nested dry_run=True"},
	}
	for _, tc := range tests {
		request := createJSONRequest(t, tc.path, `{}`)
		response := httptest.NewRecorder()
		a.ServeHTTP(response, request)
		testutil.AssertEqualsInt(t, tc.name+" code", 200, response.Code)
		var resp map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: error parsing response %q: %s", tc.name, response.Body.String(), err)
		}
		testutil.AssertEqualsString(t, tc.name, tc.status, fmt.Sprintf("%v", resp["status"]))
	}

	// Suggest is not supported for the /validate action
	request := createJSONRequest(t, "/test/api/suggest/validate", `{}`)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", http.StatusNotImplemented, response.Code)
}

func TestAPIUIUnchanged(t *testing.T) {
	// The UI form endpoints are unchanged by the API, both are served
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a", "b"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// UI form
	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")

	// UI post returns HTML, not JSON
	request = httptest.NewRequest("POST", "/test", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), `<div role="status"`)

	// API post returns JSON
	request = createJSONRequest(t, "/test/api/actions", `{}`)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	assertJSONMatch(t, "api run", `{"status": "done", "report": "TEXT", "values": ["a", "b"]}`, response.Body.String())
}
