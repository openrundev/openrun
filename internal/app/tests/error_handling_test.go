// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestNoErrorHandler(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
load("fs.in", "fs")

def test1(req):
	ret = fs.list("/tmp/invalid")
	ret = fs.list("/tmp")

app = ace.app("testApp", custom_layout=True, 
	routes = [
		ace.api("/test1", handler=test1),
	],
	permissions=[
		ace.permission("fs.in", "list"),
	]
)`,
		"index.go.html": ``,
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"fs.in"},
		[]types.Permission{
			{Plugin: "fs.in", Method: "list"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/test1", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 500, response.Code)

	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret)

	if _, ok := ret["error"]; ok {
		t.Fatal(ret["error"])
	}
}

func TestErrorHandlerDev(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
load("fs.in", "fs")

def test1(req):
	ret = fs.list("/tmp/invalid")
	ret = fs.list("/tmp")

def error_handler(req, cause):
	return {"error": cause["error"]}

app = ace.app("testApp", custom_layout=True, 
	routes = [
		ace.api("/test1", handler=test1),
	],
	permissions=[
		ace.permission("fs.in", "list"),
	]
)`,
		"index.go.html": ``,
	}

	a, _, err := CreateDevAppPlugin(logger, fileData, []string{"fs.in"},
		[]types.Permission{
			{Plugin: "fs.in", Method: "list"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/test1", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret)
	fmt.Printf("%#v", ret)

	testutil.AssertEqualsString(t, "error", "previous plugin call failed: open /tmp/invalid: no such file or directory : Function test1, Position app.star:6:15", ret["error"].(string))
}

func TestErrorHandlerProd(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
load("fs.in", "fs")

def test1(req):
	ret = fs.list("/tmp/invalid")
	ret = fs.list("/tmp")

def error_handler(req, cause):
	return {"error": cause["error"]}

app = ace.app("testApp", custom_layout=True, 
	routes = [
		ace.api("/test1", type="json", handler=test1),
	],
	permissions=[
		ace.permission("fs.in", "list"),
	]
)`,
		"index.go.html": ``,
	}

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"fs.in"},
		[]types.Permission{
			{Plugin: "fs.in", Method: "list"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/test1", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret)
	fmt.Printf("%#v", ret)

	// No source code path for prod app
	testutil.AssertEqualsString(t, "error", "previous plugin call failed: open /tmp/invalid: no such file or directory", ret["error"].(string))
}

func TestErrorHandlerBasics(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
load("fs.in", "fs")

def test1_value(req):
	ret = fs.list("/tmp/invalid")
	ret.value # checking value causes failure

def test2_error(req):
	ret = fs.list("/tmp/invalid")
	ret.error # checking error clears failure

def test3_truth(req):
	ret = fs.list("/tmp/invalid")
	if ret: # checking truth clears failures state
		pass

def test4_last_call(req):
	fs.list("/tmp/invalid")

def test5_failure(req):
	1/0

def error_handler(req, cause):
	return {"error": cause["error"]}

app = ace.app("testApp", custom_layout=True, 
	routes = [
		ace.api("/test1_value", handler=test1_value),
		ace.api("/test2_error", handler=test2_error),
		ace.api("/test3_truth", handler=test3_truth),
		ace.api("/test4_last_call", handler=test4_last_call),
		ace.api("/test5_failure", handler=test5_failure),
	],
	permissions=[
		ace.permission("fs.in", "list"),
	]
)`,
		"index.go.html": ``,
	}

	a, _, err := CreateDevAppPlugin(logger, fileData, []string{"fs.in"},
		[]types.Permission{
			{Plugin: "fs.in", Method: "list"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/test1_value", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret)

	testutil.AssertStringContains(t, ret["error"].(string), "open /tmp/invalid: no such file or directory : Function test1_value")

	request = httptest.NewRequest("GET", "/test/test2_error", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret = make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret)
	if _, ok := ret["error"]; ok {
		t.Fatal(ret["error"])
	}

	request = httptest.NewRequest("GET", "/test/test3_truth", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret = make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret)
	if _, ok := ret["error"]; ok {
		t.Fatal(ret["error"])
	}

	request = httptest.NewRequest("GET", "/test/test4_last_call", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret = make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret)
	testutil.AssertStringContains(t, ret["error"].(string), "open /tmp/invalid: no such file or directory")

	request = httptest.NewRequest("GET", "/test/test5_failure", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret = make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret)
	testutil.AssertStringContains(t, ret["error"].(string), "floating-point division by zero : Function test5_failure, Position")
}

func TestBadErrorHandler(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
load("fs.in", "fs")

def test1(req):
	ret = fs.list("/tmp/invalid")
	ret.value

def error_handler(req, cause):
	return 1/0 # bad error handler

app = ace.app("testApp", custom_layout=True, 
	routes = [
		ace.api("/test1", handler=test1),
	],
	permissions=[
		ace.permission("fs.in", "list"),
	]
)`,
		"index.go.html": ``,
	}

	a, _, err := CreateDevAppPlugin(logger, fileData, []string{"fs.in"},
		[]types.Permission{
			{Plugin: "fs.in", Method: "list"},
		}, map[string]types.PluginSettings{})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/test1", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 500, response.Code)

	testutil.AssertStringContains(t, response.Body.String(), "floating-point division by zero : Function error_handler, Position")
}
