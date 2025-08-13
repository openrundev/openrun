// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestParamsBasics(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp")

def handler(req):
	return {}
		`,
		"params.star": ``,
	}
	_, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	fileData["params.star"] = `param("param1", description="param1 description", type=STRING, default="myvalue")`
	_, _, err = CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	fileData["params.star"] = `param("param1", description="param1 description", type=INVALID, default="myvalue")`
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "undefined: INVALID")

	fileData["params.star"] = `param("", description="param1 description", type=STRING, default="myvalue")`
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "param name is required")

	fileData["params.star"] = `param("abc def", description="param1 description", type=STRING, default="myvalue")`
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "param name \"abc def\" has space")

	fileData["params.star"] = `param("p1", description="param1 description", type=STRING, default="myvalue")
param("p1", description="param2 description", type=STRING, default="myvalue")`
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "param \"p1\" already defined")

	fileData["params.star"] = `param("p1", description="param1 description", type=STRING, default="myvalue")
param("p2", description="param2 description", type=INT, default=10)
param("p3", description="param3 description", type=BOOLEAN, default=True)
param("p4", description="param4 description", type=LIST, default=[10])
param("p5", type=DICT, default={"a": 10})
param("p6", default="abc")`
	_, _, err = CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	fileData["params.star"] = `param("p1", description="param1 description", type=STRING, default=1)`
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "param p1 is of type string but default value is not a string")

	fileData["params.star"] = `param("p1", description="param1 description", type=INT, default=True)`
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "param p1 is of type int but default value is not an int")

	fileData["params.star"] = `param("p1", description="param1 description", type=BOOLEAN, default=1)`
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "param p1 is of type bool but default value is not a bool")

	fileData["params.star"] = `param("p1", description="param1 description", type=DICT, default=1)`
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "param p1 is of type dict but default value is not a dict")

	fileData["params.star"] = `param("p1", description="param1 description", type=LIST, default=1)`
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "param p1 is of type list but default value is not a list")
}

func TestParamsUse(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.api("/", type=ace.TEXT)])

def handler(req):
	return param.p1
		`,
	}

	// Test with no params, default
	fileData["params.star"] = `param("p1", type=STRING, default="myvalue")`
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "myvalue")

	// Test with custom value
	fileData["params.star"] = `param("p1", type=STRING, default="myvalue")`
	a, _, err = CreateTestAppParams(logger, fileData, map[string]string{"p1": "mycustomvalue"})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request = httptest.NewRequest("GET", "/test", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "mycustomvalue")

	// Test with int custom value
	fileData["params.star"] = `param("p1", type=INT, default=10)`
	a, _, err = CreateTestAppParams(logger, fileData, map[string]string{"p1": "20"})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request = httptest.NewRequest("GET", "/test", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "20")

	// Test with bool custom value
	fileData["params.star"] = `param("p1", type=BOOLEAN, default=False)`
	a, _, err = CreateTestAppParams(logger, fileData, map[string]string{"p1": "True"})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request = httptest.NewRequest("GET", "/test", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "true")

	// Test with dict custom value
	fileData["params.star"] = `param("p1", type=DICT, default={"a": 10})`
	a, _, err = CreateTestAppParams(logger, fileData, map[string]string{"p1": "{\"a\": 20}"})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request = httptest.NewRequest("GET", "/test", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "map[a:20]")

	// Test with list custom value
	fileData["params.star"] = `param("p1", type=LIST, default=config("aaa", [10]))`
	a, _, err = CreateTestAppParams(logger, fileData, map[string]string{"p1": "[20]"})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request = httptest.NewRequest("GET", "/test", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "[20]")
}

func TestParamsError(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.api("/", type=ace.TEXT)])

def handler(req):
	return param.p1
		`,
	}

	// Test with no params, required param
	fileData["params.star"] = `param("p1", type=STRING)`
	_, _, err := CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "param p1 is a required param, a value has to be provided")

	// Test with no params, not required param
	fileData["params.star"] = `param("p1", type=STRING, required=False)`
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertNoError(t, err)

	// Test with no params, not required INT param
	fileData["params.star"] = `param("p1", type=INT, required=False)`
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertNoError(t, err)

	// Test string empty value
	fileData["params.star"] = `param("p1", type=STRING, required=True)`
	_, _, err = CreateTestAppParams(logger, fileData, map[string]string{"p1": ""})
	testutil.AssertErrorContains(t, err, "param p1 is a required param, value cannot be empty")
}
