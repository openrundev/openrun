// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestHttpPluginBasics(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	testServerJson := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"key": "value"}`) //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `

load ("http.in", "http")
app = ace.app("testApp", custom_layout=True, routes = [ace.api("/")],
    permissions=[
	ace.permission("http.in", "get"),
	ace.permission("http.in", "post"),
	ace.permission("http.in", "delete"),
	ace.permission("http.in", "put"),
	ace.permission("http.in", "patch"),
	ace.permission("http.in", "head"),
	ace.permission("http.in", "options"),
	])

def handler(req):
	resp1 = http.get("` + testServer.URL + `?a=b", headers={"X-Test": "test"}, params={"c": "d"}, auth_basic=("user", "pass"))
	resp2 = http.post("` + testServer.URL + `")
	resp3 = http.delete("` + testServer.URL + `")
	resp4 = http.put("` + testServer.URL + `")
	resp5 = http.patch("` + testServer.URL + `")
	resp6 = http.head("` + testServer.URL + `")
	resp7 = http.options("` + testServer.URL + `")
	resp8 = http.get("` + testServerJson.URL + `")

	return {
		"key1": resp1.value.body(),
		"key2": resp2.value.body(),
		"key3": resp3.value.body(),
		"key4": resp4.value.body(),
		"key5": resp5.value.body(),
		"key6": resp6.value.body(),
		"key7": resp7.value.body(),
		"key8": resp8.value.json(),
		}
`,
	}

	a, _, err := CreateTestAppPlugin(logger, fileData,
		[]string{"http.in"},
		[]types.Permission{
			{Plugin: "http.in", Method: "get"},
			{Plugin: "http.in", Method: "post"},
			{Plugin: "http.in", Method: "delete"},
			{Plugin: "http.in", Method: "put"},
			{Plugin: "http.in", Method: "patch"},
			{Plugin: "http.in", Method: "head"},
			{Plugin: "http.in", Method: "options"},
		},
		nil)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck
	testutil.AssertEqualsString(t, "body", "test contents", ret["key1"].(string))
	testutil.AssertEqualsString(t, "body", "test contents", ret["key2"].(string))
	testutil.AssertEqualsString(t, "body", "test contents", ret["key3"].(string))
	testutil.AssertEqualsString(t, "body", "test contents", ret["key4"].(string))
	testutil.AssertEqualsString(t, "body", "test contents", ret["key5"].(string))
	testutil.AssertEqualsString(t, "body", "", ret["key6"].(string))
	testutil.AssertEqualsString(t, "body", "test contents", ret["key7"].(string))
	testutil.AssertEqualsString(t, "body", `value`, ret["key8"].(map[string]any)["key"].(string))
}

func TestSecretsConfig(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `

load ("http.in", "http")
app = ace.app("testApp", custom_layout=True, routes = [ace.api("/")],
    permissions=[
	ace.permission("http.in", "get", secrets=["abc"]),
	])

def handler(req):
	resp1 = http.get("` + testServer.URL + `?a=b", headers={"X-Test": "test"}, params={"c": "d"}, auth_basic=("user", "pass"))

	return {
		"key1": resp1.value.body(),
		}
`,
	}

	a, _, err := CreateTestAppPlugin(logger, fileData,
		[]string{"http.in"},
		[]types.Permission{
			{Plugin: "http.in", Method: "get"},
		},
		nil)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	_, err = a.Audit()
	testutil.AssertErrorContains(t, err, "entry 0 in secrets list is not a list")
}

func TestSecretsAccess(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "test contents") //nolint:errcheck
	}))

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `

load ("http.in", "http")


def test1(req):
	resp = http.get("` + testServer.URL + `?a=b", headers={"X-Test": '{{ secret_from "env" "abc"}}'}, params={"c": "d"}, auth_basic=("user", "pass"))
	return resp.value.body()

def test2(req):
	resp = http.get("` + testServer.URL + `?a=b", headers={"X-Test": '{{ secret_from "env" "abc2"}}'}, params={"c": "d"}, auth_basic=("user", "pass"))
	return resp.value.body()

app = ace.app("testApp", custom_layout=True, routes = [ace.api("/api1",  handler=test1, type=ace.TEXT), ace.api("/api2", handler=test2, type=ace.TEXT)],
    permissions=[
	ace.permission("http.in", "get", secrets=[["abc"]]),
	])
`,
	}

	a, _, err := CreateTestAppPlugin(logger, fileData,
		[]string{"http.in"},
		[]types.Permission{
			{Plugin: "http.in", Method: "get", Secrets: [][]string{{"abc"}}},
		},
		nil)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	_, err = a.Audit()
	testutil.AssertNoError(t, err)

	request := httptest.NewRequest("GET", "/test/api1", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "test contents", response.Body.String())

	request = httptest.NewRequest("GET", "/test/api2", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "error calling secret_from: plugin does not have access to secret abc")
}
