// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestStaticLoad(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return {"key": "myvalue"}`,
		"index.go.html":                `abc {{static "file1"}} def {{static "file2.txt"}}`,
		"static/file1":                 `file1data`,
		"static/file2.txt":             `file2data`,
		"static_root/robots.txt":       `deny *`,
		"static_root/abc/def/test.txt": `abc`,
	}

	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	want := `abc /test/static/file1-ca9e40772ef9119c13100a8258bc38a665a0a1976bf81c96e69a353b6605f5a7 def /test/static/file2-d044e5b148745e322fe3e916e5f3bb9c9182892fdf99850baf4ed82c2864dd30.txt`
	testutil.AssertStringMatch(t, "body", want, response.Body.String())

	request = httptest.NewRequest("GET", "/test/static/file1-ca9e40772ef9119c13100a8258bc38a665a0a1976bf81c96e69a353b6605f5a7", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	want = `file1data`
	testutil.AssertStringMatch(t, "body", want, response.Body.String())

	request = httptest.NewRequest("GET", "/test/static/file2-d044e5b148745e322fe3e916e5f3bb9c9182892fdf99850baf4ed82c2864dd30.txt", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsString(t, "header cache", "public, max-age=31536000", response.Header().Get("Cache-Control"))
	testutil.AssertEqualsBool(t, "header etag", true, response.Header().Get("ETag") != "")

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", `file2data`, response.Body.String())

	// Test static_root read
	request = httptest.NewRequest("GET", "/test/robots.txt", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsString(t, "header cache", "", response.Header().Get("Cache-Control"))
	testutil.AssertEqualsString(t, "header etag", response.Header().Get("ETag"), "") // etag is not set for now
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", `deny *`, response.Body.String())

	// Test static_root read
	request = httptest.NewRequest("GET", "/test/abc/def/test.txt", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", `abc`, response.Body.String())
}

func TestStaticLoadDevMode(t *testing.T) {
	// In dev mode, the file hashing is disabled, Assumes
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return {"key": "myvalue"}`,
		"index.go.html":    `abc {{static "file1"}} def {{static "file2.txt"}}`,
		"static/file1":     `file1data`,
		"static/file2.txt": `file2data`,
	}

	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	want := `abc /test/static/file1-ca9e40772ef9119c13100a8258bc38a665a0a1976bf81c96e69a353b6605f5a7 def /test/static/file2-d044e5b148745e322fe3e916e5f3bb9c9182892fdf99850baf4ed82c2864dd30.txt`
	testutil.AssertStringMatch(t, "body", want, response.Body.String())
}

func TestStaticError(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return {"key": "myvalue"}`,
		"index.go.html":    `abc {{static "file1"}} def {{static "file2.txt"}}`,
		"static/file2":     `file2data`,
		"static/file3.txt": `file3data`,
	}

	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/static/file1-ca9e40772ef9119c13100a8258bc38a665a0a1976bf81c96e69a353b6605f5a7", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 404, response.Code)
	testutil.AssertStringMatch(t, "body", "404 page not found", response.Body.String())

	request = httptest.NewRequest("GET", "/test/static/file4-d044e5b148745e322fe3e916e5f3bb9c9182892fdf99850baf4ed82c2864dd30.txt", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 404, response.Code)

	request = httptest.NewRequest("GET", "/test/static/file2", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	want := `file2data`
	testutil.AssertStringMatch(t, "body", want, response.Body.String())

	// When accessing static file without the hash in file name, the cache directives are not set.
	// The etag is also not set currently, that needs to be added in the future
	testutil.AssertEqualsString(t, "header", "", response.Header().Get("Cache-Control"))
	testutil.AssertEqualsBool(t, "header etag", true, response.Header().Get("ETag") == "")
}

func TestStaticDupRoute(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/"), ace.api("/static/file1"), ace.api("/robots.txt")])

def handler(req):
	return {"key": "myvalue"}`,
		"index.go.html":                `abc {{static "file1"}} def {{static "file2.txt"}}`,
		"static/file1":                 `file1data`,
		"static/file2.txt":             `file2data`,
		"static_root/robots.txt":       `deny *`,
		"static_root/abc/def/test.txt": `abc`,
	}

	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/static/file1", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	want := `{"key":"myvalue"}`
	testutil.AssertStringMatch(t, "body", want, response.Body.String())

	request = httptest.NewRequest("GET", "/test/robots.txt", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	want = `deny *`
	testutil.AssertStringMatch(t, "body", want, response.Body.String())
}

func TestStaticOnly(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.api("/static/file1"), ace.api("/robots.txt")], static_only=True)

def handler(req):
	return {"key": "myvalue"}`,
		"index.go.html":                `abc {{static "file1"}} def {{static "file2.txt"}}`,
		"static/file1":                 `file1data`,
		"static/file2.txt":             `file2data`,
		"static_root/robots.txt":       `deny *`,
		"static_root/abc/def/test.txt": `abc`,
	}

	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/index.go.html", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	want := `abc {{static "file1"}} def {{static "file2.txt"}}` // no template processing
	testutil.AssertStringMatch(t, "body", want, response.Body.String())

	request = httptest.NewRequest("GET", "/test/robots.txt", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", `{"key":"myvalue"}`, response.Body.String())

	request = httptest.NewRequest("GET", "/test/static/file2.txt", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", `file2data`, response.Body.String())

	request = httptest.NewRequest("GET", "/test/static_root/abc/def/test.txt", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", `abc`, response.Body.String())
}

func TestStaticIndex(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", static_only=True, index="static2/file1")

def handler(req):
	return {"key": "myvalue"}`,
		"index.go.html":                `abc {{static "file1"}} def {{static "file2.txt"}}`,
		"static2/file1":                `file1data`,
		"static/file2.txt":             `file2data`,
		"static_root2/robots.txt":      `deny *`,
		"static_root/abc/def/test.txt": `abc`,
	}

	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "file1data", response.Body.String())

	request = httptest.NewRequest("GET", "/test/", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "file1data", response.Body.String())

	request = httptest.NewRequest("GET", "/test/static/file2.txt", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "file2data", response.Body.String())
}

func TestStaticIndexSingle(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", static_only=True, index="static2/file1", single_file=True)

def handler(req):
	return {"key": "myvalue"}`,
		"index.go.html":                `abc {{static "file1"}} def {{static "file2.txt"}}`,
		"static2/file1":                `file1data`,
		"static/file2.txt":             `file2data`,
		"static_root2/robots.txt":      `deny *`,
		"static_root/abc/def/test.txt": `abc`,
	}

	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "file1data", response.Body.String())

	request = httptest.NewRequest("GET", "/test/", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "file1data", response.Body.String())

	request = httptest.NewRequest("GET", "/test/static/file2.txt", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 404, response.Code)
}

func TestStaticOnlyError(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/"), ace.api("/static/file1"), ace.api("/robots.txt")], static_only=True)

def handler(req):
	return {"key": "myvalue"}`,
	}

	_, _, err := CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "static_only app cannot have HTML routes")
}

func TestRedirectBarePath(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")], redirect_bare_path=True)

def handler(req):
	return {"key": "myvalue"}`,
		"index.go.html": `abc {{static "file1"}} def {{static "file2.txt"}}`,
	}

	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 307, response.Code) // redirect to the full path with trailing slash
	testutil.AssertStringContains(t, response.Header().Get("Location"), "/test/")

	request = httptest.NewRequest("GET", "/test/", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code) // no redirect for the full path with trailing slash
}
