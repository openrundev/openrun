// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestLibraryBasic(t *testing.T) {
	// Create a test server to serve the library file
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "myjs contents") //nolint:errcheck
	}))
	testUrl := testServer.URL + "/abc/mylib.js"

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
			     libraries=["%s"])`, testUrl),
	}

	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/static/gen/lib/mylib.js", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "myjs contents", response.Body.String())

	// File is cached, should be served from cache even if file server is closed
	testServer.Close()
	ok, err := a.Reload(true, true, types.DryRunFalse)
	if !ok || err != nil {
		t.Fatalf("Error %s", err)
	}

	request = httptest.NewRequest("GET", "/test/static/gen/lib/mylib.js", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "myjs contents", response.Body.String())
}

func TestLibraryESM(t *testing.T) {
	// ESM setup requires to run esbuild, which does not play well with the test FS.
	// Test basic flow without actually running esbuild
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
			     libraries=[ace.library("mylib", "1.0.0")])`,
	}
	_, _, err := CreateDevModeTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, `Could not resolve "mylib-1.0.0.js"`)

	fileData = map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
			     libraries=[ace.library("mylib", "1.0.0", args=["--minify"])])`,
	}
	_, _, err = CreateDevModeTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, `Could not resolve "mylib-1.0.0.js"`) // flag got passed to esbuild

	fileData = map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
			     libraries=[ace.library("mylib", "1.0.0", args=["--invalid"])])`,
	}
	_, _, err = CreateDevModeTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, `Invalid build flag: "--invalid"`) // esbuild did not like the arg

	fileData = map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
			     libraries=[ace.library("mylib", "1.0.0", args=10)])`,
	}
	_, _, err = CreateDevModeTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, `got int, want list`)
}
