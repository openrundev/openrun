// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestBaseTemplate(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return {"key": "myvalue"}`,
		"index.go.html":              `ABC {{.Data.key}} {{- template "base" . -}}`,
		"base_templates/aaa.go.html": `{{define "base"}} aaa{{end}}`,
	}
	a, _, err := CreateTestAppRoot(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "ABC myvalue aaa", response.Body.String())
}

func TestBaseTemplateResponse(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return ace.response({"key": "myvalue"}, "index.go.html")`,
		"index.go.html":              `ABC {{.Data.key}} {{- template "base" . -}}`,
		"base_templates/aaa.go.html": `{{define "base"}} aaa{{end}}`,
	}
	a, _, err := CreateTestAppRoot(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "ABC myvalue aaa", response.Body.String())
}

func TestBaseTemplateComplete(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [
	ace.html("/"),
	ace.html("/second", "second.go.html"),
	])

def handler(req):
	return {}`,
		"index.go.html":               `{{define "body"}} indexbody {{end}} {{- template "full" . -}}`,
		"second.go.html":              `{{define "body"}} secondbody {{end}} {{- template "full" . -}}`,
		"base_templates/head.go.html": `{{define "head"}} <head></head>{{end}}`,
		"base_templates/foot.go.html": `{{define "footer"}} <footer></footer>{{end}}`,
		"base_templates/full.go.html": `{{define "full"}} <html>{{template "head" .}}{{block "body" .}}{{end}}{{template "footer" .}}</html>{{end}}`,
	}
	a, _, err := CreateTestAppRoot(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "<html> <head></head> indexbody  <footer></footer></html>", response.Body.String())

	request = httptest.NewRequest("GET", "/second", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "<html> <head></head> secondbody  <footer></footer></html>", response.Body.String())
}
