// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestFragmentBasics(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/abc",
	fragments=[ace.fragment("frag", "ff")]
)])

def handler(req):
	return {"key": "myvalue", "key2": "myvalue2"}
		`,
		"index.go.html": `Template main {{ .Data.key }}. {{ block "ff" . }} fragdata {{ .Data.key2 }} {{ end }}`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	fullHtml := `Template main myvalue.  fragdata myvalue2 `
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", fullHtml, response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc/frag", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	// With default http request to fragment url (no htmx headers, full html is returned)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", fullHtml, response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc", nil)
	response = httptest.NewRecorder()
	request.Header.Set("HX-Request", "true")
	a.ServeHTTP(response, request)
	// With htmx request to main url, full html is returned
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", fullHtml, response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc/frag", nil)
	response = httptest.NewRecorder()
	request.Header.Set("HX-Request", "true")
	a.ServeHTTP(response, request)
	// With htmx request to fragment url, partial html is returned
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", " fragdata myvalue2 ", response.Body.String())
}

func TestFragmentInherit(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/abc", partial="ff",
	fragments=[ace.fragment("frag")]
)])

def handler(req):
	return {"key": "myvalue", "key2": "myvalue2"}
		`,
		"index.go.html": `Template main {{ .Data.key }}. {{ block "ff" . }} fragdata {{ .Data.key2 }} {{ end }}`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	fullHtml := `Template main myvalue.  fragdata myvalue2 `
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", fullHtml, response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc/frag", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	// With default http request to fragment url (no htmx headers, full html is returned)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", fullHtml, response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc", nil)
	response = httptest.NewRecorder()
	request.Header.Set("HX-Request", "true")
	a.ServeHTTP(response, request)
	// With htmx request to main url, partial html is returned
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", " fragdata myvalue2 ", response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc/frag", nil)
	response = httptest.NewRecorder()
	request.Header.Set("HX-Request", "true")
	a.ServeHTTP(response, request)
	// With htmx request to fragment url, partial html is returned
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", " fragdata myvalue2 ", response.Body.String())
}

func TestFragmentDifferentHandler(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(req):
	return {"key": "myvalue", "key2": "myvalue2"}
def handler2(req):
	return {"key": "myvalue3", "key2": "myvalue4"}

app = ace.app("testApp", custom_layout=True, routes = [ace.html("/abc",
	fragments=[ace.fragment("frag", "ff", handler=handler2)]
)])
		`,
		"index.go.html": `Template main {{ .Data.key }}. {{ block "ff" . }} fragdata {{ .Data.key2 }} {{ end }}`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	fullHtml := `Template main myvalue.  fragdata myvalue2 `
	fullHtml2 := `Template main myvalue3.  fragdata myvalue4 `
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", fullHtml, response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc/frag", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	// With default http request to fragment url (no htmx headers), full html2 is returned
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", fullHtml2, response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc", nil)
	response = httptest.NewRecorder()
	request.Header.Set("HX-Request", "true")
	a.ServeHTTP(response, request)
	// With htmx request to main url, full html is returned
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", fullHtml, response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc/frag", nil)
	response = httptest.NewRecorder()
	request.Header.Set("HX-Request", "true")
	a.ServeHTTP(response, request)
	// With htmx request to fragment url, partial html is returned
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", " fragdata myvalue4 ", response.Body.String())
}

func TestFragmentMulti(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(req):
	return {"key": "myvalue", "key2": "myvalue2"}
def handler2(req):
	return {"key": "myvalue3", "key2": "myvalue4"}

app = ace.app("testApp", custom_layout=True, routes = [ace.html("/abc",
	fragments=[ace.fragment("frag", "ff", handler=handler2), ace.fragment("frag2", "ff2", method="POST")]
)])
		`,
		"index.go.html": `Template main {{ .Data.key }}. {{ block "ff" . }} fragdata {{ .Data.key2 }} {{ end }}
		{{ block "ff2" . }} {{if contains "frag2" .PagePath}} {{.PagePath}} frag2data {{ end }} {{end}}`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/abc", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	fullHtml := `Template main myvalue.  fragdata myvalue2 `
	fullHtml2 := `Template main myvalue3.  fragdata myvalue4 `
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", fullHtml, response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc/frag", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", fullHtml2, response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc/frag2", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 405, response.Code) // GET instead of POST

	request = httptest.NewRequest("POST", "/test/abc/frag2", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code) // GET instead of POST
	testutil.AssertStringMatch(t, "body", fullHtml+"/test/abc/frag2 frag2data", response.Body.String())

	request = httptest.NewRequest("GET", "/test/abc/frag", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", " fragdata myvalue4 ", response.Body.String())

	request = httptest.NewRequest("POST", "/test/abc/frag2", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "/test/abc/frag2 frag2data", response.Body.String())
}

func TestFragmentErrors(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/abc",
	fragments=10
)])
		`,
		"index.go.html": `Template main {{ .Data.key }}. {{ block "ff" . }} fragdata {{ .Data.key2 }} {{ end }}`,
	}
	_, _, err := CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "got int, want list")

	fileData = map[string]string{
		"app.star": `
def handler(req):
		return {"key": "myvalue", "key2": "myvalue2"}
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/abc",
	fragments=[10]
)])
		`,
		"index.go.html": `Template main {{ .Data.key }}. {{ block "ff" . }} fragdata {{ .Data.key2 }} {{ end }}`,
	}
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "page 1 fragment 1 is not a struct")

	fileData = map[string]string{
		"app.star": `
def handler(req):
		return {"key": "myvalue", "key2": "myvalue2"}
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/abc",
	fragments=[ace.fragment("frag", abc="ff", handler=handler)]
)])
		`,
		"index.go.html": `Template main {{ .Data.key }}. {{ block "ff" . }} fragdata {{ .Data.key2 }} {{ end }}`,
	}
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "unexpected keyword argument \"abc\"")

	fileData = map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/abc",
	fragments=[ace.fragment("frag", "ff", handler=10)]
)])
		`,
		"index.go.html": `Template main {{ .Data.key }}. {{ block "ff" . }} fragdata {{ .Data.key2 }} {{ end }}`,
	}
	_, _, err = CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "for parameter \"handler\": got int, want callable")
}

func TestFragmentPostRedirect(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/abc", partial="ff",
	fragments=[ace.fragment("frag", method="POST")]
)])

def handler(req):
	return {"key": "myvalue", "key2": "myvalue2"}
		`,
		"index.go.html": `Template main {{ .Data.key }}. {{ block "ff" . }} fragdata {{ .Data.key2 }} {{ end }}`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("POST", "/test/abc/frag", nil)
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	// HTMX return, return fragment
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", " fragdata myvalue2 ", response.Body.String())

	request = httptest.NewRequest("POST", "/test/abc/frag", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	// Without Referer header, non htmx return, return main page
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "Template main myvalue.  fragdata myvalue2 ", response.Body.String())

	request = httptest.NewRequest("POST", "/test/abc/frag", nil)
	request.Header.Set("Referer", "/test/abc")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	// Relative same-origin referer is accepted.
	testutil.AssertEqualsInt(t, "code", 303, response.Code)
	testutil.AssertEqualsString(t, "redirect", "/test/abc", response.Header().Get("Location"))

	request = httptest.NewRequest("POST", "/test/abc/frag", nil)
	request.Header.Set("Referer", "http://example.com/test/abc?q=1#frag")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	// Absolute same-origin referer is normalized to a local redirect target.
	testutil.AssertEqualsInt(t, "code", http.StatusSeeOther, response.Code)
	testutil.AssertEqualsString(t, "redirect", "/test/abc?q=1#frag", response.Header().Get("Location"))

	request = httptest.NewRequest("POST", "/test/abc/frag", nil)
	request.Header.Set("Referer", "http://evil.com/test/abc")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	// External referer is ignored and falls back to rendering the page.
	testutil.AssertEqualsInt(t, "code", http.StatusOK, response.Code)
	testutil.AssertEqualsString(t, "body", "Template main myvalue.  fragdata myvalue2 ", response.Body.String())

	request = httptest.NewRequest("POST", "/test/abc/frag", nil)
	request.Header.Set("Referer", "relative/path")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	// Non-rooted relative referer is ignored and falls back to rendering the page.
	testutil.AssertEqualsInt(t, "code", http.StatusOK, response.Code)
	testutil.AssertEqualsString(t, "body", "Template main myvalue.  fragdata myvalue2 ", response.Body.String())
}
