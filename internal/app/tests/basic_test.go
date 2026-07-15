// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestAppLoadError(t *testing.T) {
	logger := testutil.TestLogger()

	_, _, err := CreateTestApp(logger, map[string]string{
		"app.star":      ``,
		"index.go.html": `{{.}}`,
	})
	testutil.AssertErrorContains(t, err, "app not defined, check app.star")

	_, _, err = CreateTestApp(logger, map[string]string{
		"app.star":      `app = 1`,
		"index.go.html": `{{.}}`,
	})
	testutil.AssertErrorContains(t, err, "app not of type ace.app in app.star")

	_, _, err = CreateTestApp(logger, map[string]string{
		"app.star":      `app = ace.app()`,
		"index.go.html": `{{.}}`,
	})
	testutil.AssertErrorContains(t, err, "missing argument for name")

	_, _, err = CreateTestApp(logger, map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/")])
handler = 10`,
		"index.go.html": `{{.}}`,
	})
	testutil.AssertErrorContains(t, err, "handler is not a function")

	_, _, err = CreateTestApp(logger, map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/", handler=10)])`,
		"index.go.html": `{{.}}`,
	})
	testutil.AssertErrorContains(t, err, "html: for parameter \"handler\": got int, want callable")
}

func TestAppRoutes(t *testing.T) {
	logger := testutil.TestLogger()

	_, _, err := CreateTestApp(logger, map[string]string{
		"app.star": `app = ace.app("testApp", routes = 2)`,
	})
	testutil.AssertErrorContains(t, err, "got int, want list")

	_, _, err = CreateTestApp(logger, map[string]string{
		"app.star": `app = ace.app("testApp", routes = ["abc"])`,
	})
	testutil.AssertErrorContains(t, err, "routes entry 1 is not a struct")
}

func TestAppLoadSuccess(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return {"key": "myvalue"}
		`,
		"index.go.html": `Template got {{ .Data.key }}.`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()

	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", `Template got myvalue.`, response.Body.String())
	var config apptype.CodeConfig

	json.Unmarshal([]byte(fileData[apptype.CONFIG_LOCK_FILE_NAME]), &config) //nolint:errcheck
	testutil.AssertEqualsString(t, "config", "2.0.3", config.Htmx.Version)
}

func TestAppLoadNoHtml(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.api("/", type="json")])

def handler(req):
	return {"key": "myvalue"}
		`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()

	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), `{"key":"myvalue"}`)
}

func TestAppNoArgs(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler_no_args():
	return {"key": "myvalue"}
app = ace.app("testApp", routes = [ace.api("/", type="json", handler=handler_no_args)])
		`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()

	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), `{"key":"myvalue"}`)
}

func TestAppLoadNoHtmlCustomLayout(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.api("/")])

def handler(req):
	return {"key": "myvalue"}
		`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()

	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), `{"key":"myvalue"}`)
}

func TestAppLoadPlain(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.api("/", type=ace.TEXT)])

def handler(req):
	return "abc"
		`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()

	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "abc", response.Body.String())
	testutil.AssertEqualsString(t, "content type", "text/plain", response.Header().Get("Content-Type"))
}

func TestAppLoadWithLockfile(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/", full="t1.tmpl")]
	, settings={"routing": {"template_locations": ['./templates/*.tmpl']}})

def handler(req):
	return {"key": "myvalue"}`,
		"./templates/t1.tmpl":         `Template got {{ .Data.key }}.`,
		apptype.CONFIG_LOCK_FILE_NAME: `{ "htmx": { "version": "1.8" } }`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()

	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", `Template got myvalue.`, response.Body.String())
	var config apptype.CodeConfig

	json.Unmarshal([]byte(fileData[apptype.CONFIG_LOCK_FILE_NAME]), &config) //nolint:errcheck
	testutil.AssertEqualsString(t, "config", "1.8", config.Htmx.Version)
}

func TestAppLoadWrongTemplate(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/", full="t12.tmpl")]
	, settings={"routing": {"template_locations": ['./templates/*.tmpl']}})

def handler(req):
	return {"key": "myvalue"}`,
		"./templates/t1.tmpl":         `Template got {{ .key }}.`,
		apptype.CONFIG_LOCK_FILE_NAME: `{ "htmx": { "version": "1.8" } }`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertEqualsString(t, "body",
		`html/template: "t12.tmpl" is undefined`,
		strings.TrimSpace(response.Body.String()))
	var config apptype.CodeConfig

	json.Unmarshal([]byte(fileData[apptype.CONFIG_LOCK_FILE_NAME]), &config) //nolint:errcheck
	testutil.AssertEqualsString(t, "config", "1.8", config.Htmx.Version)
}

func TestAppHeaderCustom(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return {"key": "myvalue"}`,
		"index.go.html": `Template contents {{template "openrun_gen.go.html"}}.`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	want := `Template contents <script src="/test/static/gen/lib/htmx-491955cd1810747d7d7b9ccb936400afb760e06d25d53e4572b64b6563b2784e.min.js"></script> .`
	fmt.Println(response.Body.String())
	testutil.AssertStringMatch(t, "body", want, response.Body.String())

	request = httptest.NewRequest("GET", "/test/static/gen/lib/htmx.min.js", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
}

func TestAppHtmlNoGen(t *testing.T) {
	// With no HTML route, the generated files should not be created in dev mode
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.api("/")])

def handler(req):
	return {"key": "myvalue"}`,
		"index.go.html": `Template contents {{template "openrun_gen.go.html"}}.`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/static/gen/lib/htmx.min.js", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 404, response.Code)
}

func TestAppHeaderDefault(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/")])

def handler(req):
	return {"key": "myvalue"}`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "no such template \"openrun_body\"")
}

func TestNoHandler(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])`,
		"index.go.html": `Template contents {{.Data}}.`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "Template contents map[]")
}

func TestFullData(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])`,
		"index.go.html": `Template contents {{.}}.`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "Template contents testapp:/test:get.")
}

func TestFullDataRoot(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])`,
		"index.go.html": `Template contents {{.}}.`,
	}
	a, _, err := CreateTestAppRoot(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "Template contents testapp::get.")
}

func TestAppHeaderDefaultWithBody(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/")])

def handler(req):
	return {"key": "myvalue"}`,
		"app.go.html": `{{block "openrun_body" .}}ABC{{end}}`,
	}

	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	want := `<!DOCTYPE html>
	<html lang="en">

	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>testApp</title>
		<script src="/test/static/gen/lib/htmx-491955cd1810747d7d7b9ccb936400afb760e06d25d53e4572b64b6563b2784e.min.js"></script>
		<script src="/test/static/gen/lib/sse-83eca6fa0611fe2b0bf1700b424b88b5eced38ef448ef9760a2ea08fbc875611.js"></script>
		<div id="cl_reload_listener" hx-ext="sse"
		sse-connect="/test/_openrun_app/sse" sse-swap="openrun_reload"
		hx-trigger="sse:openrun_reload"></div>
	<script>
		document .getElementById("cl_reload_listener") .addEventListener("sse:openrun_reload",
			function (event) {
				location.reload();
			});
	</script>
	</head>

	<body>
	  <h1>OpenRun: testApp</h1>
	  ABC
	</body>
	</html>`

	testutil.AssertStringMatch(t, "body", want, response.Body.String())
}

func TestRedirect(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])
def handler(req):
	return ace.redirect("/new_url", code=302)`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 302, response.Code)
	testutil.AssertStringContains(t, response.Header().Get("Location"), "/new_url")

	// Test default code is 303
	fileData = map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])
def handler(req):
	return ace.redirect("/new_url")`,
	}
	a, _, err = CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request = httptest.NewRequest("GET", "/test", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 303, response.Code)
	testutil.AssertStringContains(t, response.Header().Get("Location"), "/new_url")
}

func TestPost(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/", method=ace.POST)])
def handler(req):
	return ace.redirect("/new_url", code=302)`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 405, response.Code) // GET instead of POST

	request = httptest.NewRequest("POST", "/test", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 302, response.Code)
	testutil.AssertStringContains(t, response.Header().Get("Location"), "/new_url")
}

func TestResponse(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return ace.response({"key": "myvalue"}, "testtmpl")`,
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
	testutil.AssertStringContains(t, response.Body.String(), "ABC myvalue")
}

func TestResponseRetarget(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return ace.response({"key": "myvalue"}, "testtmpl", code=500, retarget="#abc", reswap="outerHTML")`,
		"index.go.html": `Template. {{block "testtmpl" .}}ABC {{.Data.key}} {{end}}`,
	}
	a, _, err := CreateTestAppRoot(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "ABC myvalue")
	testutil.AssertEqualsString(t, "retarget", response.Header().Get("HX-Retarget"), "#abc")
	testutil.AssertEqualsString(t, "reswap", response.Header().Get("HX-Reswap"), "outerHTML")
}

func TestSchemaLoad(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"schema.star": `

type("mytype", fields=[
			field("aint", INT),
			field("astring", STRING),
			field("abool", BOOLEAN),
			field("alist", LIST),
			field("adict", DICT),
		])
		`,
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
    myt = doc.mytype(aint=1, astring="abc", alist=[1,2,3], adict={"a": 1, "b": 2}, abool=False)
    myt.aint=2
    myt.astring="abc2"
    myt.abool=True
    myt.alist[1]=4
    myt.adict["a"]=3
    return myt
`,
		"index.go.html": `Template. ABC {{.Data}}`,
	}
	a, _, err := CreateTestAppRoot(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "Template. ABC map[")
	testutil.AssertStringContains(t, response.Body.String(), "abool:true")
	testutil.AssertStringContains(t, response.Body.String(), "adict:map[a:3 b:2]")
	testutil.AssertStringContains(t, response.Body.String(), "aint:2")
	testutil.AssertStringContains(t, response.Body.String(), "alist:[1 4 3]")
	testutil.AssertStringContains(t, response.Body.String(), "astring:abc2")
	testutil.AssertStringContains(t, response.Body.String(), "_created_at:0 _created_by: _id:0 _updated_at:")
}

func TestOutput(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def f1():
  return ace.output("abc")
def f2():
  return ace.output(error="f2error")
def f3():
  return ace.output({"k": "v"})
def h1(req):
  v = f1()
  return v.value
def h2(req):
  v = f2()
  return v.value
def h22(req):
  v = f2()
  return v.error
def h3(req):
  v = f3()
  return v.value["k"]
def h4(req):
   ret = ace.output(error="h4error")
   if ret:
     return "ok"
   else:
     return "fail"

app = ace.app("testApp", 
 routes = [
  ace.api("/api1", handler=h1),
  ace.api("/api2", handler=h2),
  ace.api("/api22", handler=h22),
  ace.api("/api3", handler=h3),
  ace.api("/api4", handler=h4)
 ]
)
`,
	}
	a, _, err := CreateTestAppRoot(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/api1", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "abc")

	request = httptest.NewRequest("GET", "/api2", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "output has error: f2error")

	request = httptest.NewRequest("GET", "/api22", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "\"f2error\"")

	request = httptest.NewRequest("GET", "/api3", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "\"v\"")

	request = httptest.NewRequest("GET", "/api4", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "\"fail\"")
}

func TestAppConfigRead(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def t1(req):
	return ace.config("AAA", "DEF")
def t2(req):
	return ace.config("AAA", "$HOME/ss")
def t3(req):
	return ace.config("AAA", "$SHELL")
app = ace.app("testApp", routes = [ace.api("/t1", t1, type=ace.TEXT), ace.api("/t2", t2, type=ace.TEXT), ace.api("/t3", t3, type=ace.TEXT)])
		`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/t1", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "DEF", response.Body.String())

	request = httptest.NewRequest("GET", "/test/t2", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	if strings.Contains(response.Body.String(), "$HOME") {
		t.Errorf("Expected $HOME to be replaced, got %s", response.Body.String())
	}

	request = httptest.NewRequest("GET", "/test/t3", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "$SHELL", response.Body.String())
}

func TestAppUserAndPerms(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return {
		"user": req.UserId,
		"user_subject": req.UserSubject,
		"user_email": req.UserEmail,
		"header_user_subject": req.Headers["X-Openrun-User-Id"][0],
		"header_user_email": req.Headers["X-Openrun-User-Email"][0],
		"perms": req.CustomPerms,
		"rbac_enabled": req.AppRBACEnabled,
	}
		`,
		"index.go.html": `Template got {{ .Data.user }} {{ .Data.user_subject }} {{ .Data.user_email }} {{ .Data.header_user_subject }} {{ .Data.header_user_email }} {{ .Data.perms }} {{ .Data.rbac_enabled }} {{ .UserId }} {{ .UserSubject }} {{ .UserEmail }} {{ .CustomPerms }} {{ .AppRBACEnabled }}`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(request.Context(), types.USER_ID, types.ANONYMOUS_USER)
	ctx = context.WithValue(ctx, types.USER_SUBJECT, "subject-123")
	ctx = context.WithValue(ctx, types.USER_EMAIL, "test@example.com")
	ctx = context.WithValue(ctx, types.CUSTOM_PERMS, []string{"read:data", "write:data", "admin"})
	ctx = context.WithValue(ctx, types.RBAC_ENABLED, true)
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()

	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", `Template got anonymous subject-123 test@example.com subject-123 test@example.com [read:data write:data admin] true anonymous subject-123 test@example.com [read:data write:data admin] true`, response.Body.String())
}

// TestAppQueryAndForm guards the request query/form population: on GET, Query
// and Form both hold the URL query; on POST, Query holds only the URL query
// while Form merges query + body and PostForm holds only the body.
func TestAppQueryAndForm(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/", fragments=[ace.fragment("f", method="POST")])])

def handler(req):
	return {
		"q_a": req.Query.get("a", [""])[0],
		"q_b": req.Query.get("b", ["NONE"])[0],
		"form_a": req.Form.get("a", [""])[0],
		"form_b": req.Form.get("b", ["NONE"])[0],
		"post_a": req.PostForm.get("a", ["NONE"])[0],
		"post_b": req.PostForm.get("b", ["NONE"])[0],
	}
		`,
		"index.go.html": `q[{{.Data.q_a}},{{.Data.q_b}}] form[{{.Data.form_a}},{{.Data.form_b}}] post[{{.Data.post_a}},{{.Data.post_b}}]`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// GET: only a URL query param "a"; Query and Form both see it, no body
	getReq := httptest.NewRequest("GET", "/test?a=qval", nil)
	getResp := httptest.NewRecorder()
	a.ServeHTTP(getResp, getReq)
	testutil.AssertEqualsInt(t, "get code", 200, getResp.Code)
	testutil.AssertEqualsString(t, "get body",
		`q[qval,NONE] form[qval,NONE] post[NONE,NONE]`, getResp.Body.String())

	// POST: query "a" in the URL, body form "b". Query sees only a; Form sees
	// both; PostForm sees only b
	postReq := httptest.NewRequest("POST", "/test/f?a=qval",
		strings.NewReader("b=bodyval"))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postResp := httptest.NewRecorder()
	a.ServeHTTP(postResp, postReq)
	testutil.AssertEqualsInt(t, "post code", 200, postResp.Code)
	testutil.AssertEqualsString(t, "post body",
		`q[qval,NONE] form[qval,bodyval] post[NONE,bodyval]`, postResp.Body.String())
}

// TestAppHeadersSanitized checks the lazily-built req.Headers view: a client
// header passes through, while a spoofed X-Openrun-* header is stripped and
// replaced with the trusted value derived from the request context (empty user
// here), so a caller cannot inject openrun identity headers.
func TestAppHeadersSanitized(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	return {
		"custom": req.Headers["X-Custom"][0],
		"spoofed_user": req.Headers["X-Openrun-User"][0],
	}
		`,
		"index.go.html": `[{{ .Data.custom }}] [{{ .Data.spoofed_user }}]`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	request.Header.Set("X-Custom", "passed-through")
	request.Header.Set(types.OPENRUN_HEADER_USER, "hacker") // spoofed by the client
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	// The custom header survives; the spoofed openrun user header is replaced
	// with the trusted (empty) value, not "hacker"
	testutil.AssertEqualsString(t, "body", `[passed-through] []`, response.Body.String())
}

// TestAppHeadersAccess exercises the lazily-materialized req.Headers view when
// the handler actually reads it: the full set of incoming request headers must
// be present, and repeated access must be consistent (the clone is built once
// and memoized). This is the read-side counterpart to the lazy header change.
func TestAppHeadersAccess(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	# Read several incoming headers, and read one of them twice to exercise
	# the memoized lazy clone
	return {
		"agent": req.Headers["User-Agent"][0],
		"accept": req.Headers["Accept"][0],
		"custom1": req.Headers["X-Custom-1"][0],
		"custom2": req.Headers["X-Custom-2"][0],
		"agent_again": req.Headers["User-Agent"][0],
		"count": len(req.Headers["X-Multi"]),
		"multi0": req.Headers["X-Multi"][0],
		"multi1": req.Headers["X-Multi"][1],
	}
		`,
		"index.go.html": `{{.Data.agent}}|{{.Data.accept}}|{{.Data.custom1}}|{{.Data.custom2}}|{{.Data.agent_again}}|{{.Data.count}}|{{.Data.multi0}}|{{.Data.multi1}}`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	request.Header.Set("User-Agent", "test-agent/1.0")
	request.Header.Set("Accept", "text/html")
	request.Header.Set("X-Custom-1", "v1")
	request.Header.Set("X-Custom-2", "v2")
	request.Header.Add("X-Multi", "m0")
	request.Header.Add("X-Multi", "m1")
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	// Every incoming header is visible; the twice-read header is stable; a
	// multi-value header keeps both values
	testutil.AssertEqualsString(t, "body",
		`test-agent/1.0|text/html|v1|v2|test-agent/1.0|2|m0|m1`, response.Body.String())
}
