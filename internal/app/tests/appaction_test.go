package app_test

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func createMultipartUploadRequest(t *testing.T, reqPath, fieldName, fileName string, fileSize int) *http.Request {
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile(fieldName, fileName)
	if err != nil {
		t.Fatalf("CreateFormFile error: %v", err)
	}

	if _, err = part.Write(bytes.Repeat([]byte("a"), fileSize)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	if err = writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	request := httptest.NewRequest("POST", reqPath, body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("HX-Request", "true")
	return request
}

func actionTester(t *testing.T, rootPath bool, actionPath string) {
	t.Helper()
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a", "b"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "` + actionPath + `", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	var a *app.App
	var err error
	if rootPath {
		a, _, err = CreateTestAppRoot(logger, fileData)
	} else {
		a, _, err = CreateTestApp(logger, fileData)
	}
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	var reqPath string
	if rootPath {
		reqPath = actionPath
	} else {
		reqPath = path.Join("/test", actionPath)
	}

	request := httptest.NewRequest("GET", reqPath, nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	testutil.AssertStringContains(t, response.Body.String(), `id="param_param1"`)

	// Single action app: the sidebar stays a slide-in drawer on all screen
	// sizes (no docked sidebar, hamburger always visible, no action nav)
	if strings.Contains(response.Body.String(), "md:drawer-open") {
		t.Error("single action app must not dock the sidebar open")
	}
	if strings.Contains(response.Body.String(), "md:hidden") {
		t.Error("single action app must keep the hamburger visible on md+")
	}
	if strings.Contains(response.Body.String(), "action-nav") {
		t.Error("single action app must not render the action nav")
	}

	request = httptest.NewRequest("POST", reqPath, nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "match response", response.Body.String(), `
	<div role="status" class="py-1 font-medium"> done </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <output id="action_result" hx-swap-oob="innerHTML"> <output role="alert" class="block"> <div class="card border border-base-300 bg-base-100 shadow-sm w-full"> <div class="card-body p-4 sm:p-6 gap-3 min-w-0"> <h2 class="section-heading">Output</h2> <textarea rows="4" class="textarea w-full font-mono text-xs leading-5" readonly>a b </textarea> </div> </div> </output> </output>
	`)

}

func TestRootAppRootAction(t *testing.T) {
	actionTester(t, true, "/")
}

func TestRootApp(t *testing.T) {
	actionTester(t, true, "/abc")
}

func TestNonRootAppRootAction(t *testing.T) {
	actionTester(t, false, "/")
}

func TestNonRootApp(t *testing.T) {
	actionTester(t, false, "/abc")
}

func TestParamErrors(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a", "b"], param_errors={"param1": "param1error", "param3": "param3error"})

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

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	testutil.AssertStringContains(t, response.Body.String(), `id="param_param1"`)

	request = httptest.NewRequest("POST", "/test", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "match response", `
	<div role="status" class="py-1 font-medium"> done </div> <output id="param_param1_error" hx-swap-oob="innerHTML"><div role="alert">param1error</div></output> <output id="param_param2_error" hx-swap-oob="innerHTML"></output> <output id="param_param3_error" hx-swap-oob="innerHTML"><div role="alert">param3error</div></output> <output id="action_result" hx-swap-oob="innerHTML"> <output role="alert" class="block"> <div class="card border border-base-300 bg-base-100 shadow-sm w-full"> <div class="card-body p-4 sm:p-6 gap-3 min-w-0"> <h2 class="section-heading">Output</h2> <textarea rows="4" class="textarea w-full font-mono text-xs leading-5" readonly>a b </textarea> </div> </div> </output> </output>
	`, response.Body.String())
}

func TestAutoReportTable(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": 1, "b": "abc"}])

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	testutil.AssertStringContains(t, response.Body.String(), `id="param_param1"`)

	request = httptest.NewRequest("POST", "/test", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "match response", `
	<div role="status" class="py-1 font-medium"> done </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <output id="action_result" hx-swap-oob="innerHTML"> <div role="alert"> <div class="card border border-base-300 bg-base-100 shadow-sm w-full"> <div class="card-body p-4 sm:p-6 gap-3 min-w-0"> <h2 class="section-heading">Report</h2> <div class="overflow-x-auto"> <table class="table table-zebra min-w-full text-sm"> <thead> <tr> <th scope="col">a</th> <th scope="col">b</th> </tr> </thead> <tbody> <tr> <td class="font-mono text-xs">1</td> <td class="font-mono text-xs">abc</td> </tr> </tbody> </table> </div> </div> </div> </div> </output>
	`, response.Body.String())
}

func TestAutoReportJSON(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": {"c": 1}, "b": "abc"}], report=ace.AUTO)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	testutil.AssertStringContains(t, response.Body.String(), `id="param_param1"`)

	request = httptest.NewRequest("POST", "/test", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "match response", `
	<div role="status" class="py-1 font-medium"> done </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <output id="action_result" hx-swap-oob="innerHTML"> <div role="alert"> <div class="card border border-base-300 bg-base-100 shadow-sm w-full"> <div class="card-body p-4 sm:p-6 gap-3 min-w-0"> <div class="flex items-center justify-between gap-2"> <h2 class="section-heading">Result</h2> <div class="flex gap-1"> <button type="button" class="btn btn-ghost btn-xs" onclick="jsonTreeSetAll(this, true)"> Expand all </button> <button type="button" class="btn btn-ghost btn-xs" onclick="jsonTreeSetAll(this, false)"> Collapse all </button> </div> </div> <div class="json-container overflow-x-auto" data-json="{&#34;a&#34;:{&#34;c&#34;:1},&#34;b&#34;:&#34;abc&#34;}"></div> </div> </div> <script> document.querySelectorAll(".json-container").forEach(function (div) { const jsonData = JSON.parse(div.getAttribute("data-json")); renderJSONWithRoot(jsonData, div); }); </script> </div> </output>
	`, response.Body.String())
}

func TestReportTable(t *testing.T) {
	// Force table format for output containing map
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": {"c": 1}, "b": "abc"}], report=ace.TABLE)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	testutil.AssertStringContains(t, response.Body.String(), `id="param_param1"`)

	request = httptest.NewRequest("POST", "/test", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "match response", `
	<div role="status" class="py-1 font-medium"> done </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <output id="action_result" hx-swap-oob="innerHTML"> <div role="alert"> <div class="card border border-base-300 bg-base-100 shadow-sm w-full"> <div class="card-body p-4 sm:p-6 gap-3 min-w-0"> <h2 class="section-heading">Report</h2> <div class="overflow-x-auto"> <table class="table table-zebra min-w-full text-sm"> <thead> <tr> <th scope="col">a</th> <th scope="col">b</th> </tr> </thead> <tbody> <tr> <td class="font-mono text-xs">map[c:1]</td> <td class="font-mono text-xs">abc</td> </tr> </tbody> </table> </div> </div> </div> </div> </output>
	`, response.Body.String())
}

func TestReportTableMissingData(t *testing.T) {
	// Force table format for output containing map
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": 1, "b": "abc"}, {"c": 1, "b": "abc2"}], report=ace.TABLE)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	testutil.AssertStringContains(t, response.Body.String(), `id="param_param1"`)

	request = httptest.NewRequest("POST", "/test", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "match response", `
	<div role="status" class="py-1 font-medium"> done </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <output id="action_result" hx-swap-oob="innerHTML"> <div role="alert"> <div class="card border border-base-300 bg-base-100 shadow-sm w-full"> <div class="card-body p-4 sm:p-6 gap-3 min-w-0"> <h2 class="section-heading">Report</h2> <div class="overflow-x-auto"> <table class="table table-zebra min-w-full text-sm"> <thead> <tr> <th scope="col">a</th> <th scope="col">b</th> </tr> </thead> <tbody> <tr> <td class="font-mono text-xs">1</td> <td class="font-mono text-xs">abc</td> </tr> <tr> <td class="font-mono text-xs"></td> <td class="font-mono text-xs">abc2</td> </tr> </tbody> </table> </div> </div> </div> </div> </output>
	`, response.Body.String())
}

func TestParamPost(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"c1": args.param1, "c2": args.param2, "c3": args.param3}], report=ace.TABLE)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")
param("param2", description="param2 description", type=BOOLEAN, default=False)
param("param3", description="param3 description", type=INT, default=10)
param("param4", description="param4 description", type=STRING, required=False, display_type=PASSWORD)`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	testutil.AssertStringContains(t, response.Body.String(), `id="param_param1"`)

	values := url.Values{
		"param1": {"abc"},
		"param2": {"true"},
		"param3": {"20"},
		"param4": {"secretvalue"},
	}

	request = httptest.NewRequest("POST", "/test", strings.NewReader(values.Encode()))
	request.Header.Set("HX-Request", "true")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "push url", "/test?param1=abc&param2=true&param3=20", response.Header().Get("HX-Push-Url"))
	testutil.AssertStringMatch(t, "match response", `
	<div role="status" class="py-1 font-medium"> done </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <output id="param_param2_error" hx-swap-oob="innerHTML"></output> <output id="param_param3_error" hx-swap-oob="innerHTML"></output> <output id="param_param4_error" hx-swap-oob="innerHTML"></output> <output id="action_result" hx-swap-oob="innerHTML"> <div role="alert"> <div class="card border border-base-300 bg-base-100 shadow-sm w-full"> <div class="card-body p-4 sm:p-6 gap-3 min-w-0"> <h2 class="section-heading">Report</h2> <div class="overflow-x-auto"> <table class="table table-zebra min-w-full text-sm"> <thead> <tr> <th scope="col">c1</th> <th scope="col">c2</th> <th scope="col">c3</th> </tr> </thead> <tbody> <tr> <td class="font-mono text-xs">abc</td> <td class="font-mono text-xs">true</td> <td class="font-mono text-xs">20</td> </tr> </tbody> </table> </div> </div> </div> </div> </output>
	`, response.Body.String())
}

func TestCustomReport(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": 1, "b": "abc"}], report="custom")

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star":    `param("param1", description="param1 description", type=STRING, default="myvalue")`,
		"myfile.go.html": `{{block "custom" .}} customdata {{end}}`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	testutil.AssertStringContains(t, response.Body.String(), `id="param_param1"`)

	request = httptest.NewRequest("POST", "/test", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "match response", `
	<div role="status" class="py-1 font-medium"> done </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <div id="action_result" hx-swap-oob="innerHTML"> <output role="alert"> customdata </output> </div>
	`, response.Body.String())

	// Unset the template
	fileData["myfile.go.html"] = ``
	a, _, err = CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	request = httptest.NewRequest("GET", "/test/", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	testutil.AssertStringContains(t, response.Body.String(), `id="param_param1"`)

	request = httptest.NewRequest("POST", "/test", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "match response", `
	<div role="status" class="py-1 font-medium"> done </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <div id="action_result" hx-swap-oob="innerHTML"> <output role="alert"> </output> </div>html/template: "custom" is undefined
	`, response.Body.String())
}

func TestActionUploadRequestBodyLimit(t *testing.T) {
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

	request := createMultipartUploadRequest(t, "/test", "upload", "report.txt", 512)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", http.StatusRequestEntityTooLarge, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "request body too large")
}

func TestCustomESMImport(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": 1, "b": "abc"}], report="custom")

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)],
	libraries=[ace.library("d3", "2.3"), ace.library("e4", "3.4")])
		`,
		"params.star":              `param("param1", description="param1 description", type=STRING, default="myvalue")`,
		"myfile.go.html":           `{{block "custom" .}} customdata {{end}}`,
		"static/gen/esm/d3-2.3.js": "abc",
		"static/gen/esm/e4-3.4.js": "def",
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "script type=\"importmap\"")
	testutil.AssertStringContains(t, response.Body.String(), "\"d3\": \"/test/static/gen/esm/d3-2-ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.3.js\"")
	testutil.AssertStringContains(t, response.Body.String(), "\"e4\": \"/test/static/gen/esm/e4-3-cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34.4.js\"")
}

func TestParamOptions(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a", "b"], param_errors={"param1": "param1error", "param3": "param3error"})

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler, hidden=["param2"])])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")
param("options-param1", description="param1 options", type=LIST, default=["a", "b", "c"])
param("param2", description="param2 description", type=STRING, default="myvalue2")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	bodyStripped := strings.Join(strings.Fields(response.Body.String()), " ")
	testutil.AssertStringContains(t, bodyStripped, `<searchable-select class="block relative" data-strict> <input id="param_param1" name="param1" type="text" class="input w-full pr-9" role="combobox"`)
	if strings.Contains(bodyStripped, `options-param1`) {
		t.Errorf("options-param1 should not be in the body")
	}
	if strings.Contains(bodyStripped, `param2`) {
		t.Errorf("hidden param2 should not be in the body")
	}
}

func TestParamOptionsUnderscore(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a", "b"], param_errors={"param1": "param1error", "param3": "param3error"})

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler, hidden=["param2"])])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")
param("options_param1", description="param1 options", type=LIST, default=["a", "b", "c"])
param("param2", description="param2 description", type=STRING, default="myvalue2")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	bodyStripped := strings.Join(strings.Fields(response.Body.String()), " ")
	testutil.AssertStringContains(t, bodyStripped, `<searchable-select class="block relative" data-strict> <input id="param_param1" name="param1" type="text" class="input w-full pr-9" role="combobox"`)
	if strings.Contains(bodyStripped, `options_param1`) {
		t.Errorf("options_param1 should not be in the body")
	}
	if strings.Contains(bodyStripped, `param2`) {
		t.Errorf("hidden param2 should not be in the body")
	}
}

// TestActionStylesheetLayering verifies the css coexistence design
// (docs/designs/actions-css-layering.md): the embedded stylesheet always
// loads first so the action chrome never depends on the app's generated
// css being current; a styled app's own css loads after it
func TestActionStylesheetLayering(t *testing.T) {
	logger := testutil.TestLogger()
	appStar := `
def handler(dry_run, args):
	return ace.result(status="done", values=["a"], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)],
	style=ace.style("daisyui"))

		`
	fileData := map[string]string{
		"app.star":    appStar,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}

	// Styled app WITHOUT a generated css (not yet run in dev mode): only
	// the embedded stylesheet loads
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	body := response.Body.String()
	testutil.AssertStringContains(t, body, `href="/test/astatic/style-`)
	if strings.Contains(body, "gen/css/style") {
		t.Error("app stylesheet link rendered without a generated css file")
	}

	// Styled app WITH a generated css: both load, embedded first
	fileData["static/gen/css/style.css"] = "/* app generated css */"
	a, _, err = CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	response = httptest.NewRecorder()
	a.ServeHTTP(response, httptest.NewRequest("GET", "/test", nil))
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	body = response.Body.String()
	embeddedAt := strings.Index(body, `href="/test/astatic/style-`)
	appAt := strings.Index(body, `href="/test/static/gen/css/style`)
	if embeddedAt == -1 || appAt == -1 {
		t.Fatalf("expected both stylesheets, embedded at %d, app at %d", embeddedAt, appAt)
	}
	if embeddedAt > appAt {
		t.Error("the embedded stylesheet must load before the app's generated css")
	}
}

func TestParamOptionsStrict(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[args.param1, args.param2], report=ace.TEXT)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param1", description="strict dropdown", type=STRING, default="a")
param("options_param1", description="param1 options", type=LIST, default=["a", "b", "c"])
param("param2", description="free text dropdown", type=STRING, default="a", display_type=COMBO)
param("options_param2", description="param2 options", type=LIST, default=["a", "b", "c"])`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// The strict (default) dropdown renders with data-strict, the COMBO one without
	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	bodyStripped := strings.Join(strings.Fields(response.Body.String()), " ")
	testutil.AssertStringContains(t, bodyStripped, `<searchable-select class="block relative" data-strict> <input id="param_param1"`)
	testutil.AssertStringContains(t, bodyStripped, `<searchable-select class="block relative" > <input id="param_param2"`)

	postForm := func(param1, param2 string) *httptest.ResponseRecorder {
		values := url.Values{"param1": {param1}, "param2": {param2}}
		request := httptest.NewRequest("POST", "/test/", strings.NewReader(values.Encode()))
		request.Header.Set("HX-Request", "true")
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		a.ServeHTTP(response, request)
		return response
	}

	// A value outside the options list is rejected for the strict param
	response = postForm("notinlist", "a")
	testutil.AssertEqualsInt(t, "code", http.StatusBadRequest, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "invalid value for param1: must be one of the configured options")

	// The COMBO param accepts free text; empty strict values are left to
	// the handler's own validation
	response = postForm("b", "freetext")
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "freetext")

	response = postForm("", "a")
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
}

func TestActionError(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	if args.param1 == "error":
		return "errormessage"
	10/args.param3 
	return ace.result(status="done", values=[{"c1": args.param1, "c2": args.param2, "c3": args.param3}], report=ace.TABLE)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")
param("param2", description="param2 description", type=BOOLEAN, default=False)
param("param3", description="param3 description", type=INT, default=10)`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	testutil.AssertStringContains(t, response.Body.String(), `id="param_param1"`)

	values := url.Values{
		"param1": {"error"},
		"param2": {"true"},
		"param3": {"20"},
	}

	request = httptest.NewRequest("POST", "/test", strings.NewReader(values.Encode()))
	request.Header.Set("HX-Request", "true")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "match response", `
	<div role="status" class="py-1 font-medium"> errormessage </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <output id="param_param2_error" hx-swap-oob="innerHTML"></output> <output id="param_param3_error" hx-swap-oob="innerHTML"></output> <output id="action_result" hx-swap-oob="innerHTML"> <div role="status" class="py-2 text-center text-sm text-base-content/70"> No output </div> </output>
	`, response.Body.String())

	values = url.Values{
		"param1": {"p1val"},
		"param2": {"true"},
		"param3": {"0"},
	}

	request = httptest.NewRequest("POST", "/test", strings.NewReader(values.Encode()))
	request.Header.Set("HX-Request", "true")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringMatch(t, "response", `floating-point division by zero`, response.Body.String())

	values = url.Values{
		"param1": {"p1val"},
		"param2": {"true"},
		"param3": {"50"},
	}

	request = httptest.NewRequest("POST", "/test", strings.NewReader(values.Encode()))
	request.Header.Set("HX-Request", "true")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "response", `
	<div role="status" class="py-1 font-medium"> done </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <output id="param_param2_error" hx-swap-oob="innerHTML"></output> <output id="param_param3_error" hx-swap-oob="innerHTML"></output> <output id="action_result" hx-swap-oob="innerHTML"> <div role="alert"> <div class="card border border-base-300 bg-base-100 shadow-sm w-full"> <div class="card-body p-4 sm:p-6 gap-3 min-w-0"> <h2 class="section-heading">Report</h2> <div class="overflow-x-auto"> <table class="table table-zebra min-w-full text-sm"> <thead> <tr> <th scope="col">c1</th> <th scope="col">c2</th> <th scope="col">c3</th> </tr> </thead> <tbody> <tr> <td class="font-mono text-xs">p1val</td> <td class="font-mono text-xs">true</td> <td class="font-mono text-xs">50</td> </tr> </tbody> </table> </div> </div> </div> </div> </output>
	`, response.Body.String())
}

func TestNonHtmxRequest(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": 1, "b": "abc"}], report="custom")

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler)])

		`,
		"params.star":    `param("param1", description="param1 description", type=STRING, default="myvalue")`,
		"myfile.go.html": `{{block "custom" .}} customdata {{end}}`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
	testutil.AssertStringContains(t, response.Body.String(), `id="param_param1"`)

	request = httptest.NewRequest("POST", "/test", nil)
	// no header request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	body := response.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("Expected full html response, got: %s", body)
	}
	if !strings.Contains(body, "</html>") {
		t.Errorf("Expected full html response, got: %s", body)
	}
}

func TestMultipleActions(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": 1, "b": "abc"}])

app = ace.app("testApp",
	actions=[ace.action("test1Action", "/test1", handler),
	         ace.action("test2Action", "/test2", handler)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/test1", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	body := strings.Join(strings.Fields(response.Body.String()), " ")
	testutil.AssertStringContains(t, body, `<a href="/test/test1" class="menu-active" aria-current="page" > test1Action </a>`)
	testutil.AssertStringContains(t, body, `<a href="/test/test2" > test2Action </a>`)

	request = httptest.NewRequest("GET", "/test/test2?param1=abc", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	body = strings.Join(strings.Fields(response.Body.String()), " ")
	testutil.AssertStringContains(t, body, `<a href="/test/test2" class="menu-active" aria-current="page" > test2Action </a>`)
	testutil.AssertStringContains(t, body, `<a href="/test/test1" > test1Action </a>`)

	values := url.Values{
		"param1": {"p1val"},
	}
	request = httptest.NewRequest("POST", "/test/test1", strings.NewReader(values.Encode()))
	request.Header.Set("HX-Request", "true")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "response", `
	<div role="status" class="py-1 font-medium"> done </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <output id="action_result" hx-swap-oob="innerHTML"> <div role="alert"> <div class="card border border-base-300 bg-base-100 shadow-sm w-full"> <div class="card-body p-4 sm:p-6 gap-3 min-w-0"> <h2 class="section-heading">Report</h2> <div class="overflow-x-auto"> <table class="table table-zebra min-w-full text-sm"> <thead> <tr> <th scope="col">a</th> <th scope="col">b</th> </tr> </thead> <tbody> <tr> <td class="font-mono text-xs">1</td> <td class="font-mono text-xs">abc</td> </tr> </tbody> </table> </div> </div> </div> </div> </output>
	`, response.Body.String())
}

func TestDisplayTypes(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": 1, "b": "abc"}])

app = ace.app("testApp",
	actions=[ace.action("test1Action", "/test1", handler)])
		`,
		"params.star": `param("param1", description="param1 description", default="myvalue", display_type=FILE)
param("param2", description="param2 description", default="myvalue", display_type=PASSWORD)
param("param3", description="param3 description", default="myvalue", display_type=TEXTAREA)`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/test1", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	body := response.Body.String()
	testutil.AssertStringContains(t, body, `type="file"`)
	testutil.AssertStringContains(t, body, `type="password"`)
	testutil.AssertStringContains(t, body, `textarea`)
}

func TestDisplayTypesError(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": 1, "b": "abc"}])

app = ace.app("testApp",
	actions=[ace.action("test1Action", "/test1", handler)])
		`,
		"params.star": `param("param1", description="param1 description", type=BOOLEAN, default=False, display_type=FILE)`,
	}
	_, _, err := CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "display_type file is allowed for string type param1 only")
}

func TestSuggest(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": {"c": 1}, "b": "abc"}], report=ace.AUTO)

def suggest_handler(args):
	return {"param1": ["a", "b", "c"], "param2": True}

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

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "/test/suggest")
	if strings.Contains(response.Body.String(), "/test/validate") {
		t.Errorf("validate API should not be in the body")
	}

	request = httptest.NewRequest("POST", "/test/suggest", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", `
	<div role="status" class="py-1 font-medium"> Suggesting values </div> <div id="param_param1_div" hx-swap-oob="innerHTML"> <div> <searchable-select class="block relative" data-strict> <input id="param_param1" name="param1" type="text" class="input w-full pr-9" role="combobox" aria-expanded="false" aria-autocomplete="list" aria-controls="param_param1_listbox" autocomplete="off" value="a" /> <button type="button" tabindex="-1" aria-label="Show all options" class="absolute right-1.5 top-1/2 -translate-y-1/2 btn btn-ghost btn-xs btn-square text-base-content/70"> <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"> <path d="M6 9l6 6 6-6" /> </svg> </button> <ul id="param_param1_listbox" role="listbox" aria-label="param1 options" hidden class="absolute z-30 mt-1 w-full max-h-60 overflow-y-auto rounded-box border border-base-300 bg-base-100 shadow-md p-1"> <li id="param_param1_opt_0" role="option" data-value="a" aria-selected="true" class="ss-option px-3 py-1.5 rounded-field cursor-pointer text-sm"> a </li> <li id="param_param1_opt_1" role="option" data-value="b" class="ss-option px-3 py-1.5 rounded-field cursor-pointer text-sm"> b </li> <li id="param_param1_opt_2" role="option" data-value="c" class="ss-option px-3 py-1.5 rounded-field cursor-pointer text-sm"> c </li> </ul> </searchable-select> <output id="param_param1_error" aria-live="assertive" aria-atomic="true" class="block text-error text-sm mt-1 empty:hidden"></output> </div> </div> <div id="param_param2_div" hx-swap-oob="innerHTML"> <div class="md:pt-2"> <input id="param_param2" name="param2" type="checkbox" value="true" class="checkbox checkbox-primary" checked /> <output id="param_param2_error" aria-live="assertive" aria-atomic="true" class="block text-error text-sm mt-1 empty:hidden"></output> </div> </div>
	`, response.Body.String())
}

func TestValidate(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
    if dry_run:
	    return "Looks good"
    return ace.result(status="done", values=[{"a": {"c": 1}, "b": "abc"}], report=ace.AUTO)

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler, show_validate=True)])

		`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")
param("param2", description="param2 description", type=BOOLEAN, default=False)`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "/test/validate")
	if strings.Contains(response.Body.String(), "/test/suggest") {
		t.Errorf("suggest API should not be in the body")
	}

	request = httptest.NewRequest("POST", "/test/validate", nil)
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", `
	<div role="status" class="py-1 font-medium"> Looks good </div> <output id="param_param1_error" hx-swap-oob="innerHTML"></output> <output id="param_param2_error" hx-swap-oob="innerHTML"></output>
	`, response.Body.String())
}

func TestStarBase(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"mydir/test/app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=["a", "b"], param_errors={"param1": "param1error", "param3": "param3error"})

app = ace.app("testApp",
	actions=[ace.action("testAction", "/", handler, hidden=["param2"])])

		`,
		"mydir/test/params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")
param("options-param1", description="param1 options", type=LIST, default=["a", "b", "c"])
param("param2", description="param2 description", type=STRING, default="myvalue2")`,
	}
	a, _, err := CreateTestAppConfig(logger, fileData, types.AppConfig{StarBase: "mydir/test/"})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "<title>testAction</title>")
}

func TestActionMountError(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def handler(dry_run, args):
	return ace.result(status="done", values=[{"a": 1, "b": "abc"}])

app = ace.app("testApp",
	actions=[ace.action("test1Action", "/test1", handler), ace.action("test1Action", "/test1", handler)])
		`,
		"params.star": `param("param1", description="param1 description", type=BOOLEAN, default=False)`,
	}
	_, _, err := CreateTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "error adding action at path /test1")
}
