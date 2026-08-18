// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/net/html"
)

// Integration tests for the actions UI, using the kitchen sink app at
// tests/actions_tests. The app exercises every actions feature: multiple
// actions with the sidebar switcher, all param display types, strict and
// COMBO searchable dropdowns, suggest/validate, every report type, file
// upload/download and custom permits. Responses are verified as parsed
// HTML, similar to the console suite (ui/console_tests).

// createActionsTestApp loads the tests/actions_tests source from disk and
// creates it as a prod app at /test with its plugin permissions approved
func createActionsTestApp(t *testing.T, rbacApi rbac.RBACAPI) *app.App {
	t.Helper()
	logger := testutil.TestLogger()

	root := filepath.Join("..", "..", "..", "tests", "actions_tests")
	fileData := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "gen" {
				// skip the dev-mode styling build artifacts
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") || d.Name() == "config_gen.lock" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		fileData[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("Error loading actions_tests app source: %s", err)
	}

	plugins := []string{"exec.in", "fs.in"}
	permissions := []types.Permission{
		{Plugin: "exec.in", Method: "run", Arguments: []string{"nl"}},
		{Plugin: "fs.in", Method: "serve_tmp_file"},
	}
	// The user file store is a process wide singleton; a fixed path keeps
	// the connect string stable across the tests in this file
	pluginConfig := map[string]types.PluginSettings{
		"fs.in": {"db_connection": "sqlite:" + filepath.Join(os.TempDir(), "openrun_actions_test_fs.db")},
	}
	appConfig := &types.AppConfig{FS: types.FS{FileAccess: []string{"$TEMPDIR", "/tmp"}}}

	a, _, err := CreateTestAppInt(logger, "/test", "", fileData, false, plugins, permissions,
		pluginConfig, "app_prd_actionstest", types.AppSettings{}, nil, appConfig, rbacApi)
	if err != nil {
		t.Fatalf("Error creating actions_tests app: %s", err)
	}
	return a
}

// actionsRequest attaches an authenticated user, as the real server does
// for action apps (privileged plugins like exec.in require one)
func actionsRequest(method, path string, body *strings.Reader) *http.Request {
	var request *http.Request
	if body != nil {
		request = httptest.NewRequest(method, path, body)
	} else {
		request = httptest.NewRequest(method, path, nil)
	}
	return request.WithContext(context.WithValue(request.Context(), types.USER_ID, "testuser@example.com"))
}

func actionsGet(t *testing.T, a *app.App, path string) (*httptest.ResponseRecorder, *html.Node) {
	t.Helper()
	request := actionsRequest("GET", path, nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	return response, parseHTMLDoc(t, response.Body.String())
}

// actionsPost posts the form values as an HTMX request (the Run/Validate/
// Suggest buttons all post with the HX-Request header set)
func actionsPost(t *testing.T, a *app.App, path string, values url.Values) (*httptest.ResponseRecorder, *html.Node) {
	t.Helper()
	request := actionsRequest("POST", path, strings.NewReader(values.Encode()))
	request.Header.Set("HX-Request", "true")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	return response, parseHTMLDoc(t, response.Body.String())
}

func parseHTMLDoc(t *testing.T, body string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Error parsing response html: %s", err)
	}
	return doc
}

func findHTMLNode(n *html.Node, pred func(*html.Node) bool) *html.Node {
	if n.Type == html.ElementNode && pred(n) {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findHTMLNode(c, pred); found != nil {
			return found
		}
	}
	return nil
}

func findAllHTMLNodes(n *html.Node, pred func(*html.Node) bool) []*html.Node {
	var out []*html.Node
	if n.Type == html.ElementNode && pred(n) {
		out = append(out, n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		out = append(out, findAllHTMLNodes(c, pred)...)
	}
	return out
}

func htmlAttr(n *html.Node, name string) (string, bool) {
	for _, attr := range n.Attr {
		if attr.Key == name {
			return attr.Val, true
		}
	}
	return "", false
}

func htmlAttrVal(n *html.Node, name string) string {
	val, _ := htmlAttr(n, name)
	return val
}

func hasHTMLAttr(n *html.Node, name string) bool {
	_, ok := htmlAttr(n, name)
	return ok
}

func htmlByID(t *testing.T, root *html.Node, id string) *html.Node {
	t.Helper()
	n := findHTMLNode(root, func(n *html.Node) bool { return htmlAttrVal(n, "id") == id })
	if n == nil {
		t.Fatalf("element with id %q not found", id)
	}
	return n
}

func htmlText(n *html.Node) string {
	var buf strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			buf.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(buf.String()), " ")
}

var actionNavEntries = []struct{ name, path string }{
	{"Deploy", "/test"},
	{"Logs", "/test/logs"},
	{"Inspect", "/test/inspect"},
	{"Release Notes", "/test/notes"},
	{"Process File", "/test/upload"},
	{"Logo Image", "/test/image"},
	{"Restricted", "/test/restricted"},
	{"Fail", "/test/fail"},
}

// TestActionsAppNav verifies the sidebar action navigation on every action
// page: all actions listed in definition order, the current one marked
// active, links without query strings (the params are appended client side)
func TestActionsAppNav(t *testing.T) {
	a := createActionsTestApp(t, nil)

	for _, entry := range actionNavEntries {
		response, doc := actionsGet(t, a, entry.path)
		testutil.AssertEqualsInt(t, entry.name+" status", 200, response.Code)
		testutil.AssertStringContains(t, response.Body.String(), "<title>"+entry.name+"</title>")

		// Multi action app: the sidebar docks open on md+ for the nav and
		// the hamburger shows only below that
		testutil.AssertStringContains(t, response.Body.String(), "md:drawer-open")
		testutil.AssertStringContains(t, response.Body.String(), "md:hidden")

		nav := htmlByID(t, doc, "action-nav")
		links := findAllHTMLNodes(nav, func(n *html.Node) bool { return n.Data == "a" })
		if len(links) != len(actionNavEntries) {
			t.Fatalf("%s: expected %d nav links, got %d", entry.name, len(actionNavEntries), len(links))
		}
		for i, link := range links {
			want := actionNavEntries[i]
			testutil.AssertEqualsString(t, "nav link name", want.name, htmlText(link))
			testutil.AssertEqualsString(t, "nav link href", want.path, htmlAttrVal(link, "href"))
			isActive := htmlAttrVal(link, "class") == "menu-active"
			if isActive != (want.name == entry.name) {
				t.Errorf("%s: nav link %s active=%v", entry.name, want.name, isActive)
			}
			if (htmlAttrVal(link, "aria-current") == "page") != (want.name == entry.name) {
				t.Errorf("%s: nav link %s aria-current mismatch", entry.name, want.name)
			}
		}

		// The action title renders as the page h1
		h1 := findHTMLNode(doc, func(n *html.Node) bool { return n.Data == "h1" })
		testutil.AssertEqualsString(t, "page title", entry.name, htmlText(h1))
	}
}

// TestActionsAppFormRender verifies the deploy form markup: hidden params
// excluded, each display type rendered with its control, the strict and
// COMBO searchable dropdowns, and content hashed asset urls
func TestActionsAppFormRender(t *testing.T) {
	a := createActionsTestApp(t, nil)
	response, doc := actionsGet(t, a, "/test")
	testutil.AssertEqualsInt(t, "status", 200, response.Code)

	// Hidden params render no field
	for _, hidden := range []string{"param_notes", "param_upload", "param_audit_tag"} {
		if findHTMLNode(doc, func(n *html.Node) bool { return htmlAttrVal(n, "id") == hidden }) != nil {
			t.Errorf("hidden param field %s rendered on the deploy form", hidden)
		}
	}

	// Text input with the default value
	appName := htmlByID(t, doc, "param_app_name")
	testutil.AssertEqualsString(t, "app_name type", "text", htmlAttrVal(appName, "type"))
	testutil.AssertEqualsString(t, "app_name value", "orders-api", htmlAttrVal(appName, "value"))

	// env: strict searchable dropdown from the options_env list
	env := htmlByID(t, doc, "param_env")
	testutil.AssertEqualsString(t, "env role", "combobox", htmlAttrVal(env, "role"))
	testutil.AssertEqualsString(t, "env value", "dev", htmlAttrVal(env, "value"))
	testutil.AssertEqualsString(t, "env listbox ref", "param_env_listbox", htmlAttrVal(env, "aria-controls"))
	envSelect := findHTMLNode(doc, func(n *html.Node) bool {
		return n.Data == "searchable-select" && findHTMLNode(n, func(c *html.Node) bool { return htmlAttrVal(c, "id") == "param_env" }) != nil
	})
	if !hasHTMLAttr(envSelect, "data-strict") {
		t.Error("env dropdown is not marked strict")
	}
	envOptions := findAllHTMLNodes(htmlByID(t, doc, "param_env_listbox"),
		func(n *html.Node) bool { return htmlAttrVal(n, "role") == "option" })
	if len(envOptions) != 3 {
		t.Fatalf("expected 3 env options, got %d", len(envOptions))
	}
	for i, want := range []string{"dev", "staging", "prod"} {
		testutil.AssertEqualsString(t, "env option", want, htmlAttrVal(envOptions[i], "data-value"))
		if hasHTMLAttr(envOptions[i], "aria-selected") != (want == "dev") {
			t.Errorf("env option %s aria-selected mismatch", want)
		}
	}

	// region: COMBO dropdown (free text), options come from suggest
	regionSelect := findHTMLNode(doc, func(n *html.Node) bool {
		return n.Data == "searchable-select" && findHTMLNode(n, func(c *html.Node) bool { return htmlAttrVal(c, "id") == "param_region" }) != nil
	})
	if regionSelect == nil {
		t.Fatal("region did not render as a searchable dropdown")
	}
	if hasHTMLAttr(regionSelect, "data-strict") {
		t.Error("COMBO region dropdown must not be strict")
	}

	// notify: checkbox, checked by default; api_token: password input
	notify := htmlByID(t, doc, "param_notify")
	testutil.AssertEqualsString(t, "notify type", "checkbox", htmlAttrVal(notify, "type"))
	if !hasHTMLAttr(notify, "checked") {
		t.Error("notify checkbox is not checked by default")
	}
	token := htmlByID(t, doc, "param_api_token")
	testutil.AssertEqualsString(t, "api_token type", "password", htmlAttrVal(token, "type"))

	// The other display types, on their actions
	_, notesDoc := actionsGet(t, a, "/test/notes")
	notes := htmlByID(t, notesDoc, "param_notes")
	testutil.AssertEqualsString(t, "notes tag", "textarea", notes.Data)
	testutil.AssertEqualsString(t, "notes rows", "5", htmlAttrVal(notes, "rows"))

	_, uploadDoc := actionsGet(t, a, "/test/upload")
	upload := htmlByID(t, uploadDoc, "param_upload")
	testutil.AssertEqualsString(t, "upload type", "file", htmlAttrVal(upload, "type"))

	// Suggest and Validate buttons show only where configured (deploy has
	// both, logs has neither)
	body := response.Body.String()
	testutil.AssertStringContains(t, body, `hx-post="/test/suggest"`)
	testutil.AssertStringContains(t, body, `hx-post="/test/validate"`)
	logsResponse, _ := actionsGet(t, a, "/test/logs")
	if strings.Contains(logsResponse.Body.String(), "/test/logs/suggest") {
		t.Error("logs action must not render a Suggest button")
	}
	if strings.Contains(logsResponse.Body.String(), "/test/logs/validate") {
		t.Error("logs action must not render a Validate button")
	}

	// Every astatic asset reference carries a content hash for caching
	refRe := regexp.MustCompile(`(?:href|src)="([^"]*astatic/[^"]*)"`)
	hashRe := regexp.MustCompile(`-[a-f0-9]{64}\.`)
	refs := refRe.FindAllStringSubmatch(body, -1)
	if len(refs) == 0 {
		t.Fatal("no astatic asset references found")
	}
	for _, ref := range refs {
		if !hashRe.MatchString(ref[1]) {
			t.Errorf("astatic asset served without a content hash: %s", ref[1])
		}
	}
}

// TestActionsAppParamPreserve verifies the server half of param
// preservation across action switches: query params prefill the form,
// including params carried through actions where they are hidden
func TestActionsAppParamPreserve(t *testing.T) {
	a := createActionsTestApp(t, nil)

	// Values entered on Deploy arrive on Logs via the nav link query params
	response, doc := actionsGet(t, a, "/test/logs?app_name=carried-app&env=staging&notify=false&replicas=7")
	testutil.AssertEqualsInt(t, "status", 200, response.Code)
	testutil.AssertEqualsString(t, "app_name carried", "carried-app",
		htmlAttrVal(htmlByID(t, doc, "param_app_name"), "value"))
	testutil.AssertEqualsString(t, "env carried", "staging",
		htmlAttrVal(htmlByID(t, doc, "param_env"), "value"))

	// Going back to Deploy with the same query restores the unchecked
	// checkbox and the int param (notify passed through Logs hidden)
	_, doc = actionsGet(t, a, "/test?app_name=carried-app&env=staging&notify=false&replicas=7")
	if hasHTMLAttr(htmlByID(t, doc, "param_notify"), "checked") {
		t.Error("notify=false in the query must render an unchecked checkbox")
	}
	testutil.AssertEqualsString(t, "replicas carried", "7",
		htmlAttrVal(htmlByID(t, doc, "param_replicas"), "value"))

	// An invalid boolean in the query fails the form render
	response, _ = actionsGet(t, a, "/test?notify=bogus")
	testutil.AssertEqualsInt(t, "bad bool status", 500, response.Code)
}

// TestActionsAppDeployRun covers the run/validate flows: the table report,
// the push url (passwords excluded), strict dropdown enforcement, COMBO
// free text, int parsing and param validation errors
func TestActionsAppDeployRun(t *testing.T) {
	a := createActionsTestApp(t, nil)

	deployValues := func() url.Values {
		return url.Values{
			"app_name":  {"orders-api"},
			"env":       {"staging"},
			"region":    {"eu-central-1"},
			"replicas":  {"2"},
			"notify":    {"true"},
			"api_token": {"sekret123"},
		}
	}

	// Success: status message, table report with one row per replica
	response, doc := actionsPost(t, a, "/test", deployValues())
	testutil.AssertEqualsInt(t, "status", 200, response.Code)
	status := findHTMLNode(doc, func(n *html.Node) bool { return htmlAttrVal(n, "role") == "status" })
	testutil.AssertEqualsString(t, "status message", "Deployed orders-api to staging (2 replicas)", htmlText(status))

	table := findHTMLNode(doc, func(n *html.Node) bool { return n.Data == "table" })
	if table == nil {
		t.Fatal("table report not rendered")
	}
	headers := findAllHTMLNodes(table, func(n *html.Node) bool { return n.Data == "th" })
	headerText := []string{}
	for _, h := range headers {
		headerText = append(headerText, htmlText(h))
	}
	testutil.AssertEqualsString(t, "table columns", "env notified region state unit", strings.Join(headerText, " "))
	rows := findAllHTMLNodes(table, func(n *html.Node) bool { return n.Data == "td" })
	if len(rows) != 10 { // 2 replicas x 5 columns
		t.Fatalf("expected 10 table cells, got %d", len(rows))
	}
	testutil.AssertStringContains(t, response.Body.String(), "orders-api-0")
	testutil.AssertStringContains(t, response.Body.String(), "orders-api-1")

	// The push url carries the submitted params but never the password
	pushUrl := response.Header().Get("HX-Push-Url")
	testutil.AssertEqualsString(t, "push url",
		"/test?app_name=orders-api&env=staging&notify=true&region=eu-central-1&replicas=2", pushUrl)
	if strings.Contains(response.Body.String(), "sekret123") {
		t.Error("password value leaked into the response body")
	}

	// Strict env: a value outside options_env is rejected server side
	values := deployValues()
	values.Set("env", "nosuchenv")
	response, _ = actionsPost(t, a, "/test", values)
	testutil.AssertEqualsInt(t, "strict status", http.StatusBadRequest, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "invalid value for env: must be one of the configured options")

	// COMBO region accepts free text; empty strict env is left to the handler
	values = deployValues()
	values.Set("region", "custom-region-x")
	values.Set("env", "")
	response, _ = actionsPost(t, a, "/test", values)
	testutil.AssertEqualsInt(t, "combo status", 200, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "custom-region-x")

	// An int param that does not parse is a request error
	values = deployValues()
	values.Set("replicas", "abc")
	response, _ = actionsPost(t, a, "/test", values)
	testutil.AssertEqualsInt(t, "int parse status", http.StatusBadRequest, response.Code)

	// Validation failure: param errors render out of band per field, no
	// result output is rendered
	values = deployValues()
	values.Set("replicas", "99")
	values.Set("region", "")
	response, doc = actionsPost(t, a, "/test/validate", values)
	testutil.AssertEqualsInt(t, "validate status", 200, response.Code)
	testutil.AssertEqualsString(t, "validate message", "Validation failed",
		htmlText(findHTMLNode(doc, func(n *html.Node) bool { return htmlAttrVal(n, "role") == "status" })))
	testutil.AssertEqualsString(t, "replicas error", "at most 10 replicas are supported",
		htmlText(htmlByID(t, doc, "param_replicas_error")))
	testutil.AssertEqualsString(t, "region error", "region is required, use Suggest to pick one",
		htmlText(htmlByID(t, doc, "param_region_error")))
	if strings.Contains(response.Body.String(), "action_result") {
		t.Error("validate response must not render results")
	}

	// Validation success clears the earlier field errors (empty OOB swaps)
	_, doc = actionsPost(t, a, "/test/validate", deployValues())
	testutil.AssertEqualsString(t, "validate pass", "Validation passed, ready to deploy orders-api to staging",
		htmlText(findHTMLNode(doc, func(n *html.Node) bool { return htmlAttrVal(n, "role") == "status" })))
	testutil.AssertEqualsString(t, "replicas error cleared", "", htmlText(htmlByID(t, doc, "param_replicas_error")))
}

// TestActionsAppSuggest covers the suggest flow: list values re-render a
// param as a searchable dropdown (strict unless COMBO), scalar values
// update the field, and a string response is just a status message
func TestActionsAppSuggest(t *testing.T) {
	a := createActionsTestApp(t, nil)

	baseValues := func() url.Values {
		return url.Values{
			"app_name": {"orders-api"}, "env": {"dev"}, "region": {""},
			"replicas": {"2"}, "notify": {"true"}, "api_token": {""},
		}
	}

	// First suggest: region list (COMBO param, not strict) + replicas value
	response, doc := actionsPost(t, a, "/test/suggest", baseValues())
	testutil.AssertEqualsInt(t, "status", 200, response.Code)
	testutil.AssertEqualsString(t, "suggest message", "Suggesting values",
		htmlText(findHTMLNode(doc, func(n *html.Node) bool { return htmlAttrVal(n, "role") == "status" })))

	regionDiv := htmlByID(t, doc, "param_region_div")
	testutil.AssertEqualsString(t, "region oob", "innerHTML", htmlAttrVal(regionDiv, "hx-swap-oob"))
	regionSelect := findHTMLNode(regionDiv, func(n *html.Node) bool { return n.Data == "searchable-select" })
	if regionSelect == nil {
		t.Fatal("suggested region did not render as a searchable dropdown")
	}
	if hasHTMLAttr(regionSelect, "data-strict") {
		t.Error("suggested COMBO region dropdown must not be strict")
	}
	regionOptions := findAllHTMLNodes(regionDiv, func(n *html.Node) bool { return htmlAttrVal(n, "role") == "option" })
	if len(regionOptions) != 4 {
		t.Fatalf("expected 4 region options, got %d", len(regionOptions))
	}
	testutil.AssertEqualsString(t, "region value", "us-east-1",
		htmlAttrVal(findHTMLNode(regionDiv, func(n *html.Node) bool { return n.Data == "input" }), "value"))
	testutil.AssertEqualsString(t, "replicas suggested", "3",
		htmlAttrVal(findHTMLNode(htmlByID(t, doc, "param_replicas_div"),
			func(n *html.Node) bool { return n.Data == "input" }), "value"))

	// Second suggest: prod without a token narrows env, a STRICT dropdown
	values := baseValues()
	values.Set("region", "us-east-1")
	values.Set("env", "prod")
	response, doc = actionsPost(t, a, "/test/suggest", values)
	testutil.AssertEqualsInt(t, "status", 200, response.Code)
	envDiv := htmlByID(t, doc, "param_env_div")
	envSelect := findHTMLNode(envDiv, func(n *html.Node) bool { return n.Data == "searchable-select" })
	if envSelect == nil || !hasHTMLAttr(envSelect, "data-strict") {
		t.Error("suggested env dropdown must be strict")
	}
	envOptions := findAllHTMLNodes(envDiv, func(n *html.Node) bool { return htmlAttrVal(n, "role") == "option" })
	if len(envOptions) != 2 {
		t.Fatalf("expected 2 suggested env options, got %d", len(envOptions))
	}

	// Third suggest: everything is set, a plain status message and no
	// field updates
	values = baseValues()
	values.Set("region", "us-east-1")
	response, doc = actionsPost(t, a, "/test/suggest", values)
	testutil.AssertEqualsString(t, "final suggest", "Suggestions complete, ready to run",
		htmlText(findHTMLNode(doc, func(n *html.Node) bool { return htmlAttrVal(n, "role") == "status" })))
	if strings.Contains(response.Body.String(), "_div") {
		t.Error("final suggest must not update any param field")
	}
}

// TestActionsAppReports covers the text, JSON, custom template and image
// report types
func TestActionsAppReports(t *testing.T) {
	a := createActionsTestApp(t, nil)

	// Text report: an auto sized readonly textarea with the log lines
	response, doc := actionsPost(t, a, "/test/logs", url.Values{"app_name": {"orders-api"}, "env": {"dev"}})
	testutil.AssertEqualsInt(t, "logs status", 200, response.Code)
	textarea := findHTMLNode(htmlByID(t, doc, "action_result"), func(n *html.Node) bool { return n.Data == "textarea" })
	if textarea == nil {
		t.Fatal("text report textarea not rendered")
	}
	testutil.AssertEqualsString(t, "textarea rows", "6", htmlAttrVal(textarea, "rows")) // 4 lines + 2
	testutil.AssertStringContains(t, htmlText(textarea), "request handled path=/api/orders status=200")

	// JSON report (AUTO with complex values): a json tree container
	response, doc = actionsPost(t, a, "/test/inspect", url.Values{"app_name": {"orders-api"}, "env": {"dev"}})
	testutil.AssertEqualsInt(t, "inspect status", 200, response.Code)
	jsonDiv := findHTMLNode(doc, func(n *html.Node) bool {
		return strings.Contains(htmlAttrVal(n, "class"), "json-container")
	})
	if jsonDiv == nil {
		t.Fatal("json report container not rendered")
	}
	testutil.AssertStringContains(t, htmlAttrVal(jsonDiv, "data-json"), "ghcr.io/example/orders-api:v1.4.2")
	// The tree carries Expand all / Collapse all controls
	testutil.AssertStringContains(t, response.Body.String(), `onclick="jsonTreeSetAll(this, true)"`)
	testutil.AssertStringContains(t, response.Body.String(), `onclick="jsonTreeSetAll(this, false)"`)

	// Custom template report: the app's release_notes define renders
	response, doc = actionsPost(t, a, "/test/notes", url.Values{
		"app_name": {"orders-api"}, "env": {"dev"}, "notes": {"- fixed rollout\n- faster startup"}})
	testutil.AssertEqualsInt(t, "notes status", 200, response.Code)
	pre := findHTMLNode(doc, func(n *html.Node) bool { return n.Data == "pre" })
	if pre == nil {
		t.Fatal("custom template pre not rendered")
	}
	testutil.AssertStringContains(t, htmlText(pre), "- fixed rollout")
	testutil.AssertStringContains(t, response.Body.String(), "Release notes")

	// Custom template validation failure
	_, doc = actionsPost(t, a, "/test/notes", url.Values{"app_name": {"orders-api"}, "env": {"dev"}, "notes": {""}})
	testutil.AssertEqualsString(t, "notes error", "release notes cannot be empty",
		htmlText(htmlByID(t, doc, "param_notes_error")))

	// Image report: the img points at the app static file, which is served
	response, doc = actionsPost(t, a, "/test/image", url.Values{})
	testutil.AssertEqualsInt(t, "image status", 200, response.Code)
	img := findHTMLNode(doc, func(n *html.Node) bool { return n.Data == "img" })
	if img == nil {
		t.Fatal("image report img not rendered")
	}
	testutil.AssertEqualsString(t, "img src", "static/openrun-logo.png", htmlAttrVal(img, "src"))
	testutil.AssertEqualsString(t, "img caption", "openrun-logo.png",
		htmlText(findHTMLNode(doc, func(n *html.Node) bool { return n.Data == "figcaption" })))
	staticResponse, _ := actionsGet(t, a, "/test/static/openrun-logo.png")
	testutil.AssertEqualsInt(t, "static image status", 200, staticResponse.Code)
	if staticResponse.Body.Len() == 0 {
		t.Error("static image served empty")
	}
}

// TestActionsAppUploadDownload covers the file upload flow end to end: the
// uploaded file is processed with exec (nl) and served back as a single
// access download
func TestActionsAppUploadDownload(t *testing.T) {
	if _, err := exec.LookPath("nl"); err != nil {
		t.Skip("nl command not available")
	}
	a := createActionsTestApp(t, nil)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("upload", "notes.txt")
	if err != nil {
		t.Fatalf("CreateFormFile error: %v", err)
	}
	if _, err := fmt.Fprint(part, "alpha\nbeta\n"); err != nil {
		t.Fatalf("Fprint error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	request := httptest.NewRequest("POST", "/test/upload", body)
	request = request.WithContext(context.WithValue(request.Context(), types.USER_ID, "testuser@example.com"))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "upload status", 200, response.Code)
	doc := parseHTMLDoc(t, response.Body.String())

	link := findHTMLNode(htmlByID(t, doc, "action_result"), func(n *html.Node) bool { return n.Data == "a" })
	if link == nil {
		t.Fatal("download link not rendered")
	}
	href := htmlAttrVal(link, "href")
	if !strings.HasPrefix(href, "/test/_openrun_app/file/usr_file_") {
		t.Fatalf("unexpected download url %s", href)
	}
	testutil.AssertEqualsString(t, "download name", "numbered_notes.txt", htmlText(link))

	// The download serves the numbered file contents
	download, _ := actionsGet(t, a, href)
	testutil.AssertEqualsInt(t, "download status", 200, download.Code)
	testutil.AssertStringContains(t, download.Body.String(), "alpha")
	testutil.AssertStringContains(t, download.Body.String(), "beta")
	testutil.AssertStringContains(t, download.Body.String(), "1")

	// Single access: a second download fails
	second, _ := actionsGet(t, a, href)
	if second.Code == 200 {
		t.Errorf("second download of a single access file must fail, got %d", second.Code)
	}

	// Upload without a file (an empty multipart form) is a param
	// validation error; a non multipart post is a request error
	emptyBody := &bytes.Buffer{}
	emptyWriter := multipart.NewWriter(emptyBody)
	if err := emptyWriter.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	request = httptest.NewRequest("POST", "/test/upload", emptyBody)
	request = request.WithContext(context.WithValue(request.Context(), types.USER_ID, "testuser@example.com"))
	request.Header.Set("Content-Type", emptyWriter.FormDataContentType())
	request.Header.Set("HX-Request", "true")
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "missing file status", 200, response.Code)
	doc = parseHTMLDoc(t, response.Body.String())
	testutil.AssertEqualsString(t, "missing file error", "a file has to be uploaded",
		htmlText(htmlByID(t, doc, "param_upload_error")))

	badResponse, _ := actionsPost(t, a, "/test/upload", url.Values{})
	testutil.AssertEqualsInt(t, "non multipart status", http.StatusBadRequest, badResponse.Code)
}

// TestActionsAppFailures covers the handler error path and the full page
// (non HTMX) POST render
func TestActionsAppFailures(t *testing.T) {
	a := createActionsTestApp(t, nil)

	// A handler failure surfaces as a 500 with the error message
	response, _ := actionsPost(t, a, "/test/fail", url.Values{"app_name": {"x"}})
	testutil.AssertEqualsInt(t, "fail status", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "intentional failure, testing action error handling")

	// A non HTMX POST renders the full page: layout with nav around the
	// results, and no push url header
	request := actionsRequest("POST", "/test/logs",
		strings.NewReader(url.Values{"app_name": {"orders-api"}, "env": {"dev"}}.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	fullResponse := httptest.NewRecorder()
	a.ServeHTTP(fullResponse, request)
	testutil.AssertEqualsInt(t, "full page status", 200, fullResponse.Code)
	body := fullResponse.Body.String()
	testutil.AssertStringContains(t, body, "<!DOCTYPE html>")
	testutil.AssertStringContains(t, body, "<title>Logs</title>")
	doc := parseHTMLDoc(t, body)
	htmlByID(t, doc, "action-nav")
	testutil.AssertStringContains(t, body, "Recent logs for orders-api")
	if fullResponse.Header().Get("HX-Push-Url") != "" {
		t.Error("full page render must not set a push url")
	}
}

// TestActionsAppRestricted covers the custom permit gating: without the
// permission the action page and run are denied and the nav renders the
// entry disabled; with it everything works
func TestActionsAppRestricted(t *testing.T) {
	denied := createActionsTestApp(t, &testRBAC{})

	response, _ := actionsGet(t, denied, "/test/restricted")
	testutil.AssertEqualsInt(t, "restricted get", http.StatusForbidden, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "does not have access to action Restricted")
	response, _ = actionsPost(t, denied, "/test/restricted", url.Values{"app_name": {"x"}})
	testutil.AssertEqualsInt(t, "restricted post", http.StatusForbidden, response.Code)

	// On other pages the nav renders Restricted disabled, without a link
	_, doc := actionsGet(t, denied, "/test")
	nav := htmlByID(t, doc, "action-nav")
	disabled := findHTMLNode(nav, func(n *html.Node) bool {
		return n.Data == "a" && htmlAttrVal(n, "aria-disabled") == "true"
	})
	if disabled == nil || htmlText(disabled) != "Restricted" {
		t.Error("restricted action must render as a disabled nav entry")
	}
	if hasHTMLAttr(disabled, "href") {
		t.Error("disabled nav entry must not be navigable")
	}
	authorized := findAllHTMLNodes(nav, func(n *html.Node) bool { return n.Data == "a" && hasHTMLAttr(n, "href") })
	if len(authorized) != len(actionNavEntries)-1 {
		t.Errorf("expected %d authorized nav links, got %d", len(actionNavEntries)-1, len(authorized))
	}

	// With the ops_admin permission granted the action works
	allowed := createActionsTestApp(t, &testRBAC{perms: []string{"ops_admin"}})
	response, doc = actionsPost(t, allowed, "/test/restricted", url.Values{"app_name": {"orders-api"}})
	testutil.AssertEqualsInt(t, "allowed post", 200, response.Code)
	testutil.AssertEqualsString(t, "allowed message", "Restricted action ran for orders-api",
		htmlText(findHTMLNode(doc, func(n *html.Node) bool { return htmlAttrVal(n, "role") == "status" })))
}
