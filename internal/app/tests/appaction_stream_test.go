// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// streamActionApp builds an action app whose run handler streams a shell
// command's output. handlerBody is the Starlark body after the exec call
func streamActionApp(t *testing.T, script, handlerTail string) *app.App {
	t.Helper()
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
load("exec.in", "exec")

def handler(dry_run, args):
	if args.param1 == "invalid":
		return ace.result("Validation failed", param_errors={"param1": "not allowed"})
	ret = exec.run("sh", ["-c", '` + script + `'], stream=True)
	if ret.error:
		return ace.result("Could not start: " + ret.error)
` + handlerTail + `

app = ace.app("testApp", actions=[ace.action("testAction", "/", handler, show_validate=True)])
`,
		"params.star": `param("param1", description="param1 description", type=STRING, default="myvalue")`,
	}
	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"exec.in"}, []types.Permission{{Plugin: "exec.in", Method: "run"}}, nil)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	return a
}

func streamPost(t *testing.T, a *app.App, path string, htmx bool, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest("POST", path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if htmx {
		request.Header.Set("HX-Request", "true")
	}
	// exec is a system plugin: an authenticated caller is required
	request = request.WithContext(context.WithValue(request.Context(), types.USER_ID, "testuser"))
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	return response
}

func TestActionStreamUI(t *testing.T) {
	a := streamActionApp(t, `echo hello; echo world; exit 3`, `	return ace.result("Running the command", stream=ret)`)

	response := streamPost(t, a, "/test", true, url.Values{"param1": {"abc"}})
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "text/event-stream", response.Header().Get("Content-Type"))
	testutil.AssertEqualsString(t, "push url", "/test?param1=abc", response.Header().Get("HX-Push-Url"))

	body := response.Body.String()
	// First (unnamed) event: the status line, cleared param errors and the
	// log pane shell, all HTML for the normal swap
	first := body[:strings.Index(body, "\n\n")]
	testutil.AssertStringContains(t, first, "data: ")
	testutil.AssertStringContains(t, first, "Running the command")
	testutil.AssertStringContains(t, first, `id="param_param1_error"`)
	testutil.AssertStringContains(t, first, `<log-tail`)
	testutil.AssertStringContains(t, first, `id="action_result" hx-swap-oob="innerHTML"`)
	if strings.HasPrefix(first, "event:") {
		t.Fatalf("the html event must be unnamed: %q", first)
	}

	// Output chunks: JSON string payloads of the openrun:output events
	testutil.AssertStringContains(t, body, "event: openrun:output\ndata: \"hello")
	testutil.AssertStringContains(t, body, "world\\n\"\n\n")
	// Exit event with the command's status, last on the wire
	testutil.AssertStringContains(t, body, "event: openrun:exit\ndata: {\"status\":3}\n\n")
	if !strings.HasSuffix(body, "data: {\"status\":3}\n\n") {
		t.Fatalf("exit event must end the stream: %q", body[len(body)-60:])
	}
}

func TestActionStreamDirectReturn(t *testing.T) {
	// Returning the stream response itself is shorthand for an empty status
	a := streamActionApp(t, `printf "no newline"`, `	return ret`)

	response := streamPost(t, a, "/test", true, url.Values{})
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "text/event-stream", response.Header().Get("Content-Type"))
	body := response.Body.String()
	testutil.AssertStringContains(t, body, "event: openrun:output\ndata: \"no newline\\n\"\n\n")
	testutil.AssertStringContains(t, body, "event: openrun:exit\ndata: {\"status\":0}\n\n")
}

func TestActionStreamParamErrorsStayHTML(t *testing.T) {
	// A validation failure returns before the command starts: the normal
	// HTML response, not a stream
	a := streamActionApp(t, `echo unused`, `	return ace.result("Running", stream=ret)`)

	response := streamPost(t, a, "/test", true, url.Values{"param1": {"invalid"}})
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	if strings.Contains(response.Header().Get("Content-Type"), "event-stream") {
		t.Fatal("param error response must not be an event stream")
	}
	testutil.AssertStringContains(t, response.Body.String(), "not allowed")
	if strings.Contains(response.Body.String(), "openrun:output") {
		t.Fatal("param error response must not stream")
	}
}

func TestActionStreamValidateRejected(t *testing.T) {
	// A handler that ignores dry_run and starts a command on validate is an
	// error, and the command is released
	a := streamActionApp(t, `echo started`, `	return ace.result("Running", stream=ret)`)

	response := streamPost(t, a, "/test/validate", true, url.Values{})
	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "validate handler returned a stream")
}

func TestActionStreamResultConflicts(t *testing.T) {
	a := streamActionApp(t, `echo x`, `	return ace.result("Running", values=["a"], stream=ret)`)
	response := streamPost(t, a, "/test", true, url.Values{})
	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "result stream cannot be combined with values")

	a = streamActionApp(t, `echo x`, `	return ace.result("Running", stream="not a stream")`)
	response = streamPost(t, a, "/test", true, url.Values{})
	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "result stream must be the response of a plugin call made with stream=True")
}

func TestActionStreamAPIText(t *testing.T) {
	// API mode: chunked plain text with the status header and exit trailer
	a := streamActionApp(t, `echo hello; echo world; exit 3`, `	return ace.result("Running the command", stream=ret)`)

	request := createJSONRequest(t, "/test/api/actions", `{"param1": "abc"}`)
	request = request.WithContext(context.WithValue(request.Context(), types.USER_ID, "testuser"))
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "text/plain; charset=utf-8", response.Header().Get("Content-Type"))
	testutil.AssertEqualsString(t, "status header", "Running the command", response.Header().Get("OpenRun-Action-Status"))
	testutil.AssertEqualsString(t, "body", "hello\nworld\n", response.Body.String())
	testutil.AssertEqualsString(t, "exit trailer", "3", response.Result().Trailer.Get("OpenRun-Exit-Status"))

	// A clean exit reports 0
	a = streamActionApp(t, `echo ok`, `	return ace.result("Running", stream=ret)`)
	request = createJSONRequest(t, "/test/api/actions", `{}`)
	request = request.WithContext(context.WithValue(request.Context(), types.USER_ID, "testuser"))
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "ok\n", response.Body.String())
	testutil.AssertEqualsString(t, "exit trailer", "0", response.Result().Trailer.Get("OpenRun-Exit-Status"))

	// Param errors keep the JSON shape
	request = createJSONRequest(t, "/test/api/actions", `{"param1": "invalid"}`)
	request = request.WithContext(context.WithValue(request.Context(), types.USER_ID, "testuser"))
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 422, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), `"param_errors"`)
}

func TestActionStreamNonHtmxPostIsText(t *testing.T) {
	// A plain form post (no HTMX) gets the text stream, not SSE
	a := streamActionApp(t, `echo plain`, `	return ace.result("Running", stream=ret)`)
	response := streamPost(t, a, "/test", false, url.Values{})
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "text/plain; charset=utf-8", response.Header().Get("Content-Type"))
	testutil.AssertEqualsString(t, "body", "plain\n", response.Body.String())
}

func TestActionStreamSharedAssets(t *testing.T) {
	// The action page loads htmx, hx-sse and the log viewer from the shared
	// server route, with content-hashed names
	a := streamActionApp(t, `echo x`, `	return ret`)
	response, _ := actionsGet(t, a, "/test")
	body := response.Body.String()
	// hashfs inserts the hash before the first dot: htmx-<sha>.min.js
	for _, name := range []string{"logtail-", "htmx-", "hx-sse-", "style-", "openrun-", "fonts/jetbrains-mono-400-"} {
		testutil.AssertStringContains(t, body, "/_openrun/static/"+name)
	}
	testutil.AssertStringContains(t, body, `"defaultTimeout": 0`)
	if strings.Contains(body, "astatic/htmx") || strings.Contains(body, "astatic/style") || strings.Contains(body, "astatic/fonts") {
		t.Fatal("shared assets must not be served from the per-app astatic route")
	}
}

func TestActionStreamInvalidUTF8(t *testing.T) {
	// Binary bytes in the output are replaced for display instead of
	// failing the stream (the JSON encoder rejects invalid UTF-8)
	a := streamActionApp(t, `printf "\\377bad\\n"; echo after`, `	return ace.result("Running", stream=ret)`)
	response := streamPost(t, a, "/test", true, url.Values{})
	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	body := response.Body.String()
	testutil.AssertStringContains(t, body, "event: openrun:output\ndata: \"\ufffdbad\\nafter\\n\"\n\n")
	testutil.AssertStringContains(t, body, "event: openrun:exit\ndata: {\"status\":0}\n\n")
}
