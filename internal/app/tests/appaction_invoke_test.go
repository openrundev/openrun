// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"encoding/json/jsontext"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// Tests for the transport neutral action invocation (action.Invoke), which the
// management API (openrun action ...) and the MCP tools are built on, and for
// the per app MCP endpoint serving the actions as tools

const invokeTestApp = `
load("exec.in", "exec")

def orders(dry_run, args):
	if args.count < 1:
		return ace.result("Validation failed", param_errors={"count": "count must be positive"})
	if dry_run:
		return ace.result("valid")
	rows = [{"id": i, "status": args.status, "rush": args.rush} for i in range(args.count)]
	return ace.result("Listed %d orders" % args.count, rows, ace.TABLE)

def orders_suggest(args):
	return {"status": "open", "count": 3}

def logs(dry_run, args):
	return ace.result("Recent logs", ["line one", "line two"], ace.TEXT)

def restricted(dry_run, args):
	return ace.result("secret done")

def stream(dry_run, args):
	if dry_run:
		return ace.result("valid")
	return ace.result("Streaming", stream=exec.run("sh", ["-c", 'echo one; echo two; exit ' + str(args.count)], stream=True))

def upload(dry_run, args):
	return ace.result("got " + args.datafile.split("/")[-1])

app = ace.app("testApp", actions=[
	ace.action("List Orders", "/", orders, suggest=orders_suggest, description="List the orders", hidden=["datafile", "token"]),
	ace.action("Logs", "/logs", logs, hidden=["count", "status", "rush", "datafile", "token"]),
	ace.action("Restricted", "/restricted", restricted, permit=["ops_admin"], hidden=["count", "status", "rush", "datafile"]),
	ace.action("Stream", "/stream", stream, hidden=["status", "rush", "datafile", "token"]),
	ace.action("Upload", "/upload", upload, hidden=["count", "status", "rush", "token"]),
])
`

const invokeTestParams = `
param("count", type=INT, description="Number of orders", default=2)
param("status", description="Order status", default="open")
param("options_status", type=LIST, description="Status options", default=["open", "closed"])
param("rush", type=BOOLEAN, description="Rush orders only", default=False)
param("datafile", description="Data file", default="", display_type=FILE, required=True)
param("token", description="API token", default="s3cret", display_type=PASSWORD)
`

func invokeApp(t *testing.T, perms []string, mcpDoc string) *app.App {
	t.Helper()
	fileData := map[string]string{"app.star": invokeTestApp, "params.star": invokeTestParams}
	permissions := []types.Permission{{Plugin: "exec.in", Method: "run"}}
	var a *app.App
	var err error
	if mcpDoc != "" {
		a, _, err = CreateTestAppMCP(testutil.TestLogger(), fileData, []string{"exec.in"}, permissions, &testRBAC{perms: perms}, mcpDoc)
	} else {
		a, _, err = CreateTestAppAuthorizer(testutil.TestLogger(), fileData, []string{"exec.in"}, permissions, nil, &testRBAC{perms: perms})
	}
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	return a
}

func userCtx() context.Context {
	return context.WithValue(context.Background(), types.USER_ID, "builtin:alice")
}

func jsonArgs(args map[string]string) map[string]jsontext.Value {
	ret := map[string]jsontext.Value{}
	for k, v := range args {
		ret[k] = jsontext.Value(v)
	}
	return ret
}

func findAction(t *testing.T, a *app.App, selector string) *action.Action {
	t.Helper()
	act, err := action.FindAction(a.Actions(), selector)
	if err != nil {
		t.Fatalf("FindAction %s: %s", selector, err)
	}
	return act
}

func TestActionInvokeRun(t *testing.T) {
	a := invokeApp(t, nil, "")
	testutil.AssertEqualsInt(t, "actions", 5, len(a.Actions()))
	act := findAction(t, a, "list_orders") // the root action is named from its name

	// String values are coerced to the param type, as form values are
	outcome, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "mgmt_execute",
		JSONArgs: jsonArgs(map[string]string{"count": `"3"`, "rush": `"true"`, "status": `"closed"`})})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	defer outcome.Close()
	testutil.AssertEqualsString(t, "status", "Listed 3 orders", outcome.Status)
	testutil.AssertEqualsInt(t, "rows", 3, len(outcome.ValuesMap))
	testutil.AssertEqualsBool(t, "stream", false, outcome.IsStream())

	doc, code := act.APIResult(outcome, false)
	testutil.AssertEqualsInt(t, "code", http.StatusOK, code)
	testutil.AssertEqualsString(t, "report", "TABLE", doc["report"].(string))
	row := doc["values"].([]map[string]any)[0]
	testutil.AssertEqualsString(t, "row status", "closed", row["status"].(string))
	testutil.AssertEqualsBool(t, "row rush", true, row["rush"].(bool))
}

func TestActionInvokeErrors(t *testing.T) {
	a := invokeApp(t, nil, "")
	act := findAction(t, a, "list_orders")

	// Param errors are an outcome (422 in the API result), not an error
	outcome, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpValidate, JSONArgs: jsonArgs(map[string]string{"count": "0"})})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	doc, code := act.APIResult(outcome, true)
	outcome.Close()
	testutil.AssertEqualsInt(t, "param error code", http.StatusUnprocessableEntity, code)
	testutil.AssertEqualsString(t, "param error", "count must be positive", doc["param_errors"].(map[string]string)["count"])

	for name, tc := range map[string]struct {
		args map[string]string
		code int
		msg  string
	}{
		"unknown param":  {map[string]string{"nope": "1"}, http.StatusBadRequest, "unknown param nope"},
		"hidden param":   {map[string]string{"token": `"x"`}, http.StatusBadRequest, "unknown param token"},
		"bad type":       {map[string]string{"count": `"abc"`}, http.StatusBadRequest, "count"},
		"invalid option": {map[string]string{"status": `"bogus"`}, http.StatusBadRequest, "must be one of the configured options"},
	} {
		_, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, JSONArgs: jsonArgs(tc.args)})
		if invErr == nil {
			t.Fatalf("%s: expected an error", name)
		}
		testutil.AssertEqualsInt(t, name+" code", tc.code, invErr.Code)
		testutil.AssertStringContains(t, invErr.Msg, tc.msg)
	}

	// No suggest handler
	_, invErr = findAction(t, a, "logs").Invoke(userCtx(), action.Invocation{Op: action.OpSuggest})
	testutil.AssertEqualsInt(t, "no suggest", http.StatusNotImplemented, invErr.Code)
}

func TestActionInvokeSuggest(t *testing.T) {
	a := invokeApp(t, nil, "")
	act := findAction(t, a, "/")
	outcome, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpSuggest})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	defer outcome.Close()
	doc, sugErr := act.SuggestResult(outcome.Suggest)
	if sugErr != nil {
		t.Fatalf("suggest: %s", sugErr)
	}
	params := doc["params"].(map[string]any)
	testutil.AssertEqualsString(t, "suggested status", "open", params["status"].(string))
}

func TestActionInvokePermit(t *testing.T) {
	a := invokeApp(t, nil, "")
	act := findAction(t, a, "restricted")
	authorized, err := act.Authorized(userCtx())
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "authorized", false, authorized)
	_, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpRun})
	testutil.AssertEqualsInt(t, "forbidden", http.StatusForbidden, invErr.Code)
	testutil.AssertStringContains(t, invErr.Msg, "builtin:alice does not have access to action Restricted")

	a = invokeApp(t, []string{"ops_admin"}, "")
	outcome, invErr := findAction(t, a, "restricted").Invoke(userCtx(), action.Invocation{Op: action.OpRun})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	testutil.AssertEqualsString(t, "status", "secret done", outcome.Status)
	outcome.Close()
}

func TestActionInvokeStream(t *testing.T) {
	a := invokeApp(t, nil, "")
	act := findAction(t, a, "stream")
	outcome, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, JSONArgs: jsonArgs(map[string]string{"count": "3"})})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	defer outcome.Close()
	testutil.AssertEqualsBool(t, "stream", true, outcome.IsStream())

	var output strings.Builder
	exitStatus, err := outcome.ConsumeStream(context.Background(), func(chunk string) error {
		output.WriteString(chunk)
		return nil
	})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "exit status", 3, exitStatus)
	testutil.AssertEqualsString(t, "output", "one\ntwo\n", output.String())

	// A validate run must not start the command
	outcome2, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpValidate})
	if invErr != nil {
		t.Fatalf("validate: %s", invErr)
	}
	testutil.AssertEqualsBool(t, "validate is not a stream", false, outcome2.IsStream())
	outcome2.Close()
}

func TestActionInvokeUpload(t *testing.T) {
	a := invokeApp(t, nil, "")
	act := findAction(t, a, "upload")
	outcome, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, Files: map[string]action.UploadedFile{
		"datafile": {Filename: "orders.csv", Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("a,b")), nil }},
	}})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	defer outcome.Close()
	testutil.AssertEqualsString(t, "status", "got orders.csv", outcome.Status)

	// A file param cannot be passed as a JSON value
	_, invErr = act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, JSONArgs: jsonArgs(map[string]string{"datafile": `"/etc/passwd"`})})
	testutil.AssertEqualsInt(t, "file as json", http.StatusBadRequest, invErr.Code)
	testutil.AssertStringContains(t, invErr.Msg, "file upload param")
}

func TestActionSchema(t *testing.T) {
	a := invokeApp(t, nil, "")
	act := findAction(t, a, "list_orders")
	schema, err := act.Schema()
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "name", "List Orders", schema.Name)
	testutil.AssertEqualsBool(t, "suggest", true, schema.Suggest)
	names := []string{}
	for _, p := range schema.Params {
		names = append(names, p.Name)
		if p.Name == "status" {
			testutil.AssertEqualsString(t, "options", "open,closed", strings.Join(p.Options, ","))
		}
	}
	// Hidden params and the options params are not listed
	testutil.AssertEqualsString(t, "params", "count,status,rush", strings.Join(names, ","))

	input, err := act.InputJSONSchema(false)
	testutil.AssertNoError(t, err)
	properties := input["properties"].(map[string]any)
	testutil.AssertEqualsString(t, "count type", "integer", properties["count"].(map[string]any)["type"].(string))
	testutil.AssertEqualsString(t, "status enum", "open", properties["status"].(map[string]any)["enum"].([]string)[0])

	// The app level value of a password param is not disclosed
	restrictedSchema, err := findAction(t, a, "restricted").Schema()
	testutil.AssertNoError(t, err)
	for _, p := range restrictedSchema.Params {
		if p.Name == "token" && p.Default != nil {
			t.Fatalf("password default disclosed: %v", p.Default)
		}
	}

	// A required file param: listed for the multipart API, not callable as a JSON tool
	upload := findAction(t, a, "upload")
	testutil.AssertEqualsBool(t, "required file", true, upload.HasRequiredFileParam())
	input, err = upload.InputJSONSchema(false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "required", "datafile", strings.Join(input["required"].([]string), ","))
}

// mcpSession connects a go-sdk client to the app's MCP endpoint. The caller
// identity is attached to each request the way the server's bearer path does
func mcpSession(t *testing.T, a *app.App, progress func(string)) *mcp.ClientSession {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), types.USER_ID, "builtin:alice")))
	}))
	t.Cleanup(server.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, &mcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, req *mcp.ProgressNotificationClientRequest) {
			if progress != nil {
				progress(req.Params.Message)
			}
		},
	})
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: server.URL + "/test/mcp"}, nil)
	if err != nil {
		t.Fatalf("mcp connect: %s", err)
	}
	t.Cleanup(func() { session.Close() }) //nolint:errcheck
	return session
}

func toolText(result *mcp.CallToolResult) string {
	var b strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String()
}

func TestActionsMCPTools(t *testing.T) {
	a := invokeApp(t, nil, `{"source":"actions"}`)
	session := mcpSession(t, a, nil)

	tools, err := session.ListTools(context.Background(), nil)
	testutil.AssertNoError(t, err)
	byName := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}
	// The permit restricted action and the action with a required file param
	// are not listed; the suggest handler gets its own tool
	for _, name := range []string{"list_orders", "list_orders_suggest", "logs", "stream"} {
		if byName[name] == nil {
			t.Fatalf("tool %s missing, got %v", name, byName)
		}
	}
	testutil.AssertEqualsInt(t, "tool count", 4, len(tools.Tools))

	tool := byName["list_orders"]
	testutil.AssertEqualsString(t, "title", "List Orders", tool.Title)
	testutil.AssertStringContains(t, tool.Description, "List the orders")
	testutil.AssertStringContains(t, tool.Description, "dry_run=true")
	schema := tool.InputSchema.(map[string]any)
	properties := schema["properties"].(map[string]any)
	for _, name := range []string{"count", "status", "rush", "dry_run"} {
		if properties[name] == nil {
			t.Fatalf("input property %s missing: %v", name, properties)
		}
	}
	if properties["token"] != nil || properties["options_status"] != nil {
		t.Fatalf("hidden/options params in the schema: %v", properties)
	}
	testutil.AssertEqualsBool(t, "suggest read only", true, byName["list_orders_suggest"].Annotations.ReadOnlyHint)

	// A table result: structured content and a markdown table
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_orders",
		Arguments: map[string]any{"count": 2, "status": "closed"}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "isError", false, result.IsError)
	text := toolText(result)
	testutil.AssertStringContains(t, text, "Listed 2 orders")
	testutil.AssertStringContains(t, text, "| id | rush | status |")
	testutil.AssertStringContains(t, text, "| 1 | false | closed |")
	structured := result.StructuredContent.(map[string]any)
	testutil.AssertEqualsString(t, "report", "TABLE", structured["report"].(string))
	testutil.AssertEqualsInt(t, "values", 2, len(structured["values"].([]any)))

	// Param errors are a tool error the model can read
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_orders", Arguments: map[string]any{"count": 0}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "param error isError", true, result.IsError)
	testutil.AssertStringContains(t, toolText(result), "param count: count must be positive")

	// dry_run validates without running
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_orders", Arguments: map[string]any{"dry_run": true}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "dry run isError", false, result.IsError)
	testutil.AssertStringContains(t, toolText(result), "valid")
	if result.StructuredContent.(map[string]any)["values"] != nil {
		t.Fatalf("dry run returned values")
	}

	// Unknown arguments are refused
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_orders", Arguments: map[string]any{"bogus": 1}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "unknown arg isError", true, result.IsError)
	testutil.AssertStringContains(t, toolText(result), "unknown param bogus")

	// Suggest
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_orders_suggest", Arguments: map[string]any{}})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), `status = "open"`)

	// Text report
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "logs"})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "line one\nline two")

	// The restricted tool is not callable either
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "restricted"})
	if err == nil && !result.IsError {
		t.Fatalf("restricted tool call passed: %v", toolText(result))
	}
}

func TestActionsMCPPermitAndStream(t *testing.T) {
	a := invokeApp(t, []string{"ops_admin"}, `{"source":"actions"}`)
	// Progress notifications are delivered to the client handler asynchronously
	var progressMu sync.Mutex
	var progress strings.Builder
	session := mcpSession(t, a, func(msg string) {
		progressMu.Lock()
		defer progressMu.Unlock()
		progress.WriteString(msg)
	})
	progressText := func() string {
		progressMu.Lock()
		defer progressMu.Unlock()
		return progress.String()
	}

	tools, err := session.ListTools(context.Background(), nil)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "tool count with the permit", 5, len(tools.Tools))

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "restricted"})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "secret done")

	// A stream is consumed to completion: output tail, exit status, and an
	// error result for a non zero exit
	params := &mcp.CallToolParams{Name: "stream", Arguments: map[string]any{"count": 2}}
	params.SetProgressToken("tok1")
	result, err = session.CallTool(context.Background(), params)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "non zero exit isError", true, result.IsError)
	text := toolText(result)
	testutil.AssertStringContains(t, text, "one\ntwo\n")
	testutil.AssertStringContains(t, text, "exit status 2")
	structured := result.StructuredContent.(map[string]any)
	testutil.AssertEqualsString(t, "report", "STREAM", structured["report"].(string))
	testutil.AssertEqualsString(t, "output", "one\ntwo\n", structured["output"].(string))
	for i := 0; i < 100 && !strings.Contains(progressText(), "one"); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	testutil.AssertStringContains(t, progressText(), "one")

	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "stream", Arguments: map[string]any{"count": 0}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "zero exit isError", false, result.IsError)
}

func TestActionsMCPMountValidation(t *testing.T) {
	logger := testutil.TestLogger()
	// source actions needs actions
	_, _, err := CreateTestAppMCP(logger, map[string]string{"app.star": `app = ace.app("testApp")`}, nil, nil, nil, `{"source":"actions"}`)
	testutil.AssertErrorContains(t, err, "mcp source actions needs the app to define actions")

	actionApp := `
def handler(dry_run, args):
	return ace.result("ok")
app = ace.app("testApp", actions=[ace.action("A", "%s", handler)])
`
	// An action cannot take the MCP endpoint path
	_, _, err = CreateTestAppMCP(logger, map[string]string{"app.star": strings.Replace(actionApp, "%s", "/mcp", 1)}, nil, nil, nil, `{"source":"actions"}`)
	testutil.AssertErrorContains(t, err, "action path /mcp is not allowed, /mcp is the MCP endpoint of the app")

	// An upstream MCP app with actions and nothing upstream to answer
	_, _, err = CreateTestAppMCP(logger, map[string]string{"app.star": strings.Replace(actionApp, "%s", "/", 1)}, nil, nil, nil, `{"path":"/"}`)
	testutil.AssertErrorContains(t, err, "use --mcp=actions")

	// The UI keeps working beside the endpoint
	a, _, err := CreateTestAppMCP(logger, map[string]string{"app.star": strings.Replace(actionApp, "%s", "/", 1)}, nil, nil, nil, `{"source":"actions","path":"/tools"}`)
	testutil.AssertNoError(t, err)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, httptest.NewRequest("GET", "/test/", nil))
	testutil.AssertEqualsInt(t, "ui status", http.StatusOK, response.Code)
}

// Tool names are unique across the run and the suggest tools, and the
// validate control never shadows a param of the action
func TestActionsMCPToolNameCollisions(t *testing.T) {
	fileData := map[string]string{
		"app.star": `
def foo(dry_run, args):
	return ace.result("foo ran dry_run=%s param=%s/%s" % (dry_run, args.dry_run, args._dry_run))

def foo_suggest(args):
	return {"dry_run": "suggested"}

def other(dry_run, args):
	return ace.result("the /foo_suggest action ran")

app = ace.app("testApp", actions=[
	ace.action("Foo", "/foo", foo, suggest=foo_suggest),
	ace.action("Other", "/foo_suggest", other, suggest=foo_suggest),
])
`,
		"params.star": `
param("dry_run", description="a param of the action", default="a")
param("_dry_run", description="another one", default="b")
`,
	}
	a, _, err := CreateTestAppMCP(testutil.TestLogger(), fileData, nil, nil, nil, `{"source":"actions"}`)
	testutil.AssertNoError(t, err)
	session := mcpSession(t, a, nil)

	tools, err := session.ListTools(context.Background(), nil)
	testutil.AssertNoError(t, err)
	byName := map[string]*mcp.Tool{}
	names := []string{}
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
		names = append(names, tool.Name)
	}
	// /foo's suggest tool gives way to the action at /foo_suggest
	testutil.AssertEqualsString(t, "tools", "foo,foo_suggest,foo_suggest_2,foo_suggest_suggest", strings.Join(names, ","))
	testutil.AssertStringContains(t, byName["foo"].Description, "foo_suggest_2 suggests argument values")
	testutil.AssertStringContains(t, byName["foo_suggest"].Description, "foo_suggest_suggest suggests argument values")

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "foo_suggest"})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "the /foo_suggest action ran")
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "foo_suggest_2"})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), `dry_run = "suggested"`)

	// dry_run and _dry_run are params of the action: the control is __dry_run,
	// the params stay usable and do not trigger validation
	properties := byName["foo"].InputSchema.(map[string]any)["properties"].(map[string]any)
	testutil.AssertEqualsString(t, "dry_run is the param", "string", properties["dry_run"].(map[string]any)["type"].(string))
	testutil.AssertEqualsString(t, "_dry_run is the param", "string", properties["_dry_run"].(map[string]any)["type"].(string))
	testutil.AssertEqualsString(t, "__dry_run is the control", "boolean", properties["__dry_run"].(map[string]any)["type"].(string))
	testutil.AssertStringContains(t, byName["foo"].Description, "Set __dry_run=true")

	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "foo",
		Arguments: map[string]any{"dry_run": "x", "_dry_run": "y"}})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "foo ran dry_run=False param=x/y")
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "foo",
		Arguments: map[string]any{"__dry_run": true, "_dry_run": "y"}})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "foo ran dry_run=True param=a/y")
}

// The text block of a tool result goes into the context of a model in full:
// it is limited for every report type, not only for tables
func TestActionsMCPTextLimit(t *testing.T) {
	fileData := map[string]string{
		"app.star": `
def text(dry_run, args):
	return ace.result("Many lines", ["line %d " % (10000 + i) + "x" * 90 for i in range(5000)], ace.TEXT)

def rows(dry_run, args):
	return ace.result("Many rows", [{"id": i, "nested": {"pad": "y" * 90}} for i in range(5000)], ace.JSON)

def oneline(dry_run, args):
	return ace.result("One huge line", ["z" * 300000], ace.TEXT)

def small(dry_run, args):
	return ace.result("Small", ["one", "two"], ace.TEXT)

app = ace.app("testApp", actions=[ace.action("Text", "/text", text), ace.action("Rows", "/rows", rows),
	ace.action("Oneline", "/oneline", oneline), ace.action("Small", "/small", small)])
`,
	}
	a, _, err := CreateTestAppMCP(testutil.TestLogger(), fileData, nil, nil, nil, `{"source":"actions"}`)
	testutil.AssertNoError(t, err)
	session := mcpSession(t, a, nil)
	const textLimit, slack = 64 << 10, 1024

	for name, first := range map[string]string{"text": "line 10000 ", "rows": `{"id":0,"nested":`} {
		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name})
		testutil.AssertNoError(t, err)
		text := toolText(result)
		if len(text) > textLimit+slack || len(text) < textLimit/2 {
			t.Fatalf("%s: text block is %d bytes, the limit is %d", name, len(text), textLimit)
		}
		testutil.AssertStringContains(t, text, first)
		testutil.AssertStringContains(t, text, "more values, the text is limited to 65536 bytes")
		// The structured result has its own (larger) limit
		structured := result.StructuredContent.(map[string]any)
		testutil.AssertEqualsBool(t, name+" structured truncated", true, structured["truncated"].(bool))
		if count := len(structured["values"].([]any)); count == 0 || count >= 5000 {
			t.Fatalf("%s: %d structured values", name, count)
		}
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "oneline"})
	testutil.AssertNoError(t, err)
	text := toolText(result)
	if len(text) > textLimit+slack {
		t.Fatalf("one huge line: text block is %d bytes", len(text))
	}
	testutil.AssertStringContains(t, text, "(cut, 65536 of 300000 bytes shown)")

	// A result within the limits is not touched
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "small"})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "small text", "Small\n\none\ntwo\n", toolText(result))
}
