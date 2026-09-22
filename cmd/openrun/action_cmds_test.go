// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

// actionTestServer stands in for the management API: it records the run
// request and answers with the configured response
type actionTestServer struct {
	*httptest.Server
	lastRequest types.ActionRunRequest
	lastFiles   map[string]string
	respond     func(w http.ResponseWriter, r *http.Request)
}

func newActionTestServer(t *testing.T) *actionTestServer {
	t.Helper()
	ats := &actionTestServer{}
	ats.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ats.lastFiles = map[string]string{}
			if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
				if err := r.ParseMultipartForm(1 << 20); err != nil {
					t.Errorf("multipart: %v", err)
				}
				_ = json.Unmarshal([]byte(r.MultipartForm.Value["request"][0]), &ats.lastRequest)
				for name, headers := range r.MultipartForm.File {
					f, _ := headers[0].Open()
					data, _ := io.ReadAll(f)
					ats.lastFiles[name] = headers[0].Filename + ":" + string(data)
				}
			} else {
				ats.lastRequest = types.ActionRunRequest{}
				_ = json.UnmarshalRead(r.Body, &ats.lastRequest)
			}
		}
		ats.respond(w, r)
	}))
	t.Cleanup(ats.Close)
	return ats
}

func writeJSONResponse(w http.ResponseWriter, code int, doc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, doc)
}

// runActionCli runs "openrun action <args>" against the test server and
// returns stdout, stderr and the exit code
func runActionCli(t *testing.T, ats *actionTestServer, args ...string) (string, string, int) {
	t.Helper()
	clientConfig := &types.ClientConfig{}
	clientConfig.ServerUri = ats.URL
	clientConfig.Client.ApiKey = "orun_pat_test" // no keychain lookup
	var stdout, stderr bytes.Buffer
	app := cli.NewApp()
	app.Writer = &stdout
	app.ErrWriter = &stderr
	app.ExitErrHandler = func(*cli.Context, error) {} // the exit code is read from the error below
	app.Commands = []*cli.Command{initActionCommand(nil, clientConfig)}

	err := app.Run(normalizeInterspersedFlags(app, append([]string{"openrun", "action"}, args...)))
	exitCode := 0
	if err != nil {
		exitCode = 1
		if exitErr, ok := err.(cli.ExitCoder); ok {
			exitCode = exitErr.ExitCode()
		}
		if err.Error() != "" {
			stderr.WriteString(err.Error() + "\n")
		}
	}
	return stdout.String(), stderr.String(), exitCode
}

func assertEq(t *testing.T, msg, want, got string) {
	t.Helper()
	if want != got {
		t.Fatalf("%s: want %q got %q", msg, want, got)
	}
}

func TestActionRunTableAndFormats(t *testing.T) {
	ats := newActionTestServer(t)
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, `{"status":"Listed 2 orders","report":"TABLE","values":[`+
			`{"id":1,"status":"open","tags":["a","b"]},{"id":22,"status":"closed","tags":[]}]}`)
	}

	stdout, stderr, code := runActionCli(t, ats, "run", "--stage", "/orders", "list_orders", "count=2", "status=open=x")
	assertEq(t, "exit", "0", string(rune('0'+code)))
	// The data goes to stdout, the status line to stderr
	assertEq(t, "table", "id  status  tags\n1   open    [\"a\",\"b\"]\n22  closed  []\n", stdout)
	assertEq(t, "status line", "Listed 2 orders\n", stderr)

	// The request: selector, stage, args as strings for the server to coerce
	assertEq(t, "app path", "/orders", ats.lastRequest.AppPath)
	assertEq(t, "action", "list_orders", ats.lastRequest.Action)
	if !ats.lastRequest.Stage || ats.lastRequest.DryRun {
		t.Fatalf("stage/dry_run: %+v", ats.lastRequest)
	}
	assertEq(t, "count arg", `"2"`, string(ats.lastRequest.Args["count"]))
	assertEq(t, "value with =", `"open=x"`, string(ats.lastRequest.Args["status"]))

	stdout, stderr, _ = runActionCli(t, ats, "run", "-q", "--format", "jsonl", "/orders", "list_orders")
	assertEq(t, "jsonl", `{"id":1,"status":"open","tags":["a","b"]}`+"\n"+`{"id":22,"status":"closed","tags":[]}`+"\n", stdout)
	assertEq(t, "quiet", "", stderr)

	stdout, _, _ = runActionCli(t, ats, "run", "--format", "csv", "/orders", "list_orders")
	assertEq(t, "csv", "id,status,tags\n1,open,\"[\"\"a\"\",\"\"b\"\"]\"\n22,closed,[]\n", stdout)

	// Without an action (single action app): the second arg is a name=value pair
	runActionCli(t, ats, "run", "/orders", "count=5")
	assertEq(t, "no selector", "", ats.lastRequest.Action)
	assertEq(t, "first pair", `"5"`, string(ats.lastRequest.Args["count"]))
}

func TestActionRunReports(t *testing.T) {
	ats := newActionTestServer(t)
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, `{"status":"Recent logs","report":"TEXT","values":["line one","line two"]}`)
	}
	stdout, _, _ := runActionCli(t, ats, "run", "/orders", "logs")
	assertEq(t, "text", "line one\nline two\n", stdout)

	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, `{"status":"Details","report":"JSON","values":[{"spec":{"ports":[80]}}]}`)
	}
	stdout, _, _ = runActionCli(t, ats, "run", "/orders", "inspect")
	if !strings.Contains(stdout, `"ports": [`) {
		t.Fatalf("json report is pretty printed, got %q", stdout)
	}

	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, `{"status":"Done","report":"TEXT","values":[]}`)
	}
	stdout, stderr, code := runActionCli(t, ats, "run", "/orders", "noop")
	assertEq(t, "no values", "", stdout)
	assertEq(t, "status only", "Done\n", stderr)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
}

func TestActionRunErrors(t *testing.T) {
	ats := newActionTestServer(t)
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusUnprocessableEntity, `{"status":"Validation failed","param_errors":{"count":"must be positive","region":"required"}}`)
	}
	stdout, stderr, code := runActionCli(t, ats, "validate", "/orders", "list_orders", "count=0")
	if code != actionExitParamError {
		t.Fatalf("param errors exit code: %d", code)
	}
	if !ats.lastRequest.DryRun {
		t.Fatal("validate must send dry_run")
	}
	assertEq(t, "no data", "", stdout)
	assertEq(t, "param errors", "Validation failed\nerror: param count: must be positive\nerror: param region: required\n", stderr)

	// Request errors of the management API, and of the action (error envelope)
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusForbidden, `{"code":403,"message":"app /orders uses login saml_okta, you are logged in as builtin:bob"}`)
	}
	_, stderr, code = runActionCli(t, ats, "run", "/orders", "list_orders")
	if code != actionExitError || !strings.Contains(stderr, "uses login saml_okta") {
		t.Fatalf("request error: %d %q", code, stderr)
	}

	_, stderr, code = runActionCli(t, ats, "run")
	if code != actionExitError || !strings.Contains(stderr, "expected args") {
		t.Fatalf("missing args: %d %q", code, stderr)
	}
	_, stderr, _ = runActionCli(t, ats, "run", "/orders", "list_orders", "novalue")
	if !strings.Contains(stderr, `invalid arg "novalue"`) {
		t.Fatalf("bad pair: %q", stderr)
	}
}

func TestActionRunStream(t *testing.T) {
	ats := newActionTestServer(t)
	exit := "3"
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set(types.ACTION_STATUS_HEADER, "Streaming build")
		w.Header().Set("Trailer", types.ACTION_EXIT_TRAILER)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "step 1\n")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "step 2\n")
		if exit != "" {
			w.Header().Set(types.ACTION_EXIT_TRAILER, exit)
		}
	}

	// The exit code of the command is the exit code of the CLI
	stdout, stderr, code := runActionCli(t, ats, "run", "/orders", "build")
	assertEq(t, "output", "step 1\nstep 2\n", stdout)
	if code != 3 || !strings.Contains(stderr, "Streaming build") || !strings.Contains(stderr, "exit status 3") {
		t.Fatalf("stream exit: %d %q", code, stderr)
	}

	exit = "0"
	_, _, code = runActionCli(t, ats, "run", "/orders", "build")
	if code != 0 {
		t.Fatalf("clean exit: %d", code)
	}

	// A stream which was cut carries no exit status
	exit = ""
	_, stderr, code = runActionCli(t, ats, "run", "/orders", "build")
	if code != actionExitError || !strings.Contains(stderr, "ended without an exit status") {
		t.Fatalf("cut stream: %d %q", code, stderr)
	}
}

func TestActionArgsJSONAndFiles(t *testing.T) {
	ats := newActionTestServer(t)
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, `{"status":"ok","report":"TEXT","values":[]}`)
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args.json")
	dataFile := filepath.Join(dir, "orders.csv")
	if err := os.WriteFile(argsFile, []byte(`{"count": 7, "tags": ["a"], "status": "open"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, []byte("id,total\n1,10\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Typed args from a file, a name=value pair overrides an entry
	runActionCli(t, ats, "run", "--json=@"+argsFile, "/orders", "import", "status=closed")
	assertEq(t, "typed count", "7", string(ats.lastRequest.Args["count"]))
	assertEq(t, "typed list", `["a"]`, string(ats.lastRequest.Args["tags"]))
	assertEq(t, "override", `"closed"`, string(ats.lastRequest.Args["status"]))

	// name=@file is a multipart upload, the request document rides along
	runActionCli(t, ats, "run", "/orders", "import", "data=@"+dataFile, "count=1")
	assertEq(t, "uploaded file", "orders.csv:id,total\n1,10\n", ats.lastFiles["data"])
	assertEq(t, "multipart app path", "/orders", ats.lastRequest.AppPath)
	assertEq(t, "multipart arg", `"1"`, string(ats.lastRequest.Args["count"]))
	if _, present := ats.lastRequest.Args["data"]; present {
		t.Fatal("the file param must not be sent as an arg")
	}

	// Anything but an object is refused: null decodes without an error and
	// would leave no map to merge the name=value args into
	for _, doc := range []string{"[1]", "null", "  null ", `"text"`, "12"} {
		_, stderr, code := runActionCli(t, ats, "run", "--json="+doc, "/orders", "import", "count=1")
		if code != actionExitError || !strings.Contains(stderr, "JSON object") {
			t.Fatalf("--json=%s: %d %q", doc, code, stderr)
		}
	}
	// An empty object is fine
	_, stderr, code := runActionCli(t, ats, "run", "--json={}", "/orders", "import", "count=1")
	if code != 0 {
		t.Fatalf("--json={}: %d %q", code, stderr)
	}
	assertEq(t, "arg with an empty object", `"1"`, string(ats.lastRequest.Args["count"]))
	_, stderr, _ = runActionCli(t, ats, "run", "/orders", "import", "data=@"+filepath.Join(dir, "missing"))
	if !strings.Contains(stderr, "error opening file for data") {
		t.Fatalf("missing file: %q", stderr)
	}
}

func TestActionSuggestListShow(t *testing.T) {
	ats := newActionTestServer(t)
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_openrun/actions/suggest":
			writeJSONResponse(w, http.StatusOK, `{"status":"Suggesting values","params":{"region":["us-east-1","eu-central-1"],"replicas":3,"env":"prod"}}`)
		case "/_openrun/actions":
			if r.URL.Query().Get("appPathGlob") == "/none" {
				writeJSONResponse(w, http.StatusOK, `{"actions":[]}`)
				return
			}
			writeJSONResponse(w, http.StatusOK, `{"actions":[{"app_path":"/orders","name":"List Orders","tool":"list_orders","path":"/","description":"List the orders\nsecond line","suggest":true}],"warnings":["/broken: load failed"]}`)
		case "/_openrun/actions/schema":
			writeJSONResponse(w, http.StatusOK, `{"app_path":"/orders","name":"List Orders","tool":"list_orders","path":"/","description":"List the orders","suggest":true,
				"url":"https://localhost/orders","input_schema":{"type":"object"},"params":[
				{"name":"count","type":"INT","description":"Number of orders","default":2,"required":false},
				{"name":"region","type":"STRING","required":true,"options":["us","eu"]},
				{"name":"data","type":"STRING","required":true,"display_type":"file"}]}`)
		}
	}

	// Suggested values are printed in the form the run command takes them
	stdout, stderr, _ := runActionCli(t, ats, "suggest", "/orders", "list_orders", "env=prod")
	assertEq(t, "suggest", "env=prod\nregion=[\"us-east-1\",\"eu-central-1\"]\nreplicas=3\n", stdout)
	assertEq(t, "suggest status", "Suggesting values\n", stderr)

	stdout, stderr, _ = runActionCli(t, ats, "list", "/orders")
	for _, want := range []string{"App", "Action", "/orders", "list_orders", "List Orders", "true", "List the orders"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("list output must contain %q: %q", want, stdout)
		}
	}
	if strings.Contains(stdout, "second line") || !strings.Contains(stderr, "warning: /broken: load failed") {
		t.Fatalf("list: %q %q", stdout, stderr)
	}
	stdout, stderr, _ = runActionCli(t, ats, "list", "/none")
	assertEq(t, "empty list", "", stdout)
	assertEq(t, "empty list note", "No actions available\n", stderr)
	stdout, _, _ = runActionCli(t, ats, "list", "--format", "json", "/orders")
	if !strings.Contains(stdout, `"tool": "list_orders"`) {
		t.Fatalf("list json: %q", stdout)
	}

	stdout, _, _ = runActionCli(t, ats, "show", "/orders", "list_orders")
	for _, want := range []string{"Action:      list_orders (List Orders)", "Url:         https://localhost/orders",
		"Name    Type", "count   int", "region  string", "us,eu", "data    string (file)",
		"Usage: openrun action run /orders list_orders [count=<int>] region=<string> data=@<file>"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("show output must contain %q:\n%s", want, stdout)
		}
	}
}

func TestActionRunOutputFiles(t *testing.T) {
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("the API credential must not be sent to an external url")
		}
		_, _ = io.WriteString(w, "external bytes")
	}))
	defer external.Close()

	ats := newActionTestServer(t)
	values := `{"name":"report.txt","url":"/orders/_openrun_app/file/usr_file_1"}`
	var fileQuery string
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_openrun/actions/run":
			writeJSONResponse(w, http.StatusOK, `{"status":"Report is ready","report":"DOWNLOAD","values":[`+values+`]}`)
		case "/_openrun/actions/file":
			fileQuery = r.URL.RawQuery
			if r.URL.Query().Get("url") == "static/gone.png" {
				writeJSONResponse(w, http.StatusNotFound, `{"code":404,"message":"file not found"}`)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "file:"+r.URL.Query().Get("url"))
		}
	}
	dir := t.TempDir()
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(data)
	}

	// Without --output the files are listed, with a hint
	stdout, stderr, code := runActionCli(t, ats, "run", "/orders", "report")
	if code != 0 || !strings.Contains(stdout, "report.txt") || !strings.Contains(stderr, "Use --output") {
		t.Fatalf("listing: %d %q %q", code, stdout, stderr)
	}

	// --output <file>: fetched through the management API as the caller
	target := filepath.Join(dir, "saved.txt")
	stdout, stderr, code = runActionCli(t, ats, "run", "--stage", "-o", target, "/orders", "report")
	if code != 0 {
		t.Fatalf("save: %d %q", code, stderr)
	}
	assertEq(t, "nothing on stdout", "", stdout)
	assertEq(t, "saved file", "file:/orders/_openrun_app/file/usr_file_1", read("saved.txt"))
	if !strings.Contains(stderr, "Saved "+target+" (41 bytes)") {
		t.Fatalf("saved note: %q", stderr)
	}
	for _, want := range []string{"appPath=%2Forders", "action=report", "stage=true"} {
		if !strings.Contains(fileQuery, want) {
			t.Fatalf("file request %q must contain %s", fileQuery, want)
		}
	}

	// --output - writes the file to stdout
	stdout, _, _ = runActionCli(t, ats, "run", "-q", "-o", "-", "/orders", "report")
	assertEq(t, "stdout file", "file:/orders/_openrun_app/file/usr_file_1", stdout)

	// Several files need a directory; names are made safe, an external url is
	// fetched directly, without the API credential
	values = `{"name":"../../evil.txt","url":"static/a.png"},{"url":"static/b.png"},{"name":"ext.bin","url":"` + external.URL + `/x"}`
	_, stderr, code = runActionCli(t, ats, "run", "-o", "-", "/orders", "report")
	if code != actionExitError || !strings.Contains(stderr, "--output has to be a directory") {
		t.Fatalf("stdout with several files: %d %q", code, stderr)
	}
	outDir := filepath.Join(dir, "out")
	_, stderr, code = runActionCli(t, ats, "run", "-o", outDir, "/orders", "report")
	if code != 0 {
		t.Fatalf("save dir: %d %q", code, stderr)
	}
	assertEq(t, "sanitized name", "file:static/a.png", read("out/evil.txt"))
	assertEq(t, "name from url", "file:static/b.png", read("out/b.png"))
	assertEq(t, "external file", "external bytes", read("out/ext.bin"))
	if _, err := os.Stat(filepath.Join(dir, "evil.txt")); err == nil {
		t.Fatal("file written outside the output directory")
	}

	// A failed fetch is an error, nothing is left behind
	values = `{"name":"gone.png","url":"static/gone.png"}`
	_, stderr, code = runActionCli(t, ats, "run", "-o", filepath.Join(dir, "gone.png"), "/orders", "report")
	if code != actionExitError || !strings.Contains(stderr, "error fetching gone.png: file not found") {
		t.Fatalf("failed fetch: %d %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "gone.png")); err == nil {
		t.Fatal("a file was created for a failed fetch")
	}
}

// Creating the API client changes the working directory to OPENRUN_HOME: a
// relative --output path is the caller's, it must not end up in OPENRUN_HOME
func TestActionRunOutputRelativePath(t *testing.T) {
	ats := newActionTestServer(t)
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_openrun/actions/file" {
			_, _ = io.WriteString(w, "report bytes")
			return
		}
		writeJSONResponse(w, http.StatusOK, `{"status":"ok","report":"DOWNLOAD","values":[{"name":"r.txt","url":"static/r.txt"}]}`)
	}
	home, work := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "report.txt"), []byte("unrelated file in OPENRUN_HOME"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENRUN_HOME", home)
	t.Chdir(work)

	_, stderr, code := runActionCli(t, ats, "run", "-o", "report.txt", "/orders", "report")
	if code != 0 {
		t.Fatalf("save: %d %q", code, stderr)
	}
	saved, err := os.ReadFile(filepath.Join(work, "report.txt"))
	if err != nil || string(saved) != "report bytes" {
		t.Fatalf("the file must be saved in the caller's directory: %q %v", saved, err)
	}
	untouched, _ := os.ReadFile(filepath.Join(home, "report.txt"))
	assertEq(t, "file in OPENRUN_HOME", "unrelated file in OPENRUN_HOME", string(untouched))
	if !strings.Contains(stderr, "Saved report.txt (12 bytes)") {
		t.Fatalf("the message names the path as given: %q", stderr)
	}

	// A directory, relative too. The first command left this process in
	// OPENRUN_HOME, each CLI run starts in the caller's directory
	t.Chdir(work)
	_, stderr, code = runActionCli(t, ats, "run", "-o", "out/", "/orders", "report")
	if code != 0 {
		t.Fatalf("save dir: %d %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(work, "out", "r.txt")); err != nil {
		t.Fatalf("out/r.txt in the caller's directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "out")); err == nil {
		t.Fatal("the output directory was created in OPENRUN_HOME")
	}
}
