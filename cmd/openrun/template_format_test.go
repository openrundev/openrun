// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

// runFormatFlag parses --format through the given flag and returns the
// parse error
func runFormatFlag(flag cli.Flag, value string) error {
	app := cli.NewApp()
	app.Writer = &bytes.Buffer{}
	app.Commands = []*cli.Command{{
		Name:   "c",
		Flags:  []cli.Flag{flag},
		Action: func(*cli.Context) error { return nil },
	}}
	return app.Run([]string{"openrun", "c", "--format", value})
}

// TestFormatFlagTemplates verifies the list format flag accepts a Go
// template and rejects a broken one or an unknown name at parse time, while
// the fixed flag of the single-document commands rejects templates
func TestFormatFlagTemplates(t *testing.T) {
	if err := runFormatFlag(newFormatFlag(), "{{.metadata.name}}"); err != nil {
		t.Fatalf("template format: %v", err)
	}
	if err := runFormatFlag(newFormatFlag(), "jsonl"); err != nil {
		t.Fatalf("fixed format: %v", err)
	}
	err := runFormatFlag(newFormatFlag(), "{{.metadata.name")
	if err == nil || !strings.Contains(err.Error(), "invalid format template") {
		t.Fatalf("broken template: %v", err)
	}
	err = runFormatFlag(newFormatFlag(), "{{nosuchfunc .}}")
	if err == nil || !strings.Contains(err.Error(), "invalid format template") {
		t.Fatalf("unknown function: %v", err)
	}
	err = runFormatFlag(newFormatFlag(), "jsno")
	if err == nil || !strings.Contains(err.Error(), `invalid format "jsno"`) {
		t.Fatalf("typo: %v", err)
	}
	err = runFormatFlag(newFixedFormatFlag(), "{{.id}}")
	if err == nil || !strings.Contains(err.Error(), `invalid format "{{.id}}"`) {
		t.Fatalf("fixed flag template: %v", err)
	}
}

func newTestContext() (*cli.Context, *bytes.Buffer) {
	var stdout bytes.Buffer
	app := cli.NewApp()
	app.Writer = &stdout
	app.ErrWriter = &bytes.Buffer{}
	return cli.NewContext(app, nil, nil), &stdout
}

// TestPrintTemplate renders a list through a template: one line per row,
// json field names, integral numbers without an exponent, sprig and json
// functions, and an execution error reported rather than panicked
func TestPrintTemplate(t *testing.T) {
	apps := []types.AppResponse{
		{AppEntry: types.AppEntry{Id: "app_prd_1", Path: "/one", IsDev: false,
			Metadata: types.AppMetadata{Name: "one", VersionMetadata: types.VersionMetadata{Version: 3, GitBranch: "main"}}}},
		{AppEntry: types.AppEntry{Id: "app_dev_2", Path: "/two", IsDev: true,
			Metadata: types.AppMetadata{Name: "two", VersionMetadata: types.VersionMetadata{Version: 1048576}}}, StagedChanges: true},
	}

	cCtx, stdout := newTestContext()
	err := printAppList(cCtx, apps, "{{.metadata.name}}\t{{.metadata.version_metadata.version}}\t{{.is_dev}}\t{{.staged_changes}}")
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "rows", "one\t3\tfalse\tfalse\ntwo\t1048576\ttrue\ttrue\n", stdout.String())

	cCtx, stdout = newTestContext()
	if err := printAppList(cCtx, apps, `{{.metadata.name | upper}} {{json .metadata.version_metadata}}`); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], `ONE {"`) || !strings.Contains(lines[0], `"git_branch":"main"`) ||
		!strings.Contains(lines[0], `"version":3`) || !strings.HasPrefix(lines[1], `TWO {"`) {
		t.Fatalf("sprig+json: %q", stdout.String())
	}

	cCtx, stdout = newTestContext()
	if err := printAppList(cCtx, apps, `{{if .is_dev}}{{.path}}{{else}}-{{end}}`); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "conditional", "-\n/two\n", stdout.String())

	cCtx, stdout = newTestContext()
	if err := printAppList(cCtx, nil, `{{.id}}`); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "empty list", "", stdout.String())

	cCtx, stdout = newTestContext()
	err = printAppList(cCtx, apps, `{{index .metadata.loads 5}}`)
	if err == nil || !strings.Contains(err.Error(), "error rendering format template") {
		t.Fatalf("execution error: %v", err)
	}
	assertEq(t, "no partial output on error", "", stdout.String())

	// Other list printers route templates the same way
	cCtx, stdout = newTestContext()
	if err := printActionRuns(cCtx, []types.ActionRun{{Id: "run1", Status: "done"}}, "{{.id}}={{.status}}"); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "action runs", "run1=done\n", stdout.String())
}

// TestActionListTemplateFormat renders action list through the CLI with a
// template, and checks the single-document action show still rejects one
func TestActionListTemplateFormat(t *testing.T) {
	ats := newActionTestServer(t)
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, `{"actions":[{"app_path":"/orders","name":"List Orders","tool":"list_orders","path":"/","suggest":true},
			{"app_path":"/orders","name":"Purge","tool":"purge","path":"/purge","hints":{"destructive":true}}]}`)
	}
	stdout, stderr, code := runActionCli(t, ats, "list", "--format", "{{.app_path}} {{.tool}} {{if .hints}}{{.hints.destructive}}{{else}}-{{end}}", "/orders")
	assertEq(t, "stderr", "", stderr)
	assertEq(t, "template list", "/orders list_orders -\n/orders purge true\n", stdout)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}

	_, stderr, code = runActionCli(t, ats, "show", "--format", "{{.tool}}", "/orders", "list_orders")
	if code == 0 || !strings.Contains(stderr, `invalid format "{{.tool}}"`) {
		t.Fatalf("show must reject templates: %d %q", code, stderr)
	}
}
