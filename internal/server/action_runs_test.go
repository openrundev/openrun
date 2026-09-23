// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// Tests for async action runs through the server: the management API ops
// (run_action returning the started run, list/get/output/cancel), the
// metadata run store, the reconciler and the app delete cleanup

const asyncActionsAppStar = `
load("exec.in", "exec")

def rows(dry_run, args):
	if args.count < 1:
		return ace.result("Validation failed", param_errors={"count": "count must be positive"})
	if dry_run:
		return ace.result("valid")
	return ace.result("Built %d rows" % args.count, [{"id": i} for i in range(args.count)], ace.TABLE)

def build(dry_run, args):
	return ace.result("Building", stream=exec.run("sh", ["-c", "echo step one; sleep " + str(args.count) + "; echo step two"], stream=True))

def restricted(dry_run, args):
	return ace.result("secret", ["done"], ace.TEXT)

app = ace.app("site", actions=[
	ace.action("Rows", "/rows", rows, is_async=True, description="Build rows"),
	ace.action("Build", "/build", build, is_async=True, timeout="20s", hidden=["status"]),
	ace.action("Restricted", "/restricted", restricted, is_async=True, permit=["ops_admin"], hidden=["count", "status"]),
], permissions=[ace.permission("exec.in", "run")])
`

func createAsyncActionsTestApp(t *testing.T, server *Server, appPath string) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"app.star": asyncActionsAppStar, "params.star": actionsTestParamsStar} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	ctx := system.WithTrustedOperation(t.Context())
	if _, err := server.CreateApp(ctx, appPath, true, false, &types.CreateAppRequest{SourceUrl: dir, AppAuthn: "builtin"}); err != nil {
		t.Fatalf("create async actions app: %v", err)
	}
	server.apps.ResetAllAppCache()
}

func waitActionRun(t *testing.T, server *Server, runId string) *types.ActionRun {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		run, err := server.db.GetActionRun(t.Context(), runId, true)
		testutil.AssertNoError(t, err)
		if !run.IsActive() {
			return run
		}
		if time.Now().After(deadline) {
			t.Fatalf("run %s still running", runId)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAsyncActionsOverRest(t *testing.T) {
	server, ts := newActionsTestServer(t)
	createAsyncActionsTestApp(t, server, "/apps/site")
	mint := func(user string) *system.HttpClient {
		key, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
			&types.ApiKeyCreateRequest{User: user, Resources: []string{ApiResourceRest}})
		if err != nil {
			t.Fatalf("key for %s: %v", user, err)
		}
		return remoteClient(ts, key.Key)
	}
	alice, carol := mint("builtin:alice"), mint("builtin:carol")

	post := func(client *system.HttpClient, apiPath, body string) (*http.Response, string) {
		t.Helper()
		resp, err := client.PostRaw(t.Context(), apiPath, nil, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %s: %v", apiPath, err)
		}
		defer resp.Body.Close() //nolint:errcheck
		data, _ := io.ReadAll(resp.Body)
		return resp, string(data)
	}

	// The list shows the run mode
	var list types.ActionListResponse
	testutil.AssertNoError(t, alice.Get("/_openrun/actions", url.Values{"appPathGlob": {"/apps/site"}}, &list))
	testutil.AssertEqualsString(t, "rest list", "/apps/site:rows,/apps/site:build", actionTools(&list))
	testutil.AssertEqualsBool(t, "async", true, list.Actions[0].Async)

	// run_action answers 202 with the run id; validate stays synchronous
	resp, body := post(alice, "/_openrun/actions/run", `{"app_path":"/apps/site","action":"rows","args":{"count":"3"}}`)
	testutil.AssertEqualsInt(t, "run status", http.StatusAccepted, resp.StatusCode)
	var started types.ActionRunStarted
	testutil.AssertNoError(t, json.Unmarshal([]byte(body), &started))
	testutil.AssertEqualsString(t, "started status", types.ActionRunRunning, started.Status)
	testutil.AssertEqualsString(t, "started url", "/apps/site/rows/runs/"+started.RunId, started.Url)
	resp, body = post(alice, "/_openrun/actions/run", `{"app_path":"/apps/site","action":"rows","dry_run":true}`)
	testutil.AssertEqualsInt(t, "dry run status", http.StatusOK, resp.StatusCode)
	testutil.AssertStringContains(t, body, `"status":"valid"`)

	// get_action_run waits for the run and returns the result
	var doc struct {
		Run    types.ActionRun    `json:"run"`
		Result types.ActionResult `json:"result"`
	}
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs/get", url.Values{"runId": {started.RunId}, "wait": {"20s"}}, &doc))
	testutil.AssertEqualsString(t, "run status", types.ActionRunSucceeded, doc.Run.Status)
	testutil.AssertEqualsString(t, "actor", "builtin:alice", doc.Run.Actor)
	testutil.AssertEqualsString(t, "source", "mgmt", doc.Run.Source)
	testutil.AssertEqualsString(t, "result status", "Built 3 rows", doc.Result.Status)
	testutil.AssertEqualsInt(t, "result values", 3, len(doc.Result.Values))
	testutil.AssertEqualsString(t, "no payload", "", doc.Run.Result)

	// The stored record has the payload
	stored, err := server.db.GetActionRun(t.Context(), started.RunId, true)
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, stored.Result, `"id":2`)
	testutil.AssertEqualsInt(t, "stored rows", 3, stored.ResultRows)
	testutil.AssertEqualsString(t, "stored arg", "3", stored.Args["count"])

	// A stream run: the output through the output op, the exit code
	resp, body = post(alice, "/_openrun/actions/run", `{"app_path":"/apps/site","action":"build","args":{"count":0}}`)
	testutil.AssertEqualsInt(t, "stream run status", http.StatusAccepted, resp.StatusCode)
	testutil.AssertNoError(t, json.Unmarshal([]byte(body), &started))
	run := waitActionRun(t, server, started.RunId)
	testutil.AssertEqualsString(t, "stream status", types.ActionRunSucceeded, run.Status)
	testutil.AssertEqualsBool(t, "is stream", true, run.IsStream)
	var output types.ActionRunOutputResponse
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs/output", url.Values{"runId": {started.RunId}}, &output))
	testutil.AssertEqualsString(t, "output", "step one\nstep two\n", output.Output)
	testutil.AssertEqualsInt(t, "output bytes", 18, int(output.Run.OutputBytes))
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs/output", url.Values{"runId": {started.RunId}, "since": {"9"}}, &output))
	testutil.AssertEqualsString(t, "output from offset", "step two\n", output.Output)

	// The runs list, all actions and one action, with a status filter
	var runs types.ActionRunsResponse
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"/apps/site"}}, &runs))
	testutil.AssertEqualsInt(t, "runs", 2, len(runs.Runs))
	testutil.AssertEqualsString(t, "newest first", started.RunId, runs.Runs[0].Id)
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"/apps/site"}, "action": {"rows"}}, &runs))
	testutil.AssertEqualsInt(t, "rows runs", 1, len(runs.Runs))
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"/apps/site"}, "status": {"failed"}}, &runs))
	testutil.AssertEqualsInt(t, "failed runs", 0, len(runs.Runs))

	// Cancel a running stream
	resp, body = post(alice, "/_openrun/actions/run", `{"app_path":"/apps/site","action":"build","args":{"count":30}}`)
	testutil.AssertEqualsInt(t, "slow run status", http.StatusAccepted, resp.StatusCode)
	testutil.AssertNoError(t, json.Unmarshal([]byte(body), &started))
	var canceled types.ActionRunResponse
	testutil.AssertNoError(t, alice.Post("/_openrun/actions/runs/cancel", url.Values{"runId": {started.RunId}}, nil, &canceled))
	run = waitActionRun(t, server, started.RunId)
	testutil.AssertEqualsString(t, "canceled", types.ActionRunCanceled, run.Status)

	// Runs of a permit restricted action are visible to the permit holder only
	resp, body = post(carol, "/_openrun/actions/run", `{"app_path":"/apps/site","action":"restricted"}`)
	testutil.AssertEqualsInt(t, "restricted run", http.StatusAccepted, resp.StatusCode)
	testutil.AssertNoError(t, json.Unmarshal([]byte(body), &started))
	waitActionRun(t, server, started.RunId)
	err = alice.Get("/_openrun/actions/runs/get", url.Values{"runId": {started.RunId}}, &doc)
	testutil.AssertEqualsInt(t, "alice no permit", http.StatusNotFound, requestErrorCode(t, err))
	testutil.AssertNoError(t, carol.Get("/_openrun/actions/runs/get", url.Values{"runId": {started.RunId}}, &doc))
	testutil.AssertEqualsString(t, "carol sees it", "secret", doc.Result.Status)
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"/apps/site"}}, &runs))
	for _, r := range runs.Runs {
		if r.ActionPath == "/restricted" {
			t.Fatal("restricted run listed for alice")
		}
	}
	err = alice.Get("/_openrun/actions/runs/get", url.Values{"runId": {"arun_missing"}}, &doc)
	testutil.AssertEqualsInt(t, "missing run", http.StatusNotFound, requestErrorCode(t, err))

	// The completion audit event
	found := false
	for i := 0; i < 100 && !found; i++ {
		var count int
		row := server.auditDB.QueryRow(`select count(*) from audit where event_type = 'action' and operation = 'run_finish' and user_id = 'builtin:alice' and target = 'Rows'`)
		testutil.AssertNoError(t, row.Scan(&count))
		found = count > 0
		if !found {
			time.Sleep(20 * time.Millisecond)
		}
	}
	testutil.AssertEqualsBool(t, "run_finish audit event", true, found)

	// The management MCP tool returns the started run, and the run when waited for
	out, err := server.mcpInvokeAction(userApiCtx(t, server, "builtin:alice"), "/apps/site", "rows", false, false, false, map[string]any{"count": 1}, 0)
	testutil.AssertNoError(t, err)
	mcpDoc := out.(map[string]any)
	testutil.AssertEqualsString(t, "mcp run status", types.ActionRunRunning, mcpDoc["run_status"].(string))
	runDoc, err := server.GetActionRun(userApiCtx(t, server, "builtin:alice"), mcpDoc["run_id"].(string), 20*time.Second)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "mcp get run", types.ActionRunSucceeded, runDoc["run"].(types.ActionRun).Status)
	out, err = server.mcpInvokeAction(userApiCtx(t, server, "builtin:alice"), "/apps/site", "rows", false, false, false, map[string]any{"count": 1}, 20)
	testutil.AssertNoError(t, err)
	mcpDoc = out.(map[string]any)
	testutil.AssertEqualsString(t, "mcp waited run", types.ActionRunSucceeded, mcpDoc["run_status"].(string))
	testutil.AssertEqualsString(t, "mcp waited report", "TABLE", mcpDoc["report"].(string))

	// The reconciler marks a run whose lease expired as lost; the app delete
	// removes the records
	expired := time.Now().Add(-2 * time.Minute)
	testutil.AssertNoError(t, server.db.CreateActionRun(t.Context(), &types.ActionRun{Id: "arun_stale", AppId: stored.AppId, AppPath: stored.AppPath,
		ActionPath: "/rows", ActionName: "Rows", Source: "ui", Actor: "builtin:alice", StartedAt: expired, Status: types.ActionRunRunning,
		NodeId: "gone", LeaseUntil: &expired}))
	server.reconcileActionRuns(t.Context())
	stale, err := server.db.GetActionRun(t.Context(), "arun_stale", false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "lost", types.ActionRunLost, stale.Status)

	if _, err := server.DeleteApps(system.WithTrustedOperation(t.Context()), "/apps/site", false); err != nil {
		t.Fatalf("delete app: %v", err)
	}
	remaining, err := server.db.ListActionRuns(t.Context(), []types.AppId{stored.AppId}, "", "", 0)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "runs after delete", 0, len(remaining))
}
