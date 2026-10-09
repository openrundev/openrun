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
	"slices"
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
	if _, err := server.CreateApp(ctx, appPath, DeployOptions{Approve: true}, &types.CreateAppRequest{SourceUrl: dir, AppAuthn: "builtin"}); err != nil {
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
	testutil.AssertEqualsString(t, "source", "cli", doc.Run.Source)
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

	// Across apps: no app path (or a glob) merges the runs of every app the
	// caller may use, newest first, with the app path on each run; a
	// selector picks one action by tool name; limit bounds the merged list
	createAsyncActionsTestApp(t, server, "/apps/other")
	resp, body = post(alice, "/_openrun/actions/run", `{"app_path":"/apps/other","action":"rows","args":{"count":"1"}}`)
	testutil.AssertEqualsInt(t, "other run status", http.StatusAccepted, resp.StatusCode)
	testutil.AssertNoError(t, json.Unmarshal([]byte(body), &started))
	waitActionRun(t, server, started.RunId)
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{}, &runs))
	testutil.AssertEqualsInt(t, "all runs", 3, len(runs.Runs))
	testutil.AssertEqualsString(t, "newest first across apps", started.RunId, runs.Runs[0].Id)
	testutil.AssertEqualsString(t, "other app", "/apps/other", runs.Runs[0].AppPath)
	testutil.AssertEqualsString(t, "site app", "/apps/site", runs.Runs[1].AppPath)
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"/apps/*"}, "action": {"build"}}, &runs))
	testutil.AssertEqualsInt(t, "build runs across apps", 1, len(runs.Runs))
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"all"}, "action": {"nosuch"}}, &runs))
	testutil.AssertEqualsInt(t, "unknown selector across apps", 0, len(runs.Runs))
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"all"}, "limit": {"2"}}, &runs))
	testutil.AssertEqualsInt(t, "limited", 2, len(runs.Runs))
	// Keyset paging: a full page carries the cursor of the next one, which
	// continues the listing; the last page has none
	if runs.NextBefore == "" {
		t.Fatal("full page without a next_before cursor")
	}
	secondPageFirst := runs.Runs[1].Id
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"all"}, "limit": {"1"}}, &runs))
	testutil.AssertEqualsInt(t, "page 1", 1, len(runs.Runs))
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"all"}, "limit": {"1"}, "before": {runs.NextBefore}}, &runs))
	testutil.AssertEqualsInt(t, "page 2", 1, len(runs.Runs))
	testutil.AssertEqualsString(t, "page 2 run", secondPageFirst, runs.Runs[0].Id)
	lastCursor := runs.NextBefore
	runs = types.ActionRunsResponse{} // a fresh decode target: an omitted next_before must read as empty
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"all"}, "limit": {"5"}, "before": {lastCursor}}, &runs))
	testutil.AssertEqualsInt(t, "last page", 1, len(runs.Runs))
	testutil.AssertEqualsString(t, "no cursor on the last page", "", runs.NextBefore)
	// The single-app listing pages the same way
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"/apps/site"}, "limit": {"1"}}, &runs))
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"/apps/site"}, "limit": {"1"}, "before": {runs.NextBefore}}, &runs))
	testutil.AssertEqualsInt(t, "single-app page 2", 1, len(runs.Runs))
	err = alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"all"}, "before": {"bogus"}}, &runs)
	testutil.AssertEqualsInt(t, "bad cursor", http.StatusBadRequest, requestErrorCode(t, err))
	// Brace alternatives are a glob too (FilterApps supports them), not
	// one app's path
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"/apps/{site,other}"}}, &runs))
	testutil.AssertEqualsInt(t, "brace glob", 3, len(runs.Runs))
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"/apps/other"}}, &runs))
	testutil.AssertEqualsInt(t, "one app", 1, len(runs.Runs))
	err = alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"/apps/other"}, "action": {"nosuch"}}, &runs)
	testutil.AssertEqualsInt(t, "unknown selector for one app", http.StatusNotFound, requestErrorCode(t, err))
	// The caller's app:access decides which apps' runs are merged: dave
	// (okta) fails the provider match of the builtin auth apps
	err = mint("okta:dave").Get("/_openrun/actions/runs", url.Values{}, &runs)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "no runs for another provider", 0, len(runs.Runs))
	if _, err := server.DeleteApps(system.WithTrustedOperation(t.Context()), "/apps/other", false); err != nil {
		t.Fatalf("delete other app: %v", err)
	}

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
	for _, appPath := range []string{"/apps/site", "all"} {
		testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {appPath}}, &runs))
		for _, r := range runs.Runs {
			if r.ActionPath == "/restricted" {
				t.Fatalf("restricted run listed for alice (%s)", appPath)
			}
		}
	}
	testutil.AssertNoError(t, carol.Get("/_openrun/actions/runs", url.Values{"action": {"/restricted"}}, &runs))
	testutil.AssertEqualsInt(t, "carol restricted runs across apps", 1, len(runs.Runs))
	// The permitted actions are filtered in the query: carol's restricted
	// run is the newest, a page of one for alice is her newest permitted
	// run (not empty), across apps and for one app alike
	for _, appPath := range []string{"all", "/apps/site"} {
		runs = types.ActionRunsResponse{}
		testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {appPath}, "limit": {"1"}}, &runs))
		testutil.AssertEqualsInt(t, "alice page of one ("+appPath+")", 1, len(runs.Runs))
		if runs.Runs[0].ActionPath == "/restricted" {
			t.Fatalf("restricted run listed for alice (%s)", appPath)
		}
		if runs.NextBefore == "" {
			t.Fatalf("no cursor after a full page (%s)", appPath)
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

	// Runs sharing a start time page by id (desc), for one app as across
	// apps: a page of one lists the higher id first, the cursor continues
	// to the other, nothing is skipped
	sameTime := time.Now().Add(time.Hour) // the newest runs of the app
	for _, id := range []string{"arun_a", "arun_z"} {
		testutil.AssertNoError(t, server.db.CreateActionRun(t.Context(), &types.ActionRun{Id: id, AppId: stored.AppId, AppPath: stored.AppPath,
			ActionPath: "/rows", ActionName: "Rows", Source: "ui", Actor: "builtin:alice", StartedAt: sameTime, Status: types.ActionRunSucceeded}))
	}
	for _, appPath := range []string{"/apps/site", "all"} {
		page, err := server.ListActionRuns(userApiCtx(t, server, "builtin:alice"), appPath, "", "", false, 1, "")
		testutil.AssertNoError(t, err)
		testutil.AssertEqualsString(t, "same time first ("+appPath+")", "arun_z", page.Runs[0].Id)
		page, err = server.ListActionRuns(userApiCtx(t, server, "builtin:alice"), appPath, "", "", false, 1, page.NextBefore)
		testutil.AssertNoError(t, err)
		testutil.AssertEqualsString(t, "same time second ("+appPath+")", "arun_a", page.Runs[0].Id)
	}

	// The staging instance is checked as itself: with staging on another
	// login (system) than prod (builtin), alice sees no staging runs, on
	// the single-app list (refused) and on the glob list (left out) alike
	prodEntry, err := server.db.GetAppEntry(t.Context(), types.CreateAppPathDomain("/apps/site", ""))
	testutil.AssertNoError(t, err)
	stageEntry, err := server.getStageAppNoTx(t.Context(), prodEntry)
	testutil.AssertNoError(t, err)
	stageEntry.Metadata.AuthnType = types.AppAuthnSystem
	tx, err := server.db.BeginTransaction(t.Context())
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, server.db.UpdateAppMetadata(t.Context(), tx, stageEntry))
	testutil.AssertNoError(t, tx.Commit())
	server.apps.ResetAllAppCache()
	trusted := system.WithTrustedOperation(t.Context())
	out, err = server.mcpInvokeAction(trusted, "/apps/site", "rows", true, false, false, map[string]any{"count": 1}, 0)
	testutil.AssertNoError(t, err)
	stageRunId := out.(map[string]any)["run_id"].(string)
	waitActionRun(t, server, stageRunId)
	adminRuns, err := server.ListActionRuns(trusted, "all", "", "", true, 0, "")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "admin sees the staging run", 1, len(adminRuns.Runs))
	testutil.AssertEqualsString(t, "staging run", stageRunId, adminRuns.Runs[0].Id)
	testutil.AssertEqualsString(t, "staging run main path", "/apps/site", adminRuns.Runs[0].MainAppPath)
	if adminRuns.Runs[0].AppPath == adminRuns.Runs[0].MainAppPath {
		t.Fatalf("staging run app path %s should be the staging instance's", adminRuns.Runs[0].AppPath)
	}
	err = alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"/apps/site"}, "stage": {"true"}}, &runs)
	testutil.AssertEqualsInt(t, "alice refused on staging", http.StatusForbidden, requestErrorCode(t, err))
	testutil.AssertNoError(t, alice.Get("/_openrun/actions/runs", url.Values{"appPath": {"all"}, "stage": {"true"}}, &runs))
	testutil.AssertEqualsInt(t, "alice sees no staging runs across apps", 0, len(runs.Runs))

	if _, err := server.DeleteApps(system.WithTrustedOperation(t.Context()), "/apps/site", false); err != nil {
		t.Fatalf("delete app: %v", err)
	}
	remaining, err := server.db.ListActionRuns(t.Context(), []types.AppId{stored.AppId}, nil, "", types.ActionRunCursor{}, 0)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "runs after delete", 0, len(remaining))
}

// A dev app has no staging instance: its runs are in the prod listing of an
// app path glob only. A caller which merges both listings (the console runs
// page) must not see each run of a dev app twice
func TestAsyncActionRunsOfDevAppListedOnce(t *testing.T) {
	server, _ := newActionsTestServer(t)
	trusted := system.WithTrustedOperation(t.Context())
	dir := t.TempDir()
	for name, content := range map[string]string{"app.star": asyncActionsAppStar, "params.star": actionsTestParamsStar} {
		testutil.AssertNoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0600))
	}
	_, err := server.CreateApp(trusted, "/apps/devsite", DeployOptions{Approve: true}, &types.CreateAppRequest{SourceUrl: dir, AppAuthn: "builtin", IsDev: true})
	testutil.AssertNoError(t, err)
	createAsyncActionsTestApp(t, server, "/apps/site")

	for _, appPath := range []string{"/apps/devsite", "/apps/site"} {
		invocation, err := server.InvokeAction(trusted, &types.ActionRunRequest{AppPath: appPath, Action: "rows"}, false, "cli", nil)
		testutil.AssertNoError(t, err)
		waitActionRun(t, server, invocation.outcome.Run.Id)
		invocation.outcome.Close()
	}

	runPaths := func(stage bool) string {
		t.Helper()
		runs, err := server.ListActionRuns(trusted, "/apps/**", "", "", stage, 0, "")
		testutil.AssertNoError(t, err)
		paths := []string{}
		for _, run := range runs.Runs {
			paths = append(paths, run.AppPath)
		}
		slices.Sort(paths)
		return strings.Join(paths, ",")
	}
	testutil.AssertEqualsString(t, "prod listing", "/apps/devsite,/apps/site", runPaths(false))
	// The prod app ran in prod, the dev app has no staging instance
	testutil.AssertEqualsString(t, "staging listing", "", runPaths(true))
}
