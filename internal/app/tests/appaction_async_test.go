// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// Tests for async action runs (arch/docs/async-actions.md): an action with
// is_async=True starts a background run recorded in the run store, with
// its output or result; the form UI, the REST API and the MCP tools show it

const asyncTestApp = `
load("exec.in", "exec")

def rows(dry_run, args):
	if args.count < 1:
		return ace.result("Validation failed", param_errors={"count": "count must be positive"})
	if dry_run:
		return ace.result("valid")
	print("building rows")
	return ace.result("Built %d rows" % args.count, [{"id": i, "status": args.status} for i in range(args.count)], ace.TABLE)

def stream(dry_run, args):
	if dry_run:
		return ace.result("valid")
	return ace.result("Streaming", stream=exec.run("sh", ["-c", 'echo one; echo two; exit ' + str(args.count)], stream=True))

def slow(dry_run, args):
	return ace.result("Slow", stream=exec.run("sh", ["-c", 'echo started; sleep 30; echo done'], stream=True))

def sync_rows(dry_run, args):
	return ace.result("Sync", ["a"], ace.TEXT)

def spew(dry_run, args):
	return exec.run("sh", ["-c", "yes 'a line of output' | head -c 300000"], stream=True)

def image(dry_run, args):
	return ace.result("Generated the logo", [{"name": "logo.png", "url": "static/logo.png"}], ace.IMAGE)

app = ace.app("asyncApp", actions=[
	ace.action("Get Run", "/get_run", sync_rows, hidden=["count", "status", "token"]),
	ace.action("Image", "/image", image, is_async=True, hidden=["count", "status", "token"]),
	ace.action("Spew", "/spew", spew, is_async=True, hidden=["count", "status", "token"]),
	ace.action("Rows", "/rows", rows, is_async=True, hidden=["token"]),
	ace.action("Stream", "/stream", stream, is_async=True, hidden=["status", "token"]),
	ace.action("Slow", "/slow", slow, is_async=True, timeout="2s", hidden=["count", "status", "token"]),
	ace.action("Sync", "/sync", sync_rows, hidden=["count", "status", "token"]),
])
`

const asyncTestParams = `
param("count", type=INT, description="Number of rows", default=2)
param("status", description="Row status", default="open")
param("token", description="API token", default="s3cret", display_type=PASSWORD)
`

// memRunStore is an in memory action.RunStore
type memRunStore struct {
	mu   sync.Mutex
	runs map[string]*types.ActionRun
}

func newMemRunStore() *memRunStore { return &memRunStore{runs: map[string]*types.ActionRun{}} }

func (m *memRunStore) CreateActionRun(_ context.Context, run *types.ActionRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *run
	m.runs[run.Id] = &c
	return nil
}

func (m *memRunStore) GetActionRun(_ context.Context, id string, _ bool) (*types.ActionRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[id]
	if !ok {
		return nil, errors.New("not found")
	}
	c := *run
	return &c, nil
}

func (m *memRunStore) ListActionRuns(_ context.Context, appIds []types.AppId, actionPath, status string, limit int) ([]types.ActionRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ret := []types.ActionRun{}
	for _, run := range m.runs {
		if (actionPath != "" && run.ActionPath != actionPath) || (status != "" && run.Status != status) {
			continue
		}
		ret = append(ret, run.BasicView())
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i].StartedAt.After(ret[j].StartedAt) })
	if limit > 0 && len(ret) > limit {
		ret = ret[:limit]
	}
	return ret, nil
}

func (m *memRunStore) UpdateActionRunLease(_ context.Context, id string, leaseUntil time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if run, ok := m.runs[id]; ok {
		run.LeaseUntil = &leaseUntil
	}
	return nil
}

func (m *memRunStore) UpdateActionRunOutput(_ context.Context, id string, head *string, tail string, outputBytes, omitted int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if run, ok := m.runs[id]; ok {
		if head != nil {
			run.OutputHead = *head
		}
		run.OutputTail, run.OutputBytes, run.OutputOmittedBytes = tail, outputBytes, omitted
	}
	return nil
}

func (m *memRunStore) FinishActionRun(_ context.Context, run *types.ActionRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if stored, ok := m.runs[run.Id]; ok && stored.Status == types.ActionRunRunning {
		c := *run
		m.runs[run.Id] = &c
	}
	return nil
}

func (m *memRunStore) PruneActionRuns(_ context.Context, _ types.AppId, keep int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	finished := []*types.ActionRun{}
	for _, run := range m.runs {
		if run.Status != types.ActionRunRunning {
			finished = append(finished, run)
		}
	}
	sort.Slice(finished, func(i, j int) bool { return finished[i].StartedAt.After(finished[j].StartedAt) })
	pruned := 0
	for i := keep; i < len(finished); i++ {
		delete(m.runs, finished[i].Id)
		pruned++
	}
	return pruned, nil
}

type asyncFixture struct {
	app      *app.App
	store    *memRunStore
	registry *system.RunRegistry
}

func asyncApp(t *testing.T, appConfig *types.AppConfig) *asyncFixture {
	return asyncAppMCP(t, appConfig, "")
}

func asyncAppMCP(t *testing.T, appConfig *types.AppConfig, mcpDoc string) *asyncFixture {
	t.Helper()
	fixture := &asyncFixture{store: newMemRunStore(), registry: &system.RunRegistry{}}
	testRunServices = &app.RunServices{Store: fixture.store, Registry: fixture.registry, NodeId: "node1"}
	defer func() { testRunServices = nil }()
	logo, err := os.ReadFile("../../../tests/actions_tests/static/openrun-logo.png")
	if err != nil {
		t.Fatalf("read logo: %s", err)
	}
	fileData := map[string]string{"app.star": asyncTestApp, "params.star": asyncTestParams, "static/logo.png": string(logo)}
	permissions := []types.Permission{{Plugin: "exec.in", Method: "run"}}
	if mcpDoc != "" {
		mcpConfig, err := types.ParseMCPConfig(mcpDoc)
		testutil.AssertNoError(t, err)
		testMetadataHook = func(metadata *types.AppMetadata) { metadata.MCP = mcpConfig }
		defer func() { testMetadataHook = nil }()
	}
	fixture.app, _, err = CreateTestAppPluginConfig(testutil.TestLogger(), fileData, []string{"exec.in"}, permissions, nil, appConfig)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	t.Cleanup(func() { fixture.registry.Stop(); fixture.registry.Wait() })
	return fixture
}

func waitRun(t *testing.T, act *action.Action, id string) *types.ActionRun {
	t.Helper()
	run, err := act.WaitRun(context.Background(), id, 20*time.Second, true)
	if err != nil {
		t.Fatalf("wait run: %s", err)
	}
	if run.IsActive() {
		t.Fatalf("run %s still running", id)
	}
	return run
}

func TestAsyncActionValuesRun(t *testing.T) {
	f := asyncApp(t, nil)
	act := findAction(t, f.app, "rows")
	testutil.AssertEqualsBool(t, "async", true, act.IsAsync())
	testutil.AssertEqualsBool(t, "sync", false, findAction(t, f.app, "sync").IsAsync())

	outcome, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "mgmt_execute",
		JSONArgs: jsonArgs(map[string]string{"count": `"3"`, "status": `"closed"`})})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	outcome.Close()
	if outcome.Run == nil {
		t.Fatal("expected a started run")
	}
	testutil.AssertEqualsString(t, "status", types.ActionRunRunning, outcome.Run.Status)
	testutil.AssertEqualsString(t, "source", "mgmt", outcome.Run.Source)
	testutil.AssertEqualsString(t, "actor", "builtin:alice", outcome.Run.Actor)
	testutil.AssertEqualsString(t, "arg count", "3", outcome.Run.Args["count"])
	if _, ok := outcome.Run.Args["token"]; ok {
		t.Fatal("password param stored in args")
	}

	run := waitRun(t, act, outcome.Run.Id)
	testutil.AssertEqualsString(t, "status", types.ActionRunSucceeded, run.Status)
	testutil.AssertEqualsString(t, "result status", "Built 3 rows", run.ResultStatus)
	testutil.AssertEqualsString(t, "report", "TABLE", run.Report)
	testutil.AssertEqualsInt(t, "rows", 3, run.ResultRows)
	testutil.AssertEqualsBool(t, "truncated", false, run.ResultTruncated)
	testutil.AssertEqualsBool(t, "stream", false, run.IsStream)
	// print() output is recorded
	testutil.AssertStringContains(t, run.OutputHead, "building rows")

	valuesMap, _, err := action.DecodeResult(run, 0)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "decoded rows", 3, len(valuesMap))
	testutil.AssertEqualsString(t, "row status", "closed", valuesMap[0]["status"].(string))

	doc := act.RunAPIResult(run)
	result := doc["result"].(types.ActionResult)
	testutil.AssertEqualsInt(t, "api values", 3, len(result.Values))

	// Validate stays synchronous
	outcome, invErr = act.Invoke(userCtx(), action.Invocation{Op: action.OpValidate, AuditOp: "validate",
		JSONArgs: jsonArgs(map[string]string{"count": `"1"`})})
	if invErr != nil {
		t.Fatalf("validate: %s", invErr)
	}
	defer outcome.Close()
	if outcome.Run != nil {
		t.Fatal("validate started a run")
	}
	testutil.AssertEqualsString(t, "validate status", "valid", outcome.Status)
}

func TestAsyncActionParamErrors(t *testing.T) {
	f := asyncApp(t, nil)
	act := findAction(t, f.app, "rows")
	outcome, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "execute",
		JSONArgs: jsonArgs(map[string]string{"count": `"0"`})})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	outcome.Close()
	run := waitRun(t, act, outcome.Run.Id)
	testutil.AssertEqualsString(t, "status", types.ActionRunFailed, run.Status)
	testutil.AssertEqualsString(t, "message", "param errors", run.Message)
	testutil.AssertEqualsString(t, "param error", "count must be positive", run.ParamErrors["count"])
	testutil.AssertEqualsString(t, "source", "ui", run.Source)

	// A bad arg is refused at submission, no run is started
	_, invErr = act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "execute",
		JSONArgs: jsonArgs(map[string]string{"count": `"abc"`})})
	if invErr == nil || invErr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %v", invErr)
	}
}

func TestAsyncActionStreamRun(t *testing.T) {
	f := asyncApp(t, nil)
	act := findAction(t, f.app, "stream")
	outcome, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "api_execute",
		JSONArgs: jsonArgs(map[string]string{"count": `"0"`})})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	outcome.Close()
	run := waitRun(t, act, outcome.Run.Id)
	testutil.AssertEqualsString(t, "status", types.ActionRunSucceeded, run.Status)
	testutil.AssertEqualsBool(t, "stream", true, run.IsStream)
	testutil.AssertEqualsString(t, "report", "STREAM", run.Report)
	testutil.AssertEqualsString(t, "output", "one\ntwo\n", run.OutputHead)
	testutil.AssertEqualsInt(t, "bytes", 8, int(run.OutputBytes))
	if run.ExitCode == nil || *run.ExitCode != 0 {
		t.Fatalf("exit code %v", run.ExitCode)
	}
	window := action.ReadOutput(run, 4)
	testutil.AssertEqualsString(t, "window", "two\n", window.Output)

	// A failing command fails the run with its exit code
	outcome, invErr = act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "api_execute",
		JSONArgs: jsonArgs(map[string]string{"count": `"3"`})})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	outcome.Close()
	run = waitRun(t, act, outcome.Run.Id)
	testutil.AssertEqualsString(t, "failed status", types.ActionRunFailed, run.Status)
	testutil.AssertEqualsString(t, "failed message", "exit code 3", run.Message)
	if run.ExitCode == nil || *run.ExitCode != 3 {
		t.Fatalf("exit code %v", run.ExitCode)
	}
}

func TestAsyncActionOutputTruncation(t *testing.T) {
	// Head and tail of 4 bytes each: "one\ntwo\n" keeps "one\n" and "two\n"
	// with nothing omitted, a longer stream drops the middle
	f := asyncApp(t, &types.AppConfig{Action: types.ActionConfig{OutputHeadBytes: 4, OutputTailBytes: 4, ResultMaxBytes: 30}})
	act := findAction(t, f.app, "stream")
	outcome, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "execute",
		JSONArgs: jsonArgs(map[string]string{"count": `"0"`})})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	outcome.Close()
	run := waitRun(t, act, outcome.Run.Id)
	testutil.AssertEqualsString(t, "head", "one\n", run.OutputHead)
	testutil.AssertEqualsString(t, "tail", "two\n", run.OutputTail)
	testutil.AssertEqualsInt(t, "omitted", 0, int(run.OutputOmittedBytes))

	// A values result over the size limit keeps the rows which fit
	rows := findAction(t, f.app, "rows")
	outcome, invErr = rows.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "execute",
		JSONArgs: jsonArgs(map[string]string{"count": `"5"`})})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	outcome.Close()
	run = waitRun(t, rows, outcome.Run.Id)
	testutil.AssertEqualsString(t, "status", types.ActionRunSucceeded, run.Status)
	testutil.AssertEqualsBool(t, "truncated", true, run.ResultTruncated)
	testutil.AssertEqualsInt(t, "rows", 5, run.ResultRows)
	valuesMap, _, err := action.DecodeResult(run, 0)
	testutil.AssertNoError(t, err)
	if len(valuesMap) == 0 || len(valuesMap) >= 5 {
		t.Fatalf("expected a truncated result, got %d rows", len(valuesMap))
	}
}

func TestAsyncActionCancelAndTimeout(t *testing.T) {
	f := asyncApp(t, nil)
	act := findAction(t, f.app, "slow")

	// Cancel stops the streamed command
	outcome, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "execute"})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	outcome.Close()
	id := outcome.Run.Id
	testutil.AssertEqualsBool(t, "registered", true, f.registry.Has(id))
	deadline := time.Now().Add(10 * time.Second)
	for {
		run, _ := act.LoadRun(context.Background(), id, true)
		if strings.Contains(run.OutputTail, "started") || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, invErr := act.CancelRun(userCtx(), id); invErr != nil {
		t.Fatalf("cancel: %s", invErr)
	}
	run := waitRun(t, act, id)
	testutil.AssertEqualsString(t, "canceled", types.ActionRunCanceled, run.Status)
	testutil.AssertEqualsString(t, "canceled by", "canceled by builtin:alice", run.Message)
	testutil.AssertStringContains(t, run.OutputHead, "started")
	testutil.AssertEqualsBool(t, "unregistered", false, f.registry.Has(id))
	if _, invErr := act.CancelRun(userCtx(), id); invErr == nil || invErr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 canceling a finished run, got %v", invErr)
	}

	// The action timeout (2s) times the run out
	outcome, invErr = act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "execute"})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	outcome.Close()
	run = waitRun(t, act, outcome.Run.Id)
	testutil.AssertEqualsString(t, "timed out", types.ActionRunTimedOut, run.Status)
}

func TestAsyncActionAdmissionAndRetention(t *testing.T) {
	f := asyncApp(t, &types.AppConfig{Action: types.ActionConfig{MaxAsyncRuns: 1, RetainRuns: 2}})
	slow := findAction(t, f.app, "slow")
	outcome, invErr := slow.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "execute"})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	outcome.Close()
	// The second concurrent run of the app is refused
	_, invErr = slow.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "execute"})
	if invErr == nil || invErr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %v", invErr)
	}
	if _, invErr := slow.CancelRun(userCtx(), outcome.Run.Id); invErr != nil {
		t.Fatalf("cancel: %s", invErr)
	}
	waitRun(t, slow, outcome.Run.Id)

	// Retention keeps the newest runs of the app instance
	rows := findAction(t, f.app, "rows")
	for i := 0; i < 3; i++ {
		outcome, invErr := rows.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "execute"})
		if invErr != nil {
			t.Fatalf("invoke: %s", invErr)
		}
		outcome.Close()
		waitRun(t, rows, outcome.Run.Id)
	}
	all, _ := f.store.ListActionRuns(context.Background(), nil, "", "", 0)
	testutil.AssertEqualsInt(t, "retained", 2, len(all))
	runs, err := rows.ListRuns(context.Background(), "", 0)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "rows runs", 2, len(runs))
}

func TestAsyncActionAppCloseDeferred(t *testing.T) {
	f := asyncApp(t, nil)
	act := findAction(t, f.app, "slow")
	outcome, invErr := act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "execute"})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	outcome.Close()

	// Close is deferred while the run pins the app: a new run is refused,
	// the running one continues
	testutil.AssertNoError(t, f.app.Close())
	_, invErr = act.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "execute"})
	if invErr == nil || invErr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 after close, got %v", invErr)
	}
	if _, invErr := act.CancelRun(userCtx(), outcome.Run.Id); invErr != nil {
		t.Fatalf("cancel: %s", invErr)
	}
	run := waitRun(t, act, outcome.Run.Id)
	testutil.AssertEqualsString(t, "canceled", types.ActionRunCanceled, run.Status)
}

func TestAsyncActionUIAndAPI(t *testing.T) {
	f := asyncApp(t, nil)
	act := findAction(t, f.app, "rows")

	// The form submit answers the run card and pushes the run page url
	form := strings.NewReader("count=2&status=open")
	req := httptest.NewRequest(http.MethodPost, "/test/rows", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req = req.WithContext(userCtx())
	rec := httptest.NewRecorder()
	f.app.ServeHTTP(rec, req)
	// The Start button (htmx) is redirected to the run page
	testutil.AssertEqualsInt(t, "submit code", http.StatusOK, rec.Code)
	pushUrl := rec.Header().Get("HX-Redirect")
	testutil.AssertStringContains(t, pushUrl, "/test/rows/runs/")
	runId := pushUrl[strings.LastIndex(pushUrl, "/")+1:]
	testutil.AssertEqualsBool(t, "no prefix", false, strings.HasPrefix(runId, "arun_"))
	waitRun(t, act, runId)
	// A plain form post is redirected too
	req = httptest.NewRequest(http.MethodPost, "/test/rows", strings.NewReader("count=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	f.app.ServeHTTP(rec, req.WithContext(userCtx()))
	testutil.AssertEqualsInt(t, "form post redirect", http.StatusSeeOther, rec.Code)
	waitRun(t, act, rec.Header().Get("Location")[strings.LastIndex(rec.Header().Get("Location"), "/")+1:])

	// The run page renders the result
	req = httptest.NewRequest(http.MethodGet, pushUrl, nil).WithContext(userCtx())
	rec = httptest.NewRecorder()
	f.app.ServeHTTP(rec, req)
	testutil.AssertEqualsInt(t, "run page", http.StatusOK, rec.Code)
	testutil.AssertStringContains(t, rec.Body.String(), "succeeded")
	testutil.AssertStringContains(t, rec.Body.String(), "Built 2 rows")

	// The runs list: an args column per param, an expand link per run, the
	// args filter
	req = httptest.NewRequest(http.MethodGet, "/test/rows/runs", nil).WithContext(userCtx())
	rec = httptest.NewRecorder()
	f.app.ServeHTTP(rec, req)
	testutil.AssertEqualsInt(t, "runs page", http.StatusOK, rec.Code)
	testutil.AssertStringContains(t, rec.Body.String(), "Run History")
	testutil.AssertStringContains(t, rec.Body.String(), `href="/test/rows/runs/`+runId+`"`)
	testutil.AssertStringContains(t, rec.Body.String(), `<th scope="col" class="font-mono">count</th>`)
	testutil.AssertEqualsInt(t, "two runs listed", 2, strings.Count(rec.Body.String(), "View details of run "))
	req = httptest.NewRequest(http.MethodGet, "/test/rows/runs?filter=count%3D2", nil).WithContext(userCtx())
	rec = httptest.NewRecorder()
	f.app.ServeHTTP(rec, req)
	testutil.AssertEqualsInt(t, "filtered", 1, strings.Count(rec.Body.String(), "View details of run "))
	// A bare term also matches the result status and the message
	req = httptest.NewRequest(http.MethodGet, "/test/rows/runs?filter=built+2+rows", nil).WithContext(userCtx())
	rec = httptest.NewRecorder()
	f.app.ServeHTTP(rec, req)
	testutil.AssertEqualsInt(t, "filtered by status text", 1, strings.Count(rec.Body.String(), "View details of run"))
	req = httptest.NewRequest(http.MethodGet, "/test/rows/runs?filter=nomatch", nil).WithContext(userCtx())
	rec = httptest.NewRecorder()
	f.app.ServeHTTP(rec, req)
	testutil.AssertStringContains(t, rec.Body.String(), "No runs")

	// The REST API: 202 on submit, the run document, the list
	req = httptest.NewRequest(http.MethodPost, "/test/api/actions/rows", strings.NewReader(`{"count": 1}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(userCtx())
	rec = httptest.NewRecorder()
	f.app.ServeHTTP(rec, req)
	testutil.AssertEqualsInt(t, "api submit", http.StatusAccepted, rec.Code)
	var started types.ActionRunStarted
	testutil.AssertNoError(t, json.Unmarshal(rec.Body.Bytes(), &started))
	testutil.AssertEqualsString(t, "api status", types.ActionRunRunning, started.Status)
	testutil.AssertStringContains(t, started.Url, "/test/rows/runs/")

	req = httptest.NewRequest(http.MethodGet, "/test/api/runs/"+started.RunId+"?wait=10s", nil).WithContext(userCtx())
	rec = httptest.NewRecorder()
	f.app.ServeHTTP(rec, req)
	testutil.AssertEqualsInt(t, "api get", http.StatusOK, rec.Code)
	var doc struct {
		Run    types.ActionRun    `json:"run"`
		Result types.ActionResult `json:"result"`
	}
	testutil.AssertNoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	testutil.AssertEqualsString(t, "api run status", types.ActionRunSucceeded, doc.Run.Status)
	testutil.AssertEqualsInt(t, "api rows", 1, len(doc.Result.Values))
	testutil.AssertEqualsString(t, "api payload stripped", "", doc.Run.Result)

	req = httptest.NewRequest(http.MethodGet, "/test/api/runs?action=/rows", nil).WithContext(userCtx())
	rec = httptest.NewRecorder()
	f.app.ServeHTTP(rec, req)
	testutil.AssertEqualsInt(t, "api list", http.StatusOK, rec.Code)
	var list types.ActionRunsResponse
	testutil.AssertNoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	testutil.AssertEqualsInt(t, "api listed", 3, len(list.Runs))

	req = httptest.NewRequest(http.MethodGet, "/test/api/runs/arun_missing", nil).WithContext(userCtx())
	rec = httptest.NewRecorder()
	f.app.ServeHTTP(rec, req)
	testutil.AssertEqualsInt(t, "api missing", http.StatusNotFound, rec.Code)

	// A stream run's output through the API
	stream := findAction(t, f.app, "stream")
	outcome, invErr := stream.Invoke(userCtx(), action.Invocation{Op: action.OpRun, AuditOp: "api_execute",
		JSONArgs: jsonArgs(map[string]string{"count": `"0"`})})
	if invErr != nil {
		t.Fatalf("invoke: %s", invErr)
	}
	outcome.Close()
	waitRun(t, stream, outcome.Run.Id)
	req = httptest.NewRequest(http.MethodGet, "/test/api/runs/"+outcome.Run.Id+"/output", nil).WithContext(userCtx())
	rec = httptest.NewRecorder()
	f.app.ServeHTTP(rec, req)
	testutil.AssertEqualsInt(t, "api output", http.StatusOK, rec.Code)
	testutil.AssertEqualsString(t, "api output body", "one\ntwo\n", rec.Body.String())
	testutil.AssertEqualsString(t, "api output bytes", "8", rec.Header().Get("OpenRun-Output-Bytes"))
	testutil.AssertEqualsString(t, "api output status", "succeeded", rec.Header().Get(types.ACTION_STATUS_HEADER))
}

func TestAsyncActionDefinition(t *testing.T) {
	f := asyncApp(t, nil)
	defs := action.Defs(f.app.Actions())
	byPath := map[string]types.ActionDef{}
	for _, def := range defs {
		byPath[def.Path] = def
	}
	testutil.AssertEqualsBool(t, "async def", true, byPath["/rows"].Async)
	testutil.AssertEqualsBool(t, "sync def", false, byPath["/sync"].Async)
	testutil.AssertEqualsString(t, "timeout", "2s", findAction(t, f.app, "slow").Timeout().String())

	// Invalid declarations fail the load
	for _, bad := range []string{
		`ace.action("Bad", "/bad", sync_rows, is_async="later")`,
		`ace.action("Bad", "/bad", sync_rows, timeout="5m")`,
		`ace.action("Bad", "/bad", sync_rows, is_async=True, timeout="soon")`,
	} {
		src := strings.Replace(asyncTestApp, `ace.action("Sync", "/sync", sync_rows, hidden=["count", "status", "token"]),`, bad+",", 1)
		_, _, err := CreateTestAppPluginConfig(testutil.TestLogger(), map[string]string{"app.star": src, "params.star": asyncTestParams},
			[]string{"exec.in"}, []types.Permission{{Plugin: "exec.in", Method: "run"}}, nil, nil)
		if err == nil {
			t.Fatalf("expected load error for %s", bad)
		}
	}
}

func TestAsyncActionMCPTools(t *testing.T) {
	f := asyncAppMCP(t, nil, `{"source":"actions"}`)
	session := mcpSession(t, f.app, nil)

	// The run tools are named around the app's own get_run action
	tools, err := session.ListTools(context.Background(), nil)
	testutil.AssertNoError(t, err)
	names := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = tool
	}
	for _, name := range []string{"get_run", "get_run_2", "list_runs", "cancel_run", "rows", "image"} {
		if names[name] == nil {
			t.Fatalf("tool %s missing from %v", name, slices.Sorted(maps.Keys(names)))
		}
	}
	testutil.AssertStringContains(t, names["rows"].Description, "check it with get_run_2")

	// An async tool returns the run id and names the resolved run tool
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "rows", Arguments: map[string]any{"count": 1}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "isError", false, result.IsError)
	testutil.AssertStringContains(t, toolText(result), "Check it with get_run_2")
	started := result.StructuredContent.(map[string]any)
	runId := started["run_id"].(string)
	testutil.AssertEqualsString(t, "running", types.ActionRunRunning, started["run_status"].(string))

	// get_run_2 waits and renders the result; the app's own get_run action is unaffected
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_run_2", Arguments: map[string]any{"run_id": runId, "wait_seconds": 20}})
	testutil.AssertNoError(t, err)
	doc := result.StructuredContent.(map[string]any)
	testutil.AssertEqualsString(t, "succeeded", types.ActionRunSucceeded, doc["run_status"].(string))
	testutil.AssertEqualsString(t, "report", "TABLE", doc["report"].(string))
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_run"})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "Sync")

	// wait_seconds on the action tool returns the finished run
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "rows", Arguments: map[string]any{"count": 2, "wait_seconds": 20}})
	testutil.AssertNoError(t, err)
	testutil.AssertStringContains(t, toolText(result), "Built 2 rows")

	// The image of an async image result is returned inline, from the
	// waited action tool and from get_run
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "image", Arguments: map[string]any{"wait_seconds": 20}})
	testutil.AssertNoError(t, err)
	hasImage := func(result *mcp.CallToolResult) bool {
		for _, content := range result.Content {
			if c, ok := content.(*mcp.ImageContent); ok && strings.HasPrefix(string(c.Data), "\x89PNG") {
				return true
			}
		}
		return false
	}
	testutil.AssertEqualsBool(t, "image inline", true, hasImage(result))
	imageRun := result.StructuredContent.(map[string]any)["run_id"].(string)
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_run_2", Arguments: map[string]any{"run_id": imageRun}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "image inline from get_run", true, hasImage(result))

	// A stream run's output in the MCP document is bounded even when the
	// MCP offset falls in the omitted region (a 200KB head, a 64 byte tail,
	// 300KB of output): the read restarts from the head and is cut to the
	// limit
	f2 := asyncAppMCP(t, &types.AppConfig{Action: types.ActionConfig{OutputHeadBytes: 200 << 10, OutputTailBytes: 64}}, `{"source":"actions"}`)
	session2 := mcpSession(t, f2.app, nil)
	result, err = session2.CallTool(context.Background(), &mcp.CallToolParams{Name: "spew", Arguments: map[string]any{"wait_seconds": 30}})
	testutil.AssertNoError(t, err)
	streamDoc := result.StructuredContent.(map[string]any)
	testutil.AssertEqualsString(t, "spew status", types.ActionRunSucceeded, streamDoc["run_status"].(string))
	if n := len(streamDoc["output"].(string)); n > 64<<10 || n < 60<<10 {
		t.Fatalf("stream output not bounded to the MCP limit: %d", n)
	}
	testutil.AssertEqualsBool(t, "truncated", true, streamDoc["truncated"].(bool))

	// list_runs merges the actions newest first and applies the limit as a whole
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_runs", Arguments: map[string]any{"limit": 1}})
	testutil.AssertNoError(t, err)
	listed := result.StructuredContent.(map[string]any)["runs"].([]any)
	testutil.AssertEqualsInt(t, "limited", 1, len(listed))
	testutil.AssertEqualsString(t, "newest", imageRun, listed[0].(map[string]any)["run_id"].(string))
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_runs", Arguments: map[string]any{}})
	testutil.AssertNoError(t, err)
	listed = result.StructuredContent.(map[string]any)["runs"].([]any)
	testutil.AssertEqualsInt(t, "all", 3, len(listed))

	// cancel_run of a running stream, and a missing run
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "slow"})
	testutil.AssertNoError(t, err)
	slowRun := result.StructuredContent.(map[string]any)["run_id"].(string)
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "cancel_run", Arguments: map[string]any{"run_id": slowRun}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "canceled", types.ActionRunCanceled, result.StructuredContent.(map[string]any)["run_status"].(string))
	testutil.AssertStringContains(t, toolText(result), "canceled by builtin:alice")
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_run_2", Arguments: map[string]any{"run_id": "nosuch"}})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "missing is a tool error", true, result.IsError)
}
