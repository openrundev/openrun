// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Tests for the async run commands against the stub management API: the run
// id of a started run, --wait and --follow, runs, output and cancel

func TestActionRunAsyncStarted(t *testing.T) {
	ats := newActionTestServer(t)
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusAccepted, `{"run_id":"arun_1","status":"running","url":"/site/rebuild/runs/arun_1"}`)
	}
	stdout, stderr, code := runActionCli(t, ats, "run", "/site", "rebuild", "target=all")
	assertEq(t, "exit", "0", string(rune('0'+code)))
	assertEq(t, "run id on stdout", "arun_1\n", stdout)
	if !strings.Contains(stderr, "Run started") || !strings.Contains(stderr, "openrun action output arun_1") {
		t.Fatalf("stderr: %q", stderr)
	}
	assertEq(t, "arg", `"all"`, string(ats.lastRequest.Args["target"]))
}

func TestActionRunAsyncWait(t *testing.T) {
	ats := newActionTestServer(t)
	var polls atomic.Int32
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			writeJSONResponse(w, http.StatusAccepted, `{"run_id":"arun_2","status":"running"}`)
		case strings.HasSuffix(r.URL.Path, "/runs/get"):
			if r.URL.Query().Get("runId") != "arun_2" {
				t.Errorf("run id: %s", r.URL.Query().Get("runId"))
			}
			if polls.Add(1) == 1 {
				writeJSONResponse(w, http.StatusOK, `{"run":{"id":"arun_2","status":"running","is_stream":false}}`)
				return
			}
			writeJSONResponse(w, http.StatusOK, `{"run":{"id":"arun_2","status":"succeeded","is_stream":false,"result_rows":2},`+
				`"result":{"status":"Built 2 rows","report":"TABLE","values":[{"id":1},{"id":2}]}}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}
	stdout, stderr, code := runActionCli(t, ats, "run", "--wait", "/site", "rebuild")
	assertEq(t, "exit", "0", string(rune('0'+code)))
	assertEq(t, "table", "id\n1\n2\n", stdout)
	assertEq(t, "status line", "Built 2 rows\n", stderr)
	if polls.Load() < 2 {
		t.Fatalf("polls: %d", polls.Load())
	}

	// A failed run: exit 1 with the message; param errors: exit 2
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			writeJSONResponse(w, http.StatusAccepted, `{"run_id":"arun_3","status":"running"}`)
			return
		}
		writeJSONResponse(w, http.StatusOK, `{"run":{"id":"arun_3","status":"failed","message":"boom","is_stream":false}}`)
	}
	_, stderr, code = runActionCli(t, ats, "run", "--wait", "/site", "rebuild")
	assertEq(t, "failed exit", "1", string(rune('0'+code)))
	if !strings.Contains(stderr, "run failed: boom") {
		t.Fatalf("stderr: %q", stderr)
	}
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			writeJSONResponse(w, http.StatusAccepted, `{"run_id":"arun_4","status":"running"}`)
			return
		}
		writeJSONResponse(w, http.StatusOK, `{"run":{"id":"arun_4","status":"failed","message":"param errors","is_stream":false},`+
			`"result":{"status":"Validation failed","param_errors":{"count":"must be positive"}}}`)
	}
	stdout, stderr, code = runActionCli(t, ats, "run", "--wait", "/site", "rebuild")
	assertEq(t, "param error exit", "2", string(rune('0'+code)))
	assertEq(t, "no stdout", "", stdout)
	if !strings.Contains(stderr, "error: param count: must be positive") {
		t.Fatalf("stderr: %q", stderr)
	}
}

func TestActionRunAsyncFollowAndOutput(t *testing.T) {
	ats := newActionTestServer(t)
	var reads atomic.Int32
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			writeJSONResponse(w, http.StatusAccepted, `{"run_id":"arun_5","status":"running"}`)
		case strings.HasSuffix(r.URL.Path, "/runs/output"):
			since := r.URL.Query().Get("since")
			if reads.Add(1) == 1 {
				if since != "0" {
					t.Errorf("first since: %s", since)
				}
				writeJSONResponse(w, http.StatusOK, `{"run":{"id":"arun_5","status":"running","is_stream":true,"output_bytes":9},"output":"step one\n","since":0}`)
				return
			}
			if since != "9" {
				t.Errorf("second since: %s", since)
			}
			writeJSONResponse(w, http.StatusOK, `{"run":{"id":"arun_5","status":"succeeded","is_stream":true,"output_bytes":18,"exit_code":0},"output":"step two\n","since":9}`)
		case strings.HasSuffix(r.URL.Path, "/runs/get"):
			writeJSONResponse(w, http.StatusOK, `{"run":{"id":"arun_5","status":"succeeded","is_stream":true,"exit_code":0}}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}
	stdout, _, code := runActionCli(t, ats, "run", "--follow", "/site", "build")
	assertEq(t, "exit", "0", string(rune('0'+code)))
	assertEq(t, "followed output", "step one\nstep two\n", stdout)

	// action output prints the stored output of a finished stream run
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/runs/get"):
			writeJSONResponse(w, http.StatusOK, `{"run":{"id":"arun_6","status":"failed","is_stream":true,"exit_code":3,"message":"exit code 3"}}`)
		case strings.HasSuffix(r.URL.Path, "/runs/output"):
			writeJSONResponse(w, http.StatusOK, `{"run":{"id":"arun_6","status":"failed","is_stream":true,"output_bytes":4},"output":"oops","since":0}`)
		}
	}
	stdout, _, code = runActionCli(t, ats, "output", "arun_6")
	assertEq(t, "output exit", "0", string(rune('0'+code)))
	assertEq(t, "output", "oops", stdout)

	// And the values of a finished values run as JSON
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, `{"run":{"id":"arun_7","status":"succeeded","is_stream":false},"result":{"status":"ok","report":"TEXT","values":["a","b"]}}`)
	}
	stdout, _, _ = runActionCli(t, ats, "output", "arun_7")
	if !strings.Contains(stdout, `"a"`) || !strings.Contains(stdout, `"b"`) {
		t.Fatalf("values output: %q", stdout)
	}
}

func TestActionRunsAndCancel(t *testing.T) {
	ats := newActionTestServer(t)
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/actions/runs"):
			q := r.URL.Query()
			assertEq(t, "app path", "/site", q.Get("appPath"))
			assertEq(t, "action", "rebuild", q.Get("action"))
			assertEq(t, "status", "failed", q.Get("status"))
			assertEq(t, "limit", "5", q.Get("limit"))
			writeJSONResponse(w, http.StatusOK, `{"runs":[{"id":"arun_8","action_name":"Rebuild","status":"failed","actor":"builtin:alice",`+
				`"started_at":"2026-09-22T10:00:00Z","ended_at":"2026-09-22T10:00:05Z","message":"exit code 2\nmore"}]}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/runs/cancel"):
			assertEq(t, "cancel id", "arun_8", r.URL.Query().Get("runId"))
			writeJSONResponse(w, http.StatusOK, `{"run":{"id":"arun_8","status":"canceled"}}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}
	stdout, _, code := runActionCli(t, ats, "runs", "--status", "failed", "--limit", "5", "/site", "rebuild")
	assertEq(t, "exit", "0", string(rune('0'+code)))
	if !strings.Contains(stdout, "Run") || !strings.Contains(stdout, "arun_8") || !strings.Contains(stdout, "builtin:alice") ||
		!strings.Contains(stdout, "5s") || !strings.Contains(stdout, "exit code 2") || strings.Contains(stdout, "more") {
		t.Fatalf("runs table: %q", stdout)
	}
	stdout, _, _ = runActionCli(t, ats, "runs", "-f", "jsonl", "--status", "failed", "--limit", "5", "/site", "rebuild")
	if !strings.Contains(stdout, `"id":"arun_8"`) {
		t.Fatalf("runs jsonl: %q", stdout)
	}

	stdout, _, code = runActionCli(t, ats, "cancel", "arun_8")
	assertEq(t, "cancel exit", "0", string(rune('0'+code)))
	assertEq(t, "cancel output", "run arun_8 canceled\n", stdout)
}

func TestActionRunAsyncWaitSavesFiles(t *testing.T) {
	ats := newActionTestServer(t)
	var fileQuery string
	ats.respond = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_openrun/actions/run":
			writeJSONResponse(w, http.StatusAccepted, `{"run_id":"r9","status":"running"}`)
		case "/_openrun/actions/runs/get":
			writeJSONResponse(w, http.StatusOK, `{"run":{"id":"r9","status":"succeeded","is_stream":false},`+
				`"result":{"status":"Report is ready","report":"DOWNLOAD","values":[{"name":"report.txt","url":"/site/_openrun_app/file/usr_file_1"}]}}`)
		case "/_openrun/actions/file":
			fileQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "file:"+r.URL.Query().Get("url"))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}
	// Without --output the rows are listed with the hint
	stdout, stderr, code := runActionCli(t, ats, "run", "--wait", "/site", "report")
	if code != 0 || !strings.Contains(stdout, "report.txt") || !strings.Contains(stderr, "Use --output") {
		t.Fatalf("listing: %d %q %q", code, stdout, stderr)
	}
	// --output saves the file of the completed async run through the
	// management API, as the sync path does
	target := filepath.Join(t.TempDir(), "saved.txt")
	_, stderr, code = runActionCli(t, ats, "run", "--wait", "--stage", "-o", target, "/site", "report")
	if code != 0 {
		t.Fatalf("save: %d %q", code, stderr)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("saved file: %v", err)
	}
	assertEq(t, "saved content", "file:/site/_openrun_app/file/usr_file_1", string(data))
	if !strings.Contains(fileQuery, "appPath=%2Fsite") || !strings.Contains(fileQuery, "stage=true") {
		t.Fatalf("file query: %s", fileQuery)
	}
}
