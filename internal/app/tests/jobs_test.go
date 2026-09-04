// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestJobsLoadAndRun(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def cleanup(dry_run, args):
	if args.cutoff == 0:
		return ace.result(status="nothing", param_errors={"cutoff": "cutoff is required"})
	return ace.result(status="deleted %d" % args.cutoff)

def fail(dry_run, args):
	return ace.output(error="boom")

def crash(dry_run, args):
	return 1 / 0

def plain(dry_run, args):
	return "hello " + args.region

def slow(dry_run, args):
	for i in range(100000000):
		pass
	return "done"

app = ace.app("testApp",
	actions=[ace.action("cleanup", "/cleanup", cleanup)],
	jobs=[
		ace.job("expire", run=cleanup, trigger=ace.cron("@hourly"), params=["cutoff"]),
		ace.job("fail", run=fail),
		ace.job("crash", run=crash),
		ace.job("plain", run=plain, params=["region"], description="says hello"),
		ace.job("slow", run=slow, timeout="1s"),
	])
`,
		"params.star": `param("cutoff", description="cutoff", type=INT, default=0)
param("region", description="region", type=STRING, default="us")`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	// The definition jobs are persisted on the metadata at load
	if len(a.Metadata.DefinitionJobs) != 5 {
		t.Fatalf("definition jobs %v", a.Metadata.DefinitionJobs)
	}
	jobs, origins, err := a.EffectiveJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 5 || jobs[0].Name != "expire" || jobs[0].Run != "cleanup" || jobs[0].TriggerType() != types.JobTriggerCron || origins[0] != types.JobOriginDefinition {
		t.Errorf("effective jobs %+v %v", jobs, origins)
	}
	if _, err := a.FindJob("missing"); err == nil {
		t.Error("missing job found")
	}

	ctx := context.Background()
	run := func(name string, args map[string]string) (string, bool, error) {
		spec, err := a.FindJob(name)
		if err != nil {
			t.Fatal(err)
		}
		result, err := a.RunJobFunction(ctx, spec, args)
		return result.Message, result.Failed, err
	}

	// ace.result status is the message; the run argument reaches the handler
	// typed by the param definition
	msg, failed, err := run("expire", map[string]string{"cutoff": "42"})
	if err != nil || failed || msg != "deleted 42" {
		t.Errorf("expire: msg=%q failed=%v err=%v", msg, failed, err)
	}
	// param_errors fail the run
	msg, failed, err = run("expire", nil)
	if err != nil || !failed || !strings.Contains(msg, "cutoff is required") {
		t.Errorf("expire param errors: msg=%q failed=%v err=%v", msg, failed, err)
	}
	// An argument the job does not declare is rejected
	if _, _, err = run("expire", map[string]string{"region": "eu"}); err == nil || !strings.Contains(err.Error(), "not in the job's params list") {
		t.Errorf("undeclared arg: %v", err)
	}
	// ace.output(error=) fails the run with the error as the message
	msg, failed, err = run("fail", nil)
	if err != nil || !failed || msg != "boom" {
		t.Errorf("fail: msg=%q failed=%v err=%v", msg, failed, err)
	}
	// A handler error is an execution error
	if _, _, err = run("crash", nil); err == nil || !strings.Contains(err.Error(), "division by zero") {
		t.Errorf("crash: %v", err)
	}
	// A plain return value is the message; params.star defaults apply
	msg, failed, err = run("plain", nil)
	if err != nil || failed || msg != "hello us" {
		t.Errorf("plain: msg=%q failed=%v err=%v", msg, failed, err)
	}
	// A canceled context stops the Starlark thread
	spec, _ := a.FindJob("slow")
	timeoutCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if _, err := a.RunJobFunction(timeoutCtx, spec, nil); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Errorf("slow: %v", err)
	}
}

func TestJobsLoadErrors(t *testing.T) {
	logger := testutil.TestLogger()
	cases := []struct {
		name string
		star string
		want string
	}{
		{"command without container", `app = ace.app("t", jobs=[ace.job("x", command=["ls"])])`, "command jobs need container config"},
		{"unknown param", `app = ace.app("t", jobs=[ace.job("x", run=lambda d, a: None, params=["nope"])])`, "not defined in params.star"},
		{"duplicate", `app = ace.app("t", jobs=[ace.job("x", run=lambda d, a: None), ace.job("x", run=lambda d, a: None)])`, "duplicate job name"},
		{"not a job", `app = ace.app("t", jobs=[{"name": "x"}])`, "must be created with ace.job()"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := CreateTestApp(logger, map[string]string{"app.star": tc.star})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestJobsMetadataOverride(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
def f(dry_run, args):
	return "ok"
app = ace.app("t", jobs=[ace.job("a", run=f, trigger=ace.cron("@daily")), ace.job("b", run=f)])
`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	// An operator job replaces the same-name definition job whole
	a.Metadata.Jobs = []string{types.JobSpec{Name: "b", Run: "f", Enabled: boolPtr(false)}.String()}
	if _, err := a.Reload(context.Background(), true, true, types.DryRunFalse, app.ReloadOptions{}); err != nil {
		t.Fatalf("reload: %v", err)
	}
	jobs, origins, err := a.EffectiveJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 || origins[1] != types.JobOriginMetadata || jobs[1].IsEnabled() {
		t.Errorf("metadata job did not replace the definition: %+v %v", jobs, origins)
	}
	gates, _ := a.BeforeDeployJobs()
	if len(gates) != 0 {
		t.Errorf("gates %v", gates)
	}
}

func boolPtr(b bool) *bool { return &b }
