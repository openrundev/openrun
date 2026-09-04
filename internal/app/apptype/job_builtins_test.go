// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package apptype

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

func evalJobs(t *testing.T, src string) starlark.StringDict {
	t.Helper()
	builtins := CreateBuiltin(types.NodeConfig{}, nil)
	thread := &starlark.Thread{Name: "test"}
	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, "app.star", src, builtins)
	if err != nil {
		t.Fatalf("eval error: %v", err)
	}
	return globals
}

func jobSpecOf(t *testing.T, v starlark.Value) types.JobSpec {
	t.Helper()
	st, ok := v.(*starlarkstruct.Struct)
	if !ok {
		t.Fatalf("not a struct: %v", v)
	}
	specJson, err := GetStringAttr(st, JOB_SPEC_ATTR)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := types.ParseJobSpec(specJson)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestAceJobBuiltin(t *testing.T) {
	t.Parallel()
	globals := evalJobs(t, `
def cleanup(dry_run, args):
    return ace.result("ok")

migrate = ace.job("migrate", command=["python", "manage.py", "migrate"], trigger=ace.before_deploy(), timeout="10m")
report = ace.job("nightly-report", command=["python", "report.py"], args=["--all"],
    trigger=ace.cron("0 3 * * *", timezone="UTC"), params=["region"], description="daily")
backup = ace.job("db-backup", image="postgres:16", inherit_env=True, shell=True,
    command=["pg_dump $DATABASE_URL"], trigger=ace.cron("@daily"), volumes=["backup:/backup"], enabled=False)
expire = ace.job("expire", run=cleanup, trigger={"type": "cron", "schedule": "@hourly"})
app = ace.app("orders", jobs=[migrate, report, backup, expire])
`)
	migrate := jobSpecOf(t, globals["migrate"])
	if migrate.TriggerType() != types.JobTriggerBeforeDeploy || migrate.Timeout != "10m" || len(migrate.Command) != 3 {
		t.Errorf("migrate %+v", migrate)
	}
	report := jobSpecOf(t, globals["report"])
	if report.TriggerType() != types.JobTriggerCron || report.Trigger.Schedule != "0 3 * * *" || report.Trigger.Timezone != "UTC" {
		t.Errorf("report trigger %+v", report.Trigger)
	}
	if len(report.Params) != 1 || report.Params[0] != "region" || report.Description != "daily" || report.Args[0] != "--all" {
		t.Errorf("report %+v", report)
	}
	backup := jobSpecOf(t, globals["backup"])
	if backup.Image != "image:postgres:16" || !backup.InheritsEnv() || !backup.Shell || backup.IsEnabled() || backup.Volumes[0] != "backup:/backup" {
		t.Errorf("backup %+v", backup)
	}
	expire := jobSpecOf(t, globals["expire"])
	if !expire.IsRun() || expire.Run != "cleanup" || expire.Trigger.Schedule != "@hourly" {
		t.Errorf("expire %+v", expire)
	}
	st := globals["expire"].(*starlarkstruct.Struct)
	if run, _ := st.Attr(JOB_RUN_ATTR); run == nil || run == starlark.None {
		t.Error("run callable not carried on the job struct")
	}
	app := globals["app"].(*starlarkstruct.Struct)
	jobs, err := app.Attr("jobs")
	if err != nil || jobs.(*starlark.List).Len() != 4 {
		t.Errorf("app jobs %v %v", jobs, err)
	}
}

func TestAceJobBuiltinErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		src  string
		want string
	}{
		{`ace.job("x")`, "one of command or run is required"},
		{`ace.job("x", command=["a"], run=lambda d, a: None)`, "either command or run"},
		{`ace.job("x", command=["a"], trigger=ace.cron("bad"))`, "invalid cron schedule"},
		{`ace.job("x", command=["a"], trigger="cron")`, "invalid trigger"},
		{`ace.job("x", run="notcallable")`, "run must be a function"},
		{`ace.job("Bad", command=["a"])`, "invalid job name"},
	}
	builtins := CreateBuiltin(types.NodeConfig{}, nil)
	for _, tc := range cases {
		thread := &starlark.Thread{Name: "test"}
		_, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, "app.star", "v = "+tc.src, builtins)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want containing %q", tc.src, err, tc.want)
		}
	}
}

func TestApplyJobAndSidecarBuiltins(t *testing.T) {
	t.Parallel()
	builtins := starlark.StringDict{
		JOB:     CreateApplyJobBuiltin(),
		SIDECAR: CreateApplySidecarBuiltin(),
	}
	for name, fn := range TriggerBuiltins() {
		builtins[name] = fn
	}
	thread := &starlark.Thread{Name: "test"}
	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, "apps.ace", `
backup = job("db-backup", image="image:postgres:16", command=["sh", "-c", "pg_dump"], trigger=cron("0 2 * * *"), timeout="30m")
weekly = job("weekly", command=["./weekly.sh"], trigger=before_deploy())
plain = job("plain", command=["x"], trigger=manual())
cache = sidecar("cache", image="memcached:1.6-alpine", port=11211, args=["-m", "64"])
`, builtins)
	if err != nil {
		t.Fatal(err)
	}
	backup := jobSpecOf(t, globals["backup"])
	if backup.Trigger.Schedule != "0 2 * * *" || backup.Timeout != "30m" {
		t.Errorf("backup %+v", backup)
	}
	if jobSpecOf(t, globals["weekly"]).TriggerType() != types.JobTriggerBeforeDeploy {
		t.Error("before_deploy trigger")
	}
	if jobSpecOf(t, globals["plain"]).TriggerType() != types.JobTriggerManual {
		t.Error("manual trigger")
	}
	cacheSt := globals["cache"].(*starlarkstruct.Struct)
	specJson, err := GetStringAttr(cacheSt, SIDECAR_SPEC_ATTR)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := types.ParseSidecarSpec(specJson)
	if err != nil {
		t.Fatal(err)
	}
	if cache.Image != "image:memcached:1.6-alpine" || cache.Port != 11211 || len(cache.Args) != 2 {
		t.Errorf("cache %+v", cache)
	}

	_, err = starlark.ExecFileOptions(&syntax.FileOptions{}, &starlark.Thread{Name: "t"}, "apps.ace", `j = job("x", run=lambda d, a: None)`, builtins)
	if err == nil || !strings.Contains(err.Error(), "only supported in app.star") {
		t.Errorf("run in declaration: %v", err)
	}
}
