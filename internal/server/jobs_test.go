// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func TestLoadApplyInfoJobs(t *testing.T) {
	t.Parallel()
	server := &Server{
		Logger:       types.NewLogger(&types.LogConfig{Level: "WARN"}),
		staticConfig: &types.ServerConfig{},
	}
	src := `
backup = job("db-backup", image="postgres:16", command=["pg_dump"], trigger=cron("@daily"))
app("/apps/a", "/tmp/a", jobs=[backup, {"name": "warm", "command": ["warm"]}, '{"name":"lit","command":["x"],"trigger":{"type":"manual"}}'])
app("/apps/b", "/tmp/b", jobs=[backup], sidecars=[sidecar("cache", image="memcached:1.6", port=11211)])
`
	apps, _, err := server.loadApplyInfo("apps.ace", []byte(src), "", false)
	if err != nil {
		t.Fatalf("loadApplyInfo returned error: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("apps length = %d, want 2", len(apps))
	}
	if len(apps[0].Jobs) != 3 {
		t.Fatalf("app a jobs = %v", apps[0].Jobs)
	}
	spec, err := types.ParseJobSpec(apps[0].Jobs[0])
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name != "db-backup" || spec.Image != "image:postgres:16" || spec.Trigger.Schedule != "@daily" {
		t.Errorf("job struct entry %+v", spec)
	}
	if spec, _ := types.ParseJobSpec(apps[0].Jobs[1]); spec.Name != "warm" {
		t.Errorf("dict entry %+v", spec)
	}
	if spec, _ := types.ParseJobSpec(apps[0].Jobs[2]); spec.Name != "lit" || spec.TriggerType() != types.JobTriggerManual {
		t.Errorf("json entry %+v", spec)
	}
	// The same struct composes into a second app
	if len(apps[1].Jobs) != 1 || apps[1].Jobs[0] != apps[0].Jobs[0] {
		t.Errorf("app b jobs = %v", apps[1].Jobs)
	}
	if len(apps[1].Sidecars) != 1 || !strings.Contains(apps[1].Sidecars[0], `"image":"image:memcached:1.6"`) {
		t.Errorf("app b sidecars = %v", apps[1].Sidecars)
	}

	_, _, err = server.loadApplyInfo("apps.ace", []byte(`app("/apps/c", "/tmp/c", jobs=[{"name": "x", "run": "f"}])`), "", false)
	if err == nil || !strings.Contains(err.Error(), "only supported in app.star") {
		t.Errorf("run job in declaration: %v", err)
	}
}

func TestMergeJobs(t *testing.T) {
	t.Parallel()
	a1 := types.JobSpec{Name: "a", Command: []string{"1"}}.String()
	a2 := types.JobSpec{Name: "a", Command: []string{"2"}}.String()
	b := types.JobSpec{Name: "b", Command: []string{"b"}}.String()

	// Adopt: no previous apply info, the declared list is merged in
	live := []string{}
	changed, err := mergeJobs(nil, []string{a1, b}, &live, false)
	if err != nil || !changed || len(live) != 2 {
		t.Fatalf("adopt: changed=%v err=%v live=%v", changed, err, live)
	}
	// Unchanged declaration: no change
	changed, err = mergeJobs([]string{a1, b}, []string{a1, b}, &live, false)
	if err != nil || changed {
		t.Fatalf("unchanged: changed=%v err=%v", changed, err)
	}
	// A changed job replaces the live document of the same name
	changed, err = mergeJobs([]string{a1, b}, []string{a2, b}, &live, false)
	if err != nil || !changed || live[0] != a2 || len(live) != 2 {
		t.Fatalf("update: changed=%v err=%v live=%v", changed, err, live)
	}
	// Clobber makes the live list match the declaration exactly
	changed, err = mergeJobs(nil, []string{b}, &live, true)
	if err != nil || !changed || len(live) != 1 || live[0] != b {
		t.Fatalf("clobber: changed=%v err=%v live=%v", changed, err, live)
	}
}

func TestValidateMetadataJobs(t *testing.T) {
	t.Parallel()
	server := &Server{
		Logger:       types.NewLogger(&types.LogConfig{Level: "WARN"}),
		staticConfig: &types.ServerConfig{Security: types.SecurityConfig{AllowedJobImages: []string{"postgres:16"}}},
	}
	server.effectiveConfig.Store(server.staticConfig)
	ok := []string{types.JobSpec{Name: "a", Image: "image:postgres:16", Command: []string{"x"}}.String()}
	if err := server.validateMetadataJobs(ok); err != nil {
		t.Fatalf("allowed image rejected: %v", err)
	}
	bad := []string{types.JobSpec{Name: "a", Image: "image:postgres:15", Command: []string{"x"}}.String()}
	if err := server.validateMetadataJobs(bad); err == nil || !strings.Contains(err.Error(), "allowed_job_images") {
		t.Errorf("disallowed image: %v", err)
	}
	if err := server.validateMetadataJobs([]string{`{"name":"r","run":"f"}`}); err == nil || !strings.Contains(err.Error(), "only supported in app.star") {
		t.Errorf("run job: %v", err)
	}
}

func TestJobApiRegistry(t *testing.T) {
	t.Parallel()
	for _, name := range []API_NAME{API_LIST_JOBS, API_RUN_JOB, API_LIST_JOB_RUNS, API_JOB_LOGS, API_CANCEL_JOB} {
		entry, ok := apiRegistry[name]
		if !ok {
			t.Fatalf("%s missing from the api registry", name)
		}
		if entry.Path == "" || entry.ApiFunc == nil || entry.Scope == "" {
			t.Errorf("%s: incomplete registry entry %+v", name, entry)
		}
	}
	if apiRegistry[API_RUN_JOB].Scope != types.PermissionUpdate || apiRegistry[API_LIST_JOBS].Scope != types.PermissionRead {
		t.Error("job api scopes: app:update runs, app:read lists")
	}
	if apiRegistry[API_LIST_JOB_RUNS].Scope != types.PermissionReadDetail || apiRegistry[API_JOB_LOGS].Scope != types.PermissionReadDetail {
		t.Error("job api scopes: app:read_detail for run history and output")
	}
}
