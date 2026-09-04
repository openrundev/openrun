// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"strings"
	"testing"
	"time"
)

func boolRef(b bool) *bool { return &b }

func TestParseJobSpecValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		doc  string
		want string // substring of the error, "" for success
	}{
		{"command job", `{"name":"nightly","command":["python","report.py"]}`, ""},
		{"run job", `{"name":"expire","run":"cleanup"}`, ""},
		{"cron trigger", `{"name":"n","command":["x"],"trigger":{"type":"cron","schedule":"0 3 * * *","timezone":"America/Los_Angeles"}}`, ""},
		{"descriptor", `{"name":"n","command":["x"],"trigger":{"type":"cron","schedule":"@daily"}}`, ""},
		{"before deploy", `{"name":"migrate","command":["x"],"trigger":{"type":"before_deploy"}}`, ""},
		{"bad name", `{"name":"Bad_Name","command":["x"]}`, "invalid job name"},
		{"no executor", `{"name":"n"}`, "one of command or run is required"},
		{"both executors", `{"name":"n","command":["x"],"run":"f"}`, "either command or run"},
		{"run with image", `{"name":"n","run":"f","image":"image:postgres:16"}`, "do not apply to run jobs"},
		{"bare image", `{"name":"n","command":["x"],"image":"postgres:16"}`, "image must be"},
		{"bad timeout", `{"name":"n","command":["x"],"timeout":"soon"}`, "invalid timeout"},
		{"bad cron", `{"name":"n","command":["x"],"trigger":{"type":"cron","schedule":"* * *"}}`, "invalid cron schedule"},
		{"bad zone", `{"name":"n","command":["x"],"trigger":{"type":"cron","schedule":"@hourly","timezone":"Mars/Olympus"}}`, "unknown timezone"},
		{"bad trigger type", `{"name":"n","command":["x"],"trigger":{"type":"webhook"}}`, "trigger type must be one of"},
		{"schedule on manual", `{"name":"n","command":["x"],"trigger":{"type":"manual","schedule":"@daily"}}`, "cron trigger only"},
		{"bind volume", `{"name":"n","command":["x"],"volumes":["/host:/data"]}`, "must be a named volume"},
		{"sqlite volume", `{"name":"n","command":["x"],"volumes":["sqlite-abc:/data"]}`, "managed sqlite volume"},
		{"unknown field", `{"name":"n","command":["x"],"retries":3}`, "invalid job definition"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseJobSpec(tc.doc)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestJobSpecDefaults(t *testing.T) {
	t.Parallel()
	appJob := JobSpec{Name: "a", Command: []string{"x"}}
	foreign := JobSpec{Name: "b", Command: []string{"x"}, Image: "image:postgres:16"}
	if !appJob.InheritsEnv() || foreign.InheritsEnv() {
		t.Error("inherit_env default: app image inherits, foreign does not")
	}
	foreign.InheritEnv = boolRef(true)
	if !foreign.InheritsEnv() {
		t.Error("explicit inherit_env ignored")
	}
	if !appJob.IsEnabled() || (JobSpec{Enabled: boolRef(false)}).IsEnabled() {
		t.Error("enabled default")
	}
	if appJob.TriggerType() != JobTriggerManual {
		t.Errorf("trigger default %s", appJob.TriggerType())
	}
	if appJob.TimeoutDuration() != time.Hour {
		t.Errorf("timeout default %s", appJob.TimeoutDuration())
	}
	if foreign.ImageRef() != "postgres:16" {
		t.Errorf("image ref %s", foreign.ImageRef())
	}
	shell := JobSpec{Name: "s", Command: []string{"pg_dump", "$DB"}, Args: []string{"| gzip"}, Shell: true}
	if argv := shell.Argv(); len(argv) != 3 || argv[0] != "sh" || argv[1] != "-c" || argv[2] != "pg_dump $DB | gzip" {
		t.Errorf("shell argv %v", argv)
	}
	if (JobSpec{Name: "my-job"}).EnvName() != "MY_JOB" {
		t.Error("env name")
	}
}

func TestJobSpecCanonicalRoundTrip(t *testing.T) {
	t.Parallel()
	spec := JobSpec{Name: "n", Command: []string{"x"}, Trigger: CronJobTrigger("@daily", ""),
		Timeout: "10m", Enabled: boolRef(false), Params: []string{"region"}}
	parsed, err := ParseJobSpec(spec.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TriggerType() != JobTriggerCron {
		t.Errorf("trigger lost in round trip: %s", spec.String())
	}
	if gate, err := ParseJobSpec(JobSpec{Name: "g", Command: []string{"x"}, Trigger: BeforeDeployTrigger()}.String()); err != nil || gate.TriggerType() != JobTriggerBeforeDeploy {
		t.Errorf("before_deploy lost in round trip: %v %+v", err, gate)
	}
	if parsed.String() != spec.String() {
		t.Errorf("round trip mismatch:\n%s\n%s", parsed.String(), spec.String())
	}
	if strings.Contains(spec.String(), `"inherit_env"`) {
		t.Errorf("omitted optional fields must stay omitted: %s", spec.String())
	}
}

func TestCronTriggerNextRun(t *testing.T) {
	t.Parallel()
	la, _ := time.LoadLocation("America/Los_Angeles")
	trigger := CronTrigger{Schedule: "0 3 * * *", Timezone: "America/Los_Angeles"}
	from := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	next, err := trigger.NextRun(from)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 9, 4, 3, 0, 0, 0, la)
	if !next.Equal(want) {
		t.Errorf("next %s, want %s", next, want)
	}
	// Interval schedules have no stable tick to claim and are rejected
	if _, err := (CronTrigger{Schedule: "@every 4h"}).NextRun(from); err == nil || !strings.Contains(err.Error(), "@every is not supported") {
		t.Errorf("@every accepted: %v", err)
	}
	daily := CronTrigger{Schedule: "@daily", Timezone: "America/Los_Angeles"}
	next, err = daily.NextRun(from)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Equal(time.Date(2026, 9, 4, 0, 0, 0, 0, la)) {
		t.Errorf("@daily next %s", next)
	}
}

func TestMergeJobSpecs(t *testing.T) {
	t.Parallel()
	fromApp := []JobSpec{
		{Name: "migrate", Command: []string{"migrate"}, Trigger: BeforeDeployTrigger()},
		{Name: "report", Command: []string{"report"}, Trigger: CronJobTrigger("@daily", "")},
	}
	fromMetadata := []JobSpec{
		{Name: "report", Command: []string{"report", "--eu"}, Trigger: CronJobTrigger("@hourly", "")},
		{Name: "backup", Command: []string{"backup"}},
	}
	merged, origins, err := MergeJobSpecs(fromApp, fromMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 3 || merged[0].Name != "migrate" || merged[1].Name != "report" || merged[2].Name != "backup" {
		t.Fatalf("merged %+v", merged)
	}
	if merged[1].Trigger.Schedule != "@hourly" || len(merged[1].Command) != 2 {
		t.Errorf("metadata job did not replace the definition job whole: %+v", merged[1])
	}
	if origins[0] != JobOriginDefinition || origins[1] != JobOriginMetadata || origins[2] != JobOriginMetadata {
		t.Errorf("origins %v", origins)
	}
	if _, _, err := MergeJobSpecs([]JobSpec{fromApp[0], fromApp[0]}, nil); err == nil {
		t.Error("duplicate definition names accepted")
	}
}

func TestEffectiveJobs(t *testing.T) {
	t.Parallel()
	metadata := &AppMetadata{
		DefinitionJobs: []string{JobSpec{Name: "a", Command: []string{"x"}}.String()},
		Jobs:           []string{JobSpec{Name: "a", Command: []string{"y"}}.String(), JobSpec{Name: "b", Command: []string{"z"}}.String()},
	}
	jobs, origins, err := EffectiveJobs(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 || jobs[0].Command[0] != "y" || origins[0] != JobOriginMetadata || jobs[1].Name != "b" {
		t.Errorf("effective %+v %v", jobs, origins)
	}
	if _, _, err := EffectiveJobs(&AppMetadata{Jobs: []string{`{"name":"bad"}`}}); err == nil {
		t.Error("invalid metadata job accepted")
	}
}

func TestJobImageAllowed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		allowed []string
		image   string
		want    bool
	}{
		{[]string{"*"}, "anything:latest", true},
		{nil, "postgres:16", false},
		{[]string{"postgres:16"}, "postgres:16", true},
		{[]string{"postgres:16"}, "postgres:15", false},
		{[]string{"regex:^ghcr.io/acme/.*"}, "ghcr.io/acme/tools:1", true},
		{[]string{"regex:^ghcr.io/acme/.*"}, "docker.io/acme/tools:1", false},
	}
	for _, tc := range cases {
		got, err := JobImageAllowed(tc.allowed, tc.image)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("allowed %v image %s: got %v want %v", tc.allowed, tc.image, got, tc.want)
		}
	}
}

func TestAppStage(t *testing.T) {
	t.Parallel()
	if AppStage("app_prd_1") != "prod" || AppStage("app_stg_1") != "stage" || AppStage("app_pre_1") != "preview" || AppStage("app_dev_1") != "dev" {
		t.Error("stage from id prefix")
	}
}
