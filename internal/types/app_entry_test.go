// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"
	"time"
)

func TestAppEntryBasicInfo(t *testing.T) {
	now := time.Now()
	full := AppEntry{
		Id: "app_prd_1", Path: "/a", Domain: "d", MainApp: "m", LinkedAppPath: "/a_cl_stage",
		SourceUrl: "https://github.com/x/y", IsDev: false, UserID: "u1", CreateTime: &now, UpdateTime: &now,
		Settings: AppSettings{WebhookTokens: WebhookTokens{Reload: "tok"}, StageWriteAccess: true},
		Metadata: AppMetadata{
			Name: "app", Spec: "python-flask", AppliedSyncId: "sync1", BuilderPublished: true,
			VersionMetadata: VersionMetadata{Version: 3, PreviousVersion: 2, GitBranch: "main", GitCommit: "abc"},
			ParamValues:     map[string]string{"k": "v"}, AppConfig: map[string]string{"c": "1"},
			Loads: []string{"x"}, Permissions: []Permission{{Plugin: "p"}}, Bindings: []string{"/b"},
			AuthnType: "google", GitAuthName: "gh", ContainerOptions: map[string]string{"o": "1"},
		},
	}
	basic := full.BasicInfo()
	if basic.Id != full.Id || basic.Path != full.Path || basic.Domain != full.Domain || basic.MainApp != full.MainApp ||
		basic.LinkedAppPath != full.LinkedAppPath || basic.UserID != full.UserID || basic.CreateTime != full.CreateTime ||
		basic.UpdateTime != full.UpdateTime {
		t.Errorf("identity fields not kept: %+v", basic)
	}
	if basic.Metadata.Name != "app" || basic.Metadata.VersionMetadata.Version != 3 || basic.Metadata.AuthnType != "google" ||
		basic.Metadata.AppliedSyncId != "sync1" || !basic.Metadata.BuilderPublished {
		t.Errorf("status fields not kept: %+v", basic.Metadata)
	}
	if basic.SourceUrl != "" || basic.Metadata.Spec != "" || basic.Metadata.VersionMetadata.GitBranch != "" ||
		basic.Metadata.VersionMetadata.GitCommit != "" || basic.Metadata.VersionMetadata.PreviousVersion != 0 ||
		basic.Metadata.ParamValues != nil || basic.Metadata.AppConfig != nil || basic.Metadata.Loads != nil ||
		basic.Metadata.Permissions != nil || basic.Metadata.Bindings != nil || basic.Metadata.GitAuthName != "" ||
		basic.Metadata.ContainerOptions != nil || basic.Settings.WebhookTokens.Reload != "" || basic.Settings.StageWriteAccess {
		t.Errorf("detail fields leaked: %+v", basic)
	}
}

func TestJobBasicViews(t *testing.T) {
	enabled := false
	spec := JobSpec{Name: "j", Image: "image:x", Command: []string{"sh"}, Args: []string{"-c", "x"}, Shell: true,
		Run: "fn", Env: map[string]string{"SECRET": "v"}, Volumes: []string{"v:/d"}, Options: map[string]string{"o": "1"},
		Trigger: &JobTrigger{Type: JobTriggerCron}, Timeout: "2h", Enabled: &enabled, Params: []string{"p"}, Description: "d"}
	basic := spec.BasicView()
	if basic.Name != "j" || basic.Trigger == nil || basic.Timeout != "2h" || basic.Enabled == nil || basic.Description != "d" {
		t.Errorf("identity/schedule fields not kept: %+v", basic)
	}
	if basic.Image != "" || basic.Command != nil || basic.Args != nil || basic.Shell || basic.Run != "" ||
		basic.Env != nil || basic.Volumes != nil || basic.Options != nil || basic.Params != nil {
		t.Errorf("execution details leaked: %+v", basic)
	}

	code := 1
	now := time.Now()
	run := JobRun{Id: "r", AppId: "app_prd_1", AppPath: "/a", JobName: "j", Trigger: "manual", Actor: "u", Version: 2,
		Image: "img", Definition: "{}", Args: map[string]string{"p": "v"}, StartedAt: now, EndedAt: &now, Status: "failed",
		ExitCode: &code, Message: "output", NodeId: "n", ContainerName: "c", RequestId: "rq", Forced: true}
	rb := run.BasicView()
	if rb.Id != "r" || rb.JobName != "j" || rb.Actor != "u" || rb.Version != 2 || rb.Status != "failed" ||
		rb.ExitCode == nil || rb.EndedAt == nil || !rb.Forced {
		t.Errorf("run identity/status not kept: %+v", rb)
	}
	if rb.Image != "" || rb.Definition != "" || rb.Args != nil || rb.Message != "" || rb.NodeId != "" ||
		rb.ContainerName != "" || rb.RequestId != "" {
		t.Errorf("run details leaked: %+v", rb)
	}
}
