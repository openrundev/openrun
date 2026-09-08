// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// TestReadDetailBasicView verifies the app:read vs app:read_detail split over
// the REST surface: carol (openrun-user, app:read only) lists and gets the
// app with identity and status only, while alice (openrun-developer,
// app:manage) gets the full entry
func TestReadDetailBasicView(t *testing.T) {
	_, ts, mintKey := newRemoteApiTestServer(t)
	carolKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:carol"})
	aliceKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice"})

	// get_app: basic for carol
	var carolGet types.AppGetResponse
	if err := remoteClient(ts, carolKey).Get("/_openrun/app",
		url.Values{"appPath": {"/apps/remote-test"}}, &carolGet); err != nil {
		t.Fatalf("carol get app: %v", err)
	}
	entry := carolGet.AppEntry
	testutil.AssertEqualsString(t, "carol path", "/apps/remote-test", entry.Path)
	testutil.AssertEqualsString(t, "carol name", "syncApp", entry.Metadata.Name)
	if entry.Metadata.VersionMetadata.Version == 0 {
		t.Error("carol basic view must keep the version")
	}
	if entry.SourceUrl != "" || entry.Metadata.Spec != "" || entry.Metadata.VersionMetadata.GitBranch != "" ||
		len(entry.Metadata.ParamValues) != 0 || len(entry.Metadata.AppConfig) != 0 ||
		len(entry.Metadata.Loads) != 0 || len(entry.Metadata.Permissions) != 0 {
		t.Errorf("carol basic view leaks detail fields: %+v", entry)
	}

	// get_app: full for alice
	var aliceGet types.AppGetResponse
	if err := remoteClient(ts, aliceKey).Get("/_openrun/app",
		url.Values{"appPath": {"/apps/remote-test"}}, &aliceGet); err != nil {
		t.Fatalf("alice get app: %v", err)
	}
	if aliceGet.AppEntry.SourceUrl == "" {
		t.Errorf("alice full view must carry the source url: %+v", aliceGet.AppEntry)
	}

	// list_apps: basic for carol, full for alice
	var carolList, aliceList types.AppListResponse
	if err := remoteClient(ts, carolKey).Get("/_openrun/apps",
		url.Values{"appPathGlob": {"/apps/**"}}, &carolList); err != nil {
		t.Fatalf("carol list apps: %v", err)
	}
	testutil.AssertEqualsInt(t, "carol apps", 1, len(carolList.Apps))
	if carolList.Apps[0].SourceUrl != "" || carolList.Apps[0].Metadata.Name != "syncApp" {
		t.Errorf("carol list must be the basic view: %+v", carolList.Apps[0])
	}
	if err := remoteClient(ts, aliceKey).Get("/_openrun/apps",
		url.Values{"appPathGlob": {"/apps/**"}}, &aliceList); err != nil {
		t.Fatalf("alice list apps: %v", err)
	}
	testutil.AssertEqualsInt(t, "alice apps", 1, len(aliceList.Apps))
	if aliceList.Apps[0].SourceUrl == "" {
		t.Errorf("alice list must be the full view: %+v", aliceList.Apps[0])
	}
}

// TestReadDetailGatesDetailApis verifies the version, files and export APIs
// need app:read_detail: denied for carol (app:read), allowed for alice
func TestReadDetailGatesDetailApis(t *testing.T) {
	_, ts, mintKey := newRemoteApiTestServer(t)
	carolKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:carol"})
	aliceKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice"})

	calls := []struct {
		name string
		path string
		args url.Values
	}{
		{"version list", "/_openrun/version", url.Values{"appPath": {"/apps/remote-test"}}},
		{"version files", "/_openrun/version/files", url.Values{"appPath": {"/apps/remote-test"}}},
	}
	for _, c := range calls {
		var resp map[string]any
		err := remoteClient(ts, carolKey).Get(c.path, c.args, &resp)
		if err == nil || !strings.Contains(err.Error(), string(types.PermissionReadDetail)) {
			t.Errorf("carol %s: want app:read_detail denial, got %v", c.name, err)
		}
		resp = nil
		if err := remoteClient(ts, aliceKey).Get(c.path, c.args, &resp); err != nil {
			t.Errorf("alice %s: %v", c.name, err)
		}
	}

	// The glob export filters apps by app:read_detail (like listing filters
	// by app:read): carol gets an empty config, alice gets the app
	var carolExport, aliceExport types.AppExportResponse
	if err := remoteClient(ts, carolKey).Get("/_openrun/export",
		url.Values{"appPathGlob": {"/apps/remote-test"}}, &carolExport); err != nil {
		t.Fatalf("carol export: %v", err)
	}
	if strings.Contains(carolExport.Config, "/apps/remote-test") {
		t.Errorf("carol export must not include the app config: %s", carolExport.Config)
	}
	if err := remoteClient(ts, aliceKey).Get("/_openrun/export",
		url.Values{"appPathGlob": {"/apps/remote-test"}}, &aliceExport); err != nil {
		t.Fatalf("alice export: %v", err)
	}
	if !strings.Contains(aliceExport.Config, "/apps/remote-test") {
		t.Errorf("alice export must include the app config: %s", aliceExport.Config)
	}

	// A *:read scoped key for alice does not cover app:read_detail (the
	// scope glob matches the permission name, read_detail is a distinct name)
	scopedKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice", Scopes: []string{"*:read"}})
	var resp map[string]any
	err := remoteClient(ts, scopedKey).Get("/_openrun/version", url.Values{"appPath": {"/apps/remote-test"}}, &resp)
	if err == nil {
		t.Error("*:read scoped key must not list versions (app:read_detail)")
	}
	var listResp types.AppListResponse
	if err := remoteClient(ts, scopedKey).Get("/_openrun/apps", url.Values{"appPathGlob": {"/apps/**"}}, &listResp); err != nil {
		t.Fatalf("scoped list apps: %v", err)
	}
	// The scope ceiling applies to the detail check too: the basic view
	if len(listResp.Apps) != 1 || listResp.Apps[0].SourceUrl != "" {
		t.Errorf("*:read scoped list must be the basic view: %+v", listResp.Apps)
	}
}

// TestReadDetailJobListBasicView verifies list_jobs (app:read) returns the
// basic view of each job for callers without app:read_detail: the name and
// schedule stay, the command, env and run definition are blanked
func TestReadDetailJobListBasicView(t *testing.T) {
	server, ts, mintKey := newRemoteApiTestServer(t)
	dir := t.TempDir()
	appDir := filepath.Join(dir, "app")
	if err := os.Mkdir(appDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "app.star"), []byte("app = ace.app(\"jobsApp\")\n"), 0600); err != nil {
		t.Fatal(err)
	}
	applyPath := filepath.Join(dir, "jobs.ace")
	applyData := fmt.Sprintf(`app("/apps/jobs-test", %q, jobs=[{"name": "backup", "command": ["sh", "-c", "echo hi"], "env": {"SECRET": "v"}, "trigger": {"type": "cron", "schedule": "0 3 * * *"}}])`, appDir)
	if err := os.WriteFile(applyPath, []byte(applyData), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.Apply(system.WithTrustedOperation(context.Background()), types.Transaction{}, applyPath, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply jobs app: %v", err)
	}
	server.apps.ResetAllAppCache()

	carolKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:carol"})
	aliceKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice"})
	var carolJobs, aliceJobs types.JobListResponse
	if err := remoteClient(ts, carolKey).Get("/_openrun/jobs",
		url.Values{"appPathGlob": {"/apps/jobs-test"}}, &carolJobs); err != nil {
		t.Fatalf("carol list jobs: %v", err)
	}
	testutil.AssertEqualsInt(t, "carol jobs", 1, len(carolJobs.Jobs))
	spec := carolJobs.Jobs[0].Spec
	if spec.Name != "backup" || spec.Trigger == nil || spec.Trigger.Schedule != "0 3 * * *" {
		t.Errorf("carol basic job view must keep the name and schedule: %+v", spec)
	}
	if spec.Command != nil || spec.Env != nil || spec.Args != nil {
		t.Errorf("carol basic job view leaks execution details: %+v", spec)
	}
	if err := remoteClient(ts, aliceKey).Get("/_openrun/jobs",
		url.Values{"appPathGlob": {"/apps/jobs-test"}}, &aliceJobs); err != nil {
		t.Fatalf("alice list jobs: %v", err)
	}
	testutil.AssertEqualsInt(t, "alice jobs", 1, len(aliceJobs.Jobs))
	if len(aliceJobs.Jobs[0].Spec.Command) == 0 || aliceJobs.Jobs[0].Spec.Env["SECRET"] != "v" {
		t.Errorf("alice full job view must carry the command and env: %+v", aliceJobs.Jobs[0].Spec)
	}
}
