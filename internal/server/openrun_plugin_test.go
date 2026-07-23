// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

func TestGetSourceUrl(t *testing.T) {
	tests := []struct {
		url    string
		branch string
		want   string
	}{
		{
			url:    "github.com/openrundev/openrun/myapp",
			branch: "main",
			want:   "https://github.com/openrundev/openrun/tree/main/myapp/",
		},
		{
			url:    "https://github.com/openrundev/openrun/myapp",
			branch: "main",
			want:   "https://github.com/openrundev/openrun/tree/main/myapp/",
		},
		{
			url:    "https://github.com/openrundev/openrun/myapp",
			branch: "main",
			want:   "https://github.com/openrundev/openrun/tree/main/myapp/",
		},
		{
			url:    "/openrundev/openrun/myapp",
			branch: "main",
			want:   "",
		},
		{
			url:    "git@github.com/openrundev/openrun.git/myapp/t1/t2",
			branch: "develop",
			want:   "",
		},
		{
			url:    "git@github.com:openrundev/openrun.git/myapp/t1/t2",
			branch: "develop",
			want:   "",
		},
		{
			url:    "github.com/openrundev",
			branch: "main",
			want:   "",
		},
		{
			url:    "https://github.com/openrundev/openrun/myapp",
			branch: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		testutil.AssertEqualsString(t, tt.url, tt.want, getSourceUrl(tt.url, tt.branch))
	}
}

func TestListAllAppsBreadcrumbGlobsCoverDisplayedBreadcrumbs(t *testing.T) {
	now := time.Now()
	apps := []types.AppInfo{
		{
			AppPathDomain: types.AppPathDomain{Domain: "counter.utils.demo.clace.io", Path: "/"},
			Name:          "Counter",
			Id:            types.ID_PREFIX_APP_PROD + "counter",
			Auth:          types.AppAuthnDefault,
			UpdateTime:    now,
		},
		{
			AppPathDomain: types.AppPathDomain{Domain: "counter.utils.demo.clace.io", Path: "/" + types.STAGE_SUFFIX},
			Name:          "Counter stage",
			Id:            types.ID_PREFIX_APP_STAGE + "counter",
			MainApp:       types.ID_PREFIX_APP_PROD + "counter",
			LinkedAppPath: "counter.utils.demo.clace.io:/",
			Auth:          types.AppAuthnDefault,
			UpdateTime:    now,
		},
	}
	staticConfig := &types.ServerConfig{
		System: types.SystemConfig{DefaultDomain: "utils.demo.clace.io"},
		Http:   types.HttpConfig{Port: 80},
	}
	rbacManager, err := rbac.NewRBACHandler(testutil.TestLogger(), &types.RBACConfig{Enabled: false}, staticConfig)
	if err != nil {
		t.Fatalf("new rbac manager: %v", err)
	}
	server := &Server{
		apps:         &AppStore{allApps: apps},
		staticConfig: staticConfig,
		rbacManager:  rbacManager,
	}

	got, err := (&openrunPlugin{server: server}).ListAllApps(
		&starlark.Thread{Name: "test"},
		nil,
		starlark.Tuple{starlark.String(""), starlark.String(""), starlark.Bool(true)},
		nil,
	)
	if err != nil {
		t.Fatalf("list all apps: %v", err)
	}

	list, ok := got.(*starlark.List)
	if !ok {
		t.Fatalf("result type = %T, want *starlark.List", got)
	}
	var foundStage bool
	for i := 0; i < list.Len(); i++ {
		app, ok := list.Index(i).(*starlark.Dict)
		if !ok {
			t.Fatalf("app %d type = %T, want *starlark.Dict", i, list.Index(i))
		}
		pathSplit := dictList(t, app, "path_split")
		pathSplitGlob := dictList(t, app, "path_split_glob")
		if pathSplitGlob.Len() < pathSplit.Len() {
			t.Fatalf("app %d path_split_glob length = %d, want at least path_split length %d", i, pathSplitGlob.Len(), pathSplit.Len())
		}

		idValue, _, err := app.Get(starlark.String("id"))
		if err != nil {
			t.Fatalf("get app id: %v", err)
		}
		if string(idValue.(starlark.String)) != types.ID_PREFIX_APP_STAGE+"counter" {
			continue
		}
		foundStage = true
		testutil.AssertEqualsInt(t, "stage path_split length", 2, pathSplit.Len())
		testutil.AssertEqualsString(t, "stage path_split domain", "counter.utils.demo.clace.io", string(pathSplit.Index(0).(starlark.String)))
		testutil.AssertEqualsString(t, "stage path_split path", "/"+types.STAGE_SUFFIX, string(pathSplit.Index(1).(starlark.String)))
		testutil.AssertEqualsString(t, "stage domain glob", "counter.utils.demo.clace.io:**", string(pathSplitGlob.Index(0).(starlark.String)))
		testutil.AssertEqualsString(t, "stage path glob", "counter.utils.demo.clace.io:/", string(pathSplitGlob.Index(1).(starlark.String)))
	}
	if !foundStage {
		t.Fatal("stage app not returned")
	}
}

func dictList(t *testing.T, dict *starlark.Dict, key string) *starlark.List {
	t.Helper()
	value, ok, err := dict.Get(starlark.String(key))
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	if !ok {
		t.Fatalf("missing %s", key)
	}
	list, ok := value.(*starlark.List)
	if !ok {
		t.Fatalf("%s type = %T, want *starlark.List", key, value)
	}
	return list
}

func pluginKwargs(values ...starlark.Value) []starlark.Tuple {
	ret := make([]starlark.Tuple, 0, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		ret = append(ret, starlark.Tuple{values[i], values[i+1]})
	}
	return ret
}

func TestOpenRunPluginManagementReads(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	home := t.TempDir()
	t.Setenv("OPENRUN_HOME", home)
	server.staticConfig.Http.Port = 8080
	server.staticConfig.GitAuth = map[string]types.GitAuthEntry{"zeta": {}, "alpha": {}}
	server.staticConfig.Auth = map[string]types.AuthConfig{"oauth_test": {}}
	server.staticConfig.SAML = map[string]types.SAMLConfig{"corp": {}}
	server.staticConfig.ClientAuth = map[string]types.ClientCertConfig{"cert_team": {}, "ignored": {}}

	if err := server.initAuditDB("sqlite:" + filepath.Join(t.TempDir(), "audit.db")); err != nil {
		t.Fatalf("init audit db: %v", err)
	}
	defer func() {
		server.stopAuditWriter()
		_ = server.auditDB.Close()
	}()
	initOpenRunPlugin(server)
	c := &openrunPlugin{server: server}
	thread := &starlark.Thread{Name: "openrun-plugin-coverage"}
	thread.SetLocal(types.TL_CONTEXT, context.WithValue(ctx, types.USER_ID, "reader"))

	applyPath := filepath.Join(t.TempDir(), "app.ace")
	writeSyncApplyFile(t, applyPath, "/apps/plugin-coverage")
	if _, _, err := server.Apply(system.WithTrustedOperation(ctx), types.Transaction{}, applyPath, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply app: %v", err)
	}
	server.apps.ResetAllAppCache()

	allValue, err := c.ListApps(thread, nil, nil, pluginKwargs(
		starlark.String("query"), starlark.String("syncApp"),
		starlark.String("path"), starlark.String("/apps/**"),
		starlark.String("include_internal"), starlark.Bool(true),
	))
	if err != nil {
		t.Fatalf("list apps: %v", err)
	}
	if allValue.(*starlark.List).Len() == 0 {
		t.Fatal("list_apps returned no apps")
	}
	if value, err := c.ListApps(thread, nil, nil, pluginKwargs(
		starlark.String("sync_id"), starlark.String("missing-sync"),
	)); err != nil || value.(*starlark.List).Len() != 0 {
		t.Fatalf("sync filtered apps = %v, %v", value, err)
	}

	appValue, err := c.GetApp(thread, nil, starlark.Tuple{starlark.String("/apps/plugin-coverage")}, nil)
	if err != nil {
		t.Fatalf("get app: %v", err)
	}
	appDict := appValue.(*starlark.Dict)
	if name, found, _ := appDict.Get(starlark.String("name")); !found || string(name.(starlark.String)) != "syncApp" {
		t.Fatalf("get_app name = %v, found=%v", name, found)
	}
	if _, err := c.GetApp(thread, nil, starlark.Tuple{starlark.String("/apps/missing")}, nil); err == nil {
		t.Fatal("get_app accepted a missing app")
	}
	if value, err := c.ListVersions(thread, nil,
		starlark.Tuple{starlark.String("/apps/plugin-coverage")}, nil); err != nil || value == nil {
		t.Fatalf("list versions = %v, %v", value, err)
	}
	if value, err := c.ListVersionFiles(thread, nil,
		starlark.Tuple{starlark.String("/apps/plugin-coverage")}, nil); err != nil || value == nil {
		t.Fatalf("list version files = %v, %v", value, err)
	}
	if value, err := c.GetVersionZip(thread, nil,
		starlark.Tuple{starlark.String("/apps/plugin-coverage")}, nil); err != nil || value == nil {
		t.Fatalf("get version zip = %v, %v", value, err)
	}

	customSpecs := filepath.Join(home, "config", APPSPECS)
	if err := os.MkdirAll(filepath.Join(customSpecs, "custom"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(customSpecs, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	specsValue, err := c.ListSpecs(thread, nil, nil, nil)
	if err != nil {
		t.Fatalf("list specs: %v", err)
	}
	specs := []string{}
	for i := 0; i < specsValue.(*starlark.List).Len(); i++ {
		specs = append(specs, string(specsValue.(*starlark.List).Index(i).(starlark.String)))
	}
	if !slices.Contains(specs, "custom") || slices.Contains(specs, ".git") {
		t.Fatalf("specs = %v", specs)
	}

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	service := &types.Service{
		Id: types.ID_PREFIX_SERVICE + "plugin", Name: "primary", ServiceType: "test",
		IsDefault: true, Config: map[string]string{"password": "redacted", "host": "localhost"},
	}
	if err := db.CreateService(ctx, tx, service); err != nil {
		tx.Rollback() //nolint:errcheck
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if value, err := c.ListServices(thread, nil, nil, nil); err != nil || value.(*starlark.List).Len() != 1 {
		t.Fatalf("list services = %v, %v", value, err)
	}
	if value, err := c.ListBindings(thread, nil, nil, nil); err != nil || value.(*starlark.List).Len() != 0 {
		t.Fatalf("list bindings = %v, %v", value, err)
	}
	if value, err := c.ListSync(thread, nil, nil, nil); err != nil || value.(*starlark.List).Len() != 0 {
		t.Fatalf("list sync = %v, %v", value, err)
	}
	if value, err := c.GetPermissions(thread, nil,
		starlark.Tuple{starlark.String("/apps/plugin-coverage")}, nil); err != nil || value.(*starlark.List).Len() == 0 {
		t.Fatalf("get permissions = %v, %v", value, err)
	}
	if value, err := c.SystemPluginsAllowed(thread, nil, nil, nil); err != nil || value == nil {
		t.Fatalf("system plugins allowed = %v, %v", value, err)
	}
	if value, err := c.ListAuths(thread, nil, nil, nil); err != nil || value.(*starlark.List).Len() < 6 {
		t.Fatalf("list auths = %v, %v", value, err)
	}
	if value, err := c.ListGitAuths(thread, nil, nil, nil); err != nil || value.(*starlark.List).Len() != 2 {
		t.Fatalf("list git auths = %v, %v", value, err)
	}

	server.staticConfig.System.ContainerCommand = types.CONTAINER_KUBERNETES
	if value, err := c.ListContainers(thread, nil, nil, pluginKwargs(
		starlark.String("type"), starlark.String("agent"),
	)); err != nil || value.(*starlark.List).Len() != 0 {
		t.Fatalf("list agent containers = %v, %v", value, err)
	}
	server.staticConfig.System.ContainerCommand = ""
	if value, err := c.ListContainers(thread, nil, nil, pluginKwargs(
		starlark.String("type"), starlark.String("kaniko"),
	)); err != nil || value.(*starlark.List).Len() != 0 {
		t.Fatalf("list kaniko containers = %v, %v", value, err)
	}
	if _, err := c.ListContainers(thread, nil, nil, pluginKwargs(
		starlark.String("type"), starlark.String("invalid"),
	)); err == nil || !strings.Contains(err.Error(), "invalid list_containers") {
		t.Fatalf("invalid container type error = %v", err)
	}
	if value, err := c.KubernetesStats(thread, nil, nil, nil); err != nil || value == nil {
		t.Fatalf("kubernetes stats = %v, %v", value, err)
	}
}

func TestOpenRunPluginAuditQueries(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	if err := server.initAuditDB("sqlite:" + filepath.Join(t.TempDir(), "audit.db")); err != nil {
		t.Fatalf("init audit db: %v", err)
	}
	defer func() {
		server.stopAuditWriter()
		_ = server.auditDB.Close()
	}()
	c := &openrunPlugin{server: server}
	thread := &starlark.Thread{Name: "openrun-audit-coverage"}
	thread.SetLocal(types.TL_CONTEXT, ctx)

	now := time.Now()
	if _, err := server.auditDB.Exec(
		"insert into audit (rid, app_id, create_time, user_id, event_type, operation, target, status, detail) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"rid_plugin", string(types.ID_PREFIX_APP_DEV)+"unknown", now.UnixNano(), "reader", "custom",
		"reload_apps", "/apps/plugin", "success", "coverage detail"); err != nil {
		t.Fatal(err)
	}
	value, err := c.ListAuditEvents(thread, nil, nil, pluginKwargs(
		starlark.String("user_id"), starlark.String("reader"),
		starlark.String("event_type"), starlark.String("custom"),
		starlark.String("operation"), starlark.String("reload_apps"),
		starlark.String("target"), starlark.String("/apps/plugin"),
		starlark.String("status"), starlark.String("success"),
		starlark.String("start_date"), starlark.String(now.Add(-24*time.Hour).Format("2006-01-02")),
		starlark.String("end_date"), starlark.String(now.Format("2006-01-02")),
		starlark.String("rid"), starlark.String("rid_plugin"),
		starlark.String("detail"), starlark.String("coverage detail"),
		starlark.String("limit"), starlark.MakeInt(10),
	))
	if err != nil || value.(*starlark.List).Len() != 1 {
		t.Fatalf("list audit events = %v, %v", value, err)
	}
	if _, err := c.ListAuditEvents(thread, nil, nil, pluginKwargs(
		starlark.String("start_date"), starlark.String(""),
		starlark.String("before_timestamp"), starlark.String("invalid"),
	)); err == nil || !strings.Contains(err.Error(), "before_timestamp") {
		t.Fatalf("invalid before timestamp error = %v", err)
	}
	if _, err := c.ListAuditEvents(thread, nil, nil, pluginKwargs(
		starlark.String("start_date"), starlark.String(""),
		starlark.String("limit"), starlark.MakeInt(0),
	)); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("invalid limit error = %v", err)
	}

	operations, err := c.ListOperations(thread, nil, nil, nil)
	if err != nil || operations.(*starlark.List).Len() < 20 {
		t.Fatalf("list operations = %v, %v", operations, err)
	}
	for _, test := range []struct {
		operation string
		want      int
	}{
		{"reload_apps", 4},
		{"approve_apps", 4},
		{"promote_apps", 5},
		{"update_metadata", 2},
		{"param_update", 2},
		{"other", 1},
	} {
		values, placeholders := getOpList(test.operation)
		if len(values) != test.want || strings.Count(placeholders, "?") != test.want {
			t.Errorf("getOpList(%q) = %v, %q", test.operation, values, placeholders)
		}
	}
}
