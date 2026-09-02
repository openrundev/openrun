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
	sdk "github.com/openrundev/openrun/pkg/plugin"
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

// pluginCall builds an SDK call the way the local dispatch would: positional
// args, then alternating kwarg name/value pairs.
func pluginCall(userId string, args []any, kwargs ...any) *sdk.Call {
	call := &sdk.Call{Args: args, Session: sdk.NewSession("test"), Thread: sdk.ThreadState{UserId: userId}}
	for i := 0; i < len(kwargs); i += 2 {
		call.Kwargs = append(call.Kwargs, sdk.Kwarg{Name: kwargs[i].(string), Value: kwargs[i+1]})
	}
	return call
}

func valueList(t *testing.T, v any, what string) []any {
	t.Helper()
	list, ok := v.([]any)
	if !ok {
		t.Fatalf("%s type = %T, want []any", what, v)
	}
	return list
}

func stringList(t *testing.T, v any, what string) []string {
	t.Helper()
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, len(x))
		for i, item := range x {
			s, ok := item.(string)
			if !ok {
				t.Fatalf("%s element %d type = %T, want string", what, i, item)
			}
			out[i] = s
		}
		return out
	default:
		t.Fatalf("%s type = %T, want string list", what, v)
		return nil
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
	staticConfig.Security.UnsafeDisableRBAC = true // listing is unfiltered in this test
	rbacManager, err := rbac.NewRBACHandler(testutil.TestLogger(), &types.RBACConfig{}, staticConfig)
	if err != nil {
		t.Fatalf("new rbac manager: %v", err)
	}
	server := &Server{
		apps:         &AppStore{allApps: apps},
		staticConfig: staticConfig,
		rbacManager:  rbacManager,
	}

	got, err := (&openrunPlugin{server: server}).ListAllApps(context.Background(),
		pluginCall("", []any{"", "", true}))
	if err != nil {
		t.Fatalf("list all apps: %v", err)
	}

	list := valueList(t, got, "result")
	var foundStage bool
	for i, item := range list {
		appEntry, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("app %d type = %T, want map[string]any", i, item)
		}
		pathSplit := stringList(t, appEntry["path_split"], "path_split")
		pathSplitGlob := stringList(t, appEntry["path_split_glob"], "path_split_glob")
		if len(pathSplitGlob) < len(pathSplit) {
			t.Fatalf("app %d path_split_glob length = %d, want at least path_split length %d", i, len(pathSplitGlob), len(pathSplit))
		}

		if appEntry["id"] != string(types.ID_PREFIX_APP_STAGE)+"counter" {
			continue
		}
		foundStage = true
		testutil.AssertEqualsInt(t, "stage path_split length", 2, len(pathSplit))
		testutil.AssertEqualsString(t, "stage path_split domain", "counter.utils.demo.clace.io", pathSplit[0])
		testutil.AssertEqualsString(t, "stage path_split path", "/"+types.STAGE_SUFFIX, pathSplit[1])
		testutil.AssertEqualsString(t, "stage domain glob", "counter.utils.demo.clace.io:**", pathSplitGlob[0])
		testutil.AssertEqualsString(t, "stage path glob", "counter.utils.demo.clace.io:/", pathSplitGlob[1])
	}
	if !foundStage {
		t.Fatal("stage app not returned")
	}
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
	readerCtx := context.WithValue(ctx, types.USER_ID, "reader")

	applyPath := filepath.Join(t.TempDir(), "app.ace")
	writeSyncApplyFile(t, applyPath, "/apps/plugin-coverage")
	if _, _, err := server.Apply(system.WithTrustedOperation(ctx), types.Transaction{}, applyPath, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply app: %v", err)
	}
	server.apps.ResetAllAppCache()

	allValue, err := c.ListApps(readerCtx, pluginCall("reader", nil,
		"query", "syncApp",
		"path", "/apps/**",
		"include_internal", true,
	))
	if err != nil {
		t.Fatalf("list apps: %v", err)
	}
	if len(valueList(t, allValue, "list_apps")) == 0 {
		t.Fatal("list_apps returned no apps")
	}
	if value, err := c.ListApps(readerCtx, pluginCall("reader", nil,
		"sync_id", "missing-sync",
	)); err != nil || len(valueList(t, value, "list_apps sync")) != 0 {
		t.Fatalf("sync filtered apps = %v, %v", value, err)
	}

	appValue, err := c.GetApp(readerCtx, pluginCall("reader", []any{"/apps/plugin-coverage"}))
	if err != nil {
		t.Fatalf("get app: %v", err)
	}
	appDict, ok := appValue.(map[string]any)
	if !ok {
		t.Fatalf("get_app type = %T, want map[string]any", appValue)
	}
	if appDict["name"] != "syncApp" {
		t.Fatalf("get_app name = %v", appDict["name"])
	}
	if _, err := c.GetApp(readerCtx, pluginCall("reader", []any{"/apps/missing"})); err == nil {
		t.Fatal("get_app accepted a missing app")
	}
	if value, err := c.ListVersions(readerCtx, pluginCall("reader", []any{"/apps/plugin-coverage"})); err != nil || value == nil {
		t.Fatalf("list versions = %v, %v", value, err)
	}
	if value, err := c.ListVersionFiles(readerCtx, pluginCall("reader", []any{"/apps/plugin-coverage"})); err != nil || value == nil {
		t.Fatalf("list version files = %v, %v", value, err)
	}
	if value, err := c.GetVersionZip(readerCtx, pluginCall("reader", []any{"/apps/plugin-coverage"})); err != nil || value == nil {
		t.Fatalf("get version zip = %v, %v", value, err)
	}

	customSpecs := filepath.Join(home, "config", APPSPECS)
	if err := os.MkdirAll(filepath.Join(customSpecs, "custom"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(customSpecs, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	specsValue, err := c.ListSpecs(readerCtx, pluginCall("reader", nil))
	if err != nil {
		t.Fatalf("list specs: %v", err)
	}
	specs := stringList(t, specsValue, "specs")
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
	if value, err := c.ListServices(readerCtx, pluginCall("reader", nil)); err != nil || len(valueList(t, value, "services")) != 1 {
		t.Fatalf("list services = %v, %v", value, err)
	}
	if value, err := c.ListBindings(readerCtx, pluginCall("reader", nil)); err != nil || len(valueList(t, value, "bindings")) != 0 {
		t.Fatalf("list bindings = %v, %v", value, err)
	}
	if value, err := c.ListSync(readerCtx, pluginCall("reader", nil)); err != nil || len(valueList(t, value, "sync")) != 0 {
		t.Fatalf("list sync = %v, %v", value, err)
	}
	if value, err := c.GetPermissions(readerCtx, pluginCall("reader", []any{"/apps/plugin-coverage"})); err != nil || len(stringList(t, value, "permissions")) == 0 {
		t.Fatalf("get permissions = %v, %v", value, err)
	}
	if value, err := c.SystemPluginsAllowed(readerCtx, pluginCall("reader", nil)); err != nil || value == nil {
		t.Fatalf("system plugins allowed = %v, %v", value, err)
	}
	if value, err := c.ListAuths(readerCtx, pluginCall("reader", nil)); err != nil || len(stringList(t, value, "auths")) < 6 {
		t.Fatalf("list auths = %v, %v", value, err)
	}
	// list_git_auths returns the sorted entry names plus the default entry
	server.staticConfig.Security.DefaultGitAuth = "alpha"
	if value, err := c.ListGitAuths(readerCtx, pluginCall("reader", nil)); err != nil {
		t.Fatalf("list git auths = %v, %v", value, err)
	} else {
		gitAuths, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("git auths type = %T", value)
		}
		entries := stringList(t, gitAuths["entries"], "git auth entries")
		if !slices.Equal(entries, []string{"alpha", "zeta"}) || gitAuths["default"] != "alpha" {
			t.Fatalf("list git auths entries = %v, default = %v", entries, gitAuths["default"])
		}
	}

	server.staticConfig.System.ContainerCommand = types.CONTAINER_KUBERNETES
	if value, err := c.ListContainers(readerCtx, pluginCall("reader", nil,
		"type", "agent",
	)); err != nil || len(valueList(t, value, "agent containers")) != 0 {
		t.Fatalf("list agent containers = %v, %v", value, err)
	}
	server.staticConfig.System.ContainerCommand = ""
	if value, err := c.ListContainers(readerCtx, pluginCall("reader", nil,
		"type", "kaniko",
	)); err != nil || len(valueList(t, value, "kaniko containers")) != 0 {
		t.Fatalf("list kaniko containers = %v, %v", value, err)
	}
	if _, err := c.ListContainers(readerCtx, pluginCall("reader", nil,
		"type", "invalid",
	)); err == nil || !strings.Contains(err.Error(), "invalid list_containers") {
		t.Fatalf("invalid container type error = %v", err)
	}
	if value, err := c.KubernetesStats(readerCtx, pluginCall("reader", nil)); err != nil || value == nil {
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

	now := time.Now()
	if _, err := server.auditDB.Exec(
		"insert into audit (rid, app_id, create_time, user_id, event_type, operation, target, status, detail) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"rid_plugin", string(types.ID_PREFIX_APP_DEV)+"unknown", now.UnixNano(), "reader", "custom",
		"reload_apps", "/apps/plugin", "success", "coverage detail"); err != nil {
		t.Fatal(err)
	}
	value, err := c.ListAuditEvents(ctx, pluginCall("reader", nil,
		"user_id", "reader",
		"event_type", "custom",
		"operation", "reload_apps",
		"target", "/apps/plugin",
		"status", "success",
		// The audit date filters are UTC days (sqlite strftime and postgres
		// EXTRACT both read the bare date as UTC midnight), so the filter
		// dates must come from the UTC clock: using the local date makes the
		// end_date filter exclude the event whenever the local date is behind
		// the UTC date (e.g. evenings in UTC-7)
		"start_date", now.UTC().Add(-24*time.Hour).Format("2006-01-02"),
		"end_date", now.UTC().Format("2006-01-02"),
		"rid", "rid_plugin",
		"detail", "coverage detail",
		"limit", int64(10),
	))
	if err != nil || len(valueList(t, value, "audit events")) != 1 {
		t.Fatalf("list audit events = %v, %v", value, err)
	}
	if _, err := c.ListAuditEvents(ctx, pluginCall("reader", nil,
		"start_date", "",
		"before_timestamp", "invalid",
	)); err == nil || !strings.Contains(err.Error(), "before_timestamp") {
		t.Fatalf("invalid before timestamp error = %v", err)
	}
	if _, err := c.ListAuditEvents(ctx, pluginCall("reader", nil,
		"start_date", "",
		"limit", int64(0),
	)); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("invalid limit error = %v", err)
	}

	operations, err := c.ListOperations(ctx, pluginCall("reader", nil))
	if err != nil || len(stringList(t, operations, "operations")) < 20 {
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
