// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	app_test "github.com/openrundev/openrun/internal/app/tests"
	"github.com/openrundev/openrun/internal/builder"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func TestMarkerBlockUpsertAndRemove(t *testing.T) {
	manual := "# manual header\napp(\"Hand Made\", \"/manual\", \"/src/manual\")\n"

	content, err := upsertMarkerBlock(manual, "/teams/pto", "app(\"PTO\", \"/teams/pto\", \"repo/apps/pto\")")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(content, manual) {
		t.Fatalf("manual content modified:\n%s", content)
	}
	if !strings.Contains(content, builderMarkerBegin+"/teams/pto\napp(\"PTO\"") {
		t.Fatalf("block not inserted:\n%s", content)
	}

	// republish replaces the block in place, not appends
	updated, err := upsertMarkerBlock(content, "/teams/pto", "app(\"PTO v2\", \"/teams/pto\", \"repo/apps/pto\")")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(updated, builderMarkerBegin+"/teams/pto") != 1 {
		t.Fatalf("expected one block after republish:\n%s", updated)
	}
	if !strings.Contains(updated, "PTO v2") || strings.Contains(updated, "\"PTO\",") {
		t.Fatalf("stanza not replaced:\n%s", updated)
	}

	// a second app gets its own block; removing the first keeps the second
	twoApps, err := upsertMarkerBlock(updated, "/tools/crm", "app(\"CRM\", \"/tools/crm\", \"repo/apps/crm\")")
	if err != nil {
		t.Fatal(err)
	}
	removed, found, err := removeMarkerBlock(twoApps, "/teams/pto")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("block for /teams/pto not found")
	}
	if strings.Contains(removed, "/teams/pto") || !strings.Contains(removed, "/tools/crm") {
		t.Fatalf("wrong block removed:\n%s", removed)
	}
	if !strings.HasPrefix(removed, manual) {
		t.Fatalf("manual content modified on remove:\n%s", removed)
	}

	// removing an absent block reports not found, no error
	_, found, err = removeMarkerBlock(removed, "/absent")
	if err != nil || found {
		t.Fatalf("expected not found without error, got found=%v err=%v", found, err)
	}
}

func TestMarkerBlockBrokenMarkers(t *testing.T) {
	// begin without end must error, not guess
	broken := builderMarkerBegin + "/teams/pto\napp(...)\n# no end marker\n"
	if _, err := upsertMarkerBlock(broken, "/teams/pto", "app(2)"); err == nil {
		t.Fatal("expected error for begin marker without end")
	}
	if _, _, err := removeMarkerBlock(broken, "/teams/pto"); err == nil {
		t.Fatal("expected error for begin marker without end")
	}
}

func TestMarkerBlockPathPrefixNoCollision(t *testing.T) {
	// /teams/pto must not match /teams/pto2's markers
	content, err := upsertMarkerBlock("", "/teams/pto2", "app(\"Other\", \"/teams/pto2\", \"repo/apps/pto2\")")
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := removeMarkerBlock(content, "/teams/pto")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("/teams/pto matched /teams/pto2's block")
	}
}

func TestBuilderSourceZip(t *testing.T) {
	workspace := t.TempDir()
	writeFile := func(rel, content string) {
		t.Helper()
		full := filepath.Join(workspace, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("app.star", "app = 1")
	writeFile("static/style.css", "body {}")
	writeFile(".git/config", "excluded")
	writeFile("node_modules/pkg/index.js", "excluded")
	writeFile(".opencode/state", "excluded")

	var buf bytes.Buffer
	if err := writeBuilderSourceZip(workspace, &buf); err != nil {
		t.Fatal(err)
	}
	zipContent := buf.Bytes()
	reader, err := zip.NewReader(bytes.NewReader(zipContent), int64(len(zipContent)))
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, f := range reader.File {
		got[f.Name] = true
	}
	for _, want := range []string{"app.star", "static/style.css"} {
		if !got[want] {
			t.Errorf("zip is missing %s, has %v", want, got)
		}
	}
	if len(got) != 2 {
		t.Errorf("zip has unexpected entries (vcs/agent dirs must be excluded): %v", got)
	}

	content, err := reader.Open("app.star")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(content)
	content.Close() //nolint:errcheck
	if string(data) != "app = 1" {
		t.Errorf("app.star content %q", data)
	}
}

// TestBuilderSourceName verifies the published source directory name is
// unique per full publish target: base-name collisions (/teams/a vs
// /other/a) or the same path on two domains must map to different dirs
func TestBuilderSourceName(t *testing.T) {
	tests := []struct{ domain, path, want string }{
		{"", "/app", "app"},
		{"", "/teams/a", "teams_a"},
		{"", "/other/a", "other_a"},
		{"example.com", "/teams/app", "example.com_teams_app"},
		{"other.example.com", "/teams/app", "other.example.com_teams_app"},
		{"Example.com", "/Teams/MyApp", "example.com_teams_myapp"},
	}
	seen := map[string]string{}
	for _, tt := range tests {
		target := types.AppPathDomain{Domain: tt.domain, Path: tt.path}
		got := builderSourceName(target)
		if got != tt.want {
			t.Errorf("builderSourceName(%s): got %q, want %q", target.String(), got, tt.want)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("source name %q collides: %s and %s", got, prev, target.String())
		}
		seen[got] = target.String()
	}
}

func TestBuilderZipName(t *testing.T) {
	cases := map[string]string{
		"my app":        "my-app-source.zip",
		"Pets/Tracker!": "Pets-Tracker-source.zip",
		"   ":           "builder-app-source.zip",
		"a.b_c-d":       "a.b_c-d-source.zip",
	}
	for in, want := range cases {
		if got := builderZipName(in); got != want {
			t.Errorf("builderZipName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateProfilePublish(t *testing.T) {
	valid := [][2]string{
		{"", ""},
		{"subdomain", "apps.example.com"},
		{"subdomain", "."},
		{"subdomain", "apps."},
		{"path", "/teams"},
		{"glob", "/teams/*"},
		{"glob", "example.com:/**"},
	}
	for _, pair := range valid {
		if err := validateProfilePublish(pair[0], pair[1]); err != nil {
			t.Errorf("mode %q target %q: unexpected error %v", pair[0], pair[1], err)
		}
	}
	invalid := [][2]string{
		{"", "/teams"},            // target without a mode
		{"subdomain", ""},         // missing target
		{"subdomain", "a.com:/x"}, // domain only
		{"path", "teams"},         // must start with /
		{"path", "/teams/*"},      // glob syntax in path mode
		{"glob", ""},              // missing target
		{"glob", "/teams/[x"},     // bad glob
		{"somewhere", "/teams"},   // unknown mode
	}
	for _, pair := range invalid {
		if err := validateProfilePublish(pair[0], pair[1]); err == nil {
			t.Errorf("mode %q target %q: expected an error", pair[0], pair[1])
		}
	}
}

func TestBuilderCheckProfileTarget(t *testing.T) {
	s := &Server{staticConfig: &types.ServerConfig{}}
	s.staticConfig.System.DefaultDomain = "example.com"

	check := func(mode, target, path string) error {
		profile := &types.BuilderProfileConfig{Agent: "opencode", PublishMode: mode, PublishTarget: target}
		appPathDomain, err := parseAppPath(path)
		if err != nil {
			t.Fatalf("parse %q: %v", path, err)
		}
		return s.builderCheckProfileTarget("prof", profile, appPathDomain)
	}

	// No mode: anywhere
	if err := check("", "", "/anywhere"); err != nil {
		t.Errorf("empty mode: %v", err)
	}

	// Subdomain: label under the target domain, path must be /
	if err := check("subdomain", "apps.example.com", "my-app.apps.example.com:/"); err != nil {
		t.Errorf("subdomain ok case: %v", err)
	}
	// trailing dot appends the default domain; "." alone is the default domain
	if err := check("subdomain", "apps.", "my-app.apps.example.com:/"); err != nil {
		t.Errorf("subdomain trailing dot: %v", err)
	}
	if err := check("subdomain", ".", "my-app.example.com:/"); err != nil {
		t.Errorf("subdomain of default domain: %v", err)
	}
	for _, bad := range []string{"/plain-path", "apps.example.com:/", "my-app.other.com:/",
		"my-app.apps.example.com:/sub"} {
		if err := check("subdomain", "apps.example.com", bad); err == nil {
			t.Errorf("subdomain: expected rejection of %q", bad)
		}
	}

	// Path prefix: no domain, path under the prefix
	if err := check("path", "/teams", "/teams/my-app"); err != nil {
		t.Errorf("path ok case: %v", err)
	}
	for _, bad := range []string{"/teamsother/x", "/other/my-app", "d.com:/teams/x"} {
		if err := check("path", "/teams", bad); err == nil {
			t.Errorf("path: expected rejection of %q", bad)
		}
	}

	// Glob: full match required
	if err := check("glob", "/teams/*", "/teams/my-app"); err != nil {
		t.Errorf("glob ok case: %v", err)
	}
	if err := check("glob", "/teams/*", "/other/my-app"); err == nil {
		t.Error("glob: expected rejection outside the glob")
	}
}

func TestBuilderSubdomainLabelValidation(t *testing.T) {
	s := &Server{staticConfig: &types.ServerConfig{}}
	s.staticConfig.System.DefaultDomain = "example.com"
	profile := &types.BuilderProfileConfig{Agent: "opencode", PublishMode: "subdomain", PublishTarget: "."}
	for _, bad := range []string{"some/path", "UPPER", "-lead", "trail-", "a_b", "dot..dot"} {
		appPathDomain := types.AppPathDomain{Domain: bad + ".example.com", Path: "/"}
		if err := s.builderCheckProfileTarget("prof", profile, appPathDomain); err == nil {
			t.Errorf("expected rejection of subdomain label %q", bad)
		}
	}
	for _, good := range []string{"my-app", "a", "team.my-app"} {
		appPathDomain := types.AppPathDomain{Domain: good + ".example.com", Path: "/"}
		if err := s.builderCheckProfileTarget("prof", profile, appPathDomain); err != nil {
			t.Errorf("subdomain label %q: %v", good, err)
		}
	}
}

func TestBuilderResolvePath(t *testing.T) {
	s := &Server{staticConfig: &types.ServerConfig{}}
	s.staticConfig.System.DefaultDomain = "example.com"

	resolved, pathDomain, err := s.builderResolvePath("my-app.:/")
	if err != nil || resolved != "my-app.example.com:/" || pathDomain.Domain != "my-app.example.com" {
		t.Errorf("relative domain not resolved: %q %+v %v", resolved, pathDomain, err)
	}
	resolved, _, err = s.builderResolvePath("my-app.other.com:/")
	if err != nil || resolved != "my-app.other.com:/" {
		t.Errorf("absolute domain changed: %q %v", resolved, err)
	}
	resolved, _, err = s.builderResolvePath("/plain/path")
	if err != nil || resolved != "/plain/path" {
		t.Errorf("plain path changed: %q %v", resolved, err)
	}
}

// TestBuilderFirstPublishConflicts: a FIRST publish is rejected when an app
// already exists at the target or the local source folder does; a republish
// to the session's own path skips both checks. Relative (trailing ".")
// domains are preserved in the returned path but resolved for the checks
func TestBuilderFirstPublishConflicts(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	server.staticConfig.System.DefaultDomain = "example.com"

	// Create an app at /apps/taken (trusted, no RBAC)
	applyPath := filepath.Join(t.TempDir(), "app.ace")
	writeSyncApplyFile(t, applyPath, "/apps/taken")
	if _, _, err := server.Apply(system.WithTrustedOperation(ctx), types.Transaction{}, applyPath, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	server.apps.ResetAllAppCache()

	session := &types.BuilderSession{Id: "bld_ses_x", Profile: ""}

	// First publish onto an existing app: rejected
	if _, _, err := server.builderCheckPublishPath(ctx, "/apps/taken", session); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected app-exists conflict, got %v", err)
	}
	// Republish to the session's own path: allowed
	session.PublishPath = "/apps/taken"
	if _, _, err := server.builderCheckPublishPath(ctx, "/apps/taken", session); err != nil {
		t.Fatalf("republish to own path rejected: %v", err)
	}
	session.PublishPath = ""

	// Local source folder conflict (publish root is $OPENRUN_HOME/app_src)
	home := t.TempDir()
	t.Setenv("OPENRUN_HOME", home)
	folder := filepath.Join(home, appSrcDir, builderSourceName(types.AppPathDomain{Path: "/apps/foldertaken"}))
	if err := os.MkdirAll(folder, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.builderCheckPublishPath(ctx, "/apps/foldertaken", session); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected folder conflict, got %v", err)
	}

	// A relative-domain target is preserved in the returned path (portable
	// apps.star declaration) while checks run against the resolved path
	publishPath, appPathDomain, err := server.builderCheckPublishPath(ctx, "my-app.:/", session)
	if err != nil {
		t.Fatalf("relative target: %v", err)
	}
	if publishPath != "my-app.:/" || appPathDomain.Domain != "my-app." {
		t.Fatalf("relative domain not preserved: %q %+v", publishPath, appPathDomain)
	}
}

func TestValidateProfileServices(t *testing.T) {
	for _, valid := range [][]string{nil, {}, {"defaults"}, {"postgres"}, {"postgres/main", "redis"}} {
		if err := validateProfileServices(valid); err != nil {
			t.Errorf("services %v: unexpected error %v", valid, err)
		}
	}
	for _, invalid := range [][]string{{"defaults", "postgres"}, {""}, {"a b"}, {"a/b/c"}} {
		if err := validateProfileServices(invalid); err == nil {
			t.Errorf("services %v: expected an error", invalid)
		}
	}
}

// TestBuilderStarlarkAPIs runs a real Starlark app which loads build.in and
// calls every builder plugin API. Read and download calls use a persisted
// detached session; operations requiring a live agent or preview exercise
// their validation paths without starting external processes.
func TestBuilderStarlarkAPIs(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	home := t.TempDir()
	t.Setenv("OPENRUN_HOME", home)
	workspaceRoot := filepath.Join(home, "builder-workspaces")
	workspace := filepath.Join(workspaceRoot, "bld_ses_starlarkapi1")
	if err := os.MkdirAll(filepath.Join(workspace, "static"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "app.star"), []byte("app = ace.app(\"fixture\")\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "static", "style.css"), []byte("body {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	server.staticConfig.AppBuilder.WorkspaceDir = workspaceRoot
	server.staticConfig.Security.UnsafeAgentWithoutSandbox = true
	if err := server.initBuilder(); err != nil {
		t.Fatalf("init builder: %v", err)
	}
	initBuilderPlugin(server)

	session := &types.BuilderSession{
		Id:           "bld_ses_starlarkapi1",
		UserID:       "builder-user",
		Name:         "Starlark Fixture",
		Agent:        "opencode",
		Status:       types.BuilderSessionDetached,
		WorkspaceDir: workspace,
		PublishPath:  "fixture.:/",
	}
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateBuilderSession(ctx, tx, session); err != nil {
		tx.Rollback() //nolint:errcheck
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	server.builderManager.LogActivity(session.Id, session.UserID, "lifecycle", "fixture ready",
		map[string]any{"source": "test"})

	source, err := os.ReadFile(filepath.Join("testdata", "builder_app", "app.star"))
	if err != nil {
		t.Fatal(err)
	}
	methods := []string{
		"list_sessions", "get_session", "get_messages", "session_events",
		"list_files", "read_file", "get_source_zip", "get_publish_config",
		"list_activity", "create_session", "send_message", "cancel_turn",
		"stop_session", "resume_session", "delete_session", "check_publish_path",
		"publish_app", "unpublish_app", "verify_config",
	}
	permissions := make([]types.Permission, 0, len(methods))
	for _, method := range methods {
		permissions = append(permissions, types.Permission{Plugin: "build.in", Method: method})
	}
	application, _, err := app_test.CreateTestAppPluginServerConfig(
		server.Logger,
		map[string]string{"app.star": string(source)},
		[]string{"build.in"},
		permissions,
		server.Config(),
	)
	if err != nil {
		t.Fatalf("create Starlark builder app: %v", err)
	}
	defer application.Close() //nolint:errcheck

	serve := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/test"+path, nil)
		req = req.WithContext(context.WithValue(req.Context(), types.USER_ID, session.UserID))
		response := httptest.NewRecorder()
		application.ServeHTTP(response, req)
		return response
	}
	decode := func(response *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		if response.Code != http.StatusOK {
			t.Fatalf("status %d: %s", response.Code, response.Body.String())
		}
		var value map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
			t.Fatalf("decode response %q: %v", response.Body.String(), err)
		}
		return value
	}

	reads := decode(serve("/reads"))
	if reads["session_count"] != float64(1) {
		t.Fatalf("session_count = %v, want 1", reads["session_count"])
	}
	sessionValue := reads["session"].(map[string]any)
	if sessionValue["id"] != session.Id || sessionValue["publish_path_resolved"] != "fixture.localhost:/" {
		t.Fatalf("unexpected session value: %#v", sessionValue)
	}
	files := make([]string, 0)
	for _, value := range reads["files"].([]any) {
		files = append(files, value.(string))
	}
	if !slices.Equal(files, []string{"app.star", filepath.Join("static", "style.css")}) {
		t.Fatalf("files = %v", files)
	}
	if reads["content"] != "app = ace.app(\"fixture\")\n" {
		t.Fatalf("content = %q", reads["content"])
	}
	checked := reads["checked"].(map[string]any)
	if checked["path"] != "/new-app" || checked["exists"] != false {
		t.Fatalf("unexpected publish-path check: %#v", checked)
	}
	messages := reads["messages"].(map[string]any)
	if messages["is_live"] != false || len(messages["messages"].([]any)) != 1 {
		t.Fatalf("unexpected messages: %#v", messages)
	}
	if len(reads["activity"].([]any)) != 1 {
		t.Fatalf("unexpected activity: %#v", reads["activity"])
	}

	eventResult := decode(serve("/events"))
	if !strings.Contains(eventResult["error"].(string), "no running sandbox") {
		t.Fatalf("unexpected event error: %#v", eventResult)
	}

	actions := decode(serve("/actions"))
	errorChecks := map[string]string{
		"create":    "app_builder is not enabled",
		"send":      "no running sandbox",
		"cancel":    "no running sandbox",
		"stop":      "no running sandbox",
		"resume":    "app_builder is not enabled",
		"publish":   "no preview app",
		"unpublish": "apps.star",
	}
	for name, want := range errorChecks {
		got, _ := actions[name].(string)
		if !strings.Contains(got, want) {
			t.Errorf("%s error = %q, want substring %q", name, got, want)
		}
	}
	checks := actions["checks"].([]any)
	if len(checks) != 1 || checks[0].(map[string]any)["name"] != "enabled" {
		t.Fatalf("unexpected verify checks: %#v", checks)
	}

	sourceResponse := serve("/source")
	if sourceResponse.Code != http.StatusOK {
		t.Fatalf("source status %d: %s", sourceResponse.Code, sourceResponse.Body.String())
	}
	zipReader, err := zip.NewReader(bytes.NewReader(sourceResponse.Body.Bytes()), int64(sourceResponse.Body.Len()))
	if err != nil {
		t.Fatalf("source response is not a zip: %v", err)
	}
	zipNames := make([]string, 0, len(zipReader.File))
	for _, file := range zipReader.File {
		zipNames = append(zipNames, file.Name)
	}
	if !slices.Equal(zipNames, []string{"app.star", "static/style.css"}) {
		t.Fatalf("zip files = %v", zipNames)
	}

	deleted := decode(serve("/delete"))
	if deleted["error"] != "" {
		t.Fatalf("delete error = %v", deleted["error"])
	}
	if _, err := db.GetBuilderSession(ctx, types.Transaction{}, session.Id); err == nil {
		t.Fatal("session still exists after Starlark delete_session")
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatalf("workspace still exists after delete: %v", err)
	}
}

func TestBuilderCreateSessionAndVerifyConfig(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	home := t.TempDir()
	t.Setenv("OPENRUN_HOME", home)
	dockerfile := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}
	missingAgent := filepath.Join(t.TempDir(), "missing-agent")
	server.staticConfig.AppBuilder.Enabled = true
	server.staticConfig.AppBuilder.WorkspaceDir = filepath.Join(home, "workspaces")
	server.staticConfig.Security.UnsafeAgentWithoutSandbox = true
	server.staticConfig.BuilderAgent = map[string]types.BuilderAgentConfig{
		"custom_coverage": {Dockerfile: dockerfile, Command: []string{missingAgent}},
	}
	server.staticConfig.BuilderProfile = map[string]types.BuilderProfileConfig{
		"coverage": {
			Agent:         "custom_coverage",
			Spec:          "coverage",
			PublishMode:   "invalid-mode",
			PublishTarget: "/apps",
		},
	}
	server.staticConfig.AppBuilder.DefaultBuilderProfile = "coverage"

	oldSpec, hadSpec := appTypes["coverage"]
	appTypes["coverage"] = types.SpecFiles{
		"app.star":         "app = ace.app(\"coverage\")\n",
		"static/style.css": "body {}\n",
	}
	defer func() {
		if hadSpec {
			appTypes["coverage"] = oldSpec
		} else {
			delete(appTypes, "coverage")
		}
	}()

	if err := server.initBuilder(); err != nil {
		t.Fatalf("init builder: %v", err)
	}
	if server.BuilderManager() == nil {
		t.Fatal("BuilderManager returned nil")
	}

	session, err := server.builderCreateSession(ctx, "builder-user", "Coverage app", "Build it", "", "", nil)
	if err != nil {
		t.Fatalf("create builder session: %v", err)
	}
	if session.Spec != "coverage" || session.Profile != "coverage" || session.Agent != "custom_coverage" {
		t.Fatalf("created session = %#v", session)
	}
	for _, name := range []string{"app.star", filepath.Join("static", "style.css")} {
		if _, err := os.Stat(filepath.Join(session.WorkspaceDir, name)); err != nil {
			t.Fatalf("seeded %s: %v", name, err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		persisted, getErr := server.builderManager.GetSession(ctx, session.Id)
		if getErr == nil && persisted.Status == types.BuilderSessionError {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent launch did not fail: %#v, %v", persisted, getErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	checks := server.builderVerify(ctx, true)
	checkByName := map[string]BuilderCheck{}
	for _, check := range checks {
		checkByName[check.Name] = check
	}
	if check := checkByName["config"]; !check.Ok {
		t.Fatalf("config check = %#v", check)
	}
	if check := checkByName["agent custom_coverage"]; check.Ok || check.Detail == "" {
		t.Fatalf("agent check = %#v", check)
	}
	if check := checkByName["builder_profile.coverage"]; check.Ok ||
		!strings.Contains(check.Detail, "unknown publish_mode") {
		t.Fatalf("profile check = %#v", check)
	}
	if check := checkByName["publish (local)"]; !check.Ok {
		t.Fatalf("local publish check = %#v", check)
	}

	profile := server.staticConfig.BuilderProfile["coverage"]
	profile.Spec = "missing-spec"
	server.staticConfig.BuilderProfile["coverage"] = profile
	if _, err := server.builderCreateSession(ctx, "builder-user", "Bad spec", "Build it", "", "", nil); err == nil ||
		!strings.Contains(err.Error(), "unknown spec") {
		t.Fatalf("unknown spec error = %v", err)
	}

	if err := server.builderDeleteSession(ctx, session.Id, session.UserID); err != nil {
		t.Fatalf("delete builder session: %v", err)
	}
	if _, err := os.Stat(session.WorkspaceDir); !os.IsNotExist(err) {
		t.Fatalf("workspace remained after delete: %v", err)
	}
}

func TestBuilderSourceAndPublishHelpers(t *testing.T) {
	oldStarlark, hadStarlark := appTypes["coverage-starlark"]
	oldContainer, hadContainer := appTypes["coverage-container"]
	appTypes["coverage-starlark"] = types.SpecFiles{"app.star": "app = 1\n"}
	appTypes["coverage-container"] = types.SpecFiles{"Containerfile": "FROM scratch\n"}
	defer func() {
		if hadStarlark {
			appTypes["coverage-starlark"] = oldStarlark
		} else {
			delete(appTypes, "coverage-starlark")
		}
		if hadContainer {
			appTypes["coverage-container"] = oldContainer
		} else {
			delete(appTypes, "coverage-container")
		}
	}()
	if got := builderSpecKind(""); got != "" {
		t.Fatalf("empty spec kind = %q", got)
	}
	if got := builderSpecKind("coverage-starlark"); got != builder.SpecKindStarlark {
		t.Fatalf("starlark spec kind = %q", got)
	}
	if got := builderSpecKind("coverage-container"); got != builder.SpecKindContainer {
		t.Fatalf("container spec kind = %q", got)
	}

	src := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		full := filepath.Join(src, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.star", "app = 1\n")
	write("static/style.css", "body {}\n")
	write(".git/config", "ignored\n")
	write(".codex/state", "ignored\n")
	if err := os.Symlink(filepath.Join(src, "app.star"), filepath.Join(src, "link.star")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "copied")
	if err := copyAppSource(src, dest); err != nil {
		t.Fatalf("copy source: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(dest, "app.star")); err != nil || string(data) != "app = 1\n" {
		t.Fatalf("copied app.star = %q, %v", data, err)
	}
	for _, excluded := range []string{".git", ".codex", "link.star"} {
		if _, err := os.Stat(filepath.Join(dest, excluded)); !os.IsNotExist(err) {
			t.Fatalf("excluded %s was copied: %v", excluded, err)
		}
	}

	existing := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(existing, []byte("value"), 0644); err != nil {
		t.Fatal(err)
	}
	if data, exists, err := readFileIfExists(existing); err != nil || !exists || string(data) != "value" {
		t.Fatalf("existing file = %q, %v, %v", data, exists, err)
	}
	if data, exists, err := readFileIfExists(existing + ".missing"); err != nil || exists || data != nil {
		t.Fatalf("missing file = %q, %v, %v", data, exists, err)
	}
	if _, _, err := readFileIfExists(filepath.Dir(existing)); err == nil {
		t.Fatal("reading directory unexpectedly succeeded")
	}

	server := &Server{staticConfig: &types.ServerConfig{
		BuilderGit: map[string]types.BuilderGitConfig{
			"publish": {Repo: "https://example.test/repo"},
		},
	}}
	cfg, name, err := server.matchBuilderGitBySource("https://example.test/repo/apps/my-app")
	if err != nil || name != "publish" || cfg.Branch != types.BuilderGitDefaultBranch ||
		cfg.AppsFile != types.BuilderGitDefaultAppsFile || cfg.SourceDir != types.BuilderGitDefaultSourceDir {
		t.Fatalf("matched git config = %#v, %q, %v", cfg, name, err)
	}
	if _, _, err := server.matchBuilderGitBySource("https://other.test/repo/apps/my-app"); err == nil {
		t.Fatal("unmatched source was accepted")
	}
	if !server.isBuilderManaged(&types.AppEntry{Metadata: types.AppMetadata{BuilderPublished: true}}) {
		t.Fatal("builder-published entry is not managed")
	}
	if !server.isBuilderManaged(&types.AppEntry{SourceUrl: "https://example.test/repo/apps/my-app"}) {
		t.Fatal("builder git entry is not managed")
	}
	if server.isBuilderManaged(&types.AppEntry{SourceUrl: "https://other.test/repo/apps/my-app"}) {
		t.Fatal("unmatched entry is managed")
	}
	if got := gitBranchRef("feature"); got != plumbing.NewBranchReferenceName("feature") {
		t.Fatalf("branch ref = %q", got)
	}
	if version, err := server.builderPublishBaseVersion(context.Background(), &types.AppEntry{
		IsDev: true,
		Metadata: types.AppMetadata{
			VersionMetadata: types.VersionMetadata{Version: 7},
		},
	}); err != nil || version != 7 {
		t.Fatalf("dev base version = %d, %v", version, err)
	}
}

func TestBuilderResolveServicesAndContainerBackends(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []*types.Service{
		{Id: types.ID_PREFIX_SERVICE + "postgres_default", Name: "default", ServiceType: "postgres", IsDefault: true},
		{Id: types.ID_PREFIX_SERVICE + "postgres_reporting", Name: "reporting", ServiceType: "postgres"},
		{Id: types.ID_PREFIX_SERVICE + "redis_default", Name: "default", ServiceType: "redis", IsDefault: true},
	} {
		if err := db.CreateService(ctx, tx, service); err != nil {
			tx.Rollback() //nolint:errcheck
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	profile := &types.BuilderProfileConfig{Services: []string{"defaults", "postgres/reporting"}}
	services, err := server.builderResolveServices(ctx, profile, []string{" postgres ", "redis/default"})
	if err != nil || !slices.Equal(services, []string{"postgres/default", "redis/default"}) {
		t.Fatalf("resolved services = %v, %v", services, err)
	}
	if _, err := server.builderResolveServices(ctx, profile, []string{"postgres", "postgres/reporting"}); err == nil ||
		!strings.Contains(err.Error(), "only one postgres") {
		t.Fatalf("duplicate service type error = %v", err)
	}
	if _, err := server.builderResolveServices(ctx, &types.BuilderProfileConfig{},
		[]string{"postgres"}); err == nil || !strings.Contains(err.Error(), "not offered") {
		t.Fatalf("unoffered service error = %v", err)
	}
	if _, err := server.builderResolveServices(ctx, profile, []string{"missing"}); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing service error = %v", err)
	}
	if services, err := server.builderResolveServices(ctx, profile, []string{" "}); err != nil || len(services) != 0 {
		t.Fatalf("blank service choice = %v, %v", services, err)
	}

	server.staticConfig.System.ContainerCommand = types.CONTAINER_KUBERNETES
	if containers, err := server.ListAgentContainers(ctx); err != nil || len(containers) != 0 {
		t.Fatalf("Kubernetes agent containers = %v, %v", containers, err)
	}
	server.staticConfig.System.ContainerCommand = ""
	if containers, err := server.ListKanikoBuildContainers(ctx); err != nil || len(containers) != 0 {
		t.Fatalf("non-Kubernetes kaniko containers = %v, %v", containers, err)
	}
}
