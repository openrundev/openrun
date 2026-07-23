// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/types"
)

func TestCancelTurnStates(t *testing.T) {
	m := &Manager{}
	ls := newLiveSession("bld_ses_test", "user")

	// idle session: nothing to cancel
	err := m.cancelTurn(ls)
	if err == nil || !strings.Contains(err.Error(), "no agent turn is running") {
		t.Fatalf("expected the no-turn error, got %v", err)
	}

	// the first turn is claimed while the sandbox launches (conn not up
	// yet): the error must direct the user to stop the session instead
	ls.turnActive = true
	err = m.cancelTurn(ls)
	if err == nil || !strings.Contains(err.Error(), "still starting") {
		t.Fatalf("expected the still-starting error, got %v", err)
	}
	if ls.turnCancelled {
		t.Fatal("a rejected cancel must not mark the turn cancelled (it would cancel pending permission requests of the coming turn)")
	}
}

func newManagerTestStore(t *testing.T) (*Manager, *metadata.Metadata, *types.ServerConfig) {
	t.Helper()
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{
		Metadata: types.MetadataConfig{
			DBConnection: "sqlite:" + filepath.Join(t.TempDir(), "metadata.db"),
			AutoUpgrade:  true,
		},
		AppBuilder: types.AppBuilderConfig{
			WorkspaceDir: t.TempDir(),
		},
		Security: types.SecurityConfig{
			UnsafeAgentWithoutSandbox: true,
		},
	}
	db, err := metadata.NewMetadata(logger, config)
	if err != nil {
		t.Fatalf("new metadata: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	manager := NewManager(logger, func() *types.ServerConfig { return config }, db,
		func(input string) (string, error) { return input, nil })
	return manager, db, config
}

func createManagerTestSession(t *testing.T, db *metadata.Metadata, session *types.BuilderSession) {
	t.Helper()
	tx, err := db.BeginTransaction(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateBuilderSession(context.Background(), tx, session); err != nil {
		tx.Rollback() //nolint:errcheck
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestManagerConfigAndStartup(t *testing.T) {
	manager, db, config := newManagerTestStore(t)
	ctx := context.Background()

	if manager.Enabled() {
		t.Fatal("builder unexpectedly enabled")
	}
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("disabled start: %v", err)
	}
	if got := manager.workspaceRoot(); got != config.AppBuilder.WorkspaceDir {
		t.Fatalf("workspaceRoot = %q, want %q", got, config.AppBuilder.WorkspaceDir)
	}

	config.AppBuilder.Enabled = true
	config.System.ContainerCommand = types.CONTAINER_KUBERNETES
	if !manager.Enabled() || !manager.hostMode() {
		t.Fatal("enabled/host mode not reflected from config")
	}
	if _, err := manager.containerCLI(); err == nil || !strings.Contains(err.Error(), "Kubernetes") {
		t.Fatalf("containerCLI Kubernetes error = %v", err)
	}

	config.BuilderAgent = map[string]types.BuilderAgentConfig{"opencode": {}}
	config.BuilderProfile = map[string]types.BuilderProfileConfig{
		"default": {Agent: "opencode"},
	}
	config.AppBuilder.DefaultBuilderProfile = "default"
	if err := manager.ValidateConfig(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if name, _, err := manager.agentConfig(""); err != nil || name != "opencode" {
		t.Fatalf("implicit agent = %q, %v", name, err)
	}
	if _, _, err := manager.agentConfig("missing"); err == nil {
		t.Fatal("missing agent config accepted")
	}

	config.AppBuilder.DefaultBuilderProfile = "missing"
	if err := manager.ValidateConfig(); err == nil || !strings.Contains(err.Error(), "has no") {
		t.Fatalf("missing default profile error = %v", err)
	}
	config.AppBuilder.DefaultBuilderProfile = "default"
	config.BuilderProfile["default"] = types.BuilderProfileConfig{}
	if err := manager.ValidateConfig(); err == nil || !strings.Contains(err.Error(), "agent is required") {
		t.Fatalf("missing profile agent error = %v", err)
	}
	config.BuilderProfile["default"] = types.BuilderProfileConfig{Agent: "opencode", GitConfig: "missing"}
	if err := manager.ValidateConfig(); err == nil || !strings.Contains(err.Error(), "git_config") {
		t.Fatalf("missing git config error = %v", err)
	}

	config.BuilderProfile["default"] = types.BuilderProfileConfig{Agent: "opencode"}
	config.AppBuilder.DefaultBuilderProfile = "default"
	session := &types.BuilderSession{
		Id:           "bld_ses_startup",
		UserID:       "user",
		Name:         "startup",
		Status:       types.BuilderSessionStarting,
		WorkspaceDir: filepath.Join(config.AppBuilder.WorkspaceDir, "bld_ses_startup"),
	}
	createManagerTestSession(t, db, session)
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("host-mode start: %v", err)
	}
	t.Cleanup(manager.Stop)
	persisted, err := manager.GetSession(ctx, session.Id)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Status != types.BuilderSessionDetached {
		t.Fatalf("startup status = %q, want detached", persisted.Status)
	}
}

func TestManagerSessionFilesActivityAndLifecycle(t *testing.T) {
	manager, db, config := newManagerTestStore(t)
	ctx := context.Background()
	workspace := filepath.Join(config.AppBuilder.WorkspaceDir, "bld_ses_manager")
	if err := os.MkdirAll(filepath.Join(workspace, "static"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "app.star"), []byte("app = 1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "static", "style.css"), []byte("body {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".git", "config"), []byte("ignored"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(workspace, "app.star"), filepath.Join(workspace, "link.star")); err != nil {
		t.Fatal(err)
	}
	session := &types.BuilderSession{
		Id:           "bld_ses_manager",
		UserID:       "user",
		Name:         "manager",
		Status:       types.BuilderSessionReady,
		WorkspaceDir: workspace,
	}
	createManagerTestSession(t, db, session)

	gotSession, err := manager.GetSession(ctx, session.Id)
	if err != nil || gotSession.Name != session.Name {
		t.Fatalf("GetSession = %#v, %v", gotSession, err)
	}
	sessions, err := manager.ListSessions(ctx, session.UserID)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("ListSessions = %#v, %v", sessions, err)
	}
	files, err := manager.ListFiles(ctx, session.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(files, []string{"app.star", filepath.Join("static", "style.css")}) {
		t.Fatalf("ListFiles = %v", files)
	}
	content, err := manager.ReadFile(ctx, session.Id, "app.star")
	if err != nil || content != "app = 1\n" {
		t.Fatalf("ReadFile = %q, %v", content, err)
	}

	manager.LogActivity(session.Id, session.UserID, "lifecycle", "ready", map[string]any{"ok": true})
	activity, err := manager.ListActivity(ctx, session.Id, "", 10)
	if err != nil || len(activity) != 1 || activity[0].Content != "ready" {
		t.Fatalf("ListActivity = %#v, %v", activity, err)
	}

	if live, active, partial := manager.LiveState(session.Id); live || active || partial != "" {
		t.Fatalf("detached LiveState = %v, %v, %q", live, active, partial)
	}
	if _, _, err := manager.Subscribe(session.Id); err == nil {
		t.Fatal("Subscribe accepted a detached session")
	}
	liveSession := newLiveSession(session.Id, session.UserID)
	manager.mu.Lock()
	manager.live[session.Id] = liveSession
	manager.mu.Unlock()
	events, cancel, err := manager.Subscribe(session.Id)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	liveSession.mu.Lock()
	liveSession.turnActive = true
	liveSession.msgBuf.WriteString("partial")
	liveSession.mu.Unlock()
	if live, active, partial := manager.LiveState(session.Id); !live || !active || partial != "partial" {
		t.Fatalf("live LiveState = %v, %v, %q", live, active, partial)
	}
	liveSession.emit(Event{Kind: "test"})
	if event := <-events; event.Kind != "test" {
		t.Fatalf("event = %#v", event)
	}

	if err := manager.SendMessage(ctx, session.Id, session.UserID, " "); err == nil ||
		!strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty SendMessage error = %v", err)
	}
	if err := manager.SendMessage(ctx, session.Id, session.UserID, "hello"); err == nil ||
		!strings.Contains(err.Error(), "still starting") {
		t.Fatalf("starting SendMessage error = %v", err)
	}
	if err := manager.StopSession(session.Id, session.UserID); err != nil {
		t.Fatalf("StopSession: %v", err)
	}
	if _, err := manager.requireLive(session.Id); err == nil {
		t.Fatal("session remained live after stop")
	}
	stopped, err := manager.GetSession(ctx, session.Id)
	if err != nil || stopped.Status != types.BuilderSessionDetached {
		t.Fatalf("stopped session = %#v, %v", stopped, err)
	}

	config.AppBuilder.Enabled = false
	if err := manager.ResumeSession(ctx, session.Id, session.UserID); err == nil ||
		!strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("disabled ResumeSession error = %v", err)
	}
	if _, err := manager.CreateSession(ctx, session.UserID, "name", "prompt", "", "", "", "", nil, nil); err == nil ||
		!strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("disabled CreateSession error = %v", err)
	}

	stopped.PublishPath = "/published"
	stopped.Status = types.BuilderSessionPublished
	if err := manager.UpdateSessionInfo(ctx, stopped); err != nil {
		t.Fatalf("UpdateSessionInfo: %v", err)
	}
	if err := manager.DeleteSession(ctx, session.Id, session.UserID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := manager.GetSession(ctx, session.Id); err == nil {
		t.Fatal("session still exists after delete")
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatalf("workspace still exists after delete: %v", err)
	}
}

func TestManagerCreateSessionValidationAndFailureLifecycle(t *testing.T) {
	manager, _, config := newManagerTestStore(t)
	ctx := context.Background()
	config.AppBuilder.Enabled = true
	config.AppBuilder.MaxSessions = 1

	dockerfile := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}
	config.BuilderAgent = map[string]types.BuilderAgentConfig{
		"custom_coverage": {
			Dockerfile: dockerfile,
			Command:    []string{filepath.Join(t.TempDir(), "missing-agent")},
		},
	}
	config.BuilderProfile = map[string]types.BuilderProfileConfig{
		"coverage": {Agent: "custom_coverage"},
	}
	config.AppBuilder.DefaultBuilderProfile = "coverage"
	if err := manager.VerifyProfile(ctx, "missing", false); err == nil ||
		!strings.Contains(err.Error(), "no [builder_agent.missing]") {
		t.Fatalf("missing verify profile error = %v", err)
	}
	if err := manager.VerifyProfile(ctx, "custom_coverage", false); err == nil {
		t.Fatal("verification unexpectedly started the missing custom agent")
	}

	create := func(name, prompt string, seed func(*types.BuilderSession) error) (*types.BuilderSession, error) {
		return manager.CreateSession(ctx, "user", name, prompt, "", SpecKindStarlark, "", "",
			[]string{"postgres/default"}, seed)
	}
	if _, err := create(" ", "prompt", nil); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("blank name error = %v", err)
	}
	if _, err := create("name", " ", nil); err == nil || !strings.Contains(err.Error(), "prompt is required") {
		t.Fatalf("blank prompt error = %v", err)
	}

	seedErr := fmt.Errorf("seed failed")
	if _, err := create("seed", "prompt", func(*types.BuilderSession) error { return seedErr }); !errors.Is(err, seedErr) {
		t.Fatalf("seed error = %v", err)
	}

	manager.mu.Lock()
	manager.live["at-capacity"] = newLiveSession("at-capacity", "user")
	manager.mu.Unlock()
	if _, err := create("capacity", "prompt", nil); err == nil || !strings.Contains(err.Error(), "max concurrent") {
		t.Fatalf("max sessions error = %v", err)
	}
	manager.mu.Lock()
	delete(manager.live, "at-capacity")
	manager.mu.Unlock()

	session, err := create("coverage", "build it", func(session *types.BuilderSession) error {
		return os.WriteFile(filepath.Join(session.WorkspaceDir, "app.star"), []byte("app = 1\n"), 0644)
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if session.Profile != "coverage" || session.Agent != "custom_coverage" ||
		!slices.Equal(session.Services, []string{"postgres/default"}) {
		t.Fatalf("created session = %#v", session)
	}
	if _, err := os.Stat(filepath.Join(session.WorkspaceDir, "app.star")); err != nil {
		t.Fatalf("seeded app.star: %v", err)
	}

	waitForStatus := func(want types.BuilderSessionStatus) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			persisted, getErr := manager.GetSession(ctx, session.Id)
			if getErr == nil && persisted.Status == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		persisted, getErr := manager.GetSession(ctx, session.Id)
		t.Fatalf("session status = %#v, %v; want %s", persisted, getErr, want)
	}
	waitForStatus(types.BuilderSessionError)

	if err := manager.ResumeSession(ctx, session.Id, session.UserID); err != nil {
		t.Fatalf("resume failed session: %v", err)
	}
	if err := manager.ResumeSession(ctx, session.Id, session.UserID); err == nil ||
		!strings.Contains(err.Error(), "already live") {
		t.Fatalf("duplicate resume error = %v", err)
	}
	waitForStatus(types.BuilderSessionError)

	activity, err := manager.ListActivity(ctx, session.Id, "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(activity) < 4 {
		t.Fatalf("activity count = %d, want create, prompt, resume, and launch failures", len(activity))
	}
}

func TestManagerFileAndStatusErrorBranches(t *testing.T) {
	manager, db, config := newManagerTestStore(t)
	ctx := context.Background()
	t.Setenv("OPENRUN_HOME", t.TempDir())
	config.AppBuilder.WorkspaceDir = ""
	if got := manager.workspaceRoot(); got != filepath.Join(os.Getenv("OPENRUN_HOME"), "run", "builder") {
		t.Fatalf("default workspace root = %q", got)
	}

	workspace := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "outside-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "large.txt"), make([]byte, maxReadFileBytes+1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(workspace, "directory"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := readWorkspaceFile(workspace, "outside-link"); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside symlink error = %v", err)
	}
	if _, err := readWorkspaceFile(workspace, "large.txt"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("large file error = %v", err)
	}
	if _, err := readWorkspaceFile(workspace, "directory"); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory error = %v", err)
	}
	if _, err := readWorkspaceFile(workspace, "missing"); err == nil {
		t.Fatal("missing file was readable")
	}

	session := &types.BuilderSession{
		Id: "bld_ses_status", UserID: "user", Status: types.BuilderSessionPublished, WorkspaceDir: workspace,
	}
	createManagerTestSession(t, db, session)
	ls := newLiveSession(session.Id, session.UserID)
	events, cancel := ls.subscribe()
	defer cancel()
	manager.setStatus(ls, types.BuilderSessionReady)
	persisted, err := manager.GetSession(ctx, session.Id)
	if err != nil || persisted.Status != types.BuilderSessionPublished {
		t.Fatalf("published status changed: %#v, %v", persisted, err)
	}
	manager.setStatus(ls, types.BuilderSessionRunning)
	if event := <-events; event.Status != string(types.BuilderSessionRunning) {
		t.Fatalf("status event = %#v", event)
	}
	if err := manager.CancelTurn("missing"); err == nil || !strings.Contains(err.Error(), "no running sandbox") {
		t.Fatalf("missing cancel error = %v", err)
	}
}
