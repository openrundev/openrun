// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

func TestStartAgentClosesStdinOnStdoutPipeFailure(t *testing.T) {
	cmd := exec.Command("unused")
	cmd.Stdout = io.Discard // Force StdoutPipe to fail after StdinPipe succeeds.
	if _, err := startAgentCmd("", "", cmd); err == nil {
		t.Fatal("expected pipe setup error")
	}
	if _, err := cmd.Stdin.(*os.File).Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("child stdin was not closed: %v", err)
	}
}

func TestStopSessionDuringHandshake(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("requires sh")
	}
	manager, db, config := newManagerTestStore(t)
	dockerfile := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM scratch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	config.BuilderAgent = map[string]types.BuilderAgentConfig{
		"custom": {Dockerfile: dockerfile, Command: []string{sh, "-c", "touch started; cat >/dev/null; touch exited"}},
	}
	session := &types.BuilderSession{Id: "bld_ses_stop_launch", UserID: "user", Agent: "custom", WorkspaceDir: workspace, Status: types.BuilderSessionStarting}
	createManagerTestSession(t, db, session)
	ls := newLiveSession(session.Id, session.UserID)
	manager.live[ls.id] = ls
	done := make(chan error, 1)
	go func() { done <- manager.launch(ls) }()
	defer manager.Stop()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(filepath.Join(workspace, "started")); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("launch ended before handshake: %v", err)
		case <-deadline:
			t.Fatal("agent did not start")
		case <-ticker.C:
		}
	}
	manager.stopLive(ls, types.BuilderSessionDetached)
	select {
	case err := <-done:
		if err == nil || !errors.Is(ls.ctx.Err(), context.Canceled) {
			t.Fatalf("launch returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stopped session left launch blocked in handshake")
	}
	if _, err := os.Stat(filepath.Join(workspace, "exited")); err != nil {
		t.Fatalf("agent was not reaped: %v", err)
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.sandbox != nil || ls.conn != nil {
		t.Fatal("stopped session acquired sandbox resources")
	}
}

func TestCreateSessionReleasesWorkspaceOnDatabaseFailure(t *testing.T) {
	manager, db, config := newManagerTestStore(t)
	config.AppBuilder.Enabled = true
	config.BuilderAgent = map[string]types.BuilderAgentConfig{"opencode": {}}
	config.BuilderProfile = map[string]types.BuilderProfileConfig{"default": {Agent: "opencode"}}
	config.AppBuilder.DefaultBuilderProfile = "default"
	db.Close()
	var workspace string
	_, err := manager.CreateSession(context.Background(), "user", "test", "build it", "", SpecKindStarlark, "", "", nil, func(session *types.BuilderSession) error {
		workspace = session.WorkspaceDir
		return nil
	})
	if err == nil {
		t.Fatal("expected database failure")
	}
	if workspace == "" {
		t.Fatal("did not reach workspace creation")
	}
	if _, err := os.Stat(workspace); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed session left workspace behind: %v", err)
	}
}

func TestCreateSessionRacingManagerStop(t *testing.T) {
	manager, _, config := newManagerTestStore(t)
	config.AppBuilder.Enabled = true
	config.BuilderAgent = map[string]types.BuilderAgentConfig{"opencode": {}}
	config.BuilderProfile = map[string]types.BuilderProfileConfig{"default": {Agent: "opencode"}}
	config.AppBuilder.DefaultBuilderProfile = "default"
	session, err := manager.CreateSession(context.Background(), "user", "test", "build it", "", SpecKindStarlark, "", "", nil, func(*types.BuilderSession) error {
		manager.Stop()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != types.BuilderSessionDetached {
		t.Fatalf("session status = %s", session.Status)
	}
	if len(manager.live) != 0 {
		t.Fatal("stopped manager acquired a live session")
	}
	if err := manager.ResumeSession(context.Background(), session.Id, "user"); err == nil {
		t.Fatal("stopped manager accepted resume")
	}
	manager.Stop() // Shutdown is idempotent.
}
