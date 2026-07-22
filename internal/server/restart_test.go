// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// TestRequestRestartRejectedAfterStopRequested covers a restart racing a
// stop: once shutdown has been requested, a concurrent or subsequent
// RequestRestart must not fork a new process that ends up serving traffic
// after this process has committed to exiting. See Server.blockRestarts,
// which synchronizes this against Stop via restartMu
func TestRequestRestartRejectedAfterStopRequested(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("in-place restart is not supported on windows")
	}
	home := t.TempDir()
	t.Setenv("OPENRUN_HOME", home)
	t.Setenv("OPENRUN_IN_CONTAINER", "false")

	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{EnableInPlaceRestart: true}
	upgrader := system.NewUpgrader(logger, config)
	if !upgrader.Supported() {
		t.Skip("in-place restart not supported in this environment")
	}
	defer upgrader.Stop()

	s := &Server{
		Logger:        logger,
		staticConfig:  config,
		upgrader:      upgrader,
		stopRequested: make(chan struct{}),
	}
	close(s.stopRequested) // simulate a stop already in progress

	if err := s.RequestRestart(); !errors.Is(err, system.ErrInPlaceRestartUnavailable) {
		t.Fatalf("expected ErrInPlaceRestartUnavailable once shutdown was requested, got: %v", err)
	}
}

// TestDrainTimeoutUsesEffectiveConfig covers reading the drain timeout from
// the live (dynamic-config-merged) config rather than a static snapshot, so
// a restart.drain_timeout_secs value applied via update-config actually
// takes effect for shutdown and websocket draining
func TestDrainTimeoutUsesEffectiveConfig(t *testing.T) {
	staticConfig := &types.ServerConfig{}
	staticConfig.Restart.DrainTimeoutSecs = 300

	s := &Server{
		Logger:       types.NewLogger(&types.LogConfig{Level: "WARN"}),
		staticConfig: staticConfig,
	}
	if got := s.DrainTimeout(); got != 300_000_000_000 {
		t.Fatalf("expected static config value 300s before any effective config is set, got: %v", got)
	}

	effective := *staticConfig
	effective.Restart.DrainTimeoutSecs = 5
	s.effectiveConfig.Store(&effective)
	if got := s.DrainTimeout(); got != 5_000_000_000 {
		t.Fatalf("expected DrainTimeout to reflect the effective config override, got: %v", got)
	}
}

// TestResumeBackgroundNoOpAfterStopRequested covers the guard against a late
// resume racing shutdown: the restart-child goroutine waiting on
// WaitForParent (or a failed restart's recovery path) may call
// ResumeBackground after Stop has begun, and must not restart background
// jobs while the server is shutting down
func TestResumeBackgroundNoOpAfterStopRequested(t *testing.T) {
	t.Parallel()

	s := &Server{
		Logger:        types.NewLogger(&types.LogConfig{Level: "WARN"}),
		staticConfig:  &types.ServerConfig{},
		stopRequested: make(chan struct{}),
	}
	close(s.stopRequested)

	s.ResumeBackground()
	if s.syncStop != nil {
		t.Fatal("expected ResumeBackground to be a no-op once shutdown was requested")
	}

	// Before shutdown is requested, resume must restart the jobs
	active := &Server{
		Logger:        types.NewLogger(&types.LogConfig{Level: "WARN"}),
		staticConfig:  &types.ServerConfig{}, // ContainerCommand empty: no container sweeper
		stopRequested: make(chan struct{}),
	}
	active.ResumeBackground()
	if active.syncStop == nil {
		t.Fatal("expected ResumeBackground to restart the sync runner before shutdown")
	}
	active.PauseBackground()
}

// TestPauseBackgroundAbortsInFlightSweep covers the join semantics of
// PauseBackground: a container sweep that is already inside
// cleanupStaleContainers when the pause lands (e.g. an in-place restart
// handoff starting mid-sweep) must be aborted via context cancellation and
// waited for, not left running concurrently with the handoff where it could
// stop containers the new process is starting to use
func TestPauseBackgroundAbortsInFlightSweep(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a shell script as the container command")
	}
	t.Parallel()

	dir := t.TempDir()
	marker := filepath.Join(dir, "sweep-started")
	// Stands in for docker/podman: signals that the sweep reached the
	// container list call, then blocks far longer than the test timeout.
	// exec replaces the shell so the context cancel kills the sleep itself
	script := filepath.Join(dir, "fake-container-cmd")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n: > "+marker+"\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	config := &types.ServerConfig{}
	config.System.ContainerCommand = script
	s := &Server{
		Logger:        types.NewLogger(&types.LogConfig{Level: "ERROR"}),
		staticConfig:  config,
		stopRequested: make(chan struct{}),
	}
	s.apps = NewAppStore(s.Logger, s)

	// Wire the runner the way startStaleContainerCleanup does, but with a
	// fast ticker so the sweep starts promptly
	runCtx, cancel := context.WithCancel(context.Background())
	s.staleContainerCleanupTicker = time.NewTicker(10 * time.Millisecond)
	s.staleContainerCleanupStop = make(chan struct{})
	s.staleContainerCleanupCancel = cancel
	s.staleContainerCleanupDone = make(chan struct{})
	go s.staleContainerCleanupRunner(s.staleContainerCleanupTicker, s.staleContainerCleanupStop, runCtx, s.staleContainerCleanupDone)

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sweep did not reach the container list call in time")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The sweep is now blocked inside ListOpenRunContainers. PauseBackground
	// must abort it and return well before the 60s sleep would finish
	pauseDone := make(chan struct{})
	go func() {
		s.PauseBackground()
		close(pauseDone)
	}()
	select {
	case <-pauseDone:
	case <-time.After(10 * time.Second):
		t.Fatal("PauseBackground did not join the in-flight sweep")
	}
	if s.staleContainerCleanupDone != nil || s.staleContainerCleanupCancel != nil {
		t.Fatal("expected PauseBackground to clear the sweep runner fields")
	}
}
