// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"errors"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func TestUpgraderFallbackWhenDisabled(t *testing.T) {
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{} // EnableInPlaceRestart false

	u := NewUpgrader(logger, config)
	if u.Supported() {
		t.Fatal("upgrader must not be supported when in-place restart is not enabled")
	}

	// Listen falls through to the bind callback
	ln, err := u.Listen("tcp", "127.0.0.1:0", net.Listen)
	if err != nil {
		t.Fatalf("fallback listen failed: %s", err)
	}
	defer ln.Close() //nolint:errcheck

	if err := u.Ready(); err != nil {
		t.Fatalf("fallback Ready must be a no-op, got: %s", err)
	}
	if ch := u.Exit(); ch != nil {
		t.Fatal("fallback Exit must return a nil channel")
	}
	if err := u.Upgrade(); !errors.Is(err, ErrInPlaceRestartUnavailable) {
		t.Fatalf("fallback Upgrade must return ErrInPlaceRestartUnavailable, got: %v", err)
	}
	if u.HasParent() {
		t.Fatal("fallback HasParent must be false")
	}
	if !u.ParentExited() {
		t.Fatal("fallback ParentExited must be true")
	}
	if err := u.WaitForParent(context.Background()); err != nil {
		t.Fatalf("fallback WaitForParent must be a no-op, got: %s", err)
	}
	u.Stop() // must not panic
}

func TestContainerRestartAdvice(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("OPENRUN_IN_CONTAINER", "")

	t.Setenv("OPENRUN_IN_CONTAINER", "1")
	if containerRestartAdvice() == "" {
		t.Fatal("OPENRUN_IN_CONTAINER=1 must report in-container")
	}

	// The env override wins over auto-detection in both directions
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("OPENRUN_IN_CONTAINER", "false")
	if advice := containerRestartAdvice(); advice != "" {
		t.Fatalf("OPENRUN_IN_CONTAINER=false must override detection, got: %s", advice)
	}

	t.Setenv("OPENRUN_IN_CONTAINER", "")
	if containerRestartAdvice() == "" {
		t.Fatal("KUBERNETES_SERVICE_HOST must report in-container")
	}
}

// TestUpgraderCreate creates the real tableflip upgrader. tableflip allows a
// single Upgrader per process, so this is the only test that may enable
// in-place restart
func TestUpgraderCreate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("in-place restart is not supported on windows")
	}
	home := t.TempDir()
	t.Setenv("OPENRUN_HOME", home)
	t.Setenv("OPENRUN_IN_CONTAINER", "false")

	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{EnableInPlaceRestart: true}
	config.Restart.UpgradeTimeoutSecs = 10

	u := NewUpgrader(logger, config)
	if !u.Supported() {
		t.Fatalf("upgrader not supported: %s", u.reason)
	}
	defer u.Stop()

	ln, err := u.Listen("tcp", "127.0.0.1:0", net.Listen)
	if err != nil {
		t.Fatalf("listen failed: %s", err)
	}
	defer ln.Close() //nolint:errcheck

	if err := u.Ready(); err != nil {
		t.Fatalf("Ready failed: %s", err)
	}
	if _, err := os.Stat(path.Join(home, "run", "openrun.pid")); err != nil {
		t.Fatalf("pid file not written: %s", err)
	}
}

// TestInvocationPathPreservesSymlink covers re-exec path pinning for binary
// updates: when openrun is invoked through a stable symlink that a package
// update repoints to a new versioned binary, the pinned path must stay on
// the symlink (unlike os.Executable, which resolves /proc/self/exe to the
// target captured at startup, which the update may then remove)
func TestInvocationPathPreservesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("in-place restart is not supported on windows")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "openrun-v1.0.0")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "openrun")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	origArg0 := os.Args[0]
	defer func() { os.Args[0] = origArg0 }()

	// Absolute symlink invocation stays on the symlink
	os.Args[0] = link
	got, err := invocationPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != link {
		t.Fatalf("absolute invocation: expected %s, got %s", link, got)
	}

	// Bare command name resolves through PATH to the symlink, not its target
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	os.Args[0] = "openrun"
	got, err = invocationPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != link {
		t.Fatalf("bare-name invocation: expected %s, got %s", link, got)
	}

	// Relative invocation with a separator becomes absolute against the
	// current directory, still without resolving the symlink
	t.Chdir(dir)
	os.Args[0] = "./openrun"
	got, err = invocationPath()
	if err != nil {
		t.Fatal(err)
	}
	// Compare via EvalSymlinks-free cleaning only: the path must end at the
	// symlink name, not the versioned target
	if filepath.Base(got) != "openrun" || !filepath.IsAbs(got) {
		t.Fatalf("relative invocation: expected absolute path ending in the symlink name, got %s", got)
	}
}
