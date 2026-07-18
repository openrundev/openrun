// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
)

// buildFixtureProvider builds the test provider binary once per test run.
func buildFixtureProvider(t *testing.T) string {
	t.Helper()
	execPath := filepath.Join(t.TempDir(), "openrun-binding-fixture")
	cmd := exec.Command("go", "build", "-o", execPath, ".")
	cmd.Dir = "testdata/fixtureprovider"
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("error building fixture provider: %v\n%s", err, out)
	}
	return execPath
}

func testLogger() *types.Logger {
	logger := zerolog.Nop()
	return &types.Logger{Logger: &logger}
}

// TestRemoteBindingE2E exercises the full out-of-process path: process launch
// and go-plugin handshake, the calls the server makes on a binding, the
// partial-failure contract, application vs transport errors, and crash
// recovery (respawn + retry).
func TestRemoteBindingE2E(t *testing.T) {
	execPath := buildFixtureProvider(t)
	ctx := context.Background()

	if err := RegisterRemoteBinding("test-fixture", "fixture", execPath, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { UnregisterProviderBindings("test-fixture") })

	builder, ok := GetServiceBinding("fixture")
	if !ok {
		t.Fatal("fixture service type not registered")
	}

	serviceBinding := builder()

	// GetAccountEnv is static info: it must work before InitializeService,
	// launching a short-lived provider process for the call.
	params, optional, err := serviceBinding.GetAccountEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 1 || params[0] != "user" || len(optional) != 1 || optional[0] != "fixture_opt" {
		t.Fatalf("pre-init GetAccountEnv = %v, %v", params, optional)
	}

	if err := serviceBinding.InitializeService(ctx, testLogger(),
		map[string]string{"url": "fixture://localhost"}, ServiceBindingRuntime{}); err != nil {
		t.Fatal(err)
	}

	// After init, GetAccountEnv is served by the running provider process.
	if params, _, err = serviceBinding.GetAccountEnv(ctx); err != nil || len(params) != 1 {
		t.Fatalf("post-init GetAccountEnv = %v, %v", params, err)
	}
	t.Cleanup(func() { serviceBinding.CloseService(ctx) }) //nolint:errcheck

	// Normal command round trip, verifying instance state (the service config
	// set at init) survives in the provider process.
	result, err := serviceBinding.RunCommand(ctx, types.BindingMetadata{}, "echo:hi")
	if err != nil {
		t.Fatal(err)
	}
	if result["echo"] != "hi" || result["url"] != "fixture://localhost" {
		t.Fatalf("result = %v", result)
	}

	// Account generation and the partial-failure contract.
	account, artifacts, err := serviceBinding.GenerateAccount(ctx, "bnd_1", "/p", types.BindingMetadata{}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if account["user"] != "fx_bnd_1" || len(artifacts) != 1 || artifacts[0].Name != "fx_bnd_1" {
		t.Fatalf("account = %v artifacts = %v", account, artifacts)
	}

	_, artifacts, err = serviceBinding.GenerateAccount(ctx, "bnd_2", "/p",
		types.BindingMetadata{Config: map[string]string{"partial_failure": "y"}}, nil, false)
	if err == nil {
		t.Fatal("expected partial failure error")
	}
	if len(artifacts) != 1 || artifacts[0].Name != "fx_bnd_2" {
		t.Fatalf("partial failure artifacts = %v", artifacts)
	}

	// Application-level error string surfaces to the caller.
	if _, err := serviceBinding.RunCommand(ctx, types.BindingMetadata{}, "fail"); err == nil || err.Error() != "fixture command failed" {
		t.Fatalf("expected fixture command failed, got %v", err)
	}

	// Crash on a non-idempotent operation: RunCommand must NOT be retried (a
	// crash after execution but before the response must not run it twice), so
	// the transport error surfaces to the caller.
	marker := filepath.Join(t.TempDir(), "crash_marker")
	if _, err := serviceBinding.RunCommand(ctx, types.BindingMetadata{}, "crash_once:"+marker); err == nil {
		t.Fatal("expected transport error for crashed non-idempotent RunCommand")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("crash marker missing: provider did not crash")
	}

	// The previous step left a dead provider process. DeleteArtifact is
	// idempotent (the rollback compensation path), so the adapter must respawn
	// the provider, replay InitializeService and retry — exactly the scenario
	// the retry exists for: cleanup after a provider crash.
	if err := serviceBinding.DeleteArtifact(ctx, Artifact{Type: ArtifactUser, Name: "fx_cleanup"}); err != nil {
		t.Fatalf("expected respawn recovery for idempotent DeleteArtifact, got %v", err)
	}

	// Crash during the idempotent operation itself: first attempt crashes the
	// healthy provider, the single retry runs on the respawned one and succeeds.
	marker2 := filepath.Join(t.TempDir(), "crash_marker2")
	if err := serviceBinding.DeleteArtifact(ctx, Artifact{Type: ArtifactUser, Name: "crash_once:" + marker2}); err != nil {
		t.Fatalf("expected crash recovery for idempotent DeleteArtifact, got %v", err)
	}
	if _, err := os.Stat(marker2); err != nil {
		t.Fatal("crash marker2 missing: provider did not crash during DeleteArtifact")
	}

	// After recovery the provider serves normal calls again.
	result, err = serviceBinding.RunCommand(ctx, types.BindingMetadata{}, "echo:back")
	if err != nil || result["echo"] != "back" {
		t.Fatalf("post-recovery result = %v err = %v", result, err)
	}

	if err := serviceBinding.CloseService(ctx); err != nil {
		t.Fatal(err)
	}

	// After close, calls fail cleanly.
	if _, err := serviceBinding.RunCommand(ctx, types.BindingMetadata{}, "echo:x"); err == nil {
		t.Fatal("expected error after close")
	}
}

// TestRemoteBindingInitFailure verifies an application-level InitializeService
// failure is returned to the caller and the provider process is not left running.
func TestRemoteBindingInitFailure(t *testing.T) {
	execPath := buildFixtureProvider(t)
	ctx := context.Background()

	serviceBinding := &remoteServiceBinding{serviceType: "fixture", execPath: execPath}
	err := serviceBinding.InitializeService(ctx, testLogger(), map[string]string{"fail_init": "bad fixture config"}, ServiceBindingRuntime{})
	if err == nil || err.Error() != "bad fixture config" {
		t.Fatalf("expected bad fixture config, got %v", err)
	}
	if serviceBinding.provider != nil {
		t.Fatal("provider process left running after init failure")
	}
}

// TestRegisterRemoteBindingConflicts verifies built-in bindings always win and
// a service type cannot be claimed by two providers.
func TestRegisterRemoteBindingConflicts(t *testing.T) {
	if err := RegisterRemoteBinding("p1", "postgres", "/does/not/matter", ""); err == nil {
		t.Fatal("expected conflict with built-in postgres binding")
	}

	if err := RegisterRemoteBinding("p1", "conflict-type", "/p1", ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { UnregisterProviderBindings("p1") })
	if err := RegisterRemoteBinding("p2", "conflict-type", "/p2", ""); err == nil {
		t.Fatal("expected conflict between providers")
	}
	// Re-registration by the same provider (reconcile) is allowed.
	if err := RegisterRemoteBinding("p1", "conflict-type", "/p1b", ""); err != nil {
		t.Fatal(err)
	}

	UnregisterProviderBindings("p1")
	if _, ok := GetServiceBinding("conflict-type"); ok {
		t.Fatal("conflict-type still registered after unregister")
	}
	if _, ok := GetServiceBinding("postgres"); !ok {
		t.Fatal("built-in postgres binding must never be unregistered")
	}
}
