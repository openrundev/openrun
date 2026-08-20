// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type closeTrackModule struct {
	closed bool
}

func (m *closeTrackModule) InitModule(ctx context.Context, init ModuleInit) error { return nil }
func (m *closeTrackModule) Close(ctx context.Context) error {
	m.closed = true
	return nil
}

// Module.Close must run when the provider process shuts down (the host
// closed the plugin on app close or reload).
func TestCloseModulesRunsModuleClose(t *testing.T) {
	m1 := &closeTrackModule{}
	m2 := &closeTrackModule{}
	host := &Host{
		logger: NewLogger("WARN"),
		modules: map[string]*moduleInstance{
			instanceKey("mod1", ""):     {module: m1},
			instanceKey("mod2", "acct"): {module: m2},
		},
	}
	host.Close(context.Background())
	if !m1.closed || !m2.closed {
		t.Errorf("expected all modules closed, got m1=%v m2=%v", m1.closed, m2.closed)
	}
	if len(host.modules) != 0 {
		t.Errorf("expected module map cleared, got %d entries", len(host.modules))
	}
}

// Strict session defers are reported (for host-side leak mirroring) until
// cleared; non-strict defers are not.
func TestSessionStrictKeys(t *testing.T) {
	s := newSession("test")
	noop := func(ctx context.Context) error { return nil }
	s.Defer("tx", true, noop)
	s.Defer("rollback", false, noop)
	s.Defer("rows", true, noop)

	if got := s.strictKeys(); !reflect.DeepEqual(got, []string{"tx", "rows"}) {
		t.Errorf("strict keys: got %v", got)
	}

	s.ClearDefer("tx")
	if got := s.strictKeys(); !reflect.DeepEqual(got, []string{"rows"}) {
		t.Errorf("strict keys after clear: got %v", got)
	}

	if err := s.end(context.Background()); err != nil {
		t.Fatalf("end: %v", err)
	}
	if got := s.strictKeys(); got != nil {
		t.Errorf("strict keys after end: got %v", got)
	}
}

// exportExecutable copies the running executable (here, the test binary)
// into the target dir with mode 0555. The Kubernetes init-container path
// runs `<provider> export <dir>` from a FROM-scratch image.
func TestExportExecutable(t *testing.T) {
	targetDir := t.TempDir() + "/providers"

	// Target dir does not exist yet: export must create it.
	if err := exportExecutable([]string{targetDir}); err != nil {
		t.Fatal(err)
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(targetDir, filepath.Base(self))
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o555 {
		t.Fatalf("exported mode = %v, want 0555", info.Mode().Perm())
	}
	want, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("exported content differs from the executable")
	}

	// Re-export over an existing copy must succeed (restarted init container)
	if err := exportExecutable([]string{targetDir}); err != nil {
		t.Fatal(err)
	}

	if err := exportExecutable(nil); err == nil {
		t.Fatal("expected usage error")
	}
}
