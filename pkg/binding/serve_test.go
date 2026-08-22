// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/openrundev/openrun/pkg/binding/proto"
)

func TestInitializeServiceFailureClosesPartialInstance(t *testing.T) {
	var built *fakeBinding
	srv := &providerServer{
		config: &ServeConfig{Bindings: map[string]Builder{
			"fake": func() ServiceBinding {
				built = &fakeBinding{}
				return built
			},
		}},
		logger: NewLogger("WARN"),
	}

	resp, err := srv.InitializeService(context.Background(), &pb.InitializeServiceRequest{
		ServiceType: "fake",
		ServiceConfig: map[string]string{
			"fail_init": "partial failure",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetError() != "partial failure" {
		t.Fatalf("initialize error = %q", resp.GetError())
	}
	if built == nil || !built.closed {
		t.Fatal("failed binding instance was not closed")
	}
	if srv.instance != nil {
		t.Fatal("failed binding instance remained installed")
	}
}

func TestExportExecutable(t *testing.T) {
	// exportExecutable copies the running executable (here, the test binary)
	// into the target dir under its base name.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Target dir does not exist yet: export must create it.
	targetDir := filepath.Join(t.TempDir(), "providers")

	if err := exportExecutable([]string{targetDir}); err != nil {
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

	// Re-export over the existing read-only copy (init container restart).
	if err := exportExecutable([]string{targetDir}); err != nil {
		t.Fatalf("re-export failed: %v", err)
	}

	// No leftover temp files from the atomic write.
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(self) {
		t.Fatalf("unexpected dir contents: %v", entries)
	}
}

func TestExportExecutableBadArgs(t *testing.T) {
	if err := exportExecutable(nil); err == nil {
		t.Fatal("expected error for missing target dir")
	}
	if err := exportExecutable([]string{""}); err == nil {
		t.Fatal("expected error for empty target dir")
	}
	if err := exportExecutable([]string{"a", "b"}); err == nil {
		t.Fatal("expected error for extra args")
	}
}
