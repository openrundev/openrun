// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	sdk "github.com/openrundev/openrun/pkg/plugin"
)

func TestExecRunTempFileOwnership(t *testing.T) {
	for _, scenario := range []string{"failure", "success", "partial", "stream"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("TMPDIR", dir)
			t.Setenv("TMP", dir)
			t.Setenv("TEMP", dir)
			script := "echo output; exit 1"
			if scenario == "success" {
				script = "echo output"
			}
			call := execRunCall(
				sdk.Kwarg{Name: "path", Value: "sh"},
				sdk.Kwarg{Name: "args", Value: []any{"-c", script}},
				sdk.Kwarg{Name: "stdout_file", Value: true},
				sdk.Kwarg{Name: "process_partial", Value: scenario == "partial"},
				sdk.Kwarg{Name: "stream", Value: scenario == "stream"},
			)
			defer call.Session.End(context.Background()) //nolint:errcheck
			result, err := execCommand(context.Background(), call, nil)
			files, globErr := filepath.Glob(filepath.Join(dir, "openrun-exec-stdout-*"))
			if globErr != nil {
				t.Fatal(globErr)
			}
			if scenario == "failure" || scenario == "stream" {
				if err == nil {
					t.Fatal("expected an error")
				}
				if len(files) != 0 {
					t.Fatalf("orphaned temp files: %v", files)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			name, ok := result.(string)
			if !ok || len(files) != 1 || files[0] != name {
				t.Fatalf("unexpected file result: %v, files %v", result, files)
			}
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "output\n" {
				t.Fatalf("file data = %q", data)
			}
		})
	}
}

func execRunCall(kwargs ...sdk.Kwarg) *sdk.Call {
	return &sdk.Call{Function: "run", Kwargs: kwargs, Session: sdk.NewSession("test")}
}

// An omitted env must give the command a clean environment, never the
// server's own environment (which carries server credentials and config).
func TestExecRunOmittedEnvIsEmpty(t *testing.T) {
	t.Setenv("OPENRUN_RUN_TEST_LEAK", "leaked")

	result, err := execCommand(context.Background(), execRunCall(
		sdk.Kwarg{Name: "path", Value: "env"},
		sdk.Kwarg{Name: "args", Value: []any{}},
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	lines, ok := result.([]any)
	if !ok {
		t.Fatalf("result type = %T", result)
	}
	for _, line := range lines {
		s, _ := line.(string)
		if s != "" {
			t.Fatalf("expected empty environment, got %q", s)
		}
	}
}

// An explicit env is passed through as the complete environment.
func TestExecRunExplicitEnv(t *testing.T) {
	result, err := execCommand(context.Background(), execRunCall(
		sdk.Kwarg{Name: "path", Value: "env"},
		sdk.Kwarg{Name: "env", Value: []any{"RUN_TEST_VAR=explicit"}},
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := result.([]any)
	if len(lines) != 1 || lines[0] != "RUN_TEST_VAR=explicit" {
		t.Fatalf("unexpected environment: %v", lines)
	}
}
