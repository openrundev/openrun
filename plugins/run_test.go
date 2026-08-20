// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"testing"

	sdk "github.com/openrundev/openrun/pkg/plugin"
)

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
