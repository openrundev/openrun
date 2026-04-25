// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package telemetry

import "testing"

func TestSQLDriverNameDisabledAndValidation(t *testing.T) {
	metricsEnabled.Store(false)
	t.Cleanup(func() { metricsEnabled.Store(false) })

	name, err := SQLDriverName("sqlite", DBSystemSQLite, "Store Plugin")
	if err != nil {
		t.Fatalf("disabled SQLDriverName returned error: %v", err)
	}
	if name != "sqlite" {
		t.Fatalf("disabled SQLDriverName mismatch: got %q", name)
	}

	metricsEnabled.Store(true)
	if _, err := SQLDriverName("unknown", "unknown", "test"); err == nil {
		t.Fatal("expected unknown driver to fail")
	}

	name, err = SQLDriverName("sqlite", DBSystemSQLite, "Store Plugin")
	if err != nil {
		t.Fatalf("wrapped SQLDriverName returned error: %v", err)
	}
	if name != "openrun_otel_sqlite_store_plugin" {
		t.Fatalf("wrapped SQLDriverName mismatch: got %q", name)
	}

	again, err := SQLDriverName("sqlite", DBSystemSQLite, "Store Plugin")
	if err != nil {
		t.Fatalf("second wrapped SQLDriverName returned error: %v", err)
	}
	if again != name {
		t.Fatalf("registered driver name changed: got %q, want %q", again, name)
	}
}

func TestSQLDriverHelpers(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  string
	}{
		{"", "unknown"},
		{"   ", "unknown"},
		{"SELECT * FROM t", "select"},
		{"\nInsert into t values (1)", "insert"},
	} {
		if got := queryOperation(tc.query); got != tc.want {
			t.Fatalf("queryOperation(%q) = %q, want %q", tc.query, got, tc.want)
		}
	}

	if got := safeDriverName("Store Plugin#1"); got != "store_plugin_1" {
		t.Fatalf("safeDriverName mismatch: got %q", got)
	}
	if baseDriver("sqlite") == nil {
		t.Fatal("sqlite base driver should resolve")
	}
	if baseDriver("pgx") == nil {
		t.Fatal("pgx base driver should resolve")
	}
	if baseDriver("unknown") != nil {
		t.Fatal("unknown base driver should be nil")
	}
}
