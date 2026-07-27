// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

// TestRenderLitestreamConfigLogging verifies the sidecar litestream.yml gets
// a logging section with the effective litestream log level, so the
// container's log volume follows logging.litestream_log_level (or the main
// logging.level when unset).
func TestRenderLitestreamConfigLogging(t *testing.T) {
	dbs := []litestreamDB{{
		config:          types.LitestreamConfig{Bucket: "bkt"},
		containerConfig: types.LitestreamConfig{Bucket: "bkt"},
		targetDir:       "/data/db",
		replicaPrefix:   "bindings/b1/prod",
	}}

	got := renderLitestreamConfig(dbs, "WARN")
	if !strings.HasPrefix(got, "logging:\n  level: warn\n") {
		t.Fatalf("logging section missing or wrong:\n%s", got)
	}
	if !strings.Contains(got, "dir: /data/db") {
		t.Fatalf("dbs section missing:\n%s", got)
	}

	if got := renderLitestreamConfig(dbs, ""); strings.Contains(got, "logging:") {
		t.Fatalf("empty level must omit the logging section:\n%s", got)
	}
}
