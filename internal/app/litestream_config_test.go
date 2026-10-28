// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/types"
)

// TestRenderLitestreamConfigLogging verifies the sidecar litestream.yml gets
// a logging section with the effective litestream log level, so the
// container's log volume follows logging.litestream_log_level (WARN when
// unset).
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

// TestRenderLitestreamConfigPattern verifies the per-binding replication
// pattern reaches the sidecar litestream.yml, with *.db as the default.
func TestRenderLitestreamConfigPattern(t *testing.T) {
	db := litestreamDB{
		config:          types.LitestreamConfig{Bucket: "bkt"},
		containerConfig: types.LitestreamConfig{Bucket: "bkt"},
		targetDir:       "/data",
		replicaPrefix:   "bindings/b1/prod",
	}

	db.pattern = "*.sqlite3"
	if got := renderLitestreamConfig([]litestreamDB{db}, ""); !strings.Contains(got, "pattern: \"*.sqlite3\"") {
		t.Fatalf("custom pattern missing:\n%s", got)
	}

	db.pattern = bindings.SqliteDefaultPattern
	if got := renderLitestreamConfig([]litestreamDB{db}, ""); !strings.Contains(got, "pattern: \"*.db\"") {
		t.Fatalf("default pattern missing:\n%s", got)
	}
}

// TestMergeSqliteVolumes verifies an app-declared volume at the sqlite
// binding's data directory is replaced by the binding's volume instead of
// producing a duplicate mount target, while other volumes are kept.
func TestMergeSqliteVolumes(t *testing.T) {
	appVols := []*container.VolumeInfo{
		{VolumeName: container.UNNAMED_VOLUME, TargetPath: "/data"},
		{VolumeName: "cache", TargetPath: "/cache"},
	}
	sqliteVols := []*container.VolumeInfo{
		{VolumeName: "sqlite-b1", TargetPath: "/data/"},
	}

	merged := mergeSqliteVolumes(appVols, sqliteVols)
	if len(merged) != 2 {
		t.Fatalf("want 2 volumes (cache + sqlite), got %d: %+v", len(merged), merged)
	}
	if merged[0].VolumeName != "cache" || merged[1].VolumeName != "sqlite-b1" {
		t.Fatalf("unexpected merge result: %+v, %+v", merged[0], merged[1])
	}

	// No sqlite bindings: volumes pass through untouched (fresh slice: the
	// merge compacts its input in place)
	fresh := []*container.VolumeInfo{
		{VolumeName: container.UNNAMED_VOLUME, TargetPath: "/data"},
		{VolumeName: "cache", TargetPath: "/cache"},
	}
	if got := mergeSqliteVolumes(fresh, nil); len(got) != 2 || got[0].TargetPath != "/data" {
		t.Fatalf("no-binding merge changed the volumes: %+v", got)
	}
}

// TestRenderLitestreamConfigSignAcceptEncoding verifies sign_accept_encoding
// reaches the sidecar litestream.yml only when turned off (the key is a
// litestream >= 0.5.17 setting; older sidecar images must not see it).
func TestRenderLitestreamConfigSignAcceptEncoding(t *testing.T) {
	db := litestreamDB{
		config:          types.LitestreamConfig{Bucket: "bkt"},
		containerConfig: types.LitestreamConfig{Bucket: "bkt"},
		targetDir:       "/data",
		replicaPrefix:   "bindings/b1/prod",
	}
	if got := renderLitestreamConfig([]litestreamDB{db}, ""); strings.Contains(got, "sign-accept-encoding") {
		t.Fatalf("default must omit sign-accept-encoding:\n%s", got)
	}

	off := false
	db.config.SignAcceptEncoding = &off
	if got := renderLitestreamConfig([]litestreamDB{db}, ""); !strings.Contains(got, "      sign-accept-encoding: false\n") {
		t.Fatalf("sign-accept-encoding: false missing:\n%s", got)
	}
}

// TestRenderLitestreamConfigTruncatePageN verifies truncate_page_n reaches
// the sidecar litestream.yml, with 0 (documented as "disable") written as
// the negative value litestream >= 0.5.16 needs to actually disable the
// truncate checkpoint (0 means "default threshold" there).
func TestRenderLitestreamConfigTruncatePageN(t *testing.T) {
	db := litestreamDB{
		config:          types.LitestreamConfig{Bucket: "bkt"},
		containerConfig: types.LitestreamConfig{Bucket: "bkt"},
		targetDir:       "/data",
		replicaPrefix:   "bindings/b1/prod",
	}
	if got := renderLitestreamConfig([]litestreamDB{db}, ""); strings.Contains(got, "truncate-page-n") {
		t.Fatalf("unset must omit truncate-page-n:\n%s", got)
	}

	zero := 0
	db.config.TruncatePageN = &zero
	if got := renderLitestreamConfig([]litestreamDB{db}, ""); !strings.Contains(got, "    truncate-page-n: -1\n") {
		t.Fatalf("truncate_page_n = 0 must disable (-1):\n%s", got)
	}

	n := 5000
	db.config.TruncatePageN = &n
	if got := renderLitestreamConfig([]litestreamDB{db}, ""); !strings.Contains(got, "    truncate-page-n: 5000\n") {
		t.Fatalf("truncate-page-n: 5000 missing:\n%s", got)
	}
}
