// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func newTestSqliteBinding(t *testing.T, serviceConfig map[string]string, litestreamNames []string) (*SqliteServiceBinding, error) {
	t.Helper()
	b := NewSqliteServiceBinding().(*SqliteServiceBinding)
	err := b.InitializeService(context.Background(), types.NewLogger(&types.LogConfig{}), serviceConfig,
		ServiceBindingRuntime{LitestreamConfigNames: litestreamNames})
	return b, err
}

func TestSqliteAccount(t *testing.T) {
	t.Parallel()

	account := SqliteAccountForDir(SqliteDefaultDir)
	if account["dir"] != "/data" {
		t.Fatalf("dir = %q", account["dir"])
	}
	if account["db_path"] != "/data/data.db" {
		t.Fatalf("db_path = %q", account["db_path"])
	}
	if account["url"] != "file:/data/data.db" {
		t.Fatalf("url = %q", account["url"])
	}
}

func TestSqliteBindingDir(t *testing.T) {
	t.Parallel()

	if dir, err := SqliteBindingDir(nil); err != nil || dir != "/data" {
		t.Fatalf("default dir = %q, %v", dir, err)
	}
	if dir, err := SqliteBindingDir(map[string]string{"path": "/mydata/test"}); err != nil || dir != "/mydata/test" {
		t.Fatalf("custom dir = %q, %v", dir, err)
	}
	if dir, err := SqliteBindingDir(map[string]string{"path": "/mydata/"}); err != nil || dir != "/mydata" {
		t.Fatalf("trailing slash dir = %q, %v", dir, err)
	}
	for _, bad := range []string{"relative/path", "/", "/a/../b", "/a//b"} {
		if _, err := SqliteBindingDir(map[string]string{"path": bad}); err == nil {
			t.Fatalf("path %q should be rejected", bad)
		}
	}
}

func TestSqliteGetAccountEnv(t *testing.T) {
	t.Parallel()

	b := NewSqliteServiceBinding()
	required, optional, err := b.GetAccountEnv(context.Background())
	if err != nil {
		t.Fatalf("GetAccountEnv: %v", err)
	}
	if len(optional) != 0 {
		t.Fatalf("optional env = %v, want none", optional)
	}
	account := SqliteAccountForDir(SqliteDefaultDir)
	for _, key := range required {
		if account[key] == "" {
			t.Fatalf("required env key %q missing from account %v", key, account)
		}
	}
	if len(required) != len(account) {
		t.Fatalf("required env %v does not cover account %v", required, account)
	}
}

func TestSqliteInitializeServiceConfigValidation(t *testing.T) {
	t.Parallel()

	if _, err := newTestSqliteBinding(t, map[string]string{"unknown": "x"}, nil); err == nil ||
		!strings.Contains(err.Error(), "unknown config key") {
		t.Fatalf("unknown key error = %v", err)
	}

	if _, err := newTestSqliteBinding(t, map[string]string{SqliteConfigLitestream: "missing"}, []string{"mainbackup"}); err == nil ||
		!strings.Contains(err.Error(), "litestream config \"missing\" is not defined") {
		t.Fatalf("undefined litestream config error = %v", err)
	}

	if _, err := newTestSqliteBinding(t, map[string]string{SqliteConfigLitestream: "mainbackup"}, []string{"mainbackup"}); err != nil {
		t.Fatalf("valid litestream config: %v", err)
	}

	// A file replica type config is host-local and unusable from app
	// containers: rejected at service create
	b := NewSqliteServiceBinding().(*SqliteServiceBinding)
	err := b.InitializeService(context.Background(), types.NewLogger(&types.LogConfig{}),
		map[string]string{SqliteConfigLitestream: "localdisk"},
		ServiceBindingRuntime{LitestreamConfigNames: []string{"localdisk"}, LitestreamFileConfigNames: []string{"localdisk"}})
	if err == nil || !strings.Contains(err.Error(), "file replica type") {
		t.Fatalf("file replica config error = %v", err)
	}

	if _, err := newTestSqliteBinding(t, map[string]string{SqliteConfigVolumeSize: "10Gigs"}, nil); err == nil ||
		!strings.Contains(err.Error(), "invalid volume_size") {
		t.Fatalf("invalid volume_size error = %v", err)
	}

	if _, err := newTestSqliteBinding(t, map[string]string{SqliteConfigVolumeSize: "10Gi", SqliteConfigPathPrefix: "team-x"}, nil); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}

func TestSqliteGenerateAccount(t *testing.T) {
	t.Parallel()

	b, err := newTestSqliteBinding(t, map[string]string{}, nil)
	if err != nil {
		t.Fatalf("InitializeService: %v", err)
	}

	account, artifacts, err := b.GenerateAccount(context.Background(), "bnd_1", "/apps/data", types.BindingMetadata{}, nil, false)
	if err != nil {
		t.Fatalf("GenerateAccount: %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("artifacts = %v, want none", artifacts)
	}
	if account["url"] != "file:/data/data.db" {
		t.Fatalf("account url = %q", account["url"])
	}

	// The binding config "path" key overrides the mount directory
	custom, _, err := b.GenerateAccount(context.Background(), "bnd_1", "/apps/data",
		types.BindingMetadata{Config: map[string]string{"path": "/mydata/test"}}, nil, false)
	if err != nil {
		t.Fatalf("GenerateAccount with path: %v", err)
	}
	if custom["url"] != "file:/mydata/test/data.db" || custom["dir"] != "/mydata/test" {
		t.Fatalf("custom path account = %v", custom)
	}
	if _, _, err := b.GenerateAccount(context.Background(), "bnd_1", "/apps/data",
		types.BindingMetadata{Config: map[string]string{"path": "not-absolute"}}, nil, false); err == nil {
		t.Fatal("invalid path should be rejected")
	}

	// Deterministic: staging and prod accounts are identical
	staged, _, err := b.GenerateAccount(context.Background(), "bnd_1", "/apps/data", types.BindingMetadata{}, nil, true)
	if err != nil {
		t.Fatalf("GenerateAccount staging: %v", err)
	}
	if staged["url"] != account["url"] || staged["dir"] != account["dir"] {
		t.Fatalf("staging account %v differs from prod %v", staged, account)
	}

	if _, _, err := b.GenerateAccount(context.Background(), "bnd_2", "/apps/derived", types.BindingMetadata{},
		&types.BindingMetadata{}, false); err == nil || !strings.Contains(err.Error(), "derived bindings") {
		t.Fatalf("derived binding error = %v", err)
	}
}

func TestSqliteUnsupportedOperations(t *testing.T) {
	t.Parallel()

	b, err := newTestSqliteBinding(t, map[string]string{}, nil)
	if err != nil {
		t.Fatalf("InitializeService: %v", err)
	}

	if _, err := b.ApplyGrants(context.Background(), nil, types.BindingMetadata{}, types.BindingMetadata{}, false); err == nil ||
		!strings.Contains(err.Error(), "grants") {
		t.Fatalf("ApplyGrants error = %v", err)
	}
	if err := b.RevokeGrants(context.Background(), nil, types.BindingMetadata{}, nil, nil); err == nil {
		t.Fatal("RevokeGrants should error")
	}
	if _, err := b.RunCommand(context.Background(), types.BindingMetadata{}, "select 1"); err == nil ||
		!strings.Contains(err.Error(), "not supported") {
		t.Fatalf("RunCommand error = %v", err)
	}
	if err := b.DeleteArtifact(context.Background(), Artifact{Type: ArtifactDatabase, Name: "x"}); err == nil {
		t.Fatal("DeleteArtifact should error")
	}
	if err := b.CloseService(context.Background()); err != nil {
		t.Fatalf("CloseService: %v", err)
	}
}
