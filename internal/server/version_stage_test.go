// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

// TestGetAppEntryOrStage verifies the stage resolution the single-app APIs
// share: stage selects the staging instance of a prod app, is a no-op on a
// path which already names the staging instance, and leaves a dev app (which
// has no staging instance) as is. stageTargetPath, the audit target of such
// calls, follows the same resolution
func TestGetAppEntryOrStage(t *testing.T) {
	t.Parallel()

	server, db, ctx := newAppAPIMetadataTestServer(t)
	defer db.Close()

	sourceDir := t.TempDir()
	appStar := `app = ace.app("stage test app", static_only=True, index="index.html")`
	if err := os.WriteFile(filepath.Join(sourceDir, "app.star"), []byte(appStar), 0o600); err != nil {
		t.Fatalf("write app.star: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "index.html"), []byte("v1"), 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}

	create := func(path string, req *types.CreateAppRequest) {
		t.Helper()
		tx, err := db.BeginTransaction(ctx)
		if err != nil {
			t.Fatalf("begin transaction: %v", err)
		}
		req.SourceUrl = sourceDir
		if _, err := server.CreateAppTx(ctx, tx, path, true, false, req, nil, server.newBindingAccountManager(false), nil); err != nil {
			_ = tx.Rollback()
			t.Fatalf("create %s: %v", path, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	create("/pathstaged", &types.CreateAppRequest{StageAt: "path"})
	create("/domainstaged", &types.CreateAppRequest{StageAt: "domain"})
	create("/devapp", &types.CreateAppRequest{IsDev: true})

	tests := []struct {
		name     string
		path     string
		stage    bool
		wantPath string
		wantId   string // id prefix
	}{
		{"prod path without stage", "/pathstaged", false, "/pathstaged", types.ID_PREFIX_APP_PROD},
		{"prod path with stage, path based", "/pathstaged", true, "/pathstaged_cl_stage", types.ID_PREFIX_APP_STAGE},
		{"stage path without stage", "/pathstaged_cl_stage", false, "/pathstaged_cl_stage", types.ID_PREFIX_APP_STAGE},
		{"stage path with stage is the stage path", "/pathstaged_cl_stage", true, "/pathstaged_cl_stage", types.ID_PREFIX_APP_STAGE},
		{"prod path with stage, domain based", "/domainstaged", true, "stage.localhost:/domainstaged", types.ID_PREFIX_APP_STAGE},
		{"stage domain path with stage", "stage.localhost:/domainstaged", true, "stage.localhost:/domainstaged", types.ID_PREFIX_APP_STAGE},
		{"dev app with stage is the dev app", "/devapp", true, "/devapp", types.ID_PREFIX_APP_DEV},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := server.getAppEntryOrStage(ctx, types.Transaction{}, tc.path, tc.stage)
			if err != nil {
				t.Fatalf("getAppEntryOrStage(%s, %t): %v", tc.path, tc.stage, err)
			}
			if got := entry.AppPathDomain().String(); got != tc.wantPath {
				t.Errorf("path = %s, want %s", got, tc.wantPath)
			}
			if !strings.HasPrefix(string(entry.Id), tc.wantId) {
				t.Errorf("id = %s, want prefix %s", entry.Id, tc.wantId)
			}
			if got := server.stageTargetPath(ctx, tc.path, tc.stage); got != tc.wantPath {
				t.Errorf("stageTargetPath = %s, want %s", got, tc.wantPath)
			}

			// The same resolution inside a transaction
			tx, err := db.BeginTransaction(ctx)
			if err != nil {
				t.Fatalf("begin transaction: %v", err)
			}
			defer tx.Rollback() //nolint:errcheck
			txEntry, err := server.getAppEntryOrStage(ctx, tx, tc.path, tc.stage)
			if err != nil {
				t.Fatalf("getAppEntryOrStage in tx: %v", err)
			}
			if txEntry.Id != entry.Id {
				t.Errorf("tx id = %s, want %s", txEntry.Id, entry.Id)
			}
		})
	}

	// An unknown app fails the lookup; the audit target then stays the input
	if _, err := server.getAppEntryOrStage(ctx, types.Transaction{}, "/missing", true); err == nil {
		t.Error("expected an error for a missing app")
	}
	if got := server.stageTargetPath(ctx, "/missing", true); got != "/missing" {
		t.Errorf("stageTargetPath of a missing app = %s, want /missing", got)
	}

	// The version APIs resolve the same way: the staging instance's versions
	// through the prod path with stage, or through its own path
	viaFlag, err := server.VersionList(ctx, "/pathstaged", true)
	if err != nil {
		t.Fatalf("version list with stage: %v", err)
	}
	viaPath, err := server.VersionList(ctx, "/pathstaged_cl_stage", false)
	if err != nil {
		t.Fatalf("version list of the stage path: %v", err)
	}
	if len(viaFlag.Versions) == 0 || len(viaFlag.Versions) != len(viaPath.Versions) {
		t.Errorf("stage versions via flag %d, via path %d", len(viaFlag.Versions), len(viaPath.Versions))
	}
	if _, err := server.VersionList(ctx, "/devapp", true); err == nil || !strings.Contains(err.Error(), "dev app") {
		t.Errorf("version list of a dev app with stage must be refused as for a dev app, got %v", err)
	}
}
