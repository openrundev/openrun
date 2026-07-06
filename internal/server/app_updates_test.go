// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

// TestReloadAppsImagePreBuildStep runs a verified reload with the image
// pre-build step enabled and disabled. For both settings the reload must
// succeed with identical results, and the pre-build pass (which loads the new
// source under a throwaway transaction) must leave no trace in the committed
// state: the app version is incremented exactly once, by the main reload pass.
func TestReloadAppsImagePreBuildStep(t *testing.T) {
	for _, preBuild := range []bool{true, false} {
		t.Run(fmt.Sprintf("useImagePreBuildStep=%v", preBuild), func(t *testing.T) {
			server, db, ctx := newApplyTestServer(t)
			defer db.Close()
			server.config.System.UseImagePreBuildStep = preBuild
			if err := server.initAuditDB("sqlite:" + filepath.Join(t.TempDir(), "audit.db")); err != nil {
				t.Fatalf("init audit db: %v", err)
			}

			applyDir := t.TempDir()
			t.Setenv("OPENRUN_HOME", applyDir)
			appSourceDir := filepath.Join(applyDir, "app")
			if err := os.Mkdir(appSourceDir, 0700); err != nil {
				t.Fatalf("create app source dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(appSourceDir, "app.star"), []byte(`app = ace.app("preBuildApp")
`), 0600); err != nil {
				t.Fatalf("write app.star: %v", err)
			}

			applyPath := filepath.Join(applyDir, "app.ace")
			applyData := []byte(fmt.Sprintf(`app("/apps/prebuild", %q)
`, appSourceDir))
			if err := os.WriteFile(applyPath, applyData, 0600); err != nil {
				t.Fatalf("write apply file: %v", err)
			}

			_, _, err := server.Apply(ctx, types.Transaction{}, applyPath, "all", false, false, false,
				types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false)
			if err != nil {
				t.Fatalf("apply: %v", err)
			}

			// Change the source so the reload loads a new version
			if err := os.WriteFile(filepath.Join(appSourceDir, "app.star"), []byte(`app = ace.app("preBuildAppUpdated")
`), 0600); err != nil {
				t.Fatalf("update app.star: %v", err)
			}

			response, err := server.ReloadApps(ctx, "/apps/prebuild", true, false, true, "", "", "", false, true)
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			if len(response.ReloadResults) != 2 {
				t.Fatalf("reload results = %v, want stage and prod", response.ReloadResults)
			}
			if len(response.PromoteResults) != 1 {
				t.Fatalf("promote results = %v, want 1 app", response.PromoteResults)
			}

			tx, err := db.BeginTransaction(ctx)
			if err != nil {
				t.Fatalf("begin read transaction: %v", err)
			}
			defer tx.Rollback() //nolint:errcheck
			entry, err := db.GetAppEntryTx(ctx, tx, types.AppPathDomain{Path: "/apps/prebuild"})
			if err != nil {
				t.Fatalf("get app entry: %v", err)
			}
			// create = version 1, reload = version 2; a leaked pre-build
			// transaction would have produced version 3
			if entry.Metadata.VersionMetadata.Version != 2 {
				t.Fatalf("app version = %d, want 2 (pre-build pass must not increment versions)",
					entry.Metadata.VersionMetadata.Version)
			}
			if entry.Metadata.Name != "preBuildAppUpdated" {
				t.Fatalf("app name = %q, want updated source to be live", entry.Metadata.Name)
			}
		})
	}
}
