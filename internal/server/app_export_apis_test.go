// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

// TestDiffLines covers the LCS line diff used by export_app_diff
func TestDiffLines(t *testing.T) {
	t.Parallel()
	rows, changed := diffLines("a\nb\nc\n", "a\nx\nc\n")
	if changed != 2 || len(rows) != 4 {
		t.Fatalf("changed = %d rows = %d, want 2 and 4: %v", changed, len(rows), rows)
	}
	kinds := make([]string, 0, len(rows))
	for _, row := range rows {
		kinds = append(kinds, row["kind"].(string))
	}
	if strings.Join(kinds, ",") != "same,del,add,same" {
		t.Fatalf("kinds = %v", kinds)
	}
	if rows[1]["left_line"].(int) != 2 || rows[1]["right_line"].(int) != 0 {
		t.Fatalf("del row lines = %v", rows[1])
	}
	if rows[2]["left_line"].(int) != 0 || rows[2]["right_line"].(int) != 2 {
		t.Fatalf("add row lines = %v", rows[2])
	}

	if rows, changed := diffLines("a\n", "a\n"); changed != 0 || len(rows) != 1 {
		t.Fatalf("identical diff = %d changed, %d rows", changed, len(rows))
	}
	if rows, changed := diffLines("", "a\nb\n"); changed != 2 || len(rows) != 2 {
		t.Fatalf("empty-left diff = %d changed, %d rows", changed, len(rows))
	}
	if _, changed := diffLines("a\nb\n", ""); changed != 2 {
		t.Fatalf("empty-right diff = %d changed", changed)
	}
}

// TestExportAppVersion covers the per-app version-scoped export: prod and
// staging declarations, version selection, the main-path identity for
// staging exports and the dev/error paths
func TestExportAppVersion(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	// Param updates write audit events, which the bare test server has no
	// audit db for
	if err := server.initAuditDB("sqlite:" + filepath.Join(t.TempDir(), "audit.db")); err != nil {
		t.Fatalf("init audit db: %v", err)
	}

	appSourceDir := writeExportTestAppSource(t)
	if _, err := server.CreateApp(ctx, "/apps/expv", false, false, &types.CreateAppRequest{
		SourceUrl:   appSourceDir,
		ParamValues: map[string]string{"P1": "v1"},
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}

	prodExport, err := server.ExportAppVersion(ctx, "/apps/expv", "", "")
	if err != nil {
		t.Fatalf("export prod: %v", err)
	}
	for _, want := range []string{`app(path="/apps/expv"`, `params={"P1": "v1"}`} {
		if !strings.Contains(prodExport, want) {
			t.Errorf("prod export missing %q:\n%s", want, prodExport)
		}
	}

	// Stage a param change; the staging declaration diverges from prod but
	// still exports with the main app path
	if _, err := server.ReplaceAppParams(ctx, "/apps/expv", false, false, map[string]string{"P1": "v2"}); err != nil {
		t.Fatalf("update params: %v", err)
	}
	stageExport, err := server.ExportAppVersion(ctx, "/apps/expv", "stage", "")
	if err != nil {
		t.Fatalf("export stage: %v", err)
	}
	if !strings.Contains(stageExport, `params={"P1": "v2"}`) {
		t.Errorf("stage export missing updated param:\n%s", stageExport)
	}
	if !strings.Contains(stageExport, `app(path="/apps/expv"`) || strings.Contains(stageExport, "_cl_stage") {
		t.Errorf("stage export must use the main app path:\n%s", stageExport)
	}

	// The prod declaration is unchanged until promote
	prodExport2, err := server.ExportAppVersion(ctx, "/apps/expv", "prod", "")
	if err != nil {
		t.Fatalf("export prod again: %v", err)
	}
	if prodExport2 != prodExport {
		t.Errorf("prod export changed by a staging-only update:\n%s\nvs\n%s", prodExport, prodExport2)
	}

	// Diff between the two active versions
	diff, err := server.ExportAppDiff(ctx, "/apps/expv", "prod:", "stage:")
	if err != nil {
		t.Fatalf("export diff: %v", err)
	}
	if diff["changed"].(int) == 0 {
		t.Errorf("diff reports no changes for diverged staging: %v", diff)
	}

	// Version-scoped export: after a promote, the old prod version still
	// exports its own params
	if _, err := server.PromoteApps(ctx, "/apps/expv", false); err != nil {
		t.Fatalf("promote: %v", err)
	}
	oldVersion, err := server.ExportAppVersion(ctx, "/apps/expv", "prod", "1")
	if err != nil {
		t.Fatalf("export old version: %v", err)
	}
	if !strings.Contains(oldVersion, `params={"P1": "v1"}`) {
		t.Errorf("version 1 export missing original param:\n%s", oldVersion)
	}
	newVersion, err := server.ExportAppVersion(ctx, "/apps/expv", "prod", "")
	if err != nil {
		t.Fatalf("export new version: %v", err)
	}
	if !strings.Contains(newVersion, `params={"P1": "v2"}`) {
		t.Errorf("promoted export missing updated param:\n%s", newVersion)
	}

	// Identical versions diff clean
	sameDiff, err := server.ExportAppDiff(ctx, "/apps/expv", "prod:", "stage:")
	if err != nil {
		t.Fatalf("export diff after promote: %v", err)
	}
	if sameDiff["changed"].(int) != 0 {
		t.Errorf("diff after promote reports changes: %v", sameDiff)
	}

	// Error paths
	if _, err := server.ExportAppVersion(ctx, "/apps/expv", "bogus", ""); err == nil {
		t.Error("invalid env did not fail")
	}
	if _, err := server.ExportAppVersion(ctx, "/apps/expv", "prod", "99"); err == nil {
		t.Error("missing version did not fail")
	}
	if _, err := server.ExportAppDiff(ctx, "/apps/expv", "nope", "stage:"); err == nil {
		t.Error("invalid version spec did not fail")
	}
}

// TestVersionFileContent covers the one-file version read used by the files
// viewer
func TestVersionFileContent(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	appSourceDir := writeExportTestAppSource(t)
	if _, err := server.CreateApp(ctx, "/apps/vfile", false, false, &types.CreateAppRequest{
		SourceUrl: appSourceDir,
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}

	content, err := server.VersionFileContent(ctx, "/apps/vfile", "", "app.star")
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !strings.Contains(content, "testApp") {
		t.Errorf("file content = %q", content)
	}

	if _, err := server.VersionFileContent(ctx, "/apps/vfile", "", "missing.star"); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Errorf("missing file error = %v", err)
	}
	if _, err := server.VersionFileContent(ctx, "/apps/vfile", "7", "app.star"); err == nil {
		t.Error("missing version did not fail")
	}
}
