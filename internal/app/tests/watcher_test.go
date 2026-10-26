// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// createDiskDevApp boots a dev-mode app from a real directory so the fsnotify
// watcher runs (the in-memory test FS cannot emit file events).
func createDiskDevApp(t *testing.T, dir string) *app.App {
	t.Helper()
	logger := testutil.TestLogger()
	sourceFS, err := appfs.NewSourceFs(logger, dir,
		&appfs.DiskWriteFS{DiskReadFS: appfs.NewDiskReadFS(logger, dir, nil)}, true)
	if err != nil {
		t.Fatalf("create source fs: %v", err)
	}
	workFS := appfs.NewWorkFs("", &TestWriteFS{TestReadFS: &TestReadFS{fileData: map[string]string{}}})

	systemConfig := testSystemConfig()
	systemConfig.FileWatcherDebounceMillis = 100

	secretManager, err := system.NewSecretManager(context.Background(),
		map[string]types.SecretConfig{"env": {}}, "env", &types.ServerConfig{})
	if err != nil {
		t.Fatalf("create secret manager: %v", err)
	}

	metadata := types.AppMetadata{Loads: []string{}, Permissions: []types.Permission{}, ParamValues: map[string]string{}}
	appEntry := &types.AppEntry{
		Id:        "app_dev_watchertest",
		Path:      "/test",
		SourceUrl: dir,
		IsDev:     true,
		Metadata:  metadata,
	}
	a, err := app.NewApp(sourceFS, workFS, logger, appEntry, &systemConfig,
		map[string]types.PluginSettings{}, types.AppConfig{}, nil,
		secretManager.AppEvalTemplateRecord, nil, &types.ServerConfig{}, nil, []*types.Binding{})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	if err := a.Initialize(context.Background(), types.DryRunFalse); err != nil {
		t.Fatalf("initialize app: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func getBody(a *app.App) string {
	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	return response.Body.String()
}

func waitForBody(t *testing.T, a *app.App, what string, markers ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		body := getBody(a)
		found := true
		for _, marker := range markers {
			if !strings.Contains(body, marker) {
				found = false
				break
			}
		}
		if found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not picked up: %q", what, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestWatcherEditDuringReload guards the file-watcher coalescing: an edit
// landing while a reload is in progress, or right after one finished, must
// still be applied by a follow-up reload. The watcher used to drop such
// events entirely (both mid-reload and for a debounce-derived window after
// each reload), so the second of two near-simultaneous edits (editor
// save-all, agent writes) was silently lost and the app served stale content
// until the next unrelated change.
func TestWatcherEditDuringReload(t *testing.T) {
	dir := t.TempDir()
	appStar := `
def handler(req):
    return {"marker": "data-initial"}
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])`
	if err := os.WriteFile(filepath.Join(dir, "app.star"), []byte(appStar), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.go.html"), []byte(`tmpl-initial {{ .Data.marker }}`), 0644); err != nil {
		t.Fatal(err)
	}

	a := createDiskDevApp(t, dir)
	body := getBody(a)
	if !strings.Contains(body, "tmpl-initial") || !strings.Contains(body, "data-initial") {
		t.Fatalf("initial response missing markers: %q", body)
	}

	// Two files written back to back: the first event starts a reload, the
	// second arrives while it is running and must not be lost (it is either
	// covered by the reload's debounce sleep or queued for a follow-up)
	if err := os.WriteFile(filepath.Join(dir, "index.go.html"), []byte(`tmpl-updated {{ .Data.marker }}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.star"), []byte(strings.Replace(appStar, "data-initial", "data-updated", 1)), 0644); err != nil {
		t.Fatal(err)
	}
	waitForBody(t, a, "back-to-back edits", "tmpl-updated", "data-updated")

	// An edit landing right AFTER a reload completed: the old watcher dropped
	// every event for debounce*5 after each reload, losing this change for
	// good. It must trigger its own reload.
	if err := os.WriteFile(filepath.Join(dir, "app.star"), []byte(strings.Replace(appStar, "data-initial", "data-final", 1)), 0644); err != nil {
		t.Fatal(err)
	}
	waitForBody(t, a, "post-reload edit", "data-final")
}
